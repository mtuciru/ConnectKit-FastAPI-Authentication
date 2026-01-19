from datetime import datetime, timezone
from typing import Callable, Any, ParamSpec

from database.asyncio.session import AsyncDatabase
from fastapi.dependencies.models import Dependant, SecurityRequirement
from fastapi.openapi.models import SecurityBase as SecurityBaseModel, HTTPBearer, HTTPBase
from fastapi.security.base import SecurityBase
from sqlalchemy import select
from sqlalchemy.orm import load_only
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection
from starlette.responses import Response
from starlette.types import ASGIApp, Scope, Receive, Send

from oauth2lib.errors import InvalidTokenError, OAuth2Error, InvalidDPoPProof
from oauth2lib.tokens import dpop_validate, dpop_present, dpop_ath_create
from .. import models
from ..control.hooks import get_nonce_by_key, validate_jti
from ..oauth.fingerprint import create_fingerprint
from ..oauth.tokens import decode_token

__all__ = ["CredentialsPlaceholder", "UserCredentials", "ClientCredentials",
           "UserPlaceholder", "EndUser", "ClientUser",
           "AuthenticationMiddleware", "mark_as_use_basic"]


class CredentialsPlaceholder:
    """
    If Authorization header with Bearer or DPoP token not specified by client, instance of this type added to request.auth
    """

    @property
    def is_authenticated(self) -> bool:
        return False


_default_none_session = CredentialsPlaceholder()


class UserCredentials(CredentialsPlaceholder):
    """
    If Authorization header with Bearer or DPoP token points to End-User
    (direct-mode by user credentials or indirect-mode by authorization_code, implicit or device_code grant)
    and token successful validated, then instance of this type added to request.auth
    """

    @property
    def is_authenticated(self) -> bool:
        return True

    def __init__(self, /, **kwargs):
        # Via uid endpoint can request additional info about session.
        self._uid: str = kwargs["uid"]
        # User id on whose behalf request done
        self._user_id: int = kwargs["user_id"]
        # Client id who made request (if client used)
        self._client_id: int | None = kwargs.get("client_id")
        # External client id via that End-User was authenticated (if external client used)
        self._external_client_id: int | None = kwargs.get("external_client_id")
        # Last time when reauthentication done (used for process max_age parameter)
        self._reauthenticated_at: datetime = kwargs["reauthenticated_at"]
        # List of used auth mechanisms (used for process amr constrains)
        self._amr: list[str] = kwargs["amr"]
        # Mark that additional authentification required for complete authentification process
        # Standard decorators return error if this is True
        self._mfa_waiting: bool = kwargs["mfa_waiting"]
        # Scopes granted to session
        self._scopes: set[str] = kwargs["scopes"]

    @property
    def uid(self) -> str:
        return self._uid

    @property
    def user_id(self) -> int:
        return self._user_id

    @property
    def client_id(self) -> int | None:
        return self._client_id

    @property
    def external_client_id(self) -> int | None:
        return self._external_client_id

    @property
    def reauthenticated_at(self) -> datetime:
        return self._reauthenticated_at

    @property
    def amr(self) -> list[str]:
        return self._amr

    @property
    def mfa_waiting(self) -> bool:
        return self._mfa_waiting

    @property
    def scopes(self) -> set[str]:
        return self._scopes


class ClientCredentials(CredentialsPlaceholder):
    """
    If Authorization header with Bearer or DPoP token points to Client (client_credential grant)
    and token successful validated, then instance of this type added to request.auth
    """

    @property
    def is_authenticated(self) -> bool:
        return True

    def __init__(self, /, **kwargs):
        # Via uid endpoint can request additional info about session.
        self._uid: str = kwargs["uid"]
        # Client id who made request
        self._client_id: int = kwargs.get("client_id")
        # Scopes granted to session
        self._scopes: set[str] = kwargs["scopes"]

    @property
    def uid(self) -> str:
        return self._uid

    @property
    def client_id(self) -> int:
        return self._client_id

    @property
    def scopes(self) -> set[str]:
        return self._scopes


class UserPlaceholder:
    """
    If session is incomplete or session is None, then instance of this type added to request as request.user
    """

    @property
    def is_authenticated(self) -> bool:
        raise False

    @property
    def display_name(self) -> str:
        return ""

    @property
    def identity(self) -> str:
        return ""


_default_none_user = UserPlaceholder()


class EndUser(UserPlaceholder):
    """
    If session point to EndUser and session complete, then instance of this type added to request as request.user
    """

    @property
    def is_authenticated(self) -> bool:
        raise True

    @property
    def display_name(self) -> str:
        return self._login

    @property
    def identity(self) -> str:
        return self._login

    def __init__(self, /, **kwargs):
        self._id: int = kwargs["id"]
        self._login: str = kwargs["login"]
        self._active: bool = kwargs["active"]
        self._provider: bool = kwargs.get("provider", False)

    @property
    def id(self) -> int:
        return self._id

    @property
    def login(self) -> str:
        return self._login

    @property
    def active(self) -> bool:
        return self._active

    @property
    def provider_user(self) -> bool:
        return self._provider


class ClientUser(UserPlaceholder):
    """
    If session point to ClientUser, then instance of this type added to request as request.user
    """

    @property
    def is_authenticated(self) -> bool:
        raise True

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def identity(self) -> str:
        return self._client_id

    def __init__(self, /, **kwargs):
        self._id: int = kwargs["id"]
        self._display_name: str = kwargs["display_name"]
        self._client_id: str = kwargs["client_id"]
        self._confidential: bool = kwargs["confidential"]
        self._transparent: bool = kwargs["transparent"]

    @property
    def id(self) -> int:
        return self._id

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def confidential(self) -> bool:
        return self._confidential

    @property
    def transparent(self) -> bool:
        return self._transparent


async def _process_token_stage_1(
        token: str, token_type: str | None, connection: HTTPConnection
) -> (tuple[str, models.OAuth2ProviderSession | models.OAuth2UserSession | models.OAuth2ClientSession] |
      tuple[None, None]):
    async def validate_dpop_constrain(
            session: models.OAuth2ProviderSession | models.OAuth2UserSession | models.OAuth2ClientSession,
            token_: str,
            token_type_: str,
            token_jti: str,
            connection_: HTTPConnection,
            now_: datetime,
    ):
        if session.dpop_jkt is not None:
            # This must be DPoP token type
            if token_type_ is None:
                token_type_ = "dpop"
            if token_type_ != "dpop":
                # Token must be sent as DPoP
                raise InvalidDPoPProof()
            # This session required DPoP token
            if not dpop_present(connection_):
                raise InvalidDPoPProof()
            bound_nonce = await get_nonce_by_key(token_jti)
            _, dpop_iat, dpop_jti = dpop_validate(connection_, bound_nonce,
                                                  session.dpop_jkt, dpop_ath_create(token_))
            if not await validate_jti(dpop_jti, now_):
                raise InvalidDPoPProof()
        else:
            # This must be Bearer token type
            if token_type_ is None:
                token_type_ = "bearer"
            if token_type_ != "bearer":
                return None
        return token_type_

    payload = decode_token(token, "access")
    if payload is None:
        # Wrong token
        return None, None
    async with AsyncDatabase() as db:
        # Check revoke list
        revoked = db.scalar(select(models.OAuth2AccessRevoked).options(
            load_only(models.OAuth2AccessRevoked.uid, models.OAuth2AccessRevoked.jti),
        ).filter_by(
            uid=payload["sub"], jti=payload["jti"]
        ))
        if revoked is not None:
            # Access token was revoked
            return None, None
        now = datetime.now(tz=timezone.utc)
        # Find provider session
        if payload["typ"] == "p":
            # uid, fingerprint, dpop_jkt, expire_mfa_at validating in this place
            # user_id, reauthenticated_at, amr validating in decorators (at this moment we don't know constrains)
            provider_session: models.OAuth2ProviderSession = await db.scalar(
                select(models.OAuth2ProviderSession).options(
                    load_only(
                        models.OAuth2ProviderSession.uid, models.OAuth2ProviderSession.user_id,
                        models.OAuth2ProviderSession.client_id, models.OAuth2ProviderSession.external_client_id,
                        models.OAuth2ProviderSession.reauthenticated_at, models.OAuth2ProviderSession.fingerprint,
                        models.OAuth2ProviderSession.dpop_jkt, models.OAuth2ProviderSession.amr,
                        models.OAuth2ProviderSession.mfa_waiting, models.OAuth2ProviderSession.expire_mfa_at
                    )
                ).filter_by(uid=payload["sub"]))
            if provider_session is None:
                # Session not exists at all
                return None, None
            # Current fingerprint
            fingerprint = create_fingerprint(connection)
            if provider_session.fingerprint != fingerprint:
                # If fingerprint changed, changed headers or ip.
                # For security, revoking any authentication after first
                provider_session.fingerprint = fingerprint
                provider_session.reauthenticated_at = provider_session.started_at
                await db.commit()
            if provider_session.mfa_waiting:
                if provider_session.expire_mfa_at is not None and provider_session.expire_mfa_at < now:
                    # MFA period expired, remove session
                    await db.delete(provider_session)
                    await db.commit()
                    return None, None
            token_type = await validate_dpop_constrain(provider_session, token, token_type,
                                                       payload["jti"], connection, now)
            if token_type is None:
                return None, None
            db.expunge(provider_session)
            return payload["typ"], provider_session
        # Find client user session
        if payload["typ"] == "u":
            # uid, access_bound_ip, dpop_jkt validating in this place
            # user_id, client_id, scope, reauthenticated_at, amr validating in decorators (at this moment we don't know constrains)
            user_session: models.OAuth2UserSession = await db.scalar(
                select(models.OAuth2UserSession).options(
                    load_only(
                        models.OAuth2UserSession.uid, models.OAuth2UserSession.user_id,
                        models.OAuth2UserSession.client_id, models.OAuth2UserSession.scope,
                        models.OAuth2UserSession.reauthenticated_at, models.OAuth2UserSession.access_bound_ip,
                        models.OAuth2UserSession.dpop_jkt, models.OAuth2ProviderSession.amr
                    )
                ).filter_by(uid=payload["sub"]))
            if user_session is None:
                # Session not exists at all
                return None, None
            client_ip = connection.client.host
            if user_session.access_bound_ip is not None and user_session.access_bound_ip != client_ip:
                # Wrong IP access. Should we close session?
                return None, None
            token_type = await validate_dpop_constrain(user_session, token, token_type,
                                                       payload["jti"], connection, now)
            if token_type is None:
                return None, None
            db.expunge(user_session)
            return payload["typ"], user_session
        # Find client session
        if payload["typ"] == "c":
            # uid, access_bound_ip, dpop_jkt validating in this place
            # client_id, scope validating in decorators (at this moment we don't know constrains)
            client_session: models.OAuth2ClientSession = await db.scalar(
                select(models.OAuth2ClientSession).options(
                    load_only(
                        models.OAuth2ClientSession.uid, models.OAuth2ClientSession.client_id,
                        models.OAuth2ClientSession.scope, models.OAuth2ClientSession.access_bound_ip,
                        models.OAuth2ClientSession.dpop_jkt
                    )
                ).filter_by(uid=payload["sub"]))
            if client_session is None:
                # Session not exists at all
                return None, None
            client_ip = connection.client.host
            if client_session.access_bound_ip is not None and client_session.access_bound_ip != client_ip:
                # Wrong IP access. Should we close session?
                return None, None
            token_type = await validate_dpop_constrain(client_session, token, token_type,
                                                       payload["jti"], connection, now)
            if token_type is None:
                return None, None
            db.expunge(client_session)
            return payload["typ"], client_session
        return None, None


async def _process_token_stage_2(
        session_type: str,
        session: models.OAuth2ProviderSession | models.OAuth2UserSession | models.OAuth2ClientSession
) -> tuple[CredentialsPlaceholder, UserPlaceholder] | tuple[None, None]:
    # Note:
    # In this function don't check UserLock.block and OAuth2Client.enabled fields.
    # Because this fields checks before session created
    # and all relative opened sessions must be closed when this fields set to True and False, respectively.
    # So, while waiting for the correct operation, we process the token a little faster
    async with AsyncDatabase() as db:
        if session_type == "p":
            provider_session: models.OAuth2ProviderSession = session
            if provider_session.mfa_waiting:
                # Partial complete session, EndUser not created
                credentials = UserCredentials(
                    uid=provider_session.uid,
                    user_id=provider_session.user_id,
                    client_id=provider_session.client_id,
                    external_client_id=provider_session.external_client_id,
                    reauthenticated_at=provider_session.reauthenticated_at,
                    amr=provider_session.amr.split(),
                    mfa_waiting=provider_session.mfa_waiting,
                    # Scopes empty because session is incomplete, only complete functions allowed
                    scopes=set()
                )
                return credentials, _default_none_user
            user: models.User = await db.scalar(select(models.User).options(
                load_only(
                    models.User.id, models.User.login, models.User.active, models.User.scope
                )
            ).filter_by(id=provider_session.user_id))
            credentials = UserCredentials(
                uid=provider_session.uid,
                user_id=provider_session.user_id,
                client_id=provider_session.client_id,
                external_client_id=provider_session.external_client_id,
                reauthenticated_at=provider_session.reauthenticated_at,
                amr=provider_session.amr.split(),
                mfa_waiting=provider_session.mfa_waiting,
                # Provider session use scope value from user
                scopes=set(user.scope.split()),
            )
            end_user = EndUser(
                id=user.id,
                login=user.login,
                active=user.active,
                provider=True
            )
            return credentials, end_user
        if session_type == "u":
            user_session: models.OAuth2UserSession = session
            user: models.User = await db.scalar(select(models.User).options(
                load_only(
                    models.User.id, models.User.login, models.User.active
                )
            ).filter_by(id=user_session.user_id))
            credentials = UserCredentials(
                uid=user_session.uid,
                user_id=user_session.user_id,
                client_id=user_session.client_id,
                external_client_id=None,
                reauthenticated_at=user_session.reauthenticated_at,
                amr=user_session.amr.split(),
                mfa_waiting=False,
                # UserSession session use scope value from itself
                scopes=set(user_session.scope.split()),
            )
            end_user = EndUser(
                id=user.id,
                login=user.login,
                active=user.active
            )
            return credentials, end_user
        if session_type == "c":
            client_session: models.OAuth2ClientSession = session
            client: models.OAuth2Client = await db.scalar(select(models.OAuth2Client).options(
                load_only(
                    models.OAuth2Client.id, models.OAuth2Client.display_name, models.OAuth2Client.client_id,
                    models.OAuth2Client.enabled, models.OAuth2Client.confidential, models.OAuth2Client.transparent
                )
            ).filter_by(id=client_session.client_id))
            credentials = ClientCredentials(
                uid=client_session.uid,
                client_id=client_session.client_id,
                scopes=set(client_session.scope.split()),
            )
            client_user = ClientUser(
                id=client.id,
                display_name=client.display_name,
                client_id=client.client_id,
                confidential=client.confidential,
                transparent=client.transparent
            )
            return credentials, client_user
    return None, None


def _extract_token(header: str) -> tuple[str, str] | tuple[None, None]:
    # Get bearer or dpop token or None
    components = header.split()
    if len(components) != 2:
        return None, None
    if components[0].lower() not in ["bearer", "dpop"]:
        return None, None
    return components[0].lower(), components[1]


def _extract_used_schemes(connection: HTTPConnection) -> list[str]:
    # We save only recognized schemes, other ignored but counted later
    used_schemes = []
    for value in connection.headers.getlist("Authorization"):
        components = value.split(maxsplit=1)
        if len(components) == 0:
            continue
        name = components[0].lower()
        if name in ["bearer", "dpop"]:
            used_schemes.append(name)
    return list(set(used_schemes))


class AuthenticationMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    async def _websocket_invalid_token(receive: Receive, send: Send, protocol: str | None, error: str):
        # receive websocket.connect
        await receive()
        await send({"type": "websocket.accept", "subprotocol": protocol, "headers": None})
        await send({"type": "websocket.close", "code": 3000, "reason": error})

    async def _bad_token_error(self, scope: Scope, receive: Receive, send: Send,
                               protocol: str | None, used_schemes: list[str] | None):
        error = InvalidTokenError()
        await self._send_error(scope, receive, send, protocol, used_schemes, error)

    async def _send_error(self, scope: Scope, receive: Receive, send: Send,
                          protocol: str | None, used_schemes: list[str] | None, error: OAuth2Error):
        if scope["type"] == "websocket":
            await self._websocket_invalid_token(receive, send, protocol, error.error)
        else:
            headers = {
                "Content-Type": "application/json",
            }
            headers.update(error.headers(["Bearer", "DPoP"], used_schemes))
            response = Response(content=error.json, status_code=error.status_code, headers=headers)
            await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        If client send Authorization, we must process token.
        """
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return
        connection = HTTPConnection(scope)
        # We can catch in this place preflight requests from browser, but...
        # Preflight request may be caused by:
        #   - well-known metadata locations
        #   - /oauth/token
        #   - /oauth/revoke
        #   - /oauth/introspect
        #   - /oauth/userinfo
        # If browser-based client add Authorization header and optional DPoP to request
        # So only for this methods will be created OPTIONS handler.
        scope["auth"] = CredentialsPlaceholder
        scope["user"] = UserPlaceholder
        protocol = None
        used_schemes = _extract_used_schemes(connection)
        auth_header = connection.headers.get("Authorization", None)
        auth_header_count = len(connection.headers.getlist("Authorization"))
        if scope["type"] == "http":
            if auth_header_count > 1:
                await self._bad_token_error(scope, receive, send, protocol, used_schemes)
                return
            if auth_header is None:
                await self.app(scope, receive, send)
                return
            token_type, token = _extract_token(auth_header)
        else:  # if scope["type"] == "websocket"
            if auth_header_count > 1:
                await self._websocket_invalid_token(receive, send, protocol, "invalid_token")
                return
            # Not all websocket implementations can add Authorization header, use alternative scheme
            if auth_header is None:
                # Use subprotocol extension
                # We're expecting receive in end of protocol list:
                #   ["Authorization", "<token>"] or ["Authorization", "<token>", "<dpop>"]
                # or
                #   ["Bearer", "<token>"]
                # or
                #   ["DPoP", "<token>", "<dpop>"]
                # where first value is case-insensitive.
                # If these are the only values in protocols list, first subprotocol will be accepted
                # Otherwise selection of subprotocol work as usual
                protocols = connection.headers.get("Sec-WebSocket-Protocol")
                if protocols is None:
                    # Authorization not specified
                    await self.app(scope, receive, send)
                    return
                protocols = list(map(lambda x: x.strip(), protocols.split(",")))
                token_id = None
                dpop_token_id = None
                # Auth part of protocol list has size 2 or 3
                if len(protocols) < 2:
                    # Authorization not specified
                    await self.app(scope, receive, send)
                    return
                # Scheme [-3, -2, -1]
                # Check bearer and guess
                if protocols[-2].lower() in ["authorization", "bearer"]:
                    # It's like bearer
                    protocol = protocols[-2]
                    token_type = "bearer"
                    token = protocols[-1]
                    scope["auth_protocol"] = protocol
                elif len(protocols) > 2 and protocols[-3].lower() in ["authorization", "dpop"]:
                    protocol = protocols[-3]
                    token_type = "dpop"
                    token = protocols[-2]
                    dpop_token = protocol[-1]
                    if dpop_present(connection):
                        await self._websocket_invalid_token(receive, send, protocol, "invalid_request")
                        return
                    mutable = connection.headers.mutablecopy()
                    mutable.append("DPoP", dpop_token)
                    connection._headers = Headers(raw=mutable.raw)
                    scope["auth_protocol"] = protocol
                else:
                    # Token not specified
                    await self.app(scope, receive, send)
                    return
            else:
                token_type, token = _extract_token(auth_header)
        if token is None:
            # Authorization not specified
            await self.app(scope, receive, send)
            return
        try:
            session_type, session = await _process_token_stage_1(token, token_type, connection)
        except OAuth2Error as e:
            e.status_code = 401
            await self._send_error(scope, receive, send, protocol, used_schemes, e)
            return
        if session is None:
            # Token is revoked or session is closed
            await self._bad_token_error(scope, receive, send, protocol, used_schemes)
            return
        cred, user_or_client = await _process_token_stage_2(session_type, session)
        if cred is None:
            # Some strange, but simple return bad_token
            await self._bad_token_error(scope, receive, send, protocol, used_schemes)
            return
        scope["auth"] = cred
        scope["user"] = user_or_client
        await self.app(scope, receive, send)


class AuthenticationScheme(SecurityBase):
    def __init__(self, scheme_name: str, model: SecurityBaseModel):
        self.scheme_name = scheme_name
        self.model = model


_secure_model_basic = AuthenticationScheme(
    "Basic client authorization",
    HTTPBase.model_validate({
        "scheme": "basic"
    })
)

_secure_model_bearer = AuthenticationScheme(
    "Standard access token",
    HTTPBearer.model_validate({
        "scheme": "bearer",
        "bearerFormat": "JWT"
    })
)

_secure_model_dpop = AuthenticationScheme(
    "Access token with proof",
    HTTPBase.model_validate({
        "scheme": "dpop",
    })
)

_P = ParamSpec("_P")


def mark_as_use_basic(
        func: Callable[_P, Any],
) -> Callable[_P, Any]:
    setattr(func, "__security_basic__", True)
    return func


def __patch_dependant():
    def has_security(security_list: list[SecurityRequirement], check_list: list[AuthenticationScheme]) -> bool:
        for requirement in security_list:
            if requirement.security_scheme in check_list:
                return True
        return False

    def post_init(self: Dependant) -> None:
        if hasattr(self.call, "__security__"):
            security_bearer_dpop = getattr(self.call, "__security__", None)
            if not has_security(self.security_requirements, [_secure_model_bearer, _secure_model_dpop]):
                self.security_requirements.append(SecurityRequirement(security_scheme=_secure_model_bearer,
                                                                      scopes=security_bearer_dpop))
                self.security_requirements.append(SecurityRequirement(security_scheme=_secure_model_dpop,
                                                                      scopes=security_bearer_dpop))
                self.security_scopes = security_bearer_dpop
            delattr(self.call, "__security__")
        if hasattr(self.call, "__security_basic__"):
            if not has_security(self.security_requirements, [_secure_model_basic]):
                self.security_requirements.append(SecurityRequirement(security_scheme=_secure_model_basic))
            delattr(self.call, "__security_basic__")
        self.cache_key = (self.call, tuple(sorted(set(self.security_scopes or []))))

    Dependant.__post_init__ = post_init


__patch_dependant()

_websocket_patched: bool = False


def _patch_websocket():
    global _websocket_patched
    if _websocket_patched:
        return
    from starlette.websockets import WebSocket
    from typing import Iterable

    WebSocket.original_accept = WebSocket.accept

    async def auth_accept(
            self,
            subprotocol: str | None = None,
            headers: Iterable[tuple[bytes, bytes]] | None = None,
    ) -> None:
        if subprotocol is None:
            subprotocol = self.scope.get("auth_protocol")
        await self.original_accept(subprotocol, headers)

    WebSocket.accept = auth_accept
    _websocket_patched = True
