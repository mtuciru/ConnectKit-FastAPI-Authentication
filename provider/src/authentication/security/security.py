from datetime import datetime, timezone, timedelta

from database import AsyncDatabase
from fastapi import Depends
from fastapi.security import SecurityScopes, OpenIdConnect
from sqlalchemy import select
from sqlalchemy.orm import load_only
from starlette.datastructures import Headers
from starlette.requests import HTTPConnection

from oauth2lib import errors
from oauth2lib.tokens import dpop_present, dpop_validate, dpop_ath_create
from .containers import *
from .handler import ExceptionContainer
from .. import models
from ..control.hooks import get_nonce_by_key, validate_jti, check_required_scopes, check_required_acr
from ..oauth.fingerprint import create_fingerprint
from ..oauth.tokens import decode_token
from oauth2lib.endpoints.metadata import well_known_oauth, well_known_oidc

__all__ = ["custom_oauth2_scheme", "anonymous_user_dependency", "AuthenticatedUserDependency",
           "AuthenticatedClientDependency", "MaybeAuthenticatedUserDependency"]


# Use OpenID Connect because metadata about flows not allowed before first call to metadata endpoint.
# So, simple expose metadata url
class CustomOAuth2Security(OpenIdConnect):
    """
    Setup request.auth and request.user when called.

    Return True if authenticated session (and maybe user, if it is complete session).
    Return False if not authenticated session.
    """

    def __init__(self):
        super().__init__(openIdConnectUrl=well_known_oauth,
                         scheme_name="OAuth2Extended",
                         description="OAuth2 with OpenID Connect")

    def configure_openid_connect_url(self):
        from ..settings import function_settings
        if function_settings.oidc_enable:
            self.model.openIdConnectUrl = well_known_oidc
        else:
            self.model.openIdConnectUrl = well_known_oauth

    @staticmethod
    def _extract_auth_information(connection: HTTPConnection) -> tuple[int, list[str], str | None]:
        # We save in 'used_schemes' only recognized schemes, other ignored but counted
        schemes = connection.headers.getlist("Authorization")
        used_schemes = []
        for value in schemes:
            components = value.split(maxsplit=1)
            if len(components) == 0:
                continue
            name = components[0].lower()
            if name in ["bearer", "dpop"]:
                used_schemes.append(name)
        # Count of Authorization headers, list of recognized schemes, actual header value (if exactly one)
        return len(schemes), list(set(used_schemes)), schemes[0] if len(schemes) == 1 else None

    @staticmethod
    def _extract_token_from_header(header_value: str) -> tuple[str, str] | tuple[None, None]:
        # Get bearer or dpop token or None
        components = header_value.split()
        if len(components) != 2:
            return None, None
        if components[0].lower() not in ["bearer", "dpop"]:
            return None, None
        return components[0].lower(), components[1]

    def _websocket_invalid_token(self, protocol: str | None):
        self._raise_error(error=errors.InvalidTokenError(), protocol=protocol, websocket_status=3000)

    def _websocket_any_error(self, error: errors.OAuth2Error, protocol: str | None):
        self._raise_error(error=error, protocol=protocol, websocket_status=3003)

    def _http_invalid_token(self, used_schemes: list[str] | None):
        self._raise_error(error=errors.InvalidTokenError(), used_schemes=used_schemes)

    def _http_any_error(self, error: errors.OAuth2Error, used_schemes: list[str] | None):
        self._raise_error(error=error, used_schemes=used_schemes)

    @staticmethod
    def _raise_error(error: errors.OAuth2Error,
                     used_schemes: list[str] | None = None,
                     protocol: str | None = None,
                     websocket_status: int | None = None):
        exception = ExceptionContainer(
            error=error,
            schemes=["Bearer", "DPoP"],
            used_schemes=used_schemes,
            protocol=protocol,
            websocket_status=websocket_status,
            use_detail=True
        )
        raise exception

    @staticmethod
    async def _validate_dpop_constrain(
            session: models.OAuth2ProviderSession | models.OAuth2UserSession | models.OAuth2ClientSession,
            access_token: str,
            access_token_type: str,
            access_token_jti: str,
            connection: HTTPConnection,
            now: datetime,
    ):
        """
        Validate DPoP token.

        Check that DPoP token required for access token.
        Check that DPoP token is valid.
        """
        if session.dpop_jkt is not None:
            # This session require bound to DPoP token access token
            if access_token_type is None:
                access_token_type = "dpop"
            if access_token_type != "dpop":
                # Token must be sent as DPoP
                raise errors.InvalidDPoPProof()
            if not dpop_present(connection):
                raise errors.InvalidDPoPProof()
            # Get current dpop nonce value bound to access_token_jti
            bound_nonce = await get_nonce_by_key(access_token_jti)
            # Validate DPoP token, error may be raised
            _, dpop_iat, dpop_jti = dpop_validate(connection, bound_nonce,
                                                  str(session.dpop_jkt), dpop_ath_create(access_token))
            # Check that this DPoP already used in time window
            if not await validate_jti(dpop_jti, now):
                raise errors.InvalidDPoPProof()
        else:
            # This session don't use DPoP tokens
            if access_token_type is None:
                access_token_type = "bearer"
            if access_token_type != "bearer":
                raise errors.InvalidTokenError()
        return access_token_type

    async def _process_token_stage(
            self, token: str, token_type: str | None, connection: HTTPConnection
    ) -> (tuple[str, models.OAuth2ProviderSession | models.OAuth2UserSession | models.OAuth2ClientSession] |
          tuple[None, None]):
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
                token_type = await self._validate_dpop_constrain(provider_session, token, token_type,
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
                token_type = await self._validate_dpop_constrain(user_session, token, token_type,
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
                token_type = await self._validate_dpop_constrain(client_session, token, token_type,
                                                                 payload["jti"], connection, now)
                if token_type is None:
                    return None, None
                db.expunge(client_session)
                return payload["typ"], client_session
            return None, None

    @staticmethod
    async def _process_session_stage(
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
                    return credentials, user_placeholder
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
                        models.OAuth2Client.enabled, models.OAuth2Client.confidential
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
                    confidential=client.confidential
                )
                return credentials, client_user
        return None, None

    async def __call__(self, connection: HTTPConnection) -> bool:
        """
        Check that client sent token, this token is valid and session exists.

        return:
            True - successfully authentication (with complete or incomplete session)
            False - not authenticated
        if token received but malformed or invalid:
            raise ExceptionContainer
        """
        connection_type = connection.scope["type"]
        connection.scope["auth"] = credentials_placeholder
        connection.scope["user"] = user_placeholder
        protocol = None
        auth_header_count, used_schemes, auth_header = self._extract_auth_information(connection)
        connection.scope["auth_used_schemes"] = used_schemes
        if connection_type == "http":
            if auth_header_count > 1:
                self._http_invalid_token(used_schemes)
            if auth_header is None:
                return False
            token_type, token = self._extract_token_from_header(auth_header)
        else:  # if scope["type"] == "websocket"
            if auth_header_count > 1:
                protocols = connection.headers.get("Sec-WebSocket-Protocol")
                if protocols is None:
                    self._websocket_invalid_token(None)
                else:
                    # For suppress websocket subprotocol mismatch error
                    protocols = list(map(lambda x: x.strip(), protocols.split(",")))
                    self._websocket_invalid_token(protocols[0] if len(protocols) > 0 else None)
            # Not all websocket implementations can add Authorization header, check usage of alternative scheme
            if auth_header is None:
                # Use subprotocol for specifying authorization token and dpop if required
                # We're expecting receive in end of protocol list:
                #   ["Authorization", "<token>"]
                # or
                #   ["Authorization", "<token>", "<dpop>"]
                # or
                #   ["Bearer", "<token>"]
                # or
                #   ["DPoP", "<token>", "<dpop>"]
                # where first value is case-insensitive.
                # If these are the only values in protocols list, first subprotocol will be accepted
                # Otherwise selection of subprotocol work as usual
                protocols = connection.headers.get("Sec-WebSocket-Protocol")
                if protocols is None:
                    # Token not specified
                    return False
                protocols = list(map(lambda x: x.strip(), protocols.split(",")))
                # Auth part of protocol list has size 2 or 3
                if len(protocols) < 2:
                    # Token not specified
                    return False
                # Scheme [..., -3, -2, -1] for dpop variant
                # Scheme [..., -2, -1] for bearer variant
                # Try bearer (because use less length)
                if protocols[-2].lower() in ["authorization", "bearer"]:
                    # It's like bearer
                    # Actual auth protocol (used for accept)
                    protocol = protocols[-2]
                    token_type = "bearer"
                    token = protocols[-1]
                elif len(protocols) > 2 and protocols[-3].lower() in ["authorization", "dpop"]:
                    protocol = protocols[-3]
                    token_type = "dpop"
                    token = protocols[-2]
                    dpop_token = protocol[-1]
                    if dpop_present(connection):
                        # Bad request, dpop sent via header and subprotocol
                        self._websocket_any_error(errors.InvalidDPoPProof(), protocol)
                    # Emulate that DPoP header sent
                    mutable = connection.headers.mutablecopy()
                    mutable.append("DPoP", dpop_token)
                    connection._headers = Headers(raw=mutable.raw)
                    connection.scope["headers"] = list(mutable.raw)
                else:
                    # Token not specified
                    return False
            else:
                token_type, token = self._extract_token_from_header(auth_header)
        if token is None:
            # Token not specified
            return False
        # Token specified. If we can't extract session, error will be raised
        session_type, session = None, None
        try:
            session_type, session = await self._process_token_stage(token, token_type, connection)
        except errors.OAuth2Error as e:
            # Any validation errors
            if connection_type == "http":
                self._http_any_error(e, used_schemes)
            else:
                self._websocket_any_error(e, protocol)
        if session is None:
            # Token is revoked or session is closed
            if connection_type == "http":
                self._http_invalid_token(used_schemes)
            else:
                self._websocket_invalid_token(protocol)
        # If session is not None, credential and user_or_client always specified
        credentials, user_or_client = await self._process_session_stage(session_type, session)
        # Modify scope
        connection.scope["auth"] = credentials
        connection.scope["user"] = user_or_client
        if connection_type == "websocket":
            connection.scope["auth_websocket_protocol"] = protocol
        return True


custom_oauth2_scheme: CustomOAuth2Security = CustomOAuth2Security()


async def anonymous_user_dependency(
        connection: HTTPConnection,
        status: bool = Depends(custom_oauth2_scheme)
) -> UserPlaceholder:
    if not status:
        return connection.user
    raise ExceptionContainer(
        error=errors.AccessDeniedError(),
        schemes=[],
        used_schemes=[],
        protocol=connection.scope.get("auth_websocket_protocol"),
        websocket_status=3003,
        use_detail=True
    )


class AuthenticatedUserDependency:
    def __init__(
            self,
            # if True then allow only activated users, if False only deactivated users, if None don't check
            active: bool | None = True,
            # Allow if diff between last auth and now less than max_age (in seconds or timedelta), None for disable
            max_age: int | timedelta | None = None,
            # Required ACR level
            required_acr: list[str] | str | None = None
    ):
        self._active = active
        if max_age is not None and not isinstance(max_age, timedelta):
            self._max_age = timedelta(seconds=max_age)
        else:
            self._max_age = max_age
        if isinstance(required_acr, str):
            self._required_acr_values = [required_acr]
        else:
            self._required_acr_values = required_acr

    async def __call__(
            self,
            connection: HTTPConnection,
            required_scopes: SecurityScopes,
            status: bool = Depends(custom_oauth2_scheme),
    ) -> EndUser:
        if not status:
            raise ExceptionContainer(
                error=errors.AccessDeniedError(status_code=401),
                schemes=["Bearer", "DPoP"],
                used_schemes=[],
                protocol=connection.scope.get("auth_websocket_protocol"),
                websocket_status=3003,
                use_detail=True
            )
        credentials: UserCredentials = connection.auth
        user: EndUser = connection.user
        if not isinstance(user, EndUser):
            # Partial session case and ClientUser
            raise ExceptionContainer(
                error=errors.AccessDeniedError(),
                schemes=[],
                used_schemes=[],
                protocol=connection.scope.get("auth_websocket_protocol"),
                websocket_status=3003,
                use_detail=True
            )
        if self._active is not None:
            if user.active != self._active:
                raise ExceptionContainer(
                    error=errors.AccessDeniedError(),
                    schemes=[],
                    used_schemes=[],
                    protocol=connection.scope.get("auth_websocket_protocol"),
                    websocket_status=3003,
                    use_detail=True
                )
        if self._max_age is not None:
            now = datetime.now(tz=timezone.utc)
            diff = now - credentials.reauthenticated_at
            if diff > self._max_age:
                raise ExceptionContainer(
                    error=errors.InsufficientUserAuthentication(
                        max_age=int(self._max_age.total_seconds()),
                        acr_values=self._required_acr_values
                    ),
                    schemes=["Bearer", "DPoP"],
                    used_schemes=connection.scope["auth_used_schemes"],
                    protocol=connection.scope.get("auth_websocket_protocol"),
                    websocket_status=3003,
                    use_detail=True
                )
        if self._required_acr_values is not None:
            if not check_required_acr(credentials.amr, self._required_acr_values):
                raise ExceptionContainer(
                    error=errors.InsufficientUserAuthentication(
                        max_age=int(self._max_age.total_seconds()) if self._max_age is not None else None,
                        acr_values=self._required_acr_values
                    ),
                    schemes=["Bearer", "DPoP"],
                    used_schemes=connection.scope["auth_used_schemes"],
                    protocol=connection.scope.get("auth_websocket_protocol"),
                    websocket_status=3003,
                    use_detail=True
                )
        if len(required_scopes.scopes) > 0:
            if not check_required_scopes(credentials.scopes, required_scopes.scopes):
                raise ExceptionContainer(
                    error=errors.InsufficientScopeError(),
                    schemes=[],
                    used_schemes=[],
                    protocol=connection.scope.get("auth_websocket_protocol"),
                    websocket_status=3003,
                    use_detail=True
                )

        return user


class MaybeAuthenticatedUserDependency(AuthenticatedUserDependency):
    def __init__(
            self,
            # if True then allow only activated users, if False only deactivated users, if None don't check
            active: bool | None = True,
            # Allow if diff between last auth and now less than max_age (in seconds or timedelta), None for disable
            max_age: int | timedelta | None = None,
            # Required ACR level
            required_acr: list[str] | str | None = None
    ):
        super().__init__(active, max_age, required_acr)

    async def __call__(
            self,
            connection: HTTPConnection,
            required_scopes: SecurityScopes,
            status: bool = Depends(custom_oauth2_scheme),
    ) -> UserPlaceholder | EndUser:
        if not status:
            return connection.user
        return await super().__call__(connection, required_scopes, status)


class AuthenticatedClientDependency:
    def __init__(
            self,
            # Require confidential type
            require_confidential: bool = False
    ):
        self._require_confidential = require_confidential

    async def __call__(
            self,
            connection: HTTPConnection,
            required_scopes: SecurityScopes,
            status: bool = Depends(custom_oauth2_scheme)
    ) -> ClientUser:
        if not status:
            raise ExceptionContainer(
                error=errors.AccessDeniedError(status_code=401),
                schemes=["Bearer", "DPoP"],
                used_schemes=[],
                protocol=connection.scope.get("auth_websocket_protocol"),
                websocket_status=3003,
                use_detail=True
            )
        credentials: ClientCredentials = connection.auth
        client: ClientUser = connection.user
        if not isinstance(client, ClientUser):
            raise ExceptionContainer(
                error=errors.AccessDeniedError(),
                schemes=[],
                used_schemes=[],
                protocol=connection.scope.get("auth_websocket_protocol"),
                websocket_status=3003,
                use_detail=True
            )
        if self._require_confidential:
            if not client.confidential:
                raise ExceptionContainer(
                    error=errors.AccessDeniedError(),
                    schemes=[],
                    used_schemes=[],
                    protocol=connection.scope.get("auth_websocket_protocol"),
                    websocket_status=3003,
                    use_detail=True
                )
        if len(required_scopes.scopes) > 0:
            if not check_required_scopes(credentials.scopes, required_scopes.scopes):
                raise ExceptionContainer(
                    error=errors.InsufficientScopeError(),
                    schemes=[],
                    used_schemes=[],
                    protocol=connection.scope.get("auth_websocket_protocol"),
                    websocket_status=3003,
                    use_detail=True
                )
        return client
