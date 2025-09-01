from datetime import datetime, timezone, timedelta
from typing import List, Callable, Any

import jwt
from database.asyncio.session import AsyncDatabase
import http.cookies

from fastapi.dependencies.models import Dependant, SecurityRequirement
from fastapi.security.base import SecurityBase
from fastapi.openapi.models import SecurityBase as SecurityBaseModel, APIKey
from sqlalchemy import select
from sqlalchemy.orm import load_only
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Scope, Receive, Send, Message

from ..impl.token_utility import (ClientInfo, decode_client_fingerprint, get_client_fingerprint,
                                  decode_session_token, TokenExpired, TokenInvalid)
from ..models import Account, AccountSession
from ..settings import settings
from ..utils import json

__all__ = ["AnonymousUser", "AnonymousCredentials",
           "AuthenticatedUser", "AuthenticatedCredentials",
           "AuthenticationMiddleware", "DummyObject",
           "auth_pair", "auth_error"]


class IsAnonymous:
    @property
    def is_anonymous(self) -> bool:
        return not self.is_authenticated

    @property
    def is_authenticated(self) -> bool:
        raise NotImplementedError()


# Dummy

class DummyObject(IsAnonymous):
    @property
    def is_authenticated(self) -> bool:
        raise Exception("Trying use authenticate for unsecured path. (Check settings of module)")


_dummy_object_single = DummyObject()


# Anonymous

class AnonymousCredentials(IsAnonymous):
    @property
    def is_authenticated(self) -> bool:
        return False

    def __decode(self, value: str | None, request: HTTPConnection) -> dict:
        if value is None:
            return {
                "fp": get_client_fingerprint(request),
                "sat": datetime.now(tz=timezone.utc),
                "lat": datetime.now(tz=timezone.utc),
                "sd": {},
            }
        try:
            data = jwt.decode(value, settings.secret + "_ANON", algorithms=[settings.secret_algorithm.value],
                              options={
                                  "require": ["fp", "sat", "sd", "lat"],
                                  "verify_exp": False,
                              })
            return data
        except jwt.PyJWTError:
            return {
                "fp": get_client_fingerprint(request),
                "sat": datetime.now(tz=timezone.utc),
                "lat": datetime.now(tz=timezone.utc),
                "sd": {},
            }

    def __encode(self, value: dict) -> str:
        return jwt.encode(value, settings.secret + "_ANON", algorithm=settings.secret_algorithm.value,
                          json_encoder=json.JSONEncoder)

    def __init__(self, data: str | None, request: HTTPConnection):
        data = self.__decode(data, request)
        self._fingerprint = data['fp']
        self._info = None
        self._started_at = datetime.fromisoformat(data['sat'])
        self._last_update_at = datetime.fromisoformat(data['lat'])
        self._session_data = data['sd']
        self._dirty = False
        self._no_cookie = False

    @property
    def start_at(self) -> datetime:
        return self._started_at

    @property
    def last_update_at(self) -> datetime:
        return self._last_update_at

    @property
    def session_data(self) -> dict:
        return self._session_data

    @property
    def client_info(self) -> ClientInfo:
        if self._info is None:
            self._info = decode_client_fingerprint(self._fingerprint)
        return self._info

    def mark_session_data_dirty(self):
        self._dirty = True

    def _no_add_cookie(self):
        self._no_cookie = True

    def _check_need_update(self):
        if self._dirty:
            return True
        if self._no_cookie:
            return False
        now = datetime.now(tz=timezone.utc)
        diff = now - self._last_update_at
        if diff > timedelta(days=6):
            return True
        return False

    def _get_cookie_data(self):
        data = {
            "fp": self._fingerprint,
            "sat": self._started_at,
            "lat": datetime.now(tz=timezone.utc),
            "sd": self._session_data,
        }
        data = self.__encode(data)
        cookie: http.cookies.BaseCookie[str] = http.cookies.SimpleCookie()
        cookie[settings.cookie_name] = data
        cookie[settings.cookie_name]["max-age"] = 604_800
        cookie[settings.cookie_name]["path"] = settings.secure_path
        cookie[settings.cookie_name]["secure"] = True
        cookie[settings.cookie_name]["httponly"] = True
        cookie[settings.cookie_name]["samesite"] = "lax"
        cookie_val = cookie.output(header="").strip()
        return cookie_val


class AnonymousUser(IsAnonymous):
    @property
    def is_authenticated(self) -> bool:
        return False


# Authenticated

class AuthenticatedCredentials(IsAnonymous):

    @property
    def is_authenticated(self) -> bool:
        return True

    def __init__(self, session: AccountSession):
        self._session = session
        self._info = None

    @property
    def session_id(self) -> int:
        return self._session.id

    @property
    def session(self) -> AccountSession:
        return self._session

    @property
    def created_at(self) -> datetime:
        return self._session.created_at

    @property
    def invalid_after(self) -> datetime:
        return self._session.invalid_after

    @property
    def client_info(self) -> ClientInfo:
        if self._info is None:
            self._info = decode_client_fingerprint(self._session.fingerprint)
        return self._info


class ManualAuthenticatedCredentials(IsAnonymous):

    @property
    def is_authenticated(self) -> bool:
        return True

    def __init__(self, info: dict | None):
        self._info = info if info is not None else {}

    @property
    def session_id(self) -> int | None:
        return self._info.get("id", None)

    @property
    def session(self) -> Any:
        return self._info.get("session", None)

    @property
    def created_at(self) -> datetime | None:
        return self._info.get("created_at", None)

    @property
    def invalid_after(self) -> datetime | None:
        return self._info.get("invalid_after", None)

    @property
    def client_info(self) -> ClientInfo | None:
        return self._info.get("client_info", None)


class AuthenticatedUser(IsAnonymous):
    def __init__(self, account: Account, scopes: list[str] = None):
        self._account = account
        if scopes is None:
            self._scopes = account.scopes
        else:
            self._scopes = scopes

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def account_id(self) -> int:
        return self._account.id

    @property
    def account(self) -> Account:
        return self._account

    @property
    def login(self) -> str:
        return self._account.login

    @property
    def active(self):
        return self._account.active

    @property
    def scopes(self) -> List[str]:
        return self._scopes


async def verify(access_payload: dict, fingerprint: str):
    async with AsyncDatabase() as db:
        session = await db.scalar(select(AccountSession).options(
            load_only(AccountSession.account, AccountSession.fingerprint,
                      AccountSession.identity, AccountSession.created_at)
        ).filter_by(id=access_payload["sid"]))
        if session is None:
            return None
        if session.fingerprint != fingerprint or session.identity != access_payload["jit"]:
            await db.delete(session)
            await db.commit()
            return None
        db.expunge(session)
        return session


auth_pair = tuple[ManualAuthenticatedCredentials, AuthenticatedUser] | None
auth_error = Response | None


def null_process_header(header_value: str) -> tuple[auth_pair, auth_error]:
    return None, None


_refresh_url_cache: str = None


def _get_path(conn: HTTPConnection):
    global _refresh_url_cache
    if _refresh_url_cache is None:
        _refresh_url_cache = conn.url_for("refresh_token")
    return _refresh_url_cache


class AuthenticationMiddleware:
    def __init__(self, app: ASGIApp,
                 header_processor: Callable[[str], tuple[auth_pair, auth_error]] = None) -> None:
        self.app = app
        self.header_processor = header_processor if header_processor is not None else null_process_header

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return
        connection = HTTPConnection(scope)
        if not connection.url.path.startswith(settings.secure_path):
            scope["auth"] = _dummy_object_single
            scope["user"] = _dummy_object_single
            await self.app(scope, receive, send)
            return
        # credentials = None
        # user = None
        auth_header = connection.headers.get("Authorization", None)
        ap, ae = self.header_processor(auth_header) if auth_header is not None else None
        if ap is not None:
            credentials, user = ap
        elif ae is not None:
            await ae(scope, receive, send)
            return
        else:
            access = connection.cookies.get(settings.cookie_name)
            if access is None:
                credentials = AnonymousCredentials(None, connection)
                credentials.mark_session_data_dirty()
                user = AnonymousUser()
            else:
                # try decode as session cookie
                try:
                    try:
                        access_payload = decode_session_token(access, "access")
                    except TokenExpired as e:
                        if connection.url == _get_path(connection):
                            access_payload = decode_session_token(access, "access", True)
                        else:
                            raise e
                    session = await verify(access_payload, get_client_fingerprint(connection))
                    if session is None:
                        raise TokenInvalid
                    account = session.account
                    credentials = AuthenticatedCredentials(session)
                    user = AuthenticatedUser(account)
                except TokenExpired as e:
                    if scope["type"] == "websocket":
                        # Use code 3000, that's mean Unauthorized.
                        await send({"type": "websocket.close", "code": 3000, "reason": str(e)})
                    else:
                        # Not standard code Auth Timeout (Access Timeout), instead of 401 or 403 to avoid code ambiguity
                        response = JSONResponse({"detail": str(e)}, status_code=419)
                        await response(scope, receive, send)
                    return
                except TokenInvalid:
                    # Don't raise error when token invalid, it's means that it for anon user (or not, but who cares)
                    credentials = AnonymousCredentials(access, connection)
                    user = AnonymousUser()
        scope["auth"] = credentials
        scope["user"] = user

        # Wrapper for update anon cookie
        if credentials.is_anonymous:
            async def send_wrapper(message: Message) -> None:
                if message["type"] == "http.response.start":
                    if credentials._check_need_update():
                        # Need to save anonymous token with new data and/or max_age
                        cookie_value = credentials._get_cookie_data()
                        headers = MutableHeaders(scope=message)
                        headers.append("Set-Cookie", cookie_value)
                await send(message)

            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)


class AuthenticationScheme(SecurityBase):
    def __init__(self, scheme_name: str, model: SecurityBaseModel):
        self.scheme_name = scheme_name
        self.model = model


_secure_model = AuthenticationScheme(
    "HttpOnly cookie JWT access token",
    APIKey.model_validate({
        "in": "cookie",
        "name": settings.cookie_name,
    })
)


def __patch_dependant():
    def post_init(self: Dependant) -> None:
        security = getattr(self.call, "__security__", None)
        if security is not None:
            if len(self.security_requirements) == 0:
                self.security_requirements.append(SecurityRequirement(security_scheme=_secure_model, scopes=[]))
                self.security_scopes = security
            delattr(self.call, "__security__")
        self.cache_key = (self.call, tuple(sorted(set(self.security_scopes or []))))

    Dependant.__post_init__ = post_init


__patch_dependant()
