import asyncio
import base64
import re
import time
from secrets import SystemRandom, randbits
from typing import Any, Coroutine, TypeVar
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse, unquote_plus

from fastapi import Request as FastAPIRequest, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import QueryParams, Headers

__all__ = ["Request", "generate_token", "generate_timestamp", "generate_nonce", "generate_client_id",
           "generate_client_secret", "generate_user_code", "safe_string_equals", "normalize_response_type",
           "add_params_to_uri", "aw", "allow_insecure_provider", "is_secure_required"]

# TODO: Add support for https://www.rfc-editor.org/rfc/rfc8707.html

SIMPLE_READABLE_UNICODE_ASCII_CHARACTER_SET = (
    'BCDFGHJKLMNPQRSTVWXZ'
    '0123456789'
)

UNICODE_ASCII_CHARACTER_SET = (
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789'
)

CLIENT_ID_CHARACTER_SET = CLIENT_SECRET_CHARACTER_SET = (
    r""" !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""
)

CODE_VERIFIER_PATTERN = re.compile("[A-Za-z0-9\-._~]*")
SANITIZE_PATTERN = re.compile(r'([^&;]*(?:password|token|client_secret|refresh_token)[^=]*=)[^&;]+', re.IGNORECASE)

T1 = TypeVar("T1")


async def aw(value: Coroutine[Any, Any, T1] | T1) -> T1:
    """
    If result is coroutine await it otherwise return unchanged
    """
    if asyncio.iscoroutine(value):
        value = await value
    return value


def generate_nonce():
    """
    Generate pseudorandom nonce that is unlikely to repeat.

    A random 64-bit number is appended to the epoch timestamp for both
    randomness and to decrease the likelihood of collisions.
    """
    return str(str(randbits(64)) + generate_timestamp())


def generate_timestamp():
    """
    Get seconds since epoch (UTC).
    """
    return str(int(time.time()))


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    """Generates a non-guessable OAuth token

    OAuth2 does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.
    """
    rand = SystemRandom()
    return ''.join(rand.choice(chars) for x in range(length))


def generate_user_code() -> str:
    left_part = generate_token(4, SIMPLE_READABLE_UNICODE_ASCII_CHARACTER_SET)
    right_part = generate_token(4, SIMPLE_READABLE_UNICODE_ASCII_CHARACTER_SET)
    return f"{left_part}-{right_part}"


def generate_client_id(length=30, chars=CLIENT_ID_CHARACTER_SET):
    """
    Generates an OAuth client_id

    OAuth 2 specify the format of client_id in
    https://tools.ietf.org/html/rfc6749#appendix-A.
    """
    return generate_token(length, chars)


def generate_client_secret(length=64, chars=CLIENT_SECRET_CHARACTER_SET):
    """
    Generates an OAuth client_secret

    OAuth 2 specify the format of client_secret in
    https://tools.ietf.org/html/rfc6749#appendix-A.
    """
    return generate_token(length, chars)


def add_params_to_qs(query, params):
    """Extend a query with a list of two-tuples."""
    if isinstance(params, dict):
        params = params.items()
    queryparams = parse_qsl(query, keep_blank_values=True)
    queryparams.extend(params)
    return urlencode(queryparams)


def add_params_to_uri(uri, params, fragment=False):
    """Add a list of two-tuples to the uri query components."""
    sch, net, path, par, query, fra = urlparse(uri)
    if fragment:
        fra = add_params_to_qs(fra, params)
    else:
        query = add_params_to_qs(query, params)
    return urlunparse((sch, net, path, par, query, fra))


def safe_string_equals(a, b):
    """ Near-constant time string comparison.

    Used in order to avoid timing attacks on sensitive information such
    as secret keys during request verification.

    https://rdist.root.org/2010/01/07/timing-independent-array-comparison/
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


_normal_response_types: dict[frozenset, str] = {
    frozenset({"code"}): "code",
    frozenset({"token"}): "token",
    frozenset({"id_token"}): "id_token",
    frozenset({"id_token", "token"}): "id_token token",
    frozenset({"code", "token"}): "code token",
    frozenset({"code", "id_token"}): "code id_token",
    frozenset({"code", "id_token", "token"}): "code id_token token",
    frozenset({"none"}): "none",
}


def normalize_response_type(response_type: str | None):
    if response_type is None:
        return response_type
    type_set = frozenset(response_type.strip().split())
    normal = _normal_response_types.get(type_set, None)
    if normal is not None:
        return normal
    return response_type


class Request:
    client_id: str = None
    client_secret: str = None
    response_type: str = None
    scope: str = None
    state: str = None
    grant_type: str = None
    code: str = None
    redirect_uri: str = None
    username: str = None
    password: str = None
    refresh_token: str = None
    code_challenge: str = None
    code_challenge_method: str = None
    code_verifier: str = None
    device_code: str = None
    token: str = None
    token_type_hint: str = None
    callback: str = None
    response_mode: str = None
    nonce: str = None
    display: str = None
    prompt: str | list[str] = None
    max_age: str | int = None
    ui_locales: str | list[str] = None
    id_token_hint: str = None
    login_hint: str = None
    acr_values: str = None
    claims_locales: str | list[str] = None
    claims: str | dict[str, Any] = None
    dpop_jkt: str = None

    # Global class level params setting up by library
    issuer: str = None
    cookie_name: str = None

    __allowed_params = (
        # OAuth2: authorize&token
        "client_id",
        "client_secret",
        "response_type",
        "scope",
        "state",
        "grant_type",
        "code",
        "redirect_uri",
        "username",
        "password",
        "refresh_token",
        "response_mode",
        # OAuth2: PKCE
        "code_challenge",
        "code_challenge_method",
        "code_verifier",
        # OAuth2: Device authorization
        "device_code",
        # OAuth2: Token Revocation&Introspection
        "token",
        "token_type_hint",
        "callback",
        # OIDC
        "nonce",
        "display",
        "prompt",
        "max_age",
        "ui_locales",
        "id_token_hint",
        "login_hint",
        "acr_values",
        "claims_locales",
        "claims"
        # DPoP verification for code binding
        "dpop_jkt"
    )
    __error_params = {
        "request_uri": "request_uri_not_supported",
        "request": "request_not_supported",
        "registration": "registration_not_supported"
    }

    @classmethod
    async def init(cls, request: FastAPIRequest, db: AsyncSession):
        query_params = request.query_params
        body_params = None
        if request.method == "POST":
            if request.headers.get("Content-Type") == "application/x-www-form-urlencoded":
                body_params = QueryParams(await request.body())
            else:
                raise HTTPException(status_code=415, detail="Unsupported Media Type",
                                    headers={"Accept-Post": "application/x-www-form-urlencoded"})
        return cls(query_params, body_params, db, request)

    def __init__(self, query: QueryParams, body_params: QueryParams | None,
                 db: AsyncSession, request: FastAPIRequest):
        from validators.request import ClientRepresentation, UserRepresentation
        self.client: ClientRepresentation | None = None
        self.user: UserRepresentation | None = None
        self.expires_in: int | None = None
        self.request: FastAPIRequest = request
        self.db: AsyncSession = db
        self._has_query = len(query) > 0
        self._query = query
        self._dirty_scope = False
        self._scopes = None
        self._body_params = body_params
        self._response_set = None
        self._extra_params = {}
        self.__extract_params(query, body_params)
        self._basic_client_id = None
        self._basic_client_secret = None
        self._is_default_redirect_uri = False
        self._is_scope_identical = True
        self._in_cookie_refresh = False
        self._used_auth_schemes = []
        if hasattr(self, "response_type"):
            self.response_type = normalize_response_type(self.response_type)
        self._store = {}
        self.__extract_schemes()

    def __setattr__(self, key, value):
        if key == "scope":
            self._dirty_scope = True
        super().__setattr__(key, value)

    @property
    def extra(self):
        return self._extra_params

    @property
    def store(self):
        return self._store

    @property
    def scopes(self) -> list[str]:
        if self._dirty_scope:
            self._scopes = self.scope.split() if self.scope is not None else None
            self._dirty_scope = False
        return self._scopes

    @property
    def is_default_redirect_uri(self) -> bool:
        return self._is_default_redirect_uri

    @property
    def is_scope_identical(self) -> bool:
        return self._is_scope_identical

    @property
    def in_cookie_refresh(self) -> bool:
        return self._in_cookie_refresh

    @scopes.setter
    def scopes(self, value: list[str]):
        self.scope = " ".join(value)

    @property
    def headers(self) -> Headers:
        return self.request.headers

    @property
    def used_auth_schemes(self) -> list[str]:
        return self._used_auth_schemes

    @property
    def response_type_set(self) -> set[str]:
        if self._response_set is None:
            self._response_set = frozenset(self.response_type.split()) if self.response_type is not None else None
        return self._response_set

    @property
    def client_credentials_post(self) -> tuple[str | None, str | None]:
        if self.client_secret is not None:
            return self.client_id, self.client_secret
        return None, None

    @property
    def client_credentials_basic(self) -> tuple[str | None, str | None]:
        from .errors import InvalidRequestError
        if self._basic_client_id is not None or self._basic_client_secret is not None:
            return self._basic_client_id, self._basic_client_secret
        header = self.request.headers.get("Authorization")
        if header is None:
            return None, None
        components = header.split(maxsplit=1)
        if len(components) != 2:
            return None, None
        if components[0].lower() != "basic":
            return None, None
        try:
            decoded_pair = base64.b64decode(components[1]).decode("utf-8").split(":")
        except Exception:
            raise InvalidRequestError(description="Malformed basic auth header", request=self)
        if len(decoded_pair) != 2:
            raise InvalidRequestError(description="Malformed basic auth header", request=self)
        username, password = decoded_pair
        username = unquote_plus(username)
        password = unquote_plus(password)
        self._basic_client_id = username
        self._basic_client_secret = password
        return self._basic_client_id, self._basic_client_secret

    def validate_client_credentials(self):
        from .errors import InvalidRequestError
        auth_header_count = len(self.headers.getlist("Authorization"))
        if auth_header_count > 1:
            raise InvalidRequestError(description='Multiple auth headers used', request=self)
        post_id, _ = self.client_credentials_post
        basic_id, _ = self.client_credentials_basic
        if post_id is not None and basic_id is not None:
            raise InvalidRequestError(description='Multiple client auth schemes used', request=self)
        if basic_id is not None and self.client_id is not None:
            if basic_id != self.client_id:
                raise InvalidRequestError(description='Duplicate "client_id" param', request=self)
        self.client_id = self.client_id or post_id or basic_id

    def clear_client_credentials(self):
        self.client_secret = None
        self._basic_client_secret = None

    @property
    def user_from_request(self) -> Any | None:
        """
        Find and extract the user by user session, None if session is None or session type is not a user session.
        Also from user object may receive:
            client object if client receive token via user.
            external client object if user authenticated via external client.

        Mechanism, that extracting session information by bearer token
        and place it in *request.auth* (Session representation) and in *request.user* (User or Client representation)
        placed in *authentication* package and worked by middleware for FastAPI.
        """
        from authentication.middleware import EndUser
        from .validators import UserRepresentation
        try:
            user = self.request.user
            if isinstance(user, EndUser) and user.provider_user:
                return UserRepresentation.from_user(user)
            return None
        except Exception:
            return None

    def __extract_params(self, query: QueryParams, body_params: QueryParams | None):
        from .errors import raise_from_error
        for param, error in self.__error_params.items():
            if param in query or param in body_params:
                raise_from_error(error)
        for param in self.__allowed_params:
            if self._has_query and param in query and len(query[param]) > 0:
                setattr(self, param, query[param])
            elif body_params is not None and param in body_params and len(body_params[param]) > 0:
                setattr(self, param, body_params[param])
            else:
                setattr(self, param, None)
        for param in query.keys():
            if param not in self.__allowed_params:
                self._extra_params[param] = query[param]
        if body_params is not None:
            for param in body_params.keys():
                if param not in self.__allowed_params:
                    self._extra_params[param] = body_params[param]

    @staticmethod
    def __find_duplicate_params(query_params: QueryParams, seen_params: set, duplicate_params: set):
        for key, _ in query_params.multi_items():
            if key in seen_params:
                duplicate_params.add(key)
            else:
                seen_params.add(key)

    def __set_duplicate_params(self):
        seen_params = set()
        duplicate_params = set()
        self.__find_duplicate_params(self._query, seen_params, duplicate_params)
        if self._body_params is not None:
            self.__find_duplicate_params(self._body_params, seen_params, duplicate_params)
        self._duplicate_params = duplicate_params
        self._query = None
        self._body_params = None

    def __extract_schemes(self):
        from . import errors
        for value in self.request.headers.getlist("Authorization"):
            components = value.split(maxsplit=1)
            if len(components) != 2:
                raise errors.InvalidRequestError(description="Malformed authorization header", request=self)
            self._used_auth_schemes.append(components[0].lower())
        if len(self._used_auth_schemes) > 1:
            self._used_auth_schemes = list(set(self._used_auth_schemes))
            raise errors.InvalidRequestError(description="Multiple authorization headers", request=self)

    def __repr__(self):
        return "<oauthlib.Request SANITIZED>"

    @property
    def has_query(self) -> bool:
        return self._has_query

    @property
    def duplicate_params(self) -> set[str]:
        if not hasattr(self, "_duplicate_params"):
            self.__set_duplicate_params()
        return self._duplicate_params


_global_allow_self_http = False


def allow_insecure_provider():
    global _global_allow_self_http
    _global_allow_self_http = True


def is_secure_required():
    global _global_allow_self_http
    return not _global_allow_self_http
