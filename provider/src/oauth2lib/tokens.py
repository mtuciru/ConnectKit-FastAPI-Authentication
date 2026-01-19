import base64
import hashlib
from base64 import urlsafe_b64encode
from collections.abc import Callable
from datetime import datetime, timezone, timedelta
from typing import Coroutine, Any
from urllib.parse import quote_plus

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from jwt.utils import to_base64url_uint, from_base64url_uint
from fastapi import Request as FastAPIRequest
from starlette.requests import HTTPConnection

import json_adapter as json
from .common import Request, generate_token, generate_nonce, aw
from .validators.request import RequestValidator
from . import errors

__all__ = ["TokenWithScopes", "create_bearer_token", "create_dpop_token",
           "set_access_token_generator", "set_refresh_token_generator",
           "prepare_bearer_header", "prepare_basic_header", "dpop_present", "dpop_validate", "dpop_ath_create",
           "set_asymmetric_keypair", "claims_signing", "claims_extracting",
           "get_jwks", "get_actual_kid", "get_keys_creation_time", "remove_old_keys",
           "save_state", "restore_state"]

_access_token_function: Callable[[Request], str | Coroutine[Any, Any, str]] | None = None
_refresh_token_function: Callable[[Request], str | Coroutine[Any, Any, str]] | None = None

_jwks = {
    "keys": []
}

_public_keys: dict[str, rsa.RSAPublicKey] = {}
_public_keys_at: dict[str, datetime] = {}

_actual_asymmetric_key: rsa.RSAPrivateKey | None = None
_actual_asymmetric_kid: str | None = None


def set_access_token_generator(func: Callable[[Request], str | Coroutine[Any, Any, str]]):
    global _access_token_function
    _access_token_function = func


def set_refresh_token_generator(func: Callable[[Request], str | Coroutine[Any, Any, str]]):
    global _refresh_token_function
    _refresh_token_function = func


class TokenWithScopes(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "scope" in self:
            self._scopes = self["scope"].split() if "scope" is not None else []
        else:
            self._scopes = []

    @property
    def scopes(self):
        return list(self._scopes)


def prepare_basic_header(client_id: str, client_secret: str, headers: dict[str, str] = None) -> dict[str, str]:
    """
    Create Authorization header with Basic scheme credential.

    Basic scheme it's valid scheme for OAuth2 and OIDC client authorization.
    """
    client_id = quote_plus(client_id)
    client_secret = quote_plus(client_secret)
    pair = f"{client_id}:{client_secret}"
    token = urlsafe_b64encode(pair.encode("ASCII")).decode("utf-8")
    headers = headers or {}
    headers['Authorization'] = f'Basic {token}'
    return headers


def prepare_bearer_header(token: str, headers: dict[str, str] = None) -> dict[str, str]:
    """
    Create Authorization header with Bearer scheme token.

    Bearer scheme it's valid scheme for OAuth2 and OIDC access and refresh tokens.
    """
    headers = headers or {}
    headers['Authorization'] = f'Bearer {token}'
    return headers


async def default_create_access_token(request: Request):
    """
    Create typical access token of Bearer type.
    """
    return generate_token(68)


async def default_create_refresh_token(request: Request):
    """
    Create typical refresh token of Bearer type.
    """
    return generate_token(68)


def calculate_dpop_jkt(jwk: dict[str, str]) -> str:
    clear_jwk = {
        "kty": jwk.get("kty"),
    }
    if jwk.get("kty") == "EC":
        clear_jwk["crv"] = jwk.get("crv")
        clear_jwk["x"] = jwk.get("x")
        clear_jwk["y"] = jwk.get("y")
    elif jwk.get("kty") == "RSA":
        clear_jwk["n"] = jwk.get("n")
        clear_jwk["e"] = jwk.get("e")
    hasher = hashlib.sha256(json.dumps(clear_jwk, sort_keys=True).encode("utf-8"))
    dpop_jkt = base64.urlsafe_b64encode(hasher.digest()).decode("utf-8").rstrip("=")
    return dpop_jkt


async def create_bearer_token(request_validator: RequestValidator, request: Request,
                              refresh_token: bool = False, token_type: str | None = None) -> TokenWithScopes:
    """
    Create a tokens of Bearer type, by default without refresh token.
    """
    token_type = token_type or "Bearer"
    token = {
        'access_token': await create_access_token(request),
        'token_type': token_type
    }

    # 'expires_in' field is optional and create_access_token function can set it for request object
    if request.expires_in is not None:
        token['expires_in'] = request.expires_in

    # Also include scope
    if request.scope is not None:
        if not request.is_scope_identical:
            token['scope'] = request.scope

    if refresh_token:
        if await aw(request_validator.is_rotate_refresh_token(request)):
            token['refresh_token'] = await create_refresh_token(request)
        elif request.refresh_token is not None:
            token['refresh_token'] = request.refresh_token

    return TokenWithScopes(token)


def dpop_present(request: Request | HTTPConnection) -> bool:
    return "DPoP" in request.headers


def dpop_ath_create(access_token: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("UTF-8")).digest()).decode("utf-8").rstrip("=")


def dpop_validate(request: HTTPConnection | FastAPIRequest, bound_nonce: str | None = None,
                  target_dpop_jkt: str | None = None, ath: str | None = None):
    dpop_token = request.headers.get("DPoP")
    dpop_token_count = len(request.headers.getlist("DPoP"))
    if dpop_token_count > 1:
        # Presented more than one time
        raise errors.InvalidDPoPProof(description="Multimple DPoP headers")
    if dpop_token is not None:
        try:
            dpop_header = jwt.get_unverified_header(dpop_token)
        except jwt.InvalidTokenError:
            raise errors.InvalidDPoPProof()
        if dpop_header.get("typ") != "dpop+jwt":
            raise errors.InvalidDPoPProof()
        if dpop_header.get("alg") not in ["RS256", "PS256", "ES256"]:
            raise errors.InvalidDPoPProof()
        dpop_jwk = dpop_header.get("jwk")
        if dpop_jwk is None:
            raise errors.InvalidDPoPProof()
        try:
            dpop_jwk_key = jwt.PyJWK(dpop_jwk)
        except (jwt.PyJWTError, jwt.PyJWKError):
            raise errors.InvalidDPoPProof()
        if not isinstance(dpop_jwk_key.key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise errors.InvalidDPoPProof()
        if isinstance(dpop_jwk_key.key, ec.EllipticCurvePublicKey):
            if not isinstance(dpop_jwk_key.key.curve, ec.SECP256R1):
                raise errors.InvalidDPoPProof()
        dpop_jkt = calculate_dpop_jkt(dpop_jwk)
        if target_dpop_jkt is not None:
            # If required special dpop_jkt
            if target_dpop_jkt != dpop_jkt:
                raise errors.InvalidDPoPProof()
        try:
            dpop_payload = jwt.decode(dpop_token, dpop_jwk.key, ["RS256", "PS256", "ES256"], options={
                "require": ["iat", "jti", "htm", "htu"]
            }, leeway=timedelta(seconds=30))
        except (jwt.InvalidTokenError, jwt.InvalidKeyError):
            raise errors.InvalidDPoPProof()
        dpop_iat = datetime.fromtimestamp(int(dpop_payload["iat"]), tz=timezone.utc)
        if dpop_payload.get("exp") is None:
            # if client not constrains time window of DPoP, do it itself
            if dpop_iat + timedelta(minutes=1) < datetime.now(tz=timezone.utc):
                # DPoP must not be older than one minute (30 seconds leeway + 30 seconds age)
                raise errors.InvalidDPoPProof()
        if "method" in request.scope:
            if dpop_payload["htm"].upper() != request.scope["method"]:
                raise errors.InvalidDPoPProof()
        current_url = request.url.components._replace(query=None, fragment=None).geturl()
        if dpop_payload["htu"] != current_url:
            raise errors.InvalidDPoPProof()
        if dpop_payload.get("nonce") != bound_nonce:
            if bound_nonce is None:
                raise errors.InvalidDPoPProof()
            else:
                e = errors.UseDPoPNonce()
                e.nonce = bound_nonce
                raise e
        if "ath" in dpop_payload or ath is not None:
            dpop_ath = dpop_payload.get("ath")
            if ath is None and dpop_ath is not None:
                # We don't expect ath, but it in token
                raise errors.InvalidDPoPProof()
            if ath != dpop_ath:
                # We expect ath, but it invalid
                raise errors.InvalidDPoPProof()
        return dpop_jkt, dpop_iat, dpop_payload["jti"]
    return None, None, None


async def create_dpop_token(request_validator: RequestValidator, request: Request,
                            refresh_token: bool = False, target_dpop_jkt: str | None = None) -> TokenWithScopes:
    # We need validate DPoP token and then process as usual
    bound_nonce = await aw(request_validator.get_client_dpop_nonce(request))
    dpop_jkt, dpop_iat, dpop_jti = dpop_validate(request, bound_nonce, target_dpop_jkt)
    if await aw(request_validator.is_client_dpop_required(request)):
        # Client required bind access and refresh tokens to DPoP token
        if dpop_jkt is None:
            raise errors.InvalidDPoPProof(description="DPoP proof required")
    request.dpop_jkt = dpop_jkt
    if not await aw(request_validator.is_client_dpop_valid_jti(request, dpop_iat, dpop_jti)):
        raise errors.InvalidDPoPProof()
    return await create_bearer_token(request_validator, request, refresh_token, "DPoP")


async def create_access_token(request: Request):
    global _access_token_function
    if _access_token_function is None:
        return await default_create_access_token(request)
    return await aw(_access_token_function(request))


async def create_refresh_token(request: Request):
    global _refresh_token_function
    if _refresh_token_function is None:
        return await default_create_refresh_token(request)
    return await aw(_refresh_token_function(request))


def set_asymmetric_keypair(private_key: str, public_key: str, kid: str | None = None, passphrase: str | None = None):
    global _jwks, _public_keys, _actual_asymmetric_key, _actual_asymmetric_kid, _public_keys_at
    private_key = load_pem_private_key(private_key.encode("utf-8"), passphrase)
    public_key = load_pem_public_key(public_key.encode("utf-8"))
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Not a rsa private key")
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Not a rsa public key")
    pb = public_key.public_numbers()
    if kid is None:
        kid = generate_nonce()
    else:
        if kid in _public_keys:
            raise ValueError("Keypair with this kid already exists")
    jwk = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": to_base64url_uint(pb.n).decode("utf-8"),
        "e": to_base64url_uint(pb.e).decode("utf-8"),
    }
    _jwks["keys"].append(jwk)
    _public_keys[kid] = public_key
    _public_keys_at[kid] = datetime.now(tz=timezone.utc)
    _actual_asymmetric_key = private_key
    _actual_asymmetric_kid = kid
    return kid


def get_jwks():
    global _jwks
    return json.dumps(_jwks)


def get_actual_kid():
    global _actual_asymmetric_kid
    return _actual_asymmetric_kid


def save_state(path: str = None, password: str | None = None):
    global _jwks, _actual_asymmetric_kid, _actual_asymmetric_key, _public_keys_at
    if path is None:
        path = "jwks_state.json"
    if password is None:
        actual_key = _actual_asymmetric_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ).decode("utf-8")
    else:
        actual_key = _actual_asymmetric_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password.encode("utf-8"))
        ).decode("utf-8")
    keys_at: dict[str, Any] = _public_keys_at.copy()
    for key in keys_at.keys():
        keys_at[key] = keys_at[key].timestamp()
    state = {
        "jwks": _jwks,
        "timestamps": keys_at,
        "actual_asymmetric_kid": _actual_asymmetric_kid,
        "actual_asymmetric_key": actual_key,
    }
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(state))


def restore_state(path: str = None, password: str | None = None):
    global _jwks, _actual_asymmetric_kid, _actual_asymmetric_key, _public_keys_at, _public_keys
    if path is None:
        path = "jwks_state.json"
    with open(path, "rb") as f:
        data = f.read()
        state = json.loads(data)
    if "jwks" not in state:
        raise ValueError("Has not 'jwks' key in state")
    else:
        if not isinstance(state["jwks"].get("keys"), list):
            raise ValueError("'jwks' key not in state")
        public_keys = {}
        for jwk in state["jwks"]["keys"]:
            kid = jwk["kid"]
            n = from_base64url_uint(jwk["n"])
            e = from_base64url_uint(jwk["e"])
            pb = rsa.RSAPublicNumbers(e, n)
            public_keys[kid] = pb.public_key()
    if "timestamps" not in state:
        raise ValueError("Has not 'timestamps' key in state")
    else:
        keys_at: dict[str, Any] = state["timestamps"]
        for key in keys_at.keys():
            keys_at[key] = datetime.fromtimestamp(keys_at[key], tz=timezone.utc)
    if "actual_asymmetric_kid" not in state:
        raise ValueError("Has not 'actual_asymmetric_kid' key in state")
    if "actual_asymmetric_key" not in state:
        raise ValueError("Has not 'actual_asymmetric_key' key in state")
    elif state["actual_asymmetric_key"] is not None:
        if password is None:
            actual_key = load_pem_private_key(state["actual_asymmetric_key"].encode("utf-8"), None)
        else:
            actual_key = load_pem_private_key(state["actual_asymmetric_key"].encode("utf-8"), password.encode("utf-8"))
    else:
        actual_key = None

    _jwks = state["jwks"]
    _public_keys = public_keys
    _public_keys_at = keys_at
    if actual_key is not None:
        _actual_asymmetric_kid = state["actual_asymmetric_kid"]
        _actual_asymmetric_key = actual_key
    else:
        _actual_asymmetric_kid = None
        _actual_asymmetric_key = None


def get_keys_creation_time():
    global _public_keys_at
    return _public_keys_at.copy()


def remove_old_keys(kids: list[str] = None):
    global _jwks, _public_keys_at, _public_keys, _actual_asymmetric_kid
    if kids is None:
        kids = set(_public_keys.keys())
        kids.remove(_actual_asymmetric_kid)
    else:
        kids = set(kids)
    for kid in kids:
        if kid == _actual_asymmetric_kid:
            continue
        if kid in _public_keys:
            _public_keys.pop(kid)
            _public_keys_at.pop(kid)
    _jwks["keys"] = list(filter(lambda k: k["kid"] not in kids, _jwks["keys"]))


def claims_signing(payload: dict) -> str:
    """
    Used for:
        - signing token_id
        - signing userinfo (if requested by client)
        - signing authorization server metadata (if enabled)

    Create JWT signed by specified early RSA key (RS256)

    Key pair (private + public) must be set before by call function *set_asymmetric_keypair*

    'kid' header value added to JWT
    """
    global _actual_asymmetric_kid, _actual_asymmetric_key
    if _actual_asymmetric_key is None:
        raise ValueError("Has not an asymmetric key")
    return jwt.encode(payload, _actual_asymmetric_key,
                      algorithm="RS256", headers={"kid": _actual_asymmetric_kid}, json_encoder=json.JSONEncoder)


def claims_extracting(jwt_string: str, require: list[str] = None,
                      leeway: float | timedelta = 0,
                      allow_expired: bool = False) -> dict[str, Any] | None:
    """
    Used for:
        - decoding early issued token_id

    Decode JWT signed by specified early RSA key (RS256 supported only)

    Key pair (private + public) must be set before by call function *set_asymmetric_keypair*

    'kid' header value used to select early added public keys

    if jwt expired or malformed, None will be returned
    """
    global _public_keys
    try:
        header = jwt.get_unverified_header(jwt_string)
        if "kid" not in header:
            return None
        public_key = _public_keys.get(header["kid"])
        if public_key is None:
            return None
    except jwt.InvalidTokenError:
        return None
    except jwt.InvalidKeyError:
        raise ValueError("Invalid asymmetric key")

    if require is None:
        require = []
    try:
        return jwt.decode(jwt_string, public_key, algorithms=["RS256"], options={
            "require": require,
            "verify_exp": not allow_expired
        }, leeway=leeway)
    except jwt.InvalidTokenError:
        return None
    except jwt.InvalidKeyError:
        raise ValueError("Invalid asymmetric key")
