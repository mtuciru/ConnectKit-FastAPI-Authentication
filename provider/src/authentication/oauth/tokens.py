import base64
from datetime import datetime, timezone, timedelta
from hashlib import new
from typing import Any

import jwt

import json_adapter as json
from authentication.settings import settings, function_settings
from oauth2lib.common import Request
from oauth2lib.tokens import set_access_token_generator, set_refresh_token_generator

__all__ = ["get_subject_id", "decode_token"]


def get_subject_id(request: Request):
    """
    Calculate subject id
    """
    if request.store.get("sub") is not None:
        return request.store["sub"]
    if "sector" in request.client:
        # Pairwise sub enabled, calculate
        sector: str = request.client.sector
        sector_salt: str = request.client.sector_salt
        hasher = new("sha1")
        hasher.update(sector.encode())
        hasher.update(str(request.user.id).encode())
        hasher.update(sector_salt.encode())
        sub = base64.urlsafe_b64encode(hasher.digest()).decode().strip("=")
    else:
        sub = str(request.user.id)
    request.store["sub"] = sub
    return sub


def _set_keys():
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    if settings.mode == "HMAC":
        secret = settings.secret
        setattr(_get_sign_key, "__key", secret)
        setattr(_get_verify_key, "__key", secret)
        setattr(_get_algorithm, "__algorithm", "HS256")
    elif settings.mode == "RSA":
        path = settings.opt_path.joinpath("setup.rsa.secret").as_posix()
        secret = settings.secret.encode("utf-8") if settings.secret is not None else None
        with open(path, "rb") as f:
            key: rsa.RSAPrivateKey = load_pem_private_key(f.read(), secret)
            public_key = key.public_key()
        setattr(_get_sign_key, "__key", key)
        setattr(_get_verify_key, "__key", public_key)
        setattr(_get_algorithm, "__algorithm", "RS256")
    elif settings.mode == "EC":
        path = settings.opt_path.joinpath("setup.ec.secret").as_posix()
        secret = settings.secret.encode("utf-8") if settings.secret is not None else None
        with open(path, "rb") as f:
            key: ec.EllipticCurvePrivateKey = load_pem_private_key(f.read(), secret)
            public_key = key.public_key()
        setattr(_get_sign_key, "__key", key)
        setattr(_get_verify_key, "__key", public_key)
        setattr(_get_algorithm, "__algorithm", "ES256")


def _get_sign_key():
    key = getattr(_get_sign_key, "__key", None)
    if key is None:
        _set_keys()
        key = getattr(_get_sign_key, "__key", None)
    return key


def _get_verify_key():
    key = getattr(_get_sign_key, "__key", None)
    if key is None:
        _set_keys()
        key = getattr(_get_sign_key, "__key", None)
    return key


def _get_algorithm():
    algorithm = getattr(_get_algorithm, "__algorithm", None)
    if algorithm is None:
        _set_keys()
        algorithm = getattr(_get_algorithm, "__algorithm", None)
    return algorithm


def _s_type_to_bytes(s_type: str):
    # 97 == ord("a")
    return bytes([ord(s_type) - 97])


def _get_or_generate_sid(request: Request, now: datetime) -> str:
    """
    Create unique Session ID
    """
    if request.store.get("sid") is not None:
        return request.store["sid"]
    timestamp = str(int(now.timestamp()))
    sub = get_subject_id(request)
    s_type = request.store["session_type"]
    hasher = new("md5")
    hasher.update(f"SessionID '{timestamp}' "
                  f"for '{sub}' "
                  f"for '{request.client_id}'".encode("utf-8"))
    sid = base64.b85encode(timestamp.encode("utf-8") + _s_type_to_bytes(s_type) + hasher.digest()).decode("utf-8")
    request.store["sid"] = sid
    return sid


def _generate_jti(request: Request, now: datetime, role: str):
    """
    Generate JTI value for auth token by his role
    """
    timestamp = str(int(now.timestamp()))
    sid = _get_or_generate_sid(request, now)
    hasher = new("md5")
    hasher.update(f"JTI '{timestamp}' "
                  f"for '{sid}' "
                  f"for '{request.client_id}' "
                  f"for '{role}'".encode("utf-8"))
    jti = base64.b85encode(timestamp.encode("utf-8") + hasher.digest()).decode("utf-8")
    return jti


# def check_jti_integrity(jti: str, iat: int, sub: str, client_id: str, role: str):
#     """
#     Check JTI integrity for access tokens
#
#     Additional protection from a falsified token
#     """
#     try:
#         decoded_jti = base64.b85decode(jti)
#         timestamp = decoded_jti[:-16]
#         iat = str(iat)
#         if not safe_string_equals(timestamp, iat):
#             return False
#         hasher = new("md5")
#         hasher.update(f"JTI '{timestamp}' "
#                       f"for '{sub}' "
#                       f"for '{client_id}' "
#                       f"for '{role}'".encode("utf-8"))
#         digest = hasher.digest()
#         return safe_string_equals(decoded_jti[-16:], digest)
#     except Exception:
#         return False


def create_access_token(request: Request) -> str:
    # Session type describe type of created session:
    #   - 'p', provider session, obtained by provider frontend or transparent app
    #   - 'u', user session, obtained by client via provider frontend
    #   - 'c', client session obtained by client for itself
    # For all types access token generates by the same way, except expires_minutes obtains
    s_type = request.store["session_type"]
    if s_type == "p":
        # Provider used base settings
        expires_minutes = function_settings.access_lifetime
    else:
        # Clients may overwrite access lifetime
        expires_minutes = request.client.access_lifetime or function_settings.access_lifetime
    now = datetime.now(tz=timezone.utc)
    request.store["access_jti"] = _generate_jti(request, now, "access")
    payload = {
        "iss": settings.issuer,
        "aud": "access",
        "typ": s_type,
        "sub": _get_or_generate_sid(request, now),
        "jti": request.store["access_jti"],
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
    }
    # If refresh token will be produced, this value will be overridden
    request.store["session_exp"] = payload["exp"]
    request.expires_in = int(timedelta(minutes=expires_minutes).total_seconds())
    return jwt.encode(payload, _get_sign_key(), algorithm=_get_algorithm(), json_encoder=json.JSONEncoder)


def create_refresh_token(request: Request) -> str:
    # Session type describe type of created session:
    #   - 'p', provider session, obtained by provider frontend or transparent app
    #   - 'u', user session, obtained by client via provider frontend
    #   - 'c', client session obtained by client for itself
    s_type = request.store["session_type"]
    if s_type == "p":
        # Provider used base settings and lookup long parameter
        long = request.extra.get("long", False)
        request.store["long"] = long
        if long:
            td = timedelta(days=function_settings.refresh_lifetime_long)
        else:
            td = timedelta(hours=function_settings.refresh_lifetime_short)
    else:
        # Clients may overwrite refresh lifetime, and they used hour units, otherwise long variant used
        if request.client.refresh_lifetime:
            td = timedelta(hours=request.client.refresh_lifetime)
        else:
            td = timedelta(days=function_settings.refresh_lifetime_long)
    now = datetime.now(tz=timezone.utc)
    request.store["refresh_jti"] = _generate_jti(request, now, "refresh")
    payload = {
        "iss": settings.issuer,
        "aud": "refresh",
        "typ": s_type,
        "sub": _get_or_generate_sid(request, now),
        "jti": request.store["refresh_jti"],
        "iat": now,
        "exp": now + td,
    }
    request.store["session_exp"] = payload["exp"]
    return jwt.encode(payload, _get_sign_key(), algorithm=_get_algorithm(), json_encoder=json.JSONEncoder)


def decode_token(token: str, role: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, _get_verify_key(), algorithms=[_get_algorithm()], options={
            "require": ["iss", "aud", "typ", "sub", "jti", "iat", "exp"],
            "strict_aud": True
        }, issuer=settings.issuer, audience=role)
    except jwt.exceptions.InvalidTokenError:
        return None


set_access_token_generator(create_access_token)
set_refresh_token_generator(create_refresh_token)
