from datetime import datetime

__all__ = ["get_nonce_by_key_hook", "validate_jti_hook", "check_required_scopes"]

from typing import Any

from ..security import UserCredentials


async def get_nonce_by_key_hook(cache_key: str) -> str | None:
    """
    Request DPoP nonce value for cache_key.

    Return if enabled DPoP nonce checks.

    Must be rotated in time window about 1-10 minutes.
    """
    return None


async def validate_jti_hook(jti: str, iat: datetime) -> bool:
    """
    Validate that this JTI not used in current time window.

    jti -- JTI for validation.
    iat -- issue at datetime.

    Expected time window: ~1 minute.
    """
    return True


async def transform_scopes_hook(requested_scopes: list[str], max_scopes: list[str]) -> list[str] | None:
    """
    TODO
    """
    new_scopes = []
    for s in requested_scopes:
        if s in max_scopes:
            new_scopes.append(s)
    return new_scopes


async def within_scopes_hook(new_scopes: list[str], old_scopes: list[str]) -> bool:
    return not all(s in old_scopes for s in new_scopes)


async def check_required_scopes(actual_scopes: set[str], required_scopes: list[str]) -> bool:
    """
    Simple all include check (each of 'required_scopes' must be included in 'actual_scopes').
    """
    for scope in required_scopes:
        if scope not in actual_scopes:
            return False
    return True


async def check_required_acr(credentials: UserCredentials, required_acr: list[str]) -> bool:
    """
    Check that these credentials is sufficient for required ACR (LoA)
    """
    return True


async def get_client_authorize_options(client_id: int) -> dict[str, Any]:
    return {}
