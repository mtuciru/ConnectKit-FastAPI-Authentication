from datetime import datetime

__all__ = ["get_nonce_by_key", "validate_jti", "check_required_scopes"]


async def get_nonce_by_key(cache_key: str) -> str | None:
    """
    Request DPoP nonce value for cache_key.

    Return if enabled DPoP nonce checks.

    Must be rotated in time window about 1-10 minutes.
    """
    return None


async def validate_jti(jti: str, now: datetime) -> bool:
    """
    Validate that this JTI not used in current time window.

    jti -- JTI for validation.
    now -- current datetime.

    Expected time window: ~1 minute.
    """
    return True


async def check_required_scopes(actual_scopes: set[str], required_scopes: list[str]) -> bool:
    """
    Simple all include check (each of 'required_scopes' must be included in 'actual_scopes').
    """
    for scope in required_scopes:
        if scope not in actual_scopes:
            return False
    return True


async def check_required_acr(amr: list[str], required_acr: list[str]) -> bool:
    """
    Check that this amr list (used authentication methods) is sufficient for required ACR (LoA)
    """
    return True
