__all__ = ["HAS_TOTP"]

try:
    from . import totp

    HAS_TOTP = True
except ImportError:
    HAS_TOTP = False
