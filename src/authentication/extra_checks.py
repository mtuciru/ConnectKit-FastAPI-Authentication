# orjson check
try:
    import orjson

    HAS_JSON = True
except  ImportError:
    HAS_JSON = False

# pyopt check
try:
    import pyotp

    HAS_OTP = True
except ImportError:
    HAS_OTP = False

# oauthlib check
try:
    import oauthlib

    HAS_OAUTH = True
except ImportError:
    HAS_OAUTH = False

# s3 check
try:
    import s3

    HAS_S3 = True
except ImportError:
    HAS_S3 = False

# pillow check
try:
    import PIL

    HAS_PIL = True
except ImportError:
    HAS_PIL = False

__all__ = ["HAS_JSON", "HAS_OTP", "HAS_OAUTH", "HAS_S3", "HAS_PIL"]
