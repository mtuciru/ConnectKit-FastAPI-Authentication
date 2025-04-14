from fastapi import HTTPException, status


def with_errors(*errors: HTTPException):
    d = {}
    for err in errors:
        if err.status_code in d:
            d[err.status_code]["description"] += f"\n\n{err.detail}"
        else:
            d[err.status_code] = {"description": err.detail}
    return d


def invalid_credentials(reason: str = None):
    if reason is not None:
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{reason}")
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


def token_expired():
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")


def token_validation_failed():
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad token specified")


def unauthorized():
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Need authorization")


def session_not_found():
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")


def account_not_active():
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not activated")


def csrf_too_many_requests():
    return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many CSRF requests")


def otp_required():
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="OTP required")


def otp_enabled():
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP already enabled")


def otp_disabled():
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP already disabled")


def otp_setup_error():
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP setup error")


def otp_verify_failed():
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OTP verify failed")


def otp_not_implemented():
    return HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="OTP feature disabled")


auth_errors = [token_expired(), token_validation_failed(), unauthorized(), account_not_active()]
