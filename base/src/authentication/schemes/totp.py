from ..settings import BaseModel
from .auth import password_type

__all__ = ["SetupOTPLink", "ReserveOTPCodes", "OTPCode"]


class SetupOTPLink(BaseModel):
    secret: str
    install_link: str


class ReserveOTPCodes(BaseModel):
    codes: list[str]


class OTPCode(BaseModel):
    code: str


class RegenerateOTPCodes(BaseModel):
    password: password_type
    confirm_csrf: str