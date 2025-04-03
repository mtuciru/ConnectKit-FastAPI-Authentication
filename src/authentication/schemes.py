import re
from datetime import datetime
from typing import Optional, List, Annotated

from pydantic import AfterValidator
from email_validator import validate_email, EmailNotValidError

from authentication.settings import settings

_login_rule = re.compile("^[a-z][-_a-z0-9]{2,31}$")
_password_rule_space = re.compile(r"\s")
_password_rule_digit = re.compile("[0-9]")
_password_rule_lower = re.compile("[a-z]")
_password_rule_upper = re.compile("[A-Z]")
_password_rule_special = re.compile(r"[-~!@#$%№^&*(){}\[\]|/\\<>?_+=]")


def can_send_email(email: str) -> bool:
    try:
        email_info = validate_email(email, check_deliverability=True)
        return True
    except EmailNotValidError:
        return False


def login_rules(login: str):
    if settings.SECURE_LOGIN_EMAIL:
        # Login as email address
        try:
            email_info = validate_email(login, check_deliverability=False)
            login = email_info.normalized
            return login
        except EmailNotValidError:
            raise ValueError(f"Invalid email format")
    else:
        # Login as linux-like login
        match = _login_rule.fullmatch(login)
        if match is None:
            raise ValueError(f"Invalid login format")
        return login


def password_rules(password: str):
    if len(password) < 8:
        raise ValueError(f"Password must be at least 8 characters long")
    if _password_rule_space.search(password) is not None:
        raise ValueError("Password must not contain spaces")
    if _password_rule_lower.search(password) is None:
        raise ValueError(f"Password must contain at least one lowercase letter")
    if _password_rule_upper.search(password) is None:
        raise ValueError(f"Password must contain at least one uppercase letter")
    if _password_rule_special.search(password) is None:
        raise ValueError(f"Password must contain at least one special character")
    if _password_rule_digit.search(password) is None:
        raise ValueError(f"Password must contain at least one digit character")
    return password


login_type = Annotated[str, AfterValidator(login_rules)]
password_type = Annotated[str, AfterValidator(password_rules)]


class CSRFRequest(BaseModel):
    login: login_type


class CSRFReturn(BaseModel):
    csrf: str


class AccountCredentials(BaseModel):
    login: login_type
    password: password_type
    csrf: str
    remember_me: Optional[bool] = False


class Refresh(BaseModel):
    refresh: str
    wait_otp: bool


class GetSession(BaseModel):
    id: int
    fingerprint: str
    invalid_after: datetime


class GetSessions(BaseModel):
    current: GetSession
    other: List[GetSession]


class NewAccount(BaseModel):
    login: login_type
    password: password_type
    active: Optional[bool] = False


class UserInfo(BaseModel):
    login: str
    active: bool
    auth_datetime: datetime


class NewPassword(BaseModel):
    old_password: password_type
    new_password: password_type


class PasswordVerify(BaseModel):
    password: password_type


if settings.SECURE_OTP_ENABLED:
    class SetupOTP(BaseModel):
        secret: str
        install_link: str


    class OTPCodes(BaseModel):
        codes: List[str]


    class OTPCode(BaseModel):
        code: str
