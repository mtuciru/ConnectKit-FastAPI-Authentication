import enum
import re
from datetime import datetime
from typing import Annotated
from pydantic import AfterValidator
from pydantic_core import PydanticCustomError

from ..settings import BaseModel, settings, SecretStore

__all__ = ["Tokens", "login_type", "password_type", "guess_login_type", "combined_login_type",
           "LoginBy", "LoginCSRFData", "CSRFResult", "AccountCredentials",
           "SessionInfo", "SessionsInfo", "UserInfo", "NewAccount",
           "email_type", "is_sendable_email", "phone_number_rules"]

if settings.secret_store == SecretStore.COOKIE:

    class Tokens(BaseModel):
        refresh: str

elif settings.secret_store == SecretStore.HEADER:

    class Tokens(BaseModel):
        access: str
        refresh: str

else:
    raise NotImplementedError(f"Not implemented access token store mode: {settings.secret_store}")

_login_rule = re.compile("^[a-z][-_a-z0-9]{2,31}$")
_password_rule_space = re.compile(r"\s")
_password_rule_digit = re.compile("[0-9]")
_password_rule_lower = re.compile("[a-z]")
_password_rule_upper = re.compile("[A-Z]")
_password_rule_special = re.compile(r"[-~!@#$%№^&*(){}\[\]|/\\<>?_+=]")


def login_rules(login: str):
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

if 'phone' in settings.user_login_properties:
    from phonenumbers import parse, format_number, PhoneNumberFormat, NumberParseException


    def phone_number_rules(phone_number: str):
        try:
            return format_number(parse(phone_number), PhoneNumberFormat.E164)
        except NumberParseException:
            raise ValueError("Invalid phone number")


    phone_number_type = Annotated[str, AfterValidator(phone_number_rules)]

else:
    phone_number_type = None

if 'email' in settings.user_login_properties:
    from pydantic import validate_email as pydantic_validate_email
    from email_validator import validate_email, EmailNotValidError


    def email_rules(email: str):
        try:
            return pydantic_validate_email(email)[1]
        except PydanticCustomError:
            return ValueError("Invalid email")


    def is_sendable_email(email: str):
        try:
            _email_info = validate_email(email, check_deliverability=True)
            return True
        except EmailNotValidError:
            return False


    email_type = Annotated[str, AfterValidator(email_rules)]
else:
    email_type = None


    def is_sendable_email(email: str):
        raise NotImplementedError("email support not enabled")


class LoginBy(enum.Enum):
    UNSPECIFIED = "unspecified"
    LOGIN = "login"
    EMAIL = "email"
    PHONE = "phone"


def guess_login_type(login: str) -> LoginBy:
    try:
        login_rules(login)
        return LoginBy.LOGIN
    except ValueError:
        pass
    if 'email' in settings.user_login_properties:
        try:
            email_rules(login)
            return LoginBy.EMAIL
        except ValueError:
            pass
    if 'phone' in settings.user_login_properties:
        try:
            phone_number_rules(login)
            return LoginBy.PHONE
        except ValueError:
            pass
    return LoginBy.UNSPECIFIED


def combined_login_rules(login: str) -> str:
    try:
        return login_rules(login)
    except ValueError:
        pass
    if 'email' in settings.user_login_properties:
        try:
            return email_rules(login)
        except ValueError:
            pass
    if 'phone' in settings.user_login_properties:
        try:
            return phone_number_rules(login)
        except ValueError:
            pass
    raise ValueError("Invalid login")


combined_login_type = Annotated[str, AfterValidator(combined_login_rules)]


class LoginCSRFData(BaseModel):
    login: combined_login_type

    @property
    def login_by(self) -> LoginBy:
        if not hasattr(self, "_login_by"):
            self._login_by = guess_login_type(self.login)
        return self._login_by


class CSRFResult(BaseModel):
    token: str


class AccountCredentials(BaseModel):
    login: combined_login_type
    password: password_type
    csrf: str
    remember_me: bool | None = False

    @property
    def login_by(self) -> LoginBy:
        if not hasattr(self, "_login_by"):
            self._login_by = guess_login_type(self.login)
        return self._login_by


class SessionInfo(BaseModel):
    id: int
    fingerprint: str
    invalid_after: datetime


class SessionsInfo(BaseModel):
    current: SessionInfo
    other: list[SessionInfo]


class UserInfo(BaseModel):
    login: str
    active: bool
    fingerprint: str
    login_at: datetime


class NewPassword(BaseModel):
    old_password: password_type
    new_password: password_type
    confirm_csrf: str


class NewAccount(BaseModel):
    login: login_type
    if 'email' in settings.user_login_properties:
        email: email_type | None = None
    if 'phone' in settings.user_login_properties:
        phone: phone_number_type | None = None
    password: password_type
    active: bool = False
    if settings.user_has_scope:
        scopes: list[str] = []
