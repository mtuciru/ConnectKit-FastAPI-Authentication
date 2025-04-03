import enum
import os
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings
from authentication.extra_checks import *


class BaseModelDB(BaseModel):
    model_config = ConfigDict(from_attributes=True,
                              str_strip_whitespace=True)


class OtpConfiguration(BaseModel):
    enabled: bool = HAS_OTP
    # Wrong otp attempts before logout (delete session). if 0 protection disabled.
    attempt_count: int = Field(default=3, ge=0)


class OAuthMode(enum.Enum):
    CLIENT = "client"
    PROVIDER = "provider"
    BOTH = "both"


class OAuthLevelEnum(enum.Enum):
    OAUTH2 = "oauth2"
    OIDC = "oidc"


class OAuthConfiguration(BaseModel):
    enabled: bool = HAS_OAUTH
    mode: OAuthMode = OAuthMode.CLIENT
    level: OAuthLevelEnum = OAuthLevelEnum.OAUTH2


class AvatarTransform(BaseModel):
    enabled: bool = HAS_PIL
    resize: tuple[int, int] | None = (128, 128)
    format: str | None = "jpeg"


class AvatarStore(BaseModel):
    enabled: bool = HAS_S3
    host: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    region: Optional[str] = None
    bucket: Optional[str] = None
    root_path: Optional[str] = None


class AvatarConfiguration(BaseModel):
    enabled: bool = True
    transform: AvatarTransform | None = AvatarTransform()
    store: AvatarStore | None = AvatarStore()


class SessionStore(BaseModel):
    enabled: bool = True
    anonymous_cookie: bool = False


class LoginConfiguration(BaseModel):
    store_email: bool = False
    store_phone: bool = False
    login_by_email: bool = False
    login_by_phone: bool = False


class AuthConfiguration(BaseModel):
    # Issuer for inner tokens and otp installer
    issuer: str = "Localhost inc."
    # Lifetime of inner access token in minutes. Must be smaller
    access_lifetime: int = Field(default=5, gt=0, le=30)
    # Lifetime of inner short refresh token in hours. (Without "remember me" option)
    refresh_lifetime_short: int = Field(default=24, gt=0, le=72)
    # Lifetime of inner long refresh token in days. (With "remember me" option)
    refresh_lifetime_long: int = Field(default=30, gt=0)
    # Name of access token cookie.
    cookie_name: str = "access"
    # URL path for access token cookie bind. (Protected path, basically api of app)
    # Note: cookie also bind for top-level domain by browser
    cookie_path: str = "/api"
    # Set up cookie only on https (TLS protected connection)
    cookie_secure: bool = True
    # Wrong password attempts before block account. If 0 protection disabled.
    login_attempt_count: int = 5
    # Wrong password attempts on protected routes before block account. If 0 protection disabled.
    check_password_attempt_count: int = 1


class FunctionalConfiguration(BaseModel):
    otp: OtpConfiguration | None = OtpConfiguration()
    oauth2: OAuthConfiguration | None = OAuthConfiguration()
    avatar: AvatarConfiguration | None = AvatarConfiguration()
    session_store: SessionStore | None = None
    login: LoginConfiguration | None = LoginConfiguration()
    auth: AuthConfiguration | None = AuthConfiguration()


class Settings(BaseSettings):
    SECURE_CONFIG_PATH: str = "./functions.yml"
    SECURE_SECRET: str  # Inner access/refresh token sign key


settings = Settings()


def __load_config(path: Optional[str]) -> FunctionalConfiguration:
    if path is None:
        return FunctionalConfiguration()
    if not os.path.exists(path):
        return FunctionalConfiguration()
    try:
        with open(path, mode="rt") as file:
            data = yaml.safe_load(file.read())
            return FunctionalConfiguration.model_validate(data, from_attributes=False)
    except Exception as e:
        return FunctionalConfiguration()


configuration = __load_config(settings.SECURE_CONFIG_PATH)
