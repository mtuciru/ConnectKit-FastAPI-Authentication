from enum import Enum
from typing import Literal

from pydantic import BaseModel as BaseModelPydantic, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from authentication.plugin_checks import *

__all__ = ["settings", "Settings", "BaseModel", "BaseModelDB"]


class BaseModelDB(BaseModelPydantic):
    model_config = ConfigDict(from_attributes=True,
                              extra="ignore",
                              use_enum_values=True)


class BaseModel(BaseModelPydantic):
    model_config = ConfigDict(extra="ignore",
                              use_enum_values=True)


class AuthConfiguration(BaseModel):
    # Allow inner authorization (not only oauth2)
    enable_login: bool = True
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


class SecretAlgorithm(Enum):
    HS256: str = "HS256"
    HS512: str = "HS512"


class SecretStore(Enum):
    COOKIE: str = "cookie"
    HEADER: str = "header"


class Settings(BaseSettings):
    """
    Auth module configuration.

    Loaded from environ (priority) and .env top-level file.
    Configuration of module depends on these settings.
    Frozen when module is loaded.
    """
    model_config = SettingsConfigDict(env_prefix="auth_",
                                      env_file='.env',
                                      env_file_encoding="utf-8",
                                      env_parse_none_str="",
                                      env_parse_enums=True,
                                      env_ignore_empty=False,
                                      extra="ignore",
                                      frozen=True,
                                      case_sensitive=False)
    secret: str | None = None
    """
    Secret for signing access/refresh tokens.
    
    Used for signing access/refresh user tokens, if None, random token will be generated on init module.
    
    Default: None
    """
    secret_algorithm: SecretAlgorithm = SecretAlgorithm.HS256
    """
    Algorithm used for signing access/refresh tokens.
    
    Available algorithms: HS256, HS512.
    
    Default: HS256
    """
    # Inner access/refresh token location
    secret_store: SecretStore = SecretStore.COOKIE

    enable_login: bool = True


settings = Settings()

