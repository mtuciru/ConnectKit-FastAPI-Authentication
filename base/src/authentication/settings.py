from enum import Enum
from typing import Literal

from pydantic import BaseModel as BaseModelPydantic, ConfigDict, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["settings", "Settings", "BaseModel", "BaseModelDB", "SecretStore"]


class BaseModelDB(BaseModelPydantic):
    model_config = ConfigDict(from_attributes=True,
                              extra="ignore",
                              use_enum_values=True)


class BaseModel(BaseModelPydantic):
    model_config = ConfigDict(extra="ignore",
                              use_enum_values=True)


class SecretAlgorithm(Enum):
    HS256 = "HS256"
    HS512 = "HS512"


class SecretStore(Enum):
    COOKIE = "cookie"
    """
    Access token stored in cookie
    Refresh token returned from login and refresh methods    
    
    
    If access token expired, return code can:
     * be 419 for http
     * be 3000 (Unautorized) for websocket
    """
    HEADER = "header"
    """
    Access token returned to client and expected in header 'Authorization'
    Refresh token returned from login and refresh methods
    
    
    If access token expired, return code can:
     * be 419 for http
     * be 3000 (Unautorized) for websocket
    """


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
    secret_store: SecretStore = SecretStore.COOKIE
    # Issuer for inner tokens and otp installer
    issuer: str = "Localhost inc."
    # Lifetime of inner access token in minutes. Must be smaller
    access_lifetime: int = Field(default=5, gt=0, le=30)
    # Lifetime of inner short refresh token in hours. (Without "remember me" option)
    refresh_lifetime_short: int = Field(default=24, gt=0, le=72)
    # Lifetime of inner long refresh token in days. (With "remember me" option)
    refresh_lifetime_long: int = Field(default=30, gt=0)
    # Lifetime of password confirmation in minutes.
    password_confirm_lifetime: int = Field(default=30, ge=5, le=1440)
    # Name of access token cookie. In header mode used for identity anon users sessions (maybe lost).
    cookie_name: str = "access"
    # Protected URL path. (Protected path, basically api of app, exclude SPA pages)
    # Note: cookie also bind for this path on top-level domain by browser
    secure_path: str = "/api"
    # Set up cookie only on https (TLS protected connection)
    cookie_secure: bool = True
    # Wrong password attempts before block account. If 0 protection disabled.
    login_attempt_count: int = 5
    # Wrong password attempts on protected routes before block account. If 0 protection disabled.
    confirm_attempt_count: int = 0
    #
    otp_attempt_count: int = 5
    # Enabled options for login (login field exists always, but can be disabled for login purposes)
    user_login_properties: list[Literal['login', 'email', 'phone']] = ['login']
    # Save user events history (update password/email/phone, success/failed login, success/failed checks, etc.)
    user_save_history: bool = False  # TODO
    user_history_events: list[str] = []
    # Use the scope model
    user_has_scope: bool = False

    @field_validator('secret', mode='after')
    @classmethod
    def setup_secret(cls, value: str | None) -> str:
        if value is None:
            import os
            from filelock import FileLock
            lock = FileLock("./setup.lock")
            path = "./setup.secret"
            with lock:
                if os.path.exists(path):
                    with open(path, "rt") as f:
                        value = f.read().strip()
                else:
                    value = os.urandom(64).hex()
                    with open(path, "wt") as f:
                        f.write(value)
        return value

    @field_validator('user_login_properties', mode='after')
    @classmethod
    def validate_user_login_properties(cls, value: list[str]) -> list[str]:
        def login_filter(item: str):
            if not isinstance(item, str):
                return False
            if item in ('login', 'email', 'phone'):
                return True
            return False

        value = list(filter(login_filter, value))

        if "email" in value:
            try:
                import email_validator
            except ImportError:
                raise ValueError("Enable extra 'email' for use login by email!")
        if "phone" in value:
            try:
                import phonenumbers
            except ImportError:
                raise ValueError("Enable extra 'phone' for use login by phone number!")

        return value


settings = Settings()
