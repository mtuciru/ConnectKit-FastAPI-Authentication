from pathlib import Path
from typing import Literal, Any, TypedDict, Callable, Coroutine

from pydantic import BaseModel as BaseModelPydantic, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["settings", "Settings", "function_settings", "FunctionSettings", "BaseModel", "BaseModelDB",
           "configure", "FunctionParamsObject"]

from oauth2lib.common import Request


class BaseModelDB(BaseModelPydantic):
    model_config = ConfigDict(from_attributes=True,
                              extra="ignore",
                              use_enum_values=True)


class BaseModel(BaseModelPydantic):
    model_config = ConfigDict(extra="ignore",
                              use_enum_values=True,
                              validate_assignment=True)


class FunctionSettings(BaseModel):
    """
    Configuration settings for the library.

    When you realize own provider or resource service, before creating FastAPI app you must
    call `configure`.
    This function configure components of authentication library and prepare enabled functions.
    """
    access_lifetime: int = Field(default=5, gt=0, le=30)
    """
    Expire time in minutes for generated access tokens.

    Always used for End-User authentication.
    Can be overridden for clients.  

    Default: 5 mins
    Min/Max: 1/30 mins
    """
    refresh_lifetime_short: int = Field(default=24, gt=0, le=72)
    """
    Expire time in hours for generated refresh tokens for End-User authentication.

    Selected if long parameter in request is omitted or False.
    Do not used for clients.

    Default: 24 hours
    Min/Max: 1/72 hours
    """
    refresh_lifetime_long: int = Field(default=30, gt=0)
    """
    Expire time in days for generated refresh tokens for End-User authentication or clients.

    Selected if long parameter in request is True.
    Used by clients if not overridden for client.

    Default: 30 days
    Min/Max: 1/unlimited days
    """
    auth_max_age: int = Field(default=30, ge=5, le=1440)
    """
    Time in minutes after what user reauthentication is required for sensitive operations.

    (change password, authenticate third-party client if it required)
    Can be overridden for clients.

    Default: 30 mins
    Min/Max: 5/1440 mins
    """
    login_attempt_count: int = Field(default=-3, ge=-30, le=30)
    """
    User account steal protection.

    User attempts to provide right login/password pair before account will be blocked (if positive) or temp blocked for 12 hours (if negative).
    (User can't login in block account, all sessions will be closed)
    Don't forget implement unblock method.

    Attempt counter will reset after successful login.

    For disable set value 0.

    Default: -3 attempts
    Min/Max: -30/30 attempts
    """
    # Wrong password attempts on protected routes before block account. If 0 protection disabled.
    reauthenticate_attempt_count: int = Field(default=0, ge=0, le=30)
    """
    User account steal protection.

    User attempts to provide right password for reauthentication before account will be blocked.
    (User can't login in block account, all sessions will be closed)
    Don't forget implement unblock method.

    Attempt counter will reset after successful reauthentication.

    For disable set value 0.

    This counter only for password reauthentication.

    Default: 0 attempts
    Min/Max: 0/30 attempts
    """
    # Wrong 2FA attempts on login before session deleted. if 0 protection disabled.
    mfa_attempt_count: int = Field(default=3, ge=0, le=30)
    """
    Multi-factor authentication attempts before session will be closed (if mfa_attempt_blocking is False).

    Attempt counter will reset after successful MFA authentication attempt.

    For disable set value 0.

    Time-based OTP and backup hash-based OTP embedded in this library.
    (You can realize other MFA methods)

    Default: 3 attempts
    Min/Max: 0/30 attempts    
    """
    mfa_attempt_blocking: bool = False
    """
    Multi-factor authentication fail by default close session. Set it True for blocking user account.

    Default: False
    """
    user_login_options: list[Literal['login', 'email', 'phone']] = ['login']
    """
    Select fields that allowed as 'login' value:
        - login - unique ASCII alphanumeric identifier
        - email - unique email address
        - phone - unique phone number

    Login, email and phone used for 'login process' stored in users table.
    If you plan store additional emails or phone numbers that not used for login, create additional tables.

    Default: ['login']
    """
    # TODO: user_login_history
    user_login_history: list[str] = []
    """
    Enable event log for authentication system.

    Set list of event names that will be logged.

    !!Not implemented!!

    Default: []
    """
    authorization_code_enable: bool = False
    """
    Enable OAuth2 authorization_code grant

    Require set parameter: authorization_endpoint

    Default: False
    """
    authorization_implicit_enable: bool = False
    """
    Enable OAuth2 implicit grant

    Require set parameter: authorization_endpoint

    Default: False
    """
    authorization_endpoint: str | None = None
    """
    Authorization endpoint, where End-User will be redirected from client via user-agent.

    It's frontend endpoint required only if authorization_code or implicit grant is enabled.
    If it's required, but value is None, stock authorization page will be created.

    Default: None
    """
    authorization_device_enable: bool = False
    """
    Enable OAuth2 device_code grant

    Require set parameter: device_verification_uri
    Optional parameter: device_complete_uri

    Default: False
    """
    device_verification_uri: Callable[[Request], str | Coroutine[Any, Any, str]] | None = None
    """
    This function must create URI that device show to End-User.

    User tap it in user-agent, enter user_code on page and approve or reject device.

    Default: None
    """
    device_complete_uri: Callable[[Request, str], str | Coroutine[Any, Any, str]] | None = None
    """
    This function must create URI that device show to End-User as QR code or a same manner.

    User open this link in user-agent and user_code already applied. User can approve or reject device.

    Default: None
    """
    client_credentials_enable: bool = False
    """
    Enable OAuth2 client_credentials grant

    Default: False
    """
    revocation_enable: bool = False
    """
    Enable OAuth2 revocation endpoint

    Default: False
    """
    introspection_enable: bool = False
    """
    Enable OAuth2 introspection endpoint

    Default: False
    """
    oidc_enable: bool = False
    """
    Enable OpenID Connect Extension

    Default: False
    """
    use_signed_metadata: bool = False
    """
    Enable signed_metadata for metadata endpoint.

    Required RSA key (set via other method)

    Default: False
    """
    scopes_supported: list[str] | None = None
    """
    Optional metadata

    Scope values used by system. May be full or partially omitted for security reasons.

    By default if oidc enabled scope 'openid' always presented in this list

    Default: None
    """
    service_documentation: str | None = None
    """
    Optional metadata

    Provider documentation for client developers.

    Default: None
    """
    ui_locales_supported: list[str] | None = None
    """
    Optional metadata

    Language tags supported by Provider UI.

    Default: None
    """
    op_policy_uri: str | None = None
    """
    Optional metadata

    URI of page with provider policy of usage. 

    Default: None
    """
    op_tos_uri: str | None = None
    """
    Optional metadata

    URI of page with provider terms of service. 

    Default: None
    """
    acr_values_supported: list[str] | None = None
    """
    Optional metadata

    Supported ACR values by provider.

    Default: None
    """
    display_values_supported: list[str] | None = None
    """
    Optional metadata

    Supported display values by provider UI.

    Default: None
    """
    claims_supported: list[str] | None = None
    """
    Optional metadata

    Supported claims by provider UI. May be full or partially omitted for security reasons.
    Special scope values from OIDC preferable than claims.

    Default: None
    """
    claims_locales_supported: list[str] | None = None
    """
    Optional metadata

    Supported translations for human-readable claims.
    Clients can request claims on special language.

    Default: None
    """

    @field_validator('user_login_options', mode='after')
    @classmethod
    def validate_user_login_options(cls, value: list[str]) -> list[str]:
        def options_filter(item: str):
            if not isinstance(item, str):
                return False
            if item in ('login', 'email', 'phone'):
                return True
            return False

        value = list(filter(options_filter, value))
        if len(value) == 0:
            value.append('login')
        return value


class Settings(BaseSettings):
    """
    Auth module configuration.

    This configuration loaded from environment, so its include only frequently changed and shared parameters:
        - issuer - changed when domain of provider changed
        - secret - key for signing access and refresh tokens and its validating when checked access by middleware.
            if service can not use middleware (do not use FastAPI, or do not use python),
            you can use introspect endpoint or implement validations logic like middleware do.
            Keep in mind, that validation process used provider database for fetch information about active session and
            bound user (with basic information about it)
            So, if you use introspect endpoint, you receive user_id, and other service can use own database,
            with such user_id, without connection to provider database.
        - opt_path - location of shared directory for several workers running by uvicorn (or other server)
            Used for syncing state of workers (example, rsa keys for id_token signing (OpenID Connect extension))


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

    issuer: str = "http://localhost"
    """
    Issuer is URL of provider. Used for validation id_token, provider metadata
    """
    require_secure: bool = True
    """
    Require that all provider endpoints will be http scheme.
    
    Default: True
    """
    opt_path: Path = "."
    """
    Path to location for work files and sync files creation
    
    Files that created:
        - setup.lock - Lock file for block write workers shared files 
        - setup.secret - File with autogenerated secret key for signing access and refresh tokens
        - tokens_state.json - JSON that save between restarts jwks and private RSA for id_token and other signing.
    """
    secret: str | None = None
    """
    If mode == "HMAC":
        Secret used as HMAC key for signing access and refresh tokens that is JWT.
    if mode == "RSA":
        Secret used as password for loading private key
        Private key: "setup.rsa.key"
        Public key derived from private.
    if mode == "EC":
        Secret used as password for loading private key
        Private key: "setup.ec.key"
        Public key derived from private.
    
    If secret not exists in HMAC mode or key file not exists they will be created.
    """
    mode: Literal["HMAC", "RSA", "EC"] | None = None
    """
    Mode for signing access and refresh tokens.
    
    "HMAC" (default) symmetric key signing.
    "RSA" asymmetric key signing.
    "EC" asymmetric key signing.
    """

    @model_validator(mode='after')
    def validate_base_settings(self):
        import os
        from filelock import FileLock
        from oauth2lib.common import generate_token, is_secure_required, allow_insecure_provider
        from oauth2lib.validators.uri import absolute_URI_compiled
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.serialization import (Encoding, PrivateFormat,
                                                                  NoEncryption, BestAvailableEncryption)
        if not self.require_secure:
            allow_insecure_provider()
        # Validate issuer
        components = absolute_URI_compiled.fullmatch(self.issuer)
        if components is None:
            raise ValueError("Invalid issuer. MUST be absolute URI without query component")
        components = components.groupdict()
        if components.get("query") is not None:
            raise ValueError("Invalid issuer. MUST be absolute URI without query component")
        if is_secure_required() and components.get("scheme") != "https":
            raise ValueError("Invalid issuer. Required secure transport for all provider URIs")
        elif components.get("scheme") not in ("http", "https"):
            raise ValueError("Invalid issuer. URI must be HTTP or HTTPS scheme")
        # Validate opt_path
        if not os.path.exists(self.opt_path.as_posix()):
            os.makedirs(self.opt_path.as_posix(), exist_ok=True)
        # Validate mode
        if self.mode is None:
            object.__setattr__(self, "mode", "HMAC")
        # Validate secret
        if self.mode == "HMAC":
            if self.secret is None:
                lock = FileLock(self.opt_path.joinpath("setup.lock").as_posix())
                path = self.opt_path.joinpath("setup.secret").as_posix()
                with lock:
                    if os.path.exists(path):
                        with open(path, "rt") as f:
                            object.__setattr__(self, "secret", f.read().strip())
                    else:
                        object.__setattr__(self, "secret", generate_token(64))
                        with open(path, "wt") as f:
                            f.write(self.secret)
        elif self.mode == "RSA":
            lock = FileLock(self.opt_path.joinpath("setup.lock").as_posix())
            path = self.opt_path.joinpath("setup.rsa.secret").as_posix()
            secret = self.secret.encode("utf-8") if self.secret is not None else None
            with lock:
                if os.path.exists(path):
                    try:
                        with open(path, "rb") as f:
                            key = load_pem_private_key(f.read(), secret)
                            # Validate that key is RSA
                            if not isinstance(key, rsa.RSAPrivateKey):
                                raise ValueError("Invalid private key. Requires RSA")
                    except Exception:
                        raise ValueError("Invalid private key. Requires RSA")
                else:
                    # It's inner key, not exposed to internet, so...
                    # It's fast validation variant
                    # All keys are kept secret. (DO NOT USE THIS KEY anywhere else)
                    key = rsa.generate_private_key(public_exponent=3, key_size=1024)
                    if self.secret is None:
                        key = key.private_bytes(
                            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                        )
                    else:
                        key = key.private_bytes(
                            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(self.secret.encode("utf-8"))
                        )
                    with open(path, "wb") as f:
                        f.write(key)
        elif self.mode == "EC":
            lock = FileLock(self.opt_path.joinpath("setup.lock").as_posix())
            path = self.opt_path.joinpath("setup.ec.secret").as_posix()
            secret = self.secret.encode("utf-8") if self.secret is not None else None
            with lock:
                if os.path.exists(path):
                    try:
                        with open(path, "rb") as f:
                            key = load_pem_private_key(f.read(), secret)
                            # Validate that key is EC
                            if not isinstance(key, ec.EllipticCurvePrivateKey):
                                raise ValueError("Invalid private key. Requires EC")
                            if not isinstance(key.curve, ec.SECP256R1):
                                raise ValueError(
                                    "Invalid private key. JWT ES256 requires EC with curve P-256 (SECP256R1)")
                    except Exception:
                        raise ValueError("Invalid private key. Requires EC")
                else:  # P-256
                    key = ec.generate_private_key(curve=ec.SECP256R1())
                    if self.secret is None:
                        key = key.private_bytes(
                            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
                        )
                    else:
                        key = key.private_bytes(
                            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(self.secret.encode("utf-8"))
                        )
                    with open(path, "wb") as f:
                        f.write(key)
        return self


settings = Settings()
function_settings = FunctionSettings()


class FunctionParamsObject(TypedDict, total=False):
    """
    Configuration options for module.
    Set default values
    Enable features
    """
    access_lifetime: int
    """
    Expire time in minutes for generated access tokens.

    Always used for End-User authentication.
    Can be overridden for clients.  
    
    Default: 5 mins
    Min/Max: 1/30 mins
    """
    refresh_lifetime_short: int
    """
    Expire time in hours for generated refresh tokens for End-User authentication.
    
    Selected if long parameter in request is omitted or False.
    Do not used for clients.
    
    Default: 24 hours
    Min/Max: 1/72 hours
    """
    refresh_lifetime_long: int
    """
    Expire time in days for generated refresh tokens for End-User authentication or clients.

    Selected if long parameter in request is True.
    Used by clients if not overridden for client.

    Default: 30 days
    Min/Max: 1/unlimited days
    """
    auth_max_age: int
    """
    Time in minutes after what user reauthentication is required for sensitive operations.
    
    (change password, authenticate third-party client if it required)
    Can be overridden for clients.
    
    Default: 30 mins
    Min/Max: 5/1440 mins
    """
    login_attempt_count: int
    """
    User account steal protection.
    
    User attempts to provide right login/password pair before account will be blocked.
    (User can't login in block account, all sessions will be closed)
    Don't forget implement unblock method.
    
    Attempt counter will reset after successful login.
    
    For disable set value 0.
    
    Default: 5 attempts
    Min/Max: 0/30 attempts
    """
    reauthenticate_attempt_count: int
    """
    User account steal protection.
    
    User attempts to provide right password for reauthentication before account will be blocked.
    (User can't login in block account, all sessions will be closed)
    Don't forget implement unblock method.
    
    Attempt counter will reset after successful reauthentication.
    
    For disable set value 0.
    
    This counter only for password reauthentication.
    
    Default: 0 attempts
    Min/Max: 0/30 attempts
    """
    # Wrong 2FA attempts on login before session deleted. if 0 protection disabled.
    mfa_attempt_count: int
    """
    Multi-factor authentication attempts before session will be closed (if mfa_attempt_blocking is False).
    
    Attempt counter will reset after successful MFA authentication attempt.
    
    For disable set value 0.
    
    Time-based OTP and backup hash-based OTP embedded in this library.
    (You can realize other MFA methods)
    
    Default: 3 attempts
    Min/Max: 0/30 attempts    
    """
    mfa_attempt_blocking: bool
    """
    Multi-factor authentication fail by default close session. Set it True for blocking user account.
    
    Default: False
    """
    # Enabled options for login (login field exists always, but can be disabled for login purposes)
    user_login_options: list[Literal['login', 'email', 'phone']]
    """
    Select fields that allowed as 'login' value:
        - login - unique ASCII alphanumeric identifier
        - email - unique email address
        - phone - unique phone number
    
    Login, email and phone used for 'login process' stored in users table.
    If you plan store additional emails or phone numbers that not used for login, create additional tables.
    
    Default: ['login']
    """
    # TODO: user_login_history
    user_login_history: list[str]
    """
    Enable event log for authentication system.
    
    Set list of event names that will be logged.
    
    !!Not implemented!!
    
    Default: []
    """
    authorization_code_enable: bool
    """
    Enable OAuth2 authorization_code grant
    
    Require set parameter: authorization_endpoint
    
    Default: False
    """
    authorization_implicit_enable: bool
    """
    Enable OAuth2 implicit grant
    
    Require set parameter: authorization_endpoint
    
    Default: False
    """
    authorization_endpoint: str | None
    """
    Authorization endpoint, where End-User will be redirected from client via user-agent.
    
    It's frontend endpoint required only if authorization_code or implicit grant is enabled.
    If it's required, but value is None, stock authorization page will be created.
    
    Default: None
    """
    authorization_device_enable: bool
    """
    Enable OAuth2 device_code grant
    
    Require set parameter: device_verification_uri
    Optional parameter: device_complete_uri
    
    Default: False
    """
    device_verification_uri: Callable[[Request], str | Coroutine[Any, Any, str]]
    """
    This function must create URI that device show to End-User.
    
    User tap it in user-agent, enter user_code on page and approve or reject device.
    
    Default: None
    """
    device_complete_uri: Callable[[Request, str], str | Coroutine[Any, Any, str]]
    """
    This function must create URI that device show to End-User as QR code or a same manner.

    User open this link in user-agent and user_code already applied. User can approve or reject device.

    Default: None
    """
    client_credentials_enable: bool
    """
    Enable OAuth2 client_credentials grant
    
    Default: False
    """
    revocation_enable: bool
    """
    Enable OAuth2 revocation endpoint

    Default: False
    """
    introspection_enable: bool
    """
    Enable OAuth2 introspection endpoint

    Default: False
    """
    oidc_enable: bool
    """
    Enable OpenID Connect Extension
    
    Default: False
    """
    use_signed_metadata: bool
    """
    Enable signed_metadata for metadata endpoint.
    
    Required RSA key (set via other method)

    Default: False
    """
    scopes_supported: list[str]
    """
    Optional metadata
    
    Scope values used by system. May be full or partially omitted for security reasons.
    
    By default if oidc enabled scope 'openid' always presented in this list
    
    Default: None
    """
    service_documentation: str
    """
    Optional metadata

    Provider documentation for client developers.

    Default: None
    """
    ui_locales_supported: list[str]
    """
    Optional metadata

    Language tags supported by Provider UI.

    Default: None
    """
    op_policy_uri: str
    """
    Optional metadata

    URI of page with provider policy of usage. 

    Default: None
    """
    op_tos_uri: str
    """
    Optional metadata

    URI of page with provider terms of service. 

    Default: None
    """
    acr_values_supported: list[str]
    """
    Optional metadata

    Supported ACR values by provider.

    Default: None
    """
    display_values_supported: list[str]
    """
    Optional metadata

    Supported display values by provider UI.

    Default: None
    """
    claims_supported: list[str]
    """
    Optional metadata
    
    Supported claims by provider UI. May be full or partially omitted for security reasons.
    Special scope values from OIDC preferable than claims.

    Default: None
    """
    claims_locales_supported: list[str]
    """
    Optional metadata

    Supported translations for human-readable claims.
    Clients can request claims on special language.

    Default: None
    """


def configure(params: FunctionParamsObject) -> None:
    """
    Update functions settings
    """
    global function_settings
    for key, value in params.items():
        if not hasattr(function_settings, key):
            raise ValueError(f"Unknown function setting: '{key}'")
        if value is None:
            continue
        setattr(function_settings, key, value)
