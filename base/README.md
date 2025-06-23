# ConnectKit FastAPI Authentication [*en*|[ru](./README_RU.md)]

___

ConnectKit FastAPI Authentication adds accounts, user sessions, and
a user authentication mechanism using JWT for FastAPI applications.

Logging in via oauth2 or OpenID connect is not supported at the moment.

Not fully tested version

## Installation

___

```shell
pip install ConnectKit-FastAPI-Authentication
```

## Usage

___

Configuration parameters are loaded from environment variables, and can be redefined later.

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

Settings loaded from `.env` in pwd or from `environ` and can't be redefined later.

[To set up a database connection](https://github.com/mtuciru/ConnectKit-Database/blob/master/README.md).

To enable authorization endpoints and middleware:

```python
from fastapi import FastAPI
from authentication import setup_app

app = FastAPI()
setup_app(app)

```

To require auth or anon use decorators:

```python
from fastapi import APIRouter, Request
from authentication import (anonymous, authenticated, any_scopes, all_scopes,
                            AnonymousCredentials, AnonymousUser,
                            AuthenticatedCredentials, AuthenticatedUser)
from authentication import responses, common
from authentication.models import Account, AccountSession

router = APIRouter()


@router.get("/test", responses=common.responses(
    responses.unauthorized, responses.access_timeout
))
@authenticated()
async def test(request: Request):
    assert request.auth.is_authenticated
    assert request.user.is_authenticated
    creds: AuthenticatedCredentials = request.auth
    user: AuthenticatedUser = request.user


@router.get("/test2", responses=common.responses(
    responses.already_authenticated
))
@anonymous
async def test2(request: Request):
    assert request.auth.is_anonymous
    assert request.user.is_anonymous
    creds: AnonymousCredentials = request.auth
    user: AnonymousUser = request.user


@router.get("/test3", responses=common.responses(
    responses.already_authenticated
))
async def test3(request: Request):
    try:
        a = request.auth.is_anonymous
        b = request.user.is_anonymous
    except Exception:
        # Exception("Trying use authenticate for unsecured path. (Check settings of module)")
        pass

```

The `anonymous` function decorator checks for anonymous user.

The `authenticated` function decorator checks for authenticated user.

The `any_scopes` function decorator checks for authenticated user with any subset of required scopes
(if scopes enabled in settings).

The `all_scopes` function decorator checks for authenticated user with all the required scopes
(if scopes enabled in settings).


To implement the registration form, manually add users and administrative work:

[//]: # (```python)

[//]: # (from authentication import &#40;NewAccount, login_rules, password_rules,)

[//]: # (                            login_type, password_type,)

[//]: # (                            create_new_account, delete_account,)

[//]: # (                            block_account, unblock_account, get_block_status,)

[//]: # (                            get_status_otp, disable_otp&#41;)

[//]: # (from pydantic import BaseModel, EmailStr)

[//]: # ()
[//]: # (# Creating a new user)

[//]: # ()
[//]: # (try:)

[//]: # (    new_acc = NewAccount&#40;)

[//]: # (        login="root",  # The user's unique login is set by the login_rules rule)

[//]: # (        password="password",  # The user's password is set by the password_rules rule)

[//]: # (        active=True  # Is the account activated, False by default)

[//]: # (    &#41;)

[//]: # (    account = await create_new_account&#40;new_acc&#41;)

[//]: # (except ValueError as e:)

[//]: # (    # The user already exists, or there is a validation error in the New Account)

[//]: # (    pass)

[//]: # ()
[//]: # ()
[//]: # (# Example of a registration scheme)

[//]: # ()
[//]: # (class UserRegistration&#40;BaseModel&#41;:)

[//]: # (    login: login_type)

[//]: # (    nickname: str)

[//]: # (    email: EmailStr)

[//]: # (    password: password_type)

[//]: # ()
[//]: # ()
[//]: # (# Deleting an account)

[//]: # (await delete_account&#40;account&#41;)

[//]: # ()
[//]: # (# Getting the blocking status &#40;bool, Optional[str]&#41;)

[//]: # (block, reason = await get_block_status&#40;account&#41;)

[//]: # ()
[//]: # (# Getting 2FA status)

[//]: # (otp_enabled = await get_status_otp&#40;account&#41;)

[//]: # ()
[//]: # (# Account blocking &#40;a blocked account cannot log in&#41;)

[//]: # (await block_account&#40;account, "reason"&#41;)

[//]: # ()
[//]: # (# Unblocking account)

[//]: # (await unblock_account&#40;account&#41;)

[//]: # ()
[//]: # (# Forced disable of 2FA)

[//]: # (await disable_otp&#40;account&#41;)

[//]: # ()
[//]: # ()
[//]: # (```)

Authentication diagram:

![Authentication diagram](./login.jpg)

Token update diagram:

![Token update diagram](./refresh.jpg)

## License

___

ConnectKit FastAPIAuthentication is [MIT License](./LICENSE).