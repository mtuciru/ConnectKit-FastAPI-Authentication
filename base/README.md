# ConnectKit FastAPIAuthentication [*en*|[ru](./README_RU.md)]

___

ConnectKit FastAPIAuthentication adds accounts, user sessions, and
a user authentication mechanism using JWT for FastAPI applications.

Logging in via oauth2 or OpenID connect is not supported at the moment.

## Installation

___

```shell
pip install ConnectKit-FastAPIAuthentication
```

## Usage

___

Configuration parameters are loaded from environment variables, and can be redefined later.

    SECURE_SECRET=str                 # Key for signing JWT
    SECURE_ACCESS_EXPIRE=5            # Access token validity period in minutes
    SECURE_REFRESH_EXPIRE=24          # Refresh token validity time in hours for a short session
    SECURE_REFRESH_LONG_EXPIRE=720    # Refresh token validity time in hours for a long session
    SECURE_PATH=/api                  # Prefix of the path to which the cookie with the token will be bound
    SECURE_COOKIE_NAME=access         # The name of the cookie in which the token will be
    SECURE_ONLY=True                  # Instructing the browser to accept the token only if https
    SECURE_BLOCK_TRIES=5              # Number of attempts to enter the wrong password before the account is blocked
    SECURE_OTP_ENABLED=True           # Use 2FA via one-time passwords
    SECURE_OTP_BLOCK_TRIES=3          # Number of attempts to transfer OTP before logout
    SECURE_OTP_ISSUER=Localhost inc.  # The OTP ISSUER transmitted to user when 2FA is enabled
    SECURE_STRICT_VERIFICATION=True   # Strict verification for re-entering the password

To redefine:

```python
from authentication.settings import settings

settings.SECURE_COOKIE_NAME = "new_name"
```

[To set up a database connection](https://github.com/mtuciru/ConnectKit-Database/blob/master/README.md).

To enable authorization endpoints:

```python
from fastapi import FastAPI
from authentication import router as auth_router

app = FastAPI()
app.include_router(auth_router, prefix="/api/auth")

```

To get the current account or session:

```python
from fastapi import APIRouter, Depends
from authentication import get_account, get_session
from authentication.models import Account, AccountSession
from authentication.errors import auth_errors, with_errors

router = APIRouter()


@router.get("/test", responses=with_errors(*auth_errors))
async def test(account: Account = Depends(get_account)):
    print(account)


@router.get("/test2", responses=with_errors(*auth_errors))
async def test2(account_session: AccountSession = Depends(get_session)):
    print(account_session)

```

The `get_session` function checks for the presence of a session and the passage of 2FA.

The `get_account` function checks the same as `get_session`, as well as the account activation status.

If the login is not completed or outdated, HttpException will be raised from the list of `auth_errors` exceptions.

To implement the registration form, manually add users and administrative work:

```python
from authentication import (NewAccount, login_rules, password_rules,
                            login_type, password_type,
                            create_new_account, delete_account,
                            block_account, unblock_account, get_block_status,
                            get_status_otp, disable_otp)
from pydantic import BaseModel, EmailStr

# Creating a new user

try:
    new_acc = NewAccount(
        login="root",  # The user's unique login is set by the login_rules rule
        password="password",  # The user's password is set by the password_rules rule
        properties={  # User properties required in a specific task, Dict[str, Any]
            "name": "name"
        },
        active=True  # Is the account activated, False by default
    )
    account = await create_new_account(new_acc)
except ValueError as e:
    # The user already exists, or there is a validation error in the New Account
    pass


# Example of a registration scheme

class UserRegistration(BaseModel):
    login: login_type
    nickname: str
    email: EmailStr
    password: password_type


# Deleting an account
await delete_account(account)

# Getting the blocking status (bool, Optional[str])
block, reason = await get_block_status(account)

# Getting 2FA status
otp_enabled = await get_status_otp(account)

# Account blocking (a blocked account cannot log in)
await block_account(account, "reason")

# Unblocking account
await unblock_account(account)

# Forced disable of 2FA
await disable_otp(account)


```

Authentication diagram:

![Authentication diagram](./login.jpg)

Token update diagram:

![Token update diagram](./refresh.jpg)

## License

___

ConnectKit FastAPIAuthentication is [MIT License](./LICENSE).