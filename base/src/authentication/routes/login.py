from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Request, Response, Body, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import undefer_group
from starlette import status

from ..impl import BlockedAccount
from ..impl.token_utility import reset_cookie, TokenExpired, TokenInvalid
from ..middleware import anonymous, authenticated, has_any_user_scope, AnonymousCredentials
from ..models import Account, AccountProtection, AccountSession

from ..schemes.auth import LoginBy, Tokens, AccountCredentials, ConfirmPassword
from ..schemes.responses import (already_authenticated, csrf_invalid, invalid_credentials, account_blocked,
                                 unauthorized, access_timeout, forbidden)
from ..settings import settings

from ..utils.common import get_database, responses, sleep_protection, uuid_extract_time, csrf_expired, \
    direct_block_account
from ..utils.functions import validate_confirm_csrf, count_attempts
from ..impl.auth_utility import init_tokens, refresh_tokens, InvalidRefreshToken
from database.asyncio import AsyncSession

router = APIRouter(tags=["Login operations"])


@router.post("/login", response_model=Tokens, responses=responses(
    already_authenticated, csrf_invalid, invalid_credentials, account_blocked
))
@anonymous
async def login(
        request: Request,
        response: Response,
        credentials: AccountCredentials,
        db: AsyncSession = Depends(get_database)
):
    """Логин"""
    login_by = credentials.login_by
    protection: AccountProtection | None = None
    if login_by == LoginBy.LOGIN:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("csrf"),
            undefer_group("block")
        ).filter_by(login=credentials.login).with_for_update())
    elif login_by == LoginBy.EMAIL:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("csrf"),
            undefer_group("block")
        ).filter_by(email=credentials.login).with_for_update())
    elif login_by == LoginBy.PHONE:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("csrf"),
            undefer_group("block")
        ).filter_by(phone=credentials.login).with_for_update())
    if protection is None:
        # No registered user
        await sleep_protection()
        # check token exists
        auth: AnonymousCredentials = request.auth
        token: str | None = auth.session_data.get("token", None)
        if token is not None:
            date = uuid_extract_time(token)
            auth.session_data["token"] = None
            auth.mark_session_data_dirty()
            if csrf_expired(date):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if protection.login_uuid is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if csrf_expired(uuid_extract_time(protection.login_uuid)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if protection.login_by != login_by:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if protection.block:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=protection.block_reason)
    account = await db.scalar(select(Account).options(
        undefer_group("sensitive"), undefer_group("totp")
    ).filter_by(id=protection.id))
    # Protect by CSRF
    if credentials.csrf != protection.login_uuid:
        protection.login_uuid = None
        await db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if not account.verify_password(credentials.password):
        protection.login_uuid = None
        protection.login_attempt_count += 1
        if 0 < settings.login_attempt_count <= protection.login_attempt_count:
            await direct_block_account(protection,
                                       "The limit of login attempts has been reached. Access to administrator", db)
            protection.login_attempt_count = 0
            await db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=protection.block_reason)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    protection.login_uuid = None
    protection.login_by = None
    protection.login_delay = None
    protection.login_attempt_count = 0
    await db.commit()
    return await init_tokens(account, credentials.remember_me, request, response, db)


@router.post("/logout", response_model=Tokens, responses=responses(
    unauthorized, access_timeout, forbidden
))
@authenticated(active_only=False)
async def logout(
        request: Request,
        response: Response,
        db: AsyncSession = Depends(get_database)
):
    """Логаут"""
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    session = request.auth.session
    db.add(session)
    await db.refresh(session)
    await db.delete(session)
    await db.commit()
    reset_cookie(response)


@router.post("/refresh", response_model=Tokens, responses=responses(
    unauthorized, access_timeout, forbidden, {419: "Session expired", 403: "Token invalid"}
))
@authenticated(active_only=False)
async def refresh_token(
        request: Request,
        response: Response,
        refresh: str = Body(embed=True),
        db: AsyncSession = Depends(get_database)
):
    """рефреш"""
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    session = request.auth.session
    db.add(session)
    try:
        return await refresh_tokens(request, response, request.auth.session, refresh, db)
    except TokenExpired:
        await db.delete(session)
        await db.commit()
        raise HTTPException(status_code=419, detail="Session expired")
    except (TokenInvalid, InvalidRefreshToken, BlockedAccount):
        await db.delete(session)
        await db.commit()
        raise HTTPException(status_code=403, detail="Token invalid")


@router.post("/confirm", status_code=204, responses=responses(
    unauthorized, access_timeout, csrf_invalid, invalid_credentials, forbidden
))
@authenticated()
async def confirm_password(
        request: Request,
        params: ConfirmPassword,
        db: AsyncSession = Depends(get_database),
):
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    account: Account = request.user.account
    session: AccountSession = request.auth.session
    await validate_confirm_csrf(account, params.confirm_csrf)
    db.add(account)
    if not await account.async_verify_password(params.password):
        await count_attempts(account, session, False)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    await count_attempts(account, session, True)
    db.add(session)
    session.confirmed_before = datetime.now(tz=timezone.utc) + timedelta(minutes=settings.password_confirm_lifetime)
    await db.commit()
