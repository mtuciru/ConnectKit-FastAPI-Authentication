import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response, Body, status, Query
from sqlalchemy import select
from sqlalchemy.orm import undefer_group, load_only

import authentication.errors as errors
from authentication.auth import get_session, init_tokens, refresh_tokens, get_account, _get_inactive_account
from authentication.models import LoginProtection, Account, AccountSession
from authentication.schemes import (Refresh, AccountCredentials, GetSessions,
                                    CSRFRequest, CSRFReturn,
                                    UserInfo, NewPassword)
from authentication.settings import settings
from authentication.utils import get_database
from database.asyncio import AsyncSession

router = APIRouter()


@router.post("/csrf", response_model=CSRFReturn, responses=errors.with_errors(
    errors.csrf_too_many_requests()
))
async def csrf(
        params: CSRFRequest,
        db: AsyncSession = Depends(get_database)
):
    """Защита от перебора паролей и от утечки аккаунта"""
    await asyncio.sleep(random.random())  # Защита от определения поведения кода по времени исполнения
    protection = await db.scalar(select(LoginProtection).options(
        undefer_group("csrf")
    ).filter_by(login=params.login).with_for_update())
    if protection is None:
        protection = LoginProtection()
        protection.login = params.login
        db.add(protection)
        await db.commit()
    if protection.csrf_uuid is None:
        if protection.csrf_until_date > datetime.now(tz=timezone.utc):
            raise errors.csrf_too_many_requests()
        protection.csrf_uuid = str(uuid.uuid4())
        protection.csrf_until_date = datetime.now(tz=timezone.utc) + timedelta(
            seconds=(1.5 * (protection.csrf_failed_count + 1)))
        await db.commit()
        return CSRFReturn.model_validate({
            "csrf": protection.csrf_uuid
        })
    return CSRFReturn.model_validate({
        "csrf": protection.csrf_uuid
    })


@router.post("/login", response_model=Refresh, responses=errors.with_errors(
    errors.invalid_credentials(), errors.invalid_credentials("Block reason")
))
async def login(
        request: Request,
        response: Response,
        credentials: AccountCredentials,
        db: AsyncSession = Depends(get_database)
):
    """Логин"""
    protection = await db.scalar(select(LoginProtection).options(
        undefer_group("csrf"),
        undefer_group("block")
    ).filter_by(login=credentials.login).with_for_update())
    account = await db.scalar(select(Account).options(undefer_group("sensitive")).filter_by(login=credentials.login))
    await asyncio.sleep(random.random())
    if protection is None or protection.csrf_uuid is None:
        raise errors.invalid_credentials()
    if protection.block:
        raise errors.invalid_credentials(protection.block_reason)
    if account is None:
        raise errors.invalid_credentials()
    # Protect by CSRF
    if credentials.csrf != protection.csrf_uuid:
        protection.csrf_uuid = None
        protection.csrf_failed_count += 1
        await db.commit()
        raise errors.invalid_credentials()
    if not account.verify_password(credentials.password):
        protection.csrf_uuid = None
        protection.csrf_failed_count += 1
        if 0 < settings.SECURE_BLOCK_TRIES <= protection.csrf_failed_count:
            protection.block = True
            protection.block_reason = "The limit of login attempts has been reached. Access to administrator"
            await db.commit()
            raise errors.invalid_credentials(protection.block_reason)
        await db.commit()
        raise errors.invalid_credentials()
    protection.csrf_uuid = None
    protection.csrf_failed_count = 0
    await db.commit()
    return await init_tokens(account, credentials.remember_me, protection.otp_enabled, request, response, db)


@router.post("/refresh", response_model=Refresh, responses=errors.with_errors(
    *errors.auth_errors
))
async def refresh_token(request: Request,
                        response: Response,
                        params: Refresh = Body(),
                        db: AsyncSession = Depends(get_database)):
    """рефреш"""
    access = request.cookies.get("access")
    return await refresh_tokens(access, params.refresh, request, response, db)


@router.get("/sessions", response_model=GetSessions, responses=errors.with_errors(
    *errors.auth_errors
))
async def account_sessions(account_session: AccountSession = Depends(get_session),
                           db: AsyncSession = Depends(get_database)):
    _load = await account_session.awaitable_attrs.fingerprint
    _load = await account_session.awaitable_attrs.invalid_after

    other_sessions = await db.scalars(select(AccountSession).options(
        load_only(AccountSession.fingerprint, AccountSession.invalid_after)
    ).filter_by(account_id=account_session.account_id).filter(AccountSession.id != account_session.id))

    return GetSessions.model_validate({
        "current": account_session,
        "other": other_sessions
    })


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT, responses=errors.with_errors(
    *errors.auth_errors, errors.session_not_found()
))
async def close_account_session(response: Response,
                                sid: Optional[int] = Query(None),
                                account_session: AccountSession = Depends(get_session),
                                db: AsyncSession = Depends(get_database)):
    if sid is None or account_session.id == sid:
        response.delete_cookie(key="access")
        await db.delete(account_session)
        await db.commit()
        return
    session = db.scalar(select(AccountSession).options(
        load_only(AccountSession.id)
    ).filter_by(id=sid, account_id=account_session.account_id))
    if session is None:
        raise errors.session_not_found()
    await db.delete(session)
    await db.commit()


@router.get("/me", response_model=UserInfo, responses=errors.with_errors(
    *errors.auth_errors
))
async def get_me(account: Account = Depends(_get_inactive_account)):
    return UserInfo.model_validate({
        "login": account.login,
        "active": account.active,
        "auth_datetime": account.auth_datetime
    })


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT, responses=errors.with_errors(
    *errors.auth_errors, errors.invalid_credentials("Verification failed")
))
async def update_password(params: NewPassword = Body(),
                          account: Account = Depends(get_account),
                          db: AsyncSession = Depends(get_database)):
    await asyncio.sleep(random.random())
    if not (await account.awaitable_attrs.verify_password(params.old_password)):
        if settings.SECURE_STRICT_VERIFICATION:
            protection = await db.scalar(select(LoginProtection).options(
                load_only(LoginProtection.login)
            ).filter_by(login=account.login).with_for_update())
            protection.block = True
            protection.block_reason = "Old password is incorrect when changing password."
            await db.commit()
        raise errors.invalid_credentials("Verification failed")
    account.password = params.new_password
    account.password_changed_at = datetime.now(tz=timezone.utc)
    await db.commit()

# OTP section
