from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response, Body, status, Query, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import load_only, undefer_group
from database.asyncio import AsyncSession

from ..impl.token_utility import reset_cookie
from ..models import Account, AccountSession, AccountProtection
from ..schemes.auth import SessionsInfo, UserInfo, NewPassword
from ..schemes.responses import unauthorized, access_timeout, invalid_credentials, csrf_invalid
from ..settings import settings
from ..utils.common import get_database, responses, sleep_protection, csrf_expired, uuid_extract_time, direct_block_account
from ..middleware import authenticated

router = APIRouter(prefix="/account", tags=["Base account operations"])


@router.get("/sessions", response_model=SessionsInfo, responses=responses(
    unauthorized, access_timeout
))
@authenticated(active_only=False)
async def account_sessions(
        request: Request,
        db: AsyncSession = Depends(get_database)
):
    session: AccountSession = request.auth.session
    db.add(session)
    _load = await session.awaitable_attrs.invalid_after

    other_sessions = await db.scalars(select(AccountSession).options(
        load_only(AccountSession.fingerprint, AccountSession.invalid_after)
    ).filter_by(account_id=session.account_id).filter(AccountSession.id != session.id))

    return SessionsInfo.model_validate({
        "current": session,
        "other": other_sessions
    })


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT, responses=responses(
    unauthorized, access_timeout
))
@authenticated(active_only=False)
async def close_account_session(
        request: Request,
        response: Response,
        sid: Optional[int] = Query(None),
        db: AsyncSession = Depends(get_database)
):
    session: AccountSession = request.auth.session
    db.add(session)
    if sid is None or session.id == sid:
        reset_cookie(response)
        await db.delete(session)
        await db.commit()
        return
    session = await db.scalar(select(AccountSession).options(
        load_only(AccountSession.id)
    ).filter_by(id=sid, account_id=session.account_id))
    if session is not None:
        await db.delete(session)
        await db.commit()


@router.get("/", response_model=UserInfo, responses=responses(
    unauthorized, access_timeout
))
@authenticated(active_only=False)
async def get_me(
        request: Request,
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    session: AccountSession = request.auth.session
    db.add(session)
    _load = await session.awaitable_attrs.created_at
    return UserInfo.model_validate({
        "login": account.login,
        "active": account.active,
        "fingerprint": session.fingerprint,
        "login_at": session.created_at
    })


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT, responses=responses(
    unauthorized, access_timeout, csrf_invalid, invalid_credentials
))
@authenticated()
async def update_password(
        request: Request,
        params: NewPassword = Body(),
        db: AsyncSession = Depends(get_database)
):
    await sleep_protection()
    account: Account = request.user.account
    session: AccountSession = request.auth.session
    db.add(account)
    db.add(session)
    protection: AccountProtection = await db.scalar(select(AccountProtection).options(
        undefer_group("confirm"), undefer_group("block")
    ).filter_by(login=account.login).with_for_update())
    if protection.confirm_uuid is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if csrf_expired(uuid_extract_time(protection.confirm_uuid)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if params.csrf != protection.confirm_uuid:
        protection.confirm_uuid = None
        protection.confirm_attempt_count += 1
        await db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
    if not (await account.awaitable_attrs.verify_password(params.old_password)):
        protection.confirm_uuid = None
        protection.confirm_attempt_count += 1
        if 0 < settings.confirm_password_attempt_count <= protection.confirm_attempt_count:
            await direct_block_account(protection,
                                "The limit of change password attempts has been reached. Access to administrator", db)
            protection.confirm_attempt_count = 0
            await db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=protection.block_reason)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Verification failed")
    account.password = params.new_password
    account.password_changed_at = datetime.now(tz=timezone.utc)
    await db.commit()
