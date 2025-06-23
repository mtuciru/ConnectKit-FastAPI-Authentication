from datetime import datetime, timezone
from typing import Optional

from authentication.utils.functions import validate_confirm_csrf, count_attempts
from fastapi import APIRouter, Depends, Request, Response, Body, status, Query, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import load_only
from database.asyncio import AsyncSession

from .. import has_any_user_scope
from ..impl.token_utility import reset_cookie
from ..models import Account, AccountSession
from ..schemes.auth import SessionsInfo, UserInfo, NewPassword
from ..schemes.responses import unauthorized, access_timeout, invalid_credentials, csrf_invalid, forbidden
from ..utils.common import get_database, responses, sleep_protection
from ..middleware import authenticated

router = APIRouter(prefix="/account", tags=["Base account operations"])


@router.get("/sessions", response_model=SessionsInfo, responses=responses(
    unauthorized, access_timeout, forbidden
))
@authenticated(active_only=False)
async def account_sessions(
        request: Request,
        db: AsyncSession = Depends(get_database)
):
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
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
    unauthorized, access_timeout, forbidden
))
@authenticated(active_only=False)
async def close_account_session(
        request: Request,
        response: Response,
        sid: Optional[int] = Query(None),
        db: AsyncSession = Depends(get_database)
):
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
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
    unauthorized, access_timeout, forbidden
))
@authenticated(active_only=False)
async def get_me(
        request: Request,
        db: AsyncSession = Depends(get_database)
):
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
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
    unauthorized, access_timeout, csrf_invalid, invalid_credentials, forbidden
))
@authenticated(active_only=False, require_password_confirm=True)
async def update_password(
        request: Request,
        params: NewPassword = Body(),
        db: AsyncSession = Depends(get_database)
):
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    await sleep_protection()
    account: Account = request.user.account
    session: AccountSession = request.auth.session
    await validate_confirm_csrf(account, params.confirm_csrf)
    if not await account.async_verify_password(params.old_password):
        await count_attempts(account, session, False)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    await count_attempts(account, session, True)
    db.add(account)
    account.password = params.new_password
    account.password_changed_at = datetime.now(tz=timezone.utc)
    await db.commit()
