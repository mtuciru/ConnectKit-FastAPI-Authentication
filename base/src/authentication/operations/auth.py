import uuid
from hashlib import md5
from datetime import datetime, timedelta, timezone
from typing import Optional

from database.asyncio import AsyncSession
from fastapi import Request, Response, Depends
from sqlalchemy import select
from sqlalchemy.orm import load_only, undefer_group

import authentication.errors as errors
from authentication.models import Account, AccountSession, LoginProtection
from authentication.schemes import Refresh
from authentication.settings import settings, configuration
from authentication.utils import (get_database, get_client_fingerprint, set_cookie, reset_cookie,
                                  encode_session_token, decode_session_token)


async def _update_session(request: Request, response: Response,
                          session: AccountSession, long: bool,
                          db: AsyncSession):
    now = datetime.now(timezone.utc)
    identity = f"{uuid.UUID(bytes=md5(now.isoformat().encode('utf8')).digest())}"
    session.fingerprint = get_client_fingerprint(request)
    session.identity = identity
    if long:
        session.invalid_after = now + timedelta(days=configuration.auth.refresh_lifetime_long)
        max_age = configuration.auth.refresh_lifetime_long * 86_400
    else:
        session.invalid_after = now + timedelta(hours=configuration.auth.refresh_lifetime_short)
        max_age = configuration.auth.refresh_lifetime_short * 3_600
    await db.flush([session])
    access_payload = {
        "iss": configuration.auth.issuer,
        "role": "access",
        "session": f"{session.id}",
        "identity": identity,
        "exp": now + timedelta(minutes=configuration.auth.access_lifetime),
    }
    refresh_payload = {
        "iss": configuration.auth.issuer,
        "role": "refresh",
        "session": f"{session.id}",
        "identity": identity,
        "long": long,
        "exp": session.invalid_after
    }
    access = encode_session_token(access_payload)
    refresh = encode_session_token(refresh_payload)
    set_cookie(access, response, max_age)
    return refresh


async def init_tokens(account: Account, long: bool, wait_otp: bool, request: Request, response: Response,
                      db: AsyncSession):
    session = AccountSession()
    db.add(session)
    session.account_id = account.id
    session.wait_otp = wait_otp
    refresh = await _update_session(request, response, session, long, db)
    await db.commit()
    return Refresh(refresh=refresh, wait_otp=wait_otp)


async def verify_access(access: Optional[str], request: Request, db: AsyncSession) -> AccountSession:
    if access is None:
        raise errors.unauthorized()
    access_payload = decode_token(access, "access")
    session = await db.scalar(select(AccountSession).options(
        load_only(AccountSession.fingerprint, AccountSession.identity,
                  AccountSession.wait_otp, AccountSession.created_at)
    ).filter_by(id=access_payload["session"]))
    if session is None:
        raise errors.unauthorized()
    if session.fingerprint != get_user_agent_info(request) or session.identity != access_payload["identity"]:
        await db.delete(session)
        await db.commit()
        raise errors.unauthorized()
    return session


async def refresh_tokens(access: Optional[str], refresh: str, request: Request, response: Response, db: AsyncSession):
    if access is None:
        raise errors.unauthorized()
    access_payload = decode_token(access, "access", suppress=True)
    refresh_payload = decode_token(refresh, "refresh")

    if access_payload["identity"] != refresh_payload["identity"]:
        raise errors.token_validation_failed()
    if access_payload["session"] != refresh_payload["session"]:
        raise errors.token_validation_failed()

    session = await db.scalar(select(AccountSession).options(
        load_only(AccountSession.fingerprint, AccountSession.identity, AccountSession.wait_otp)
    ).filter_by(id=access_payload["session"]))
    if session is None:
        raise errors.unauthorized()
    if session.wait_otp:
        await db.delete(session)
        await db.commit()
        raise errors.unauthorized()
    if session.fingerprint != get_user_agent_info(request) or session.identity != access_payload["identity"]:
        await db.delete(session)
        await db.commit()
        raise errors.unauthorized()

    protection = await db.scalar(select(LoginProtection).options(
        undefer_group("block")
    ).filter_by(login=(await session.awaitable_attrs.account).login).with_for_update())
    if protection.block:
        await db.delete(session)
        await db.commit()
        raise errors.invalid_credentials(protection.block_reason)

    long = "long" in refresh_payload and refresh_payload["long"]
    refresh = await _update_session(request, response, session, long, db)
    await db.commit()
    return Refresh(refresh=refresh, wait_otp=session.wait_otp)


async def _get_unverified_session(request: Request,
                                  db: AsyncSession = Depends(get_database)) -> AccountSession:
    """Получение сессии пользователя без проверки 2FA"""
    access = request.cookies.get("access")
    session = await verify_access(access, request, db)
    return session


async def get_session(request: Request,
                      db: AsyncSession = Depends(get_database)) -> AccountSession:
    """Получение сессии пользователя, после проверки OTP"""
    access = request.cookies.get("access")
    session = await verify_access(access, request, db)
    if session.wait_otp:
        raise errors.otp_required()
    return session


async def _get_inactive_account(request: Request,
                                db: AsyncSession = Depends(get_database)) -> Account:
    """Получение пользователя без проверки активности, но с проверкой otp"""
    session = await get_session(request, db)
    account = await session.awaitable_attrs.account
    account.auth_time = session.created_at.timestamp()
    account.auth_datetime = session.created_at
    return account


async def get_account(request: Request,
                      db: AsyncSession = Depends(get_database)) -> Account:
    """Получение пользователя"""
    session = await get_session(request, db)
    account: Account = await session.awaitable_attrs.account
    if not account.active:
        raise errors.account_not_active()
    account.auth_time = session.created_at.timestamp()
    account.auth_datetime = session.created_at
    return account


async def try_account(request: Request,
                      db: AsyncSession = Depends(get_database)) -> Optional[Account]:
    """Получение пользователя, если он есть"""
    access = request.cookies.get("access")
    if access is None:
        return None
    return await get_account(request, db)
