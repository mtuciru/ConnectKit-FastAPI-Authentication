import json
import re
from typing import Dict, Any, Optional, List

from fastapi import Request, Response, Depends

import jwt
from datetime import datetime, timedelta, timezone
import uuid

from ietfparse import headers
from sqlalchemy import select
from sqlalchemy.orm import load_only, undefer_group

import authentication.errors as errors
from authentication.models import Account, AccountSession, LoginProtection
from authentication.schemes import Refresh
from authentication.utils import get_database
from database.asyncio import AsyncSession
from authentication.settings import settings

agent_parser = re.compile(r"^([\w]*)/([\d.]*)\s*(?:\((.*?)\)\s*(.*))?$")


def set_cookie(access: str, response: Response, max_age: int):
    response.set_cookie(settings.SECURE_COOKIE_NAME, access, httponly=True, samesite="lax", max_age=max_age,
                        path=settings.SECURE_PATH,
                        secure=settings.SECURE_ONLY)


def get_user_agent_info(request: Request):
    user_agent = request.headers.get("user-agent")
    info = [get_real_client_ip(request)]
    match = agent_parser.fullmatch(user_agent)
    if match:
        info += list(match.groups())
    return "".join(json.dumps(info, ensure_ascii=False, separators=(",", ":")))


def parse_forwarded_for(data: str) -> List[str]:
    return list(map(lambda s: s.strip(), data.split(",")))


def get_real_client_ip(request: Request):
    ip = request.client[0]
    if "X-Forwarded-For" in request.headers:
        ips = parse_forwarded_for(request.headers["X-Forwarded-For"])
        if ips[-1] != ip:
            return ip
        ip = ips[0]
    elif "Forwarded" in request.headers:
        parsed = headers.parse_forwarded(request.headers["Forwarded"])
        for p in parsed:
            if "for" in p:
                ip = p["for"]
                break
    elif "X-Real-IP" in request.headers:
        ip = request.headers["X-Real-IP"]
    return ip


def encode_token(payload) -> str:
    return jwt.encode(payload, settings.SECURE_SECRET, algorithm='HS256')


def decode_token(token: str, token_type: str, suppress: bool = False) -> Dict[str, Any]:
    try:
        data = jwt.decode(token, settings.SECURE_SECRET, algorithms=['HS256'],
                          options={"require": ["exp", "role", "session", "identity"]})
        if data["role"] != token_type:
            raise errors.token_validation_failed()
        return data
    except jwt.ExpiredSignatureError:
        if suppress:
            data = jwt.decode(token, settings.SECURE_SECRET, algorithms=['HS256'],
                              options={"verify_signature": False})
            if data["role"] != token_type:
                raise errors.token_validation_failed()
            return data
        raise errors.token_expired()
    except jwt.DecodeError:
        raise errors.token_validation_failed()


async def _init_and_get_refresh(request: Request, response: Response, session: AccountSession, long: bool,
                                db: AsyncSession):
    now = datetime.now(timezone.utc)
    identity = f"{uuid.uuid1(int(now.timestamp()))}"
    session.fingerprint = get_user_agent_info(request)
    session.identity = identity
    if long:
        session.invalid_after = now + timedelta(hours=settings.SECURE_REFRESH_LONG_EXPIRE)
        max_age = settings.SECURE_REFRESH_LONG_EXPIRE * 3600
    else:
        session.invalid_after = now + timedelta(hours=settings.SECURE_REFRESH_EXPIRE)
        max_age = settings.SECURE_REFRESH_EXPIRE * 3600
    await db.flush([session])
    access_payload = {
        "role": "access",
        "session": session.id,
        "identity": identity,
        "exp": now + timedelta(minutes=settings.SECURE_ACCESS_EXPIRE)
    }
    refresh_payload = {
        "role": "refresh",
        "session": session.id,
        "identity": identity,
        "long": long,
        "exp": session.invalid_after
    }
    access = encode_token(access_payload)
    refresh = encode_token(refresh_payload)
    set_cookie(access, response, max_age)

    return refresh


async def init_tokens(account: Account, long: bool, wait_otp: bool, request: Request, response: Response,
                      db: AsyncSession):
    session = AccountSession()
    db.add(session)
    session.account_id = account.id
    session.wait_otp = wait_otp
    refresh = await _init_and_get_refresh(request, response, session, long, db)
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
    ).filter_by(login=(await session.awaitable_attrs.account).login))
    if protection.block:
        await db.delete(session)
        await db.commit()
        raise errors.invalid_credentials(protection.block_reason)

    long = "long" in refresh_payload and refresh_payload["long"]
    refresh = await _init_and_get_refresh(request, response, session, long, db)
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
