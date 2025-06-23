import uuid
from datetime import datetime, timedelta, timezone

from database.asyncio import AsyncSession
from fastapi import Request, Response
from sqlalchemy import select
from sqlalchemy.orm import undefer_group

from ..models import Account, AccountSession, AccountProtection
from ..schemes.auth import Tokens
from ..settings import settings
from ..impl.token_utility import (get_client_fingerprint, set_cookie,
                                  encode_session_token, decode_session_token)

__all__ = ["InvalidRefreshToken", "BlockedAccount", "init_tokens", "refresh_tokens"]


class InvalidRefreshToken(ValueError):
    pass


class BlockedAccount(ValueError):
    pass


def _create_identity_pair():
    now = datetime.now(timezone.utc)
    return now, uuid.uuid1().hex


async def _new_session(request: Request, response: Response,
                       account: Account, long: bool,
                       db: AsyncSession):
    session = AccountSession()
    db.add(session)
    session.account_id = account.id
    session.fingerprint = get_client_fingerprint(request)
    session.confirmed_before = datetime.now(tz=timezone.utc) + timedelta(minutes=settings.password_confirm_lifetime)
    session.otp_success = not account.totp
    return _update_session(response, session, long, db)


async def _update_session(response: Response,
                          session: AccountSession, long: bool,
                          db: AsyncSession):
    now, identity = _create_identity_pair()
    session.identity = identity
    if long:
        session.invalid_after = now + timedelta(days=settings.refresh_lifetime_long)
        max_age = settings.refresh_lifetime_long * 86_400
    else:
        session.invalid_after = now + timedelta(hours=settings.refresh_lifetime_short)
        max_age = settings.refresh_lifetime_short * 3_600
    await db.flush([session])
    access_payload = {
        "iss": settings.issuer,
        "sub": f"{session.account_id}",
        "sid": f"{session.id}",
        "aud": "access",
        "jit": identity,
        "exp": now + timedelta(minutes=settings.access_lifetime),
    }
    refresh_payload = {
        "iss": settings.issuer,
        "sub": f"{session.account_id}",
        "sid": f"{session.id}",
        "aud": "refresh",
        "jit": identity,
        "exp": session.invalid_after,
        "long": long
    }
    access = encode_session_token(access_payload)
    refresh = encode_session_token(refresh_payload)
    set_cookie(access, response, max_age)
    return Tokens(refresh=refresh)


async def init_tokens(account: Account, long: bool, request: Request, response: Response, db: AsyncSession):
    tokens = await _new_session(request, response, account, long, db)
    await db.commit()
    return tokens


async def refresh_tokens(request: Request, response: Response, session: AccountSession, refresh: str, db: AsyncSession):
    refresh_payload = decode_session_token(refresh, "refresh")
    if session.fingerprint != get_client_fingerprint(request) or session.identity != refresh_payload["jit"]:
        await db.delete(session)
        await db.commit()
        raise InvalidRefreshToken("Invalid refresh token")
    protection = await db.scalar(select(AccountProtection).options(
        undefer_group("block")
    ).filter_by(id=(await session.awaitable_attrs.account).id).with_for_update())
    if protection.block:
        await db.delete(session)
        await db.commit()
        raise BlockedAccount(protection.block_reason)
    long = "long" in refresh_payload and refresh_payload["long"]
    refresh = await _update_session(response, session, long, db)
    await db.commit()
    return refresh
