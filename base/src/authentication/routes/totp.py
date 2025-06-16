import asyncio
import random
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import md5
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response, Body, status, Query, HTTPException
from pyotp import HOTP, TOTP
from sqlalchemy import select
from sqlalchemy.orm import undefer_group, load_only
from database.asyncio import AsyncSession

from ..middleware import anonymous, authenticated, AnonymousCredentials
from ..models import Account, AccountProtection, AccountSession
from ..schemes.auth import CSRFToken

from ..schemes.totp import SetupOTPLink, ReserveOTPCodes, OTPCode
from ..schemes.responses import (already_authenticated, csrf_invalid, invalid_credentials, account_blocked,
                                 unauthorized, access_timeout)
from ..settings import settings

from ..utils.common import get_database, responses, sleep_protection, uuid_extract_time, csrf_expired, \
    direct_block_account
from ..utils.functions import validate_confirm_csrf

router = APIRouter(prefix="/otp", tags=["TOTP"])

_base_chars = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_sr = random.SystemRandom()


def get_secret():
    return "".join(random.choice(_base_chars) for _ in range(32))


@router.post("/setup_init", response_model=SetupOTPLink, responses=responses(
    unauthorized, access_timeout, csrf_invalid, {400: "TOTP setup already initiated"}
))
@authenticated(require_password_confirm=True)
async def otp_setup_init(
        request: Request,
        csrf: CSRFToken = Body(),
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    await validate_confirm_csrf(account, csrf.token)
    protection = await db.scalar(select(AccountProtection).options(
        undefer_group("otp")
    ).filter_by(id=account.id).with_for_update())
    if protection.otp_codes_init is None:
        if protection.otp_secret is None:
            protection.otp_secret = get_secret()
            await db.commit()
        totp = TOTP(protection.otp_secret)
        link = totp.provisioning_uri(name=account.login, issuer_name=settings.issuer)
        return SetupOTPLink(secret=protection.otp_secret, install_link=link)
    raise HTTPException(status_code=400, detail="TOTP setup already initiated")


@router.post("/setup_complete", response_model=ReserveOTPCodes, responses=responses(
    unauthorized, access_timeout,
    {400: "TOTP setup already completed"},
    {400: "TOTP setup not started"},
    {400: "TOTP setup validation failed"}
))
@authenticated()
async def otp_setup_verify(
        request: Request,
        params: OTPCode,
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    db.add(account)
    protection = await db.scalar(select(AccountProtection).options(
        undefer_group("otp"), undefer_group("otp_codes")
    ).filter_by(id=account.id).with_for_update())
    if protection.otp_secret is None:
        raise HTTPException(status_code=400, detail="TOTP setup not started")
    if protection.otp_codes_init is not None:
        raise HTTPException(status_code=400, detail="TOTP setup already completed")
    totp = TOTP(protection.otp_secret)
    if not totp.verify(params.code):
        raise HTTPException(status_code=400, detail="TOTP setup validation failed")
    protection.otp_codes_secret = get_secret()
    protection.otp_codes_init = _sr.randint(10, 300)
    hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
    codes = []
    codes_md5 = []
    for i in range(10):
        code = hotp.at(i)
        codes.append(code)
        codes_md5.append(md5(code.encode("UTF-8")).hexdigest())
    protection.otp_codes = codes_md5
    account.totp = True
    await db.commit()
    return ReserveOTPCodes(codes=codes)


@router.post("/setup_abort", status_code=status.HTTP_204_NO_CONTENT, responses=responses(
    unauthorized, access_timeout,
    {400: "TOTP setup not started"},
    {400: "TOTP setup validation failed"}
))
@authenticated()
async def otp_setup_abort(
        request: Request,
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    db.add(account)
    protection: AccountProtection = await db.scalar(select(AccountProtection).options(
        undefer_group("otp"), undefer_group("otp_codes")
    ).filter_by(id=account.id).with_for_update())
    if protection.otp_secret is None:
        raise HTTPException(status_code=400, detail="TOTP setup not started")
    if protection.otp_codes_init is not None:
        raise HTTPException(status_code=400, detail="TOTP setup already completed")
    protection.otp_secret = None
    account.totp = False
    await db.commit()


@router.post("/gen_reserve_codes", response_model=ReserveOTPCodes, responses=responses(
    unauthorized, access_timeout, csrf_invalid,
    {400: "TOTP not enabled"},
))
@authenticated(require_password_confirm=True)
async def otp_update_codes(
        request: Request,
        csrf: CSRFToken = Body(),
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    await validate_confirm_csrf(account, csrf.token)
    protection: AccountProtection = await db.scalar(select(AccountProtection).options(
        undefer_group("otp_codes")
    ).filter_by(id=account.id).with_for_update())
    if protection.otp_codes_init is None:
        raise HTTPException(status_code=400, detail="TOTP not enabled")
    protection.otp_codes_secret = get_secret()
    protection.otp_codes_init = _sr.randint(10, 300)
    hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
    codes = []
    codes_md5 = []
    for i in range(10):
        code = hotp.at(i)
        codes.append(code)
        codes_md5.append(md5(code.encode("UTF-8")).hexdigest())
    protection.otp_codes = codes_md5
    await db.commit()
    return ReserveOTPCodes(codes=codes)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT, responses=responses(
    unauthorized, access_timeout, csrf_invalid
))
@authenticated(require_password_confirm=True)
async def otp_disable(
        request: Request,
        csrf: CSRFToken = Body(),
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    await validate_confirm_csrf(account, csrf.token)
    db.add(account)
    protection = await db.scalar(select(AccountProtection).options(
        load_only(AccountProtection.id)
    ).filter_by(id=account.id).with_for_update())
    protection.otp_secret = None
    protection.otp_codes_secret = None
    protection.otp_codes_init = None
    protection.otp_codes = None
    account.totp = False
    await db.commit()


@router.post("/verify", status_code=status.HTTP_204_NO_CONTENT, responses=responses(
    unauthorized, access_timeout, {403: "Wrong code"}
))
@authenticated(active_only=False)
async def otp_verify(
        request: Request,
        otp_code: OTPCode,
        db: AsyncSession = Depends(get_database)
):
    account: Account = request.user.account
    session: AccountSession = request.auth.session
    if session.otp_success:
        return
    protection: AccountProtection = await db.scalar(
        select(AccountProtection).options(
            undefer_group("otp")
        ).filter_by(id=account.id).with_for_update())
    totp = TOTP(protection.otp_secret)
    if totp.verify(otp_code.code):
        session.otp_success = True
        await db.commit()
        return
    await protection.awaitable_attrs.otp_codes_secret
    await protection.awaitable_attrs.otp_codes_init
    await protection.awaitable_attrs._otp_codes
    hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
    codes_md5 = list(protection.otp_codes)
    try:
        digest = md5(otp_code.code.encode("UTF-8")).hexdigest()
        i = codes_md5.index(digest)
        if not hotp.verify(otp_code.code, i):
            raise ValueError
        codes_md5[i] = ""
        protection.otp_codes = codes_md5
        session.otp_success = True
        await db.commit()
        return
    except ValueError:
        await session.awaitable_attrs.otp_attempt_count
        session.otp_attempt_count += 1
        if 0 < settings.otp_attempt_count <= session.otp_attempt_count:
            await db.delete(session)
            await db.commit()
        raise HTTPException(status_code=403, detail="OTP verification failed")
