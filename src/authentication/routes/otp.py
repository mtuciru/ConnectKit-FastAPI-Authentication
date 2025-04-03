import asyncio
import random
from hashlib import md5

from fastapi import APIRouter, Depends, Body, status
from pyotp import HOTP, TOTP
from sqlalchemy import select
from sqlalchemy.orm import undefer_group, load_only

import authentication.errors as errors
from authentication.auth import get_account, _get_unverified_session
from authentication.models import LoginProtection, Account, AccountSession
from authentication.schemes import SetupOTP, OTPCodes, OTPCode, PasswordVerify
from authentication.settings import settings
from authentication.utils import get_database
from database.asyncio import AsyncSession

router = APIRouter()

if settings.SECURE_OTP_ENABLED:

    _base_chars = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    _sr = random.SystemRandom()


    def _get_secret():
        return "".join(random.choice(_base_chars) for _ in range(32))


    @router.get("/otp/setup", response_model=SetupOTP, responses=errors.with_errors(
        *errors.auth_errors, errors.otp_enabled()
    ))
    async def otp_setup(account: Account = Depends(get_account),
                        db: AsyncSession = Depends(get_database)):
        protection = await db.scalar(select(LoginProtection).options(
            undefer_group("otp")
        ).filter_by(login=account.login).with_for_update())
        if not protection.otp_enabled:
            if protection.otp_secret is None:
                protection.otp_secret = _get_secret()
                await db.commit()
            totp = TOTP(protection.otp_secret)
            link = totp.provisioning_uri(name=account.login, issuer_name=settings.SECURE_ISSUER)
            return SetupOTP(secret=protection.otp_secret, install_link=link)
        raise errors.otp_enabled()


    @router.post("/otp/setup_verify", response_model=OTPCodes, responses=errors.with_errors(
        *errors.auth_errors, errors.otp_setup_error(), errors.otp_enabled()
    ))
    async def otp_setup_verify(otp_code: OTPCode,
                               account: Account = Depends(get_account),
                               db: AsyncSession = Depends(get_database)):
        protection = await db.scalar(select(LoginProtection).options(
            undefer_group("otp")
        ).filter_by(login=account.login).with_for_update())
        if protection.otp_secret is None:
            raise errors.otp_setup_error()
        if protection.otp_enabled:
            raise errors.otp_enabled()
        totp = TOTP(protection.otp_secret)
        if not totp.verify(otp_code.code):
            protection.otp_secret = None
            await db.commit()
            raise errors.otp_setup_error()
        protection.otp_codes_secret = _get_secret()
        protection.otp_codes_init = _sr.randint(10, 300)
        hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
        codes = []
        codes_md5 = []
        for i in range(10):
            code = hotp.at(i)
            codes.append(code)
            codes_md5.append(md5(code.encode("UTF-8")).hexdigest())
        protection.otp_codes_list = codes_md5
        protection.otp_enabled = True
        await db.commit()
        return OTPCodes(codes=codes)


    @router.post("/otp/update_codes", response_model=OTPCodes, responses=errors.with_errors(
        *errors.auth_errors, errors.otp_disabled()
    ))
    async def otp_update_codes(verify: PasswordVerify = Body(),
                               account: Account = Depends(get_account),
                               db: AsyncSession = Depends(get_database)):
        protection = await db.scalar(select(LoginProtection).options(
            undefer_group("otp_codes")
        ).filter_by(login=account.login).with_for_update())
        if not protection.otp_enabled:
            raise errors.otp_disabled()
        if not (await account.awaitable_attrs.verify_password(verify.password)):
            if settings.SECURE_STRICT_VERIFICATION:
                protection.block = True
                protection.block_reason = "Password is incorrect when update otp codes."
                await db.commit()
            raise errors.invalid_credentials("Verification failed")
        protection.otp_codes_secret = _get_secret()
        protection.otp_codes_init = _sr.randint(10, 300)
        hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
        codes = []
        codes_md5 = []
        for i in range(10):
            code = hotp.at(i)
            codes.append(code)
            codes_md5.append(md5(code.encode("UTF-8")).hexdigest())
        protection.otp_codes_list = codes_md5
        await db.commit()
        return OTPCodes(codes=codes)


    @router.post("/otp/disable", status_code=status.HTTP_204_NO_CONTENT, responses=errors.with_errors(
        *errors.auth_errors, errors.otp_disabled()
    ))
    async def otp_disable(verify: PasswordVerify = Body(),
                          account: Account = Depends(get_account),
                          db: AsyncSession = Depends(get_database)):
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=account.login).with_for_update())
        if not (await account.awaitable_attrs.verify_password(verify.password)):
            if settings.SECURE_STRICT_VERIFICATION:
                protection.block = True
                protection.block_reason = "Password is incorrect when disabling 2FA."
                await db.commit()
            raise errors.invalid_credentials("Verification failed")
        protection.otp_enabled = False
        protection.otp_secret = None
        protection.otp_codes_secret = None
        protection.otp_codes_init = None
        protection.otp_codes_list = None
        await db.commit()


    @router.post("/otp/verify", status_code=status.HTTP_204_NO_CONTENT, responses=errors.with_errors(
        *errors.auth_errors, errors.otp_verify_failed()
    ))
    async def otp_verify(otp_code: OTPCode,
                         account_session: AccountSession = Depends(_get_unverified_session),
                         db: AsyncSession = Depends(get_database)):
        if not (await account_session.awaitable_attrs.wait_otp):
            await asyncio.sleep(random.random())
            return
        protection = await db.scalar(
            select(LoginProtection).options(
                undefer_group("otp"), undefer_group("otp_codes")
            ).filter_by(login=(await account_session.awaitable_attrs.account).login).with_for_update())
        await asyncio.sleep(1)
        totp = TOTP(protection.otp_secret)
        hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
        if totp.verify(otp_code.code):
            await asyncio.sleep(random.random())
            account_session.wait_otp = False
            await db.commit()
            return
        codes_md5 = protection.otp_codes_list
        await asyncio.sleep(random.random())
        try:
            digest = md5(otp_code.code.encode("UTF-8")).hexdigest()
            i = codes_md5.index(digest)
            if not hotp.verify(otp_code.code, i):
                raise ValueError
            codes_md5[i] = ""
            protection.otp_codes_list = codes_md5
            account_session.wait_otp = False
            await db.commit()
            return
        except ValueError:
            _load = await account_session.awaitable_attrs.otp_attempts
            account_session.otp_attempts += 1
            if 0 < settings.SECURE_OTP_BLOCK_TRIES <= account_session.otp_attempts:
                await db.delete(account_session)
                await db.commit()
            raise errors.otp_verify_failed()
