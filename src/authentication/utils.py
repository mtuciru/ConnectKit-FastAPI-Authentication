from hashlib import md5
from typing import Tuple, Optional, Any, AsyncGenerator

from pyotp import TOTP, HOTP
from sqlalchemy import select
from sqlalchemy.orm import load_only, undefer_group

from authentication.models import Account, LoginProtection
from authentication.schemes import NewAccount, can_send_email
from database.asyncio import AsyncDatabase, AsyncSession

from authentication.settings import settings


async def create_new_account(new_account: NewAccount, check_can_send_email: bool = False) -> Account:
    if settings.SECURE_LOGIN_EMAIL and check_can_send_email:
        if not can_send_email(new_account.login):
            raise ValueError("Can't send email to this account")
    async with AsyncDatabase() as db:
        account = await db.scalar(select(Account).options(
            load_only(Account.id)
        ).filter_by(login=new_account.login))
        if account is not None:
            raise ValueError(f'Account with login {new_account.login} already exists')
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=new_account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            db.add(protection)
        protection.login = new_account.login
        protection.csrf_uuid = None
        protection.csrf_failed_count = 0
        protection.csrf_until_date = None
        protection.block = False
        protection.block_reason = None
        protection.otp_codes = None
        protection.otp_secret = None
        protection.otp_codes_init = None
        protection.otp_codes_secret = None
        account = Account()
        account.login = new_account.login
        account.password = new_account.password
        account.active = new_account.active
        db.add(account)
        await db.commit()
        db.expunge(account)
        return account


async def delete_account(temp_account: Account) -> None:
    async with AsyncDatabase() as db:
        account = await db.scalar(select(Account).options(
            load_only(Account.id)
        ).filter_by(login=temp_account.login))
        if account is not None:
            await db.delete(account)
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=temp_account.login).with_for_update())
        if protection is not None:
            await db.delete(protection)
        await db.commit()


async def _set_block_account(account: Account, block: bool, reason: str = None) -> None:
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(LoginProtection).options(
            load_only(LoginProtection.login)
        ).filter_by(login=account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            protection.login = account.login
            db.add(protection)
        protection.block = block
        protection.block_reason = reason
        await db.commit()


async def block_account(account: Account, reason: str) -> None:
    await _set_block_account(account, block=True, reason=reason)


async def unblock_account(account: Account) -> None:
    await _set_block_account(account, block=False)


async def get_block_status(account: Account) -> Tuple[bool, Optional[str]]:
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(LoginProtection).options(
            undefer_group("block")
        ).filter_by(login=account.login).with_for_update())
        if protection is None:
            protection = LoginProtection()
            protection.login = account.login
            protection.block = False
            protection.block_reason = None
            db.add(protection)
            await db.commit()
        return protection.block, protection.block_reason


if settings.SECURE_OTP_ENABLED:
    async def disable_otp(account: Account):
        async with AsyncDatabase() as db:
            protection = await db.scalar(select(LoginProtection).options(
                load_only(LoginProtection.login)
            ).filter_by(login=account.login).with_for_update())
            if protection is None:
                protection = LoginProtection()
                protection.login = account.login
            protection.otp_secret = None
            protection.otp_codes = None
            protection.otp_codes_secret = None
            protection.otp_codes_init = None
            await db.commit()


    async def get_status_otp(account: Account):
        async with AsyncDatabase() as db:
            protection = await db.scalar(select(LoginProtection).options(
                load_only(LoginProtection.otp_enabled)
            ).filter_by(login=account.login).with_for_update())
            if protection is None:
                protection = LoginProtection()
                protection.login = account.login
                await db.commit()
            return protection.otp_enabled


    async def verify_otp_code(account: Account, otp_code: str) -> bool:
        async with AsyncDatabase() as db:
            protection = await db.scalar(
                select(LoginProtection).options(
                    undefer_group("otp"), undefer_group("otp_codes")
                ).filter_by(login=account.login).with_for_update())
            totp = TOTP(protection.otp_secret)
            hotp = HOTP(protection.otp_codes_secret, initial_count=protection.otp_codes_init)
            if totp.verify(otp_code):
                return True
            codes_md5 = list(protection.otp_codes)
            digest = md5(otp_code.encode("UTF-8")).hexdigest()
            i = codes_md5.index(digest)
            if not hotp.verify(otp_code, i):
                return False
            codes_md5[i] = ""
            protection.otp_codes = codes_md5
            await db.commit()
            return True


async def get_database() -> AsyncGenerator[AsyncSession, Any]:
    async with AsyncDatabase() as db:
        yield db
