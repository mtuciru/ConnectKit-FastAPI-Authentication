from typing import Tuple, Optional

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import load_only, undefer_group

from .common import csrf_expired, uuid_extract_time
from ..models import Account, AccountProtection, AccountSession
from ..schemes.auth import NewAccount, is_sendable_email
from database.asyncio import AsyncDatabase

from ..settings import settings

__all__ = ["create_new_account", "delete_account", "block_account", "unblock_account", "get_block_status",
           "validate_confirm_csrf", "count_attempts"]


async def create_new_account(new_account: NewAccount, check_can_send_email: bool = False) -> Account:
    if "email" in settings.user_login_properties and check_can_send_email:
        if not is_sendable_email(new_account.email):
            raise ValueError("Can't send email to this email address")
    async with AsyncDatabase() as db:
        account = await db.scalar(select(Account).options(
            load_only(Account.id)
        ).filter_by(login=new_account.login))
        if account is not None:
            raise ValueError(f'Account with login {new_account.login} already exists')
        account = Account()
        account.login = new_account.login
        if "email" in settings.user_login_properties:
            account.email = new_account.email
        if "phone" in settings.user_login_properties:
            account.phone = new_account.phone
        account.password = new_account.password
        account.active = new_account.active
        if settings.user_has_scope:
            account.scopes = new_account.scopes
        db.add(account)
        await db.flush()
        protection = AccountProtection()
        protection.id = account.id
        protection.login = new_account.login
        if "email" in settings.user_login_properties:
            protection.email = new_account.email
        if "phone" in settings.user_login_properties:
            protection.phone = new_account.phone
        await db.commit()
        db.expunge(account)
    return account


async def delete_account(account: Account) -> None:
    async with AsyncDatabase() as db:
        db.add(account)
        protection = await db.scalar(select(AccountProtection).options(
            load_only(AccountProtection.id)
        ).filter_by(id=account.id).with_for_update())
        await db.delete(account)
        await db.delete(protection)
        await db.commit()


async def _set_block_account(account: Account, block: bool, reason: str = None) -> None:
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("block")
        ).filter_by(id=account.id).with_for_update())
        protection.block = block
        protection.block_reason = reason
        if block:
            sessions = await db.scalars(select(AccountSession).filter_by(account_id=account.id))
            for session in sessions:
                await db.delete(session)
        await db.commit()


async def block_account(account: Account, reason: str) -> None:
    await _set_block_account(account, block=True, reason=reason)


async def unblock_account(account: Account) -> None:
    await _set_block_account(account, block=False)


async def get_block_status(account: Account) -> Tuple[bool, Optional[str]]:
    async with AsyncDatabase() as db:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("block")
        ).filter_by(id=account.id).with_for_update())
        return protection.block, protection.block_reason


async def validate_confirm_csrf(account: Account, csrf: str):
    async with AsyncDatabase() as db:
        protection: AccountProtection = await db.scalar(select(AccountProtection).options(
            undefer_group("confirm")
        ).filter_by(id=account.id).with_for_update())
        if protection.confirm_uuid is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
        if csrf_expired(uuid_extract_time(protection.confirm_uuid)):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")
        if csrf != protection.confirm_uuid:
            protection.confirm_uuid = None
            await db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")


async def count_attempts(account: Account, session: AccountSession, success: bool):
    async with AsyncDatabase() as db:
        protection: AccountProtection = await db.scalar(select(AccountProtection).options(
            undefer_group("confirm")
        ).filter_by(id=account.id).with_for_update())
        if success:
            protection.confirm_attempt_count = 0
        else:
            protection.confirm_attempt_count += 1
            if 0 < settings.confirm_attempt_count <= protection.confirm_attempt_count:
                protection.confirm_attempt_count = 0
                db.add(session)
                await db.delete(session)
                await db.commit()
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Attempts limit reached")
        await db.commit()
