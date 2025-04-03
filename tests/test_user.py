import pytest
from sqlalchemy import select
from tests.common import session, auth_settings, client, init_models

from authentication.models import Account

from authentication import create_new_account, delete_account, NewAccount


@pytest.mark.asyncio
async def test_create_user_inactive(session, auth_settings):
    await init_models()
    await create_new_account(NewAccount.model_validate({
        "login": "inactive",
        "password": "SuperPass@123dda",
        "active": False
    }))

    async with session as db:
        account = await db.scalar(select(Account).filter_by(login="inactive"))
        assert account is not None
        assert account.active == False


@pytest.mark.asyncio
async def test_create_user_active(session, auth_settings):
    await init_models()
    await create_new_account(NewAccount.model_validate({
        "login": "active",
        "password": "SuperPass@123dda",
        "active": True
    }))

    async with session as db:
        account = await db.scalar(select(Account).filter_by(login="active"))
        assert account is not None
        assert account.active == True


@pytest.mark.asyncio
async def test_create_user_already_exists(session, auth_settings):
    await init_models()
    try:
        await create_new_account(NewAccount.model_validate({
            "login": "active",
            "password": "SuperPass@123dda",
            "active": True
        }))
        assert False
    except ValueError as e:
        assert str(e) == "Account with login active already exists"


@pytest.mark.asyncio
async def test_delete_user_exists(session, auth_settings):
    await init_models()
    account = None
    async with session as db:
        account = await db.scalar(select(Account).filter_by(login="inactive"))
        assert account is not None
        assert account.active == False
        db.expunge(account)
    await delete_account(account)
    async with session as db:
        account = await db.scalar(select(Account).filter_by(login="inactive"))
        assert account is None
