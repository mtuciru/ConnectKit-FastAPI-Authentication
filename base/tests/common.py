import pytest
from database import AsyncDatabase, Adapter, async_init_default_base, Base
from fastapi import FastAPI
from starlette.testclient import TestClient

import os

os.environ["SECURE_SECRET"] = "ABC"

from database.settings import settings as database_settings
from authentication.settings import settings as authentication_settings

from authentication import router

database_settings.DB_ADAPTER = Adapter.sqlite
database_settings.DB_NAME = ":memory:"

_fastapi = FastAPI()


@_fastapi.get("/")
async def root():
    return "It's root"


_fastapi.include_router(router, prefix="/api")


@pytest.fixture
def client():
    return TestClient(_fastapi)


@pytest.fixture
def session():
    return AsyncDatabase()


@pytest.fixture
def auth_settings():
    return authentication_settings


async def init_models():
    await async_init_default_base(Base.metadata)
