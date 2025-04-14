from typing import AsyncGenerator, Any

from database.asyncio import AsyncDatabase, AsyncSession


async def get_database() -> AsyncGenerator[AsyncSession, Any]:
    async with AsyncDatabase() as db:
        yield db
