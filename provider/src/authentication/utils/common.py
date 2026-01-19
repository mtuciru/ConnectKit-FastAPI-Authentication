import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from random import random
from typing import AsyncGenerator, Any

from database.asyncio import AsyncDatabase, AsyncSession
from fastapi import HTTPException, WebSocketException
# from sqlalchemy import select

# from ..models import UserProtection, AccessSession

__all__ = ["get_database", "AsyncSession", "create_http_exception", "create_websocket_exception",
           "responses", "sleep_protection", "csrf_expired", "uuid_extract_time"]


async def get_database() -> AsyncGenerator[AsyncSession, Any]:
    async with AsyncDatabase() as db:
        yield db


def create_http_exception(status_code: int, detail: str | Exception) -> HTTPException:
    status_code = int(status_code)
    assert 400 <= status_code < 600, "Status code must be [400, 600) (HTTP error codes range)"
    return HTTPException(status_code=status_code, detail=str(detail))


def create_websocket_exception(status_code: int, detail: str | Exception) -> WebSocketException:
    status_code = int(status_code)
    assert 1000 <= status_code < 5000, "Status code must be [1000, 5000) (WebSocket codes range)"
    return WebSocketException(code=status_code, reason=str(detail))


# def with_errors(*errors: HTTPException):
#     d = {}
#     for err in errors:
#         if err.status_code in d:
#             d[err.status_code]["description"] += f"\n\n{err.detail}"
#         else:
#             d[err.status_code] = {"description": err.detail}
#     return d

def responses(*responses_set: dict[int, str]):
    d = {}
    for resps in responses_set:
        for code, description in resps.items():
            if code in d:
                d[code]["description"] += f"\n\n{description}"
            else:
                d[code] = {
                    "description": f"Variants of detail:\n\n"
                                   f"{description}",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "detail": {
                                        "type": "string",
                                    }
                                }
                            }
                        }
                    }
                }
    return d


async def sleep_protection():
    # Sleep around (0, 0.3) seconds
    await asyncio.sleep(random() * 0.3)


def uuid_extract_time(uuid_v1: str):
    try:
        ns = uuid.UUID(hex=uuid_v1).time
        timestamp = (ns - 0x01b21dd213814000) / 10_000_000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except Exception:
        return datetime.now(tz=timezone.utc)


def csrf_expired(create_datetime: datetime):
    now = datetime.now()
    delta = now - create_datetime
    if timedelta() < delta < timedelta(minutes=1):
        return False
    return True


# async def direct_block_account(protection: UserProtection, reason: str, db: AsyncSession) -> None:
#     protection.block = True
#     protection.block_reason = reason
#     sessions = await db.scalars(select(AccessSession).filter_by(account_id=protection.id))
#     for session in sessions:
#         await db.delete(session)
