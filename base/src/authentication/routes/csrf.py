import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, status, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import undefer_group

from ..middleware import anonymous, authenticated, has_any_user_scope, AnonymousCredentials
from ..models import AccountProtection

from ..schemes.auth import LoginBy, LoginCSRFData, CSRFToken
from ..schemes.responses import access_timeout, inactive_disallowed, already_authenticated, unauthorized, forbidden

from ..utils.common import get_database, responses, sleep_protection, uuid_extract_time, csrf_expired
from database.asyncio import AsyncSession

router = APIRouter(prefix="/csrf", tags=["Create csrf protection tokens"])


@router.post("/login", response_model=CSRFToken, responses=responses(already_authenticated))
@anonymous
async def login_csrf(
        request: Request,
        params: LoginCSRFData,
        db: AsyncSession = Depends(get_database)
):
    """Защита от перебора паролей и от утечки аккаунта"""
    login_by = params.login_by
    protection: AccountProtection | None = None
    if login_by == LoginBy.LOGIN:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("csrf")
        ).filter_by(login=params.login).with_for_update())
    elif login_by == LoginBy.EMAIL:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("csrf")
        ).filter_by(email=params.login).with_for_update())
    elif login_by == LoginBy.PHONE:
        protection = await db.scalar(select(AccountProtection).options(
            undefer_group("csrf")
        ).filter_by(phone=params.login).with_for_update())
    if protection is None:
        # Unregistered user, emulate norm work
        await sleep_protection()
        auth: AnonymousCredentials = request.auth
        token: str | None = auth.session_data.get("token", None)
        if token is None:
            token = str(uuid.uuid1())
            auth.session_data["token"] = token
            auth.session_data["count"] = 0
            auth.mark_session_data_dirty()
            return CSRFToken(token=token)
        else:
            count = max(0, auth.session_data.get("count", 0)) + 1
            old_date = uuid_extract_time(token) + timedelta(seconds=(1.5 * count))
            if old_date > datetime.now(tz=timezone.utc):
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
            token = str(uuid.uuid1())
            auth.session_data["token"] = token
            if count > 9:
                auth.session_data["count"] = 9
            else:
                auth.session_data["count"] = count
            auth.mark_session_data_dirty()
            return CSRFToken(token=token)
    await sleep_protection()
    if protection.login_uuid is None:
        # Old CSRF used or not yet generated, create new
        token = str(uuid.uuid1())
        protection.login_uuid = token
        protection.login_delay = (datetime.now(tz=timezone.utc) +
                                  timedelta(seconds=(1.5 * (protection.login_attempt_count + 1))))
        protection.login_by = login_by.value()
        await db.commit()
        return CSRFToken(token=token)
    else:
        # Try to generate new CSRF when old exists
        if protection.login_delay > datetime.now(tz=timezone.utc):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
        if csrf_expired(protection.login_uuid):
            protection.login_uuid = str(uuid.uuid1())
        if datetime.now(tz=timezone.utc) - protection.login_delay > timedelta(hours=1):
            # За давностью лет (Если неудачная попытка логина была давно, то счётчик попыток сбрасывается)
            protection.login_attempt_count = 0
        # Update only props
        protection.login_delay = (datetime.now(tz=timezone.utc) +
                                  timedelta(seconds=(1.5 * (protection.login_attempt_count + 1))))
        protection.login_by = login_by.value()
        await db.commit()
        # Return exists token
        # Note: In login process only one token per user exists
        return CSRFToken(token=str(protection.login_uuid))


@router.post("/confirm", response_model=CSRFToken, responses=responses(
    unauthorized, inactive_disallowed, access_timeout, forbidden
))
@authenticated()
async def confirm_csrf(
        request: Request,
        db: AsyncSession = Depends(get_database)
):
    if not has_any_user_scope(request, ["user"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    await sleep_protection()
    protection: AccountProtection = await db.scalar(select(AccountProtection).options(
        undefer_group("confirm")
    ).filter_by(login=request.user.login).with_for_update())
    if protection.confirm_uuid is None:
        token = str(uuid.uuid1())
        protection.confirm_uuid = token
        protection.confirm_delay = (datetime.now(tz=timezone.utc) +
                                    timedelta(seconds=(1.5 * (protection.confirm_attempt_count + 1))))
        await db.commit()
        return CSRFToken(token=token)
    else:
        if protection.confirm_delay > datetime.now(tz=timezone.utc):
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")
        if csrf_expired(uuid_extract_time(protection.confirm_uuid)):
            protection.confirm_uuid = str(uuid.uuid1())
        if datetime.now(tz=timezone.utc) - protection.confirm_delay > timedelta(hours=1):
            # За давностью лет (Если неудачная попытка проверки была давно, то счётчик попыток сбрасывается)
            protection.confirm_attempt_count = 0
        protection.confirm_delay = (datetime.now(tz=timezone.utc) +
                                    timedelta(seconds=(1.5 * (protection.confirm_attempt_count + 1))))
        await db.commit()
        return CSRFToken(token=str(protection.confirm_uuid))
