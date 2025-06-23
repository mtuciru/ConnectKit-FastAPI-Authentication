import functools
import inspect
from typing import Sequence, ParamSpec, Callable, Any
from urllib.parse import urlencode

from database import AsyncDatabase, Database
from starlette import status
from starlette._utils import is_async_callable
from starlette.exceptions import HTTPException
from starlette.requests import HTTPConnection, Request
from starlette.responses import RedirectResponse
from starlette.websockets import WebSocket

from .auth_extractor import AuthenticatedUser
from ..models import AccountSession

_P = ParamSpec("_P")

__all__ = ["anonymous", "authenticated", "has_all_user_scope", "has_any_user_scope", "has_all_scope", "has_any_scope"]


def _get_route_type(func: Callable[_P, Any]):
    sig = inspect.signature(func)
    type_ = None
    idx = None
    for idx, parameter in enumerate(sig.parameters.values(), 0):
        if parameter.name == "request" or parameter.name == "websocket":
            type_ = parameter.name
            break
    if type_ is None:
        raise Exception(f'No "request" or "websocket" argument on function "{func}"')
    return idx, type_


def anonymous(
        func: Callable[_P, Any],
) -> Callable[_P, Any]:
    idx, type_ = _get_route_type(func)
    if type_ == "websocket":
        # Handle websocket functions. (Always async)
        @functools.wraps(func)
        async def websocket_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> None:
            websocket = kwargs.get("websocket", args[idx] if idx < len(args) else None)
            assert isinstance(websocket, WebSocket)
            if websocket.user.is_authenticated:
                await websocket.close(code=3003, reason="Already authenticated")
                return
            await func(*args, **kwargs)

        return websocket_wrapper

    elif is_async_callable(func):
        # Handle async request/response functions.
        @functools.wraps(func)
        async def async_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
            request = kwargs.get("request", args[idx] if idx < len(args) else None)
            assert isinstance(request, Request)
            if request.user.is_authenticated:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Already authenticated")
            return await func(*args, **kwargs)

        return async_wrapper

    else:
        # Handle sync request/response functions.
        @functools.wraps(func)
        def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
            request = kwargs.get("request", args[idx] if idx < len(args) else None)
            assert isinstance(request, Request)
            if request.user.is_authenticated:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Already authenticated")
            return func(*args, **kwargs)

        return sync_wrapper


def authenticated(
        active_only: bool = True,
        require_password_confirm: bool = False,
        redirect: str | None = None
) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
    def decorator(
            func: Callable[_P, Any],
    ) -> Callable[_P, Any]:
        idx, type_ = _get_route_type(func)
        if type_ == "websocket":
            # Handle websocket functions. (Always async)
            @functools.wraps(func)
            async def websocket_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> None:
                websocket = kwargs.get("websocket", args[idx] if idx < len(args) else None)
                assert isinstance(websocket, WebSocket)
                user: AuthenticatedUser = websocket.user
                session: AccountSession = websocket.auth
                if user.is_authenticated:
                    if active_only:
                        if not user.active:
                            await websocket.close(code=3003, reason="Inactive user disallowed")
                            return
                        if not session.otp_success:
                            await websocket.close(code=3003, reason="OTP verification required")
                            return
                    if require_password_confirm:
                        async with AsyncDatabase() as db:
                            db.add(session)
                            if await session.async_need_password_confirm():
                                await websocket.close(code=3003, reason="Need password confirmation")
                            db.expunge(session)

                else:
                    await websocket.close(code=3000, reason="Unauthorized")
                    return
                await func(*args, **kwargs)

            return websocket_wrapper

        elif is_async_callable(func):
            # Handle async request/response functions.
            @functools.wraps(func)
            async def async_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
                request = kwargs.get("request", args[idx] if idx < len(args) else None)
                assert isinstance(request, Request)
                user: AuthenticatedUser = request.user
                session: AccountSession = request.auth
                if user.is_authenticated:
                    if active_only:
                        if not user.active:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                detail="Inactive user disallowed")
                        if not session.otp_success:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                detail="OTP verification required")
                    if require_password_confirm:
                        async with AsyncDatabase() as db:
                            db.add(session)
                            if await session.async_need_password_confirm():
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                    detail="Need password confirmation")
                            db.expunge(session)
                else:
                    if redirect is not None:
                        orig_request_qparam = urlencode({"next": str(request.url)})
                        next_url = f"{redirect}?{orig_request_qparam}"
                        return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
                return await func(*args, **kwargs)

            setattr(async_wrapper, "__security__", [])
            return async_wrapper

        else:
            # Handle sync request/response functions.
            @functools.wraps(func)
            def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
                request = kwargs.get("request", args[idx] if idx < len(args) else None)
                assert isinstance(request, Request)
                user: AuthenticatedUser = request.user
                session: AccountSession = request.auth
                if user.is_authenticated:
                    if active_only:
                        if not user.active:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                detail="Inactive user disallowed")
                        if not session.otp_success:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                detail="OTP verification required")
                    if require_password_confirm:
                        with Database() as db:
                            db.add(session)
                            if session.need_password_confirm():
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                    detail="Need password confirmation")
                            db.expunge(session)
                else:
                    if redirect is not None:
                        orig_request_qparam = urlencode({"next": str(request.url)})
                        next_url = f"{redirect}?{orig_request_qparam}"
                        return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
                return func(*args, **kwargs)

            setattr(sync_wrapper, "__security__", [])
            return sync_wrapper

    return decorator


def has_any_scope(required_scopes: Sequence[str], object_scopes: Sequence[str]) -> bool:
    scopes = set(required_scopes)
    allowed = False
    for scope in object_scopes:
        if scope in scopes:
            allowed = True
            break
    return allowed


def has_all_scope(required_scopes: Sequence[str], object_scopes: Sequence[str]) -> bool:
    object_scopes = set(object_scopes)
    for scope in required_scopes:
        if scope not in object_scopes:
            return False
    return True


def has_any_user_scope(conn: HTTPConnection, scopes: Sequence[str]) -> bool:
    return has_all_scope(scopes, conn.user.scopes)


def has_all_user_scope(conn: HTTPConnection, scopes: Sequence[str]) -> bool:
    return has_all_scope(scopes, conn.user.scopes)
