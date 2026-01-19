"""
These decorators used before FastAPI router decorators.

Used for validating request.auth and request.user set by middleware.
"""

import functools
import inspect
from typing import ParamSpec, Callable, Any
from urllib.parse import urlencode

from database import AsyncDatabase, Database
from starlette import status
from starlette._utils import is_async_callable
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.websockets import WebSocket

_P = ParamSpec("_P")

__all__ = ["anonymous_user", "authenticated_user", "authenticated_client"]


def _get_route_type(func: Callable[_P, Any]):
    sig = inspect.signature(func)
    type_ = None
    idx = None
    for idx, parameter in enumerate(sig.parameters.values(), 0):
        if parameter.name == "request" or parameter.name == "websocket":
            type_ = parameter.name
            break
        if parameter.annotation == Request:
            type_ = "request"
            break
        if parameter.annotation == WebSocket:
            type_ = "websocket"
            break
    if type_ is None:
        raise Exception(f'No "request" or "websocket" argument on function "{func}"')
    return idx, type_


def _get_websocket(idx: int, args: list[Any], kwargs: dict[str, Any]) -> WebSocket:
    websocket = kwargs.get("websocket", args[idx] if idx < len(args) else None)
    assert isinstance(websocket, WebSocket)
    return websocket


def _get_request(idx: int, args: list[Any], kwargs: dict[str, Any]) -> Request:
    request = kwargs.get("request", args[idx] if idx < len(args) else None)
    assert isinstance(request, Request)
    return request


def anonymous_user(
        func: Callable[_P, Any],
) -> Callable[_P, Any]:
    """
    User must not be authenticated.

    If authenticated, 403 error is raised (3003 for WebSocket).
    """
    idx, type_ = _get_route_type(func)
    if type_ == "websocket":
        # Handle websocket functions. (Always async)
        @functools.wraps(func)
        async def websocket_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> None:
            websocket = _get_websocket(idx, args, kwargs)
            if websocket.user.is_authenticated:
                await websocket.accept()
                await websocket.close(code=3003, reason="Forbidden")
                return
            await func(*args, **kwargs)

        return websocket_wrapper

    elif is_async_callable(func):
        # Handle async request/response functions.
        @functools.wraps(func)
        async def async_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
            request = _get_request(idx, args, kwargs)
            if request.user.is_authenticated:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            return await func(*args, **kwargs)

        return async_wrapper

    else:
        # Handle sync request/response functions.
        @functools.wraps(func)
        def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
            request = _get_request(idx, args, kwargs)
            if request.user.is_authenticated:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
            return func(*args, **kwargs)

        return sync_wrapper


# Authenticated user, with validation options
def authenticated_user(
        active_only: bool = True,
        require_password_confirm: bool = False,
        redirect: str | None = None,
        requested_scopes: list[str] | None = None
) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
    if requested_scopes is not None and isinstance(requested_scopes, list):
        requested_scopes = list(requested_scopes)

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
                if user.authorized:
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
                if user.authorized:
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

            setattr(async_wrapper, "__security__", requested_scopes)
            return async_wrapper

        else:
            # Handle sync request/response functions.
            @functools.wraps(func)
            def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
                request = kwargs.get("request", args[idx] if idx < len(args) else None)
                assert isinstance(request, Request)
                user: AuthenticatedUser = request.user
                session: AccountSession = request.auth
                if user.authorized:
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

            setattr(sync_wrapper, "__security__", requested_scopes)
            return sync_wrapper

    return decorator


# Authenticated client, with validation options
def authenticated_client(
        active_only: bool = True,
        require_password_confirm: bool = False,
        redirect: str | None = None,
        scopes_info: list[str] | None = None
) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
    pass

# def has_any_scope(required_scopes: Sequence[str], object_scopes: Sequence[str]) -> bool:
#     scopes = set(required_scopes)
#     allowed = False
#     for scope in object_scopes:
#         if scope in scopes:
#             allowed = True
#             break
#     return allowed
#
#
# def has_all_scope(required_scopes: Sequence[str], object_scopes: Sequence[str]) -> bool:
#     object_scopes = set(object_scopes)
#     for scope in required_scopes:
#         if scope not in object_scopes:
#             return False
#     return True
#
#
# def has_any_user_scope(conn: HTTPConnection, scopes: Sequence[str]) -> bool:
#     return has_all_scope(scopes, conn.user.scopes)
#
#
# def has_all_user_scope(conn: HTTPConnection, scopes: Sequence[str]) -> bool:
#     return has_all_scope(scopes, conn.user.scopes)
