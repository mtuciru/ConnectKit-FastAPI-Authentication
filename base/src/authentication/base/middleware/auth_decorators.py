import functools
import inspect
from typing import Sequence, ParamSpec, Callable, Any
from urllib.parse import urlencode

from starlette import status
from starlette._utils import is_async_callable
from starlette.exceptions import HTTPException
from starlette.requests import HTTPConnection, Request
from starlette.responses import RedirectResponse
from starlette.websockets import WebSocket

from .auth_extractor import AuthenticatedUser
from ..settings import settings

_P = ParamSpec("_P")

__all__ = ["anonymous", "authenticated", "all_scopes", "any_scopes"]


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
                if user.is_authenticated:
                    if active_only:
                        if not user.active:
                            await websocket.close(code=3003, reason="Inactive user disallowed")
                            return
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
                if user.is_authenticated:
                    if active_only:
                        if not user.active:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                detail="Inactive user disallowed")
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
                if user.is_authenticated:
                    if active_only:
                        if not user.active:
                            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                detail="Inactive user disallowed")
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


if settings.user_has_scope:

    def has_any_scope(conn: HTTPConnection, scopes: Sequence[str]) -> bool:
        allowed = False
        for scope in conn.user.scopes:
            if scope in scopes:
                allowed = True
                break
        return allowed


    def has_all_scope(conn: HTTPConnection, scopes: Sequence[str]) -> bool:
        for scope in scopes:
            if scope not in conn.user.scopes:
                return False
        return True


    def all_scopes(
            scopes: Sequence[str] | str,
            active_only: bool = True,
            status_code: tuple[int, str] | None = None,
            redirect: str | None = None
    ) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
        if isinstance(scopes, str):
            scopes = [scopes]

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
                    if user.is_authenticated:
                        if active_only:
                            if not user.active:
                                await websocket.close(code=3003, reason="Inactive user disallowed")
                                return
                        if not has_all_scope(websocket, scopes):
                            if status_code is not None:
                                await websocket.close(code=status_code[0], reason=status_code[1])
                            else:
                                await websocket.close(code=3003, reason="Forbidden")
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
                    if user.is_authenticated:
                        if active_only:
                            if not user.active:
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                    detail="Inactive user disallowed")
                            if not has_all_scope(request, scopes):
                                if status_code is not None:
                                    raise HTTPException(status_code=status_code[0], detail=status_code[1])
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                    else:
                        if redirect is not None:
                            orig_request_qparam = urlencode({"next": str(request.url)})
                            next_url = f"{redirect}?{orig_request_qparam}"
                            return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
                        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
                    return await func(*args, **kwargs)

                setattr(async_wrapper, "__security__", scopes)
                return async_wrapper

            else:
                # Handle sync request/response functions.
                @functools.wraps(func)
                def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
                    request = kwargs.get("request", args[idx] if idx < len(args) else None)
                    assert isinstance(request, Request)
                    user: AuthenticatedUser = request.user
                    if user.is_authenticated:
                        if active_only:
                            if not user.active:
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                    detail="Inactive user disallowed")
                            if not has_all_scope(request, scopes):
                                if status_code is not None:
                                    raise HTTPException(status_code=status_code[0], detail=status_code[1])
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                    else:
                        if redirect is not None:
                            orig_request_qparam = urlencode({"next": str(request.url)})
                            next_url = f"{redirect}?{orig_request_qparam}"
                            return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
                        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
                    return func(*args, **kwargs)

                setattr(sync_wrapper, "__security__", scopes)
                return sync_wrapper

        return decorator


    def any_scopes(
            scopes: Sequence[str] | str,
            active_only: bool = True,
            status_code: tuple[int, str] | None = None,
            redirect: str | None = None
    ) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
        if isinstance(scopes, str):
            scopes = [scopes]

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
                    if user.is_authenticated:
                        if active_only:
                            if not user.active:
                                await websocket.close(code=3003, reason="Inactive user disallowed")
                                return
                        if not has_any_scope(websocket, scopes):
                            if status_code is not None:
                                await websocket.close(code=status_code[0], reason=status_code[1])
                            else:
                                await websocket.close(code=3003, reason="Forbidden")
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
                    if user.is_authenticated:
                        if active_only:
                            if not user.active:
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                    detail="Inactive user disallowed")
                            if not has_any_scope(request, scopes):
                                if status_code is not None:
                                    raise HTTPException(status_code=status_code[0], detail=status_code[1])
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                    else:
                        if redirect is not None:
                            orig_request_qparam = urlencode({"next": str(request.url)})
                            next_url = f"{redirect}?{orig_request_qparam}"
                            return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
                        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
                    return await func(*args, **kwargs)

                setattr(async_wrapper, "__security__", scopes)
                return async_wrapper

            else:
                # Handle sync request/response functions.
                @functools.wraps(func)
                def sync_wrapper(*args: _P.args, **kwargs: _P.kwargs) -> Any:
                    request = kwargs.get("request", args[idx] if idx < len(args) else None)
                    assert isinstance(request, Request)
                    user: AuthenticatedUser = request.user
                    if user.is_authenticated:
                        if active_only:
                            if not user.active:
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                                    detail="Inactive user disallowed")
                            if not has_any_scope(request, scopes):
                                if status_code is not None:
                                    raise HTTPException(status_code=status_code[0], detail=status_code[1])
                                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
                    else:
                        if redirect is not None:
                            orig_request_qparam = urlencode({"next": str(request.url)})
                            next_url = f"{redirect}?{orig_request_qparam}"
                            return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
                        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
                    return func(*args, **kwargs)

                setattr(sync_wrapper, "__security__", scopes)
                return sync_wrapper

        return decorator
else:
    def all_scopes(
            scopes: Sequence[str] | str,
            active_only: bool = True,
            status_code: tuple[int, str] | None = None,
            redirect: str | None = None
    ) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
        raise NotImplementedError("Scopes support not enabled")


    def any_scopes(
            scopes: Sequence[str] | str,
            active_only: bool = True,
            status_code: tuple[int, str] | None = None,
            redirect: str | None = None
    ) -> Callable[[Callable[_P, Any]], Callable[_P, Any]]:
        raise NotImplementedError("Scopes support not enabled")
