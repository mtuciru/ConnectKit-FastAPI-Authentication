from fastapi import Request, Response, WebSocket, HTTPException
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocketState

from oauth2lib.errors import OAuth2Error, UseDPoPNonce

__all__ = ["ExceptionContainer", "oauth2wrap_exception_handler", "oauth2_exception_handler"]


class ExceptionContainer(Exception):
    def __init__(self, error: OAuth2Error,
                 schemes: list[str] = None,
                 used_schemes: list[str] = None,
                 headers: dict[str, str] = None,
                 protocol: str = None,
                 websocket_status: int = None,
                 use_detail: bool = False):
        self._error = error
        self._schemes = schemes or []
        self._used_schemes = used_schemes or []
        self._headers = headers or {}
        self._protocol = protocol
        self._websocket_status = websocket_status
        self._use_detail = use_detail

    async def response(self, request: Request | WebSocket) -> Response | None:
        # As WebSocket
        if request.scope["type"] == "websocket":
            await self._websocket_response(request)
            return None
        # As HTTP
        return self._http_response(request)

    async def _websocket_response(self, websocket: WebSocket) -> None:
        # Accepting connection and close immediately with error
        if websocket.application_state != WebSocketState.CONNECTED:
            await websocket.accept(subprotocol=self._protocol)
        reason = self._error.error
        # Browser WebSocket not support read response headers, so, add nonce to error message
        if isinstance(self._error, UseDPoPNonce):
            reason += f":{self._error.nonce}"
        await websocket.close(code=self._websocket_status, reason=reason)

    def _http_response(self, request: Request):
        headers = {"Content-Type": "application/json"}
        headers.update(self._headers)
        headers.update(self._error.headers(self._schemes, self._used_schemes))
        if self._use_detail:
            # Use FastAPI HTTPException 'detail' field (and 'error' field from OAuth2)
            import json_adapter as json
            data = self._error.asdict
            data["detail"] = self._error.error
            return Response(content=json.dumps(data), headers=headers, status_code=self._error.status_code)
        return Response(content=self._error.json, headers=headers, status_code=self._error.status_code)


async def oauth2wrap_exception_handler(request: Request | WebSocket,
                                       error: Exception | ExceptionContainer) -> Response | None:
    return await error.response(request)


async def oauth2_exception_handler(request: Request | WebSocket,
                                   error: Exception | OAuth2Error) -> Response | None:
    return await oauth2wrap_exception_handler(request, ExceptionContainer(
        error=error,
        schemes=["Bearer", "DPoP"],
        used_schemes=None,
        headers=None,
        protocol=request.scope.get("auth_websocket_protocol"),
        websocket_status=3003,
        use_detail=True
    ))
