import functools
from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request as FastAPIRequest, Response as FastAPIResponse, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

import json_adapter as json
from ..common import Request, aw, safe_string_equals, is_secure_required
from ..errors import InvalidRequestError, OAuth2Error, ServerError, TemporarilyUnavailableError

__all__ = ["BaseEndpoint", "endpoint"]

_endpoint_signature = Callable[["BaseEndpoint", Request], Coroutine[Any, Any, tuple[dict[str, str], str, int]]]
_result_signature = Callable[["BaseEndpoint", FastAPIRequest, AsyncSession], Coroutine[Any, Any, FastAPIResponse]]


class BaseEndpoint:
    def __init__(self):
        self.available = True

    @staticmethod
    def _raise_on_missing_token(request: Request):
        """Raise error on missing token."""
        if not request.token:
            raise InvalidRequestError(request=request, description='Missing token parameter.')

    @staticmethod
    def _raise_on_bad_post_request(request: Request):
        """Raise if invalid POST request received
        """
        if request.request.method.upper() == 'POST':
            if request.has_query:
                raise InvalidRequestError(request=request, description='URL query parameters are not allowed')

    async def _create_cors_headers(self, request: Request):
        """If CORS is allowed, create the appropriate headers."""
        if request is None:
            return {}
        if 'origin' not in request.headers:
            # CORS not required
            return {}
        origin = request.headers['origin']
        if not origin.startswith('https://'):
            # Insecure CORS requests not allowed
            return {}
        if hasattr(self, 'request_validator'):
            client_origin = await aw(self.request_validator.get_client_origin(request))
            if isinstance(client_origin, str) and safe_string_equals(origin, client_origin):
                # Origin checked and allowed
                return {'Access-Control-Allow-Origin': origin,
                        "Access-Control-Expose-Headers": "DPoP-Nonce",
                        "Vary": "Origin"}
            elif isinstance(client_origin, bool) and client_origin:
                # Origin not checked and all allowed
                return {'Access-Control-Allow-Origin': "*",
                        "Access-Control-Expose-Headers": "DPoP-Nonce",
                        "Vary": "Origin"}
            else:
                # Origin not checked and not allowed
                return {}
        else:
            return {}


def endpoint(f: _endpoint_signature) -> _result_signature:
    @functools.wraps(f, updated=())
    async def wrapper(self: BaseEndpoint, fastapi_request: FastAPIRequest, db: AsyncSession):
        request = None
        try:
            request = await Request.init(fastapi_request, db)
            if not self.available:
                raise TemporarilyUnavailableError()
            try:
                headers, body, status_code = await f(self, request)
                response = FastAPIResponse(content=body, status_code=status_code, headers=headers)
                if request.in_cookie_refresh:
                    max_age = request.store['cookie_max_age']
                    path = request.store['cookie_path']
                    response.set_cookie(Request.cookie_name, request.refresh_token, httponly=True, samesite="strict",
                                        max_age=max_age, path=path, secure=is_secure_required())
                return response
            except OAuth2Error:
                raise
            except Exception:
                raise ServerError(description="Unexpected server error")
        except OAuth2Error as e:
            h, b, s = {"Content-Type": "application/json"}, e.json, e.status_code
            h.update(await self._create_cors_headers(request))
            return FastAPIResponse(content=b, status_code=s, headers=h)
        except HTTPException as e:
            error = InvalidRequestError(description=e.detail)
            headers, body, status_code = {}, error.json, e.status_code
            headers.update({"Content-Type": "application/json"})
            return FastAPIResponse(content=body, status_code=status_code, headers=headers)

    return wrapper
