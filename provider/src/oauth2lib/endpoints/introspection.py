import json_adapter as json
from .base import BaseEndpoint, endpoint
from .. import errors
from ..common import Request, aw
from ..validators import RequestValidator

__all__ = ["IntrospectEndpoint"]


class IntrospectEndpoint(BaseEndpoint):
    def __init__(self, request_validator: RequestValidator):
        BaseEndpoint.__init__(self, request_validator)

    @endpoint
    async def create_introspect_response(self, request: Request):
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        try:
            await self.validate_introspect_request(request)
            claims = await aw(self.request_validator.introspect_token(request))
        except errors.OAuth2Error as e:
            headers.update(e.headers(["Basic"], request.used_auth_schemes))
            headers.update(await self._create_cors_headers(request))
            return headers, e.json, e.status_code

        if claims is None:
            return headers, json.dumps({'active': False}), 200
        claims['active'] = True
        headers.update(await self._create_cors_headers(request))
        return headers, json.dumps(claims), 200

    async def validate_introspect_request(self, request: Request):
        self._raise_on_bad_post_request(request)
        self._raise_on_invalid_token_param(request)

        if await aw(self.request_validator.client_authentication_required(request)):
            # Check that single auth scheme used, validate match basic client_id and parameter client_id
            request.client = await aw(self.request_validator.authenticate_client(request))
            if request.client is None:
                raise errors.InvalidClientError(request=request)
        else:
            if request.client_id is None:
                raise errors.MissingClientIdError(request=request)
            request.client = await aw(self.request_validator.authenticate_client_id(request))
            if request.client is None:
                raise errors.InvalidClientIdError(request=request)
