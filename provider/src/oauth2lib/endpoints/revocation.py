from .base import BaseEndpoint, endpoint
from .. import errors
from ..common import Request, aw
from ..validators import RequestValidator

__all__ = ['RevocationEndpoint']


class RevocationEndpoint(BaseEndpoint):
    def __init__(self, request_validator: RequestValidator):
        BaseEndpoint.__init__(self, request_validator)

    @endpoint
    async def create_revocation_response(self, request: Request):
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        try:
            await self.validate_revocation_request(request)
            if not await aw(self.request_validator.revoke_token(request)):
                raise errors.UnsupportedTokenTypeError()
        except errors.OAuth2Error as e:
            headers.update(e.headers(["Basic"], request.used_auth_schemes))
            headers.update(await self._create_cors_headers(request))
            body = self._response_body(request, e, headers)
            return headers, body, e.status_code
        response_body = ''
        if request.callback is not None:
            headers['Content-Type'] = 'text/javascript'
            response_body = request.callback + '();'
        else:
            headers['Content-Type'] = 'text/plain'
        headers.update(await self._create_cors_headers(request))
        return headers, response_body, 200

    async def validate_revocation_request(self, request: Request):
        self._raise_on_bad_post_request(request)
        self._raise_on_invalid_token_param(request)
        for param in ('callback',):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description=f'Duplicate "{param}" parameter.', request=request)
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

    @staticmethod
    def _response_body(request: Request, error: errors.OAuth2Error, headers: dict):
        if request.callback is not None:
            headers['Content-Type'] = 'text/javascript'
            return f'{request.callback}({error.json});'
        else:
            return error.json
