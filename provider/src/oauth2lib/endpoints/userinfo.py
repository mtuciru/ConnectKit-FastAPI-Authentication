import json_adapter as json
from .base import BaseEndpoint, endpoint
from .. import errors
from ..common import Request, aw
from ..validators import RequestValidator

__all__ = ['UserInfoEndpoint']


class UserInfoEndpoint(BaseEndpoint):
    def __init__(self, request_validator: RequestValidator):
        BaseEndpoint.__init__(self)
        self.request_validator = request_validator

    @endpoint
    async def create_userinfo_response(self, request: Request):
        headers = {
            'Content-Type': 'application/json',
        }
        try:
            await self.validate_userinfo_request(request)
            claims = await aw(self.request_validator.get_userinfo_claims(request))
            if isinstance(claims, dict):
                body = json.dumps(claims)
            elif isinstance(claims, str):
                headers["Content-Type"] = "application/jwt"
                body = claims
            else:
                raise errors.ServerError(status_code=500)
        except errors.OAuth2Error as e:
            headers.update(e.headers(["Bearer", "DPoP"], request.used_auth_schemes))
            headers.update(await self._create_cors_headers(request))
            return headers, e.json, e.status_code
        headers.update(await self._create_cors_headers(request))
        return headers, body, 200

    async def validate_userinfo_request(self, request: Request):
        self._raise_on_bad_post_request(request)
        # User from specified access_token in Authorization header
        # If user is None, that access_token is invalid, expire, etc.
        maybe_user = request.user_from_request
        if maybe_user is None:
            raise errors.InvalidTokenError()
        request.user = maybe_user
