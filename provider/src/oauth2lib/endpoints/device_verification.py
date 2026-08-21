import json_adapter as json
from .base import BaseEndpoint, endpoint
from .. import errors
from ..common import Request, aw
from ..validators import RequestValidator

__all__ = ["DeviceVerificationEndpoint"]


class DeviceVerificationEndpoint(BaseEndpoint):
    def __init__(self, request_validator: RequestValidator):
        BaseEndpoint.__init__(self, request_validator)

    @endpoint
    async def create_device_verification_response(self, request: Request):
        """

        """
        # We raise error if POST request contains query component
        self._raise_on_bad_post_request(request)
        if request.headers.get("Origin") is not None:
            raise errors.InvalidRequestError(description="CORS is not allowed", request=request)
        # Get authenticated End-User
        request.user = request.user_from_request
        if request.user is None:
            raise errors.AccessDeniedError(description="Access Denied", request=request)
        for param in ('user_code', 'approve'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description=f'Duplicate "{param}" parameter.', request=request)
        if request.user_code is None:
            raise errors.InvalidRequestError(description='Missing "user_code" parameter.', request=request)
        if request.approve is None:
            request.approve = False
        if not isinstance(request.approve, bool):
            try:
                request.approve = bool(request.approve)
            except Exception:
                raise errors.InvalidRequestError(description='Invalid "approve" parameter.', request=request)
        result = await aw(self.request_validator.approve_user_code_info(request.request))
        if result is None:
            raise errors.AccessDeniedError(description="Access Denied", request=request)
        result = {"success": result}
        return {}, json.dumps(result), 200

    @endpoint
    async def validate_device_verification_request(self, request: Request):
        """
        Validating user_code and get info about client
        """
        # We raise error if POST request contains query component
        self._raise_on_bad_post_request(request)
        if request.headers.get("Origin") is not None:
            raise errors.InvalidRequestError(description="CORS is not allowed", request=request)
        # Get authenticated End-User
        request.user = request.user_from_request
        if request.user is None:
            raise errors.AccessDeniedError(description="Access Denied", request=request)
        for param in ('user_code',):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description=f'Duplicate "{param}" parameter.', request=request)
        if request.user_code is None:
            raise errors.InvalidRequestError(description='Missing "user_code" parameter.', request=request)
        result = await aw(self.request_validator.get_user_code_info(request.request))
        if result is None:
            raise errors.AccessDeniedError(description="Access Denied", request=request)
        return {}, json.dumps(result), 200
