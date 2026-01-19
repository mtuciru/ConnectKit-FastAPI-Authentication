from .base import BaseEndpoint, endpoint
from ..common import Request
from ..grant_types import DeviceCodeGrant

__all__ = ["DeviceAuthorizationEndpoint"]


class DeviceAuthorizationEndpoint(BaseEndpoint):
    def __init__(self, device_code_grant: DeviceCodeGrant):
        BaseEndpoint.__init__(self)
        self._device_code_grant = device_code_grant

    @property
    def interval(self):
        return self._device_code_grant._interval

    @property
    def expires_in(self):
        return self._device_code_grant._expires_in

    @property
    def device_code_grant(self):
        return self._device_code_grant

    @endpoint
    async def create_device_authorization_response(self, request: Request):
        """Extract response_type and route to the designated grant."""
        # Device endpoint working on POST
        self._raise_on_bad_post_request(request)
        return await self.device_code_grant.create_authorization_response(request)
