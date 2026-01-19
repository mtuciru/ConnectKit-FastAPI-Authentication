from .base import BaseEndpoint, endpoint
from ..common import Request
from ..grant_types.base import GrantTypeBase

__all__ = ["TokenEndpoint"]


class TokenEndpoint(BaseEndpoint):
    def __init__(self, default_grant_type: str, grant_types: dict[str, GrantTypeBase]):
        BaseEndpoint.__init__(self)
        self._grant_types = grant_types
        self._default_grant_type = default_grant_type

    @property
    def grant_types(self):
        return self._grant_types

    @property
    def default_grant_type(self):
        return self._default_grant_type

    @property
    def default_grant_type_grant(self):
        return self.grant_types.get(self.default_grant_type)

    @endpoint
    async def create_token_response(self, request: Request):
        """Extract grant_type and route to the designated grant."""
        self._raise_on_bad_post_request(request)
        grant_type_grant = self.grant_types.get(request.grant_type, self.default_grant_type_grant)
        if request.grant_type == "refresh_token" and request.refresh_token is None:
            request.refresh_token = request.request.cookies.get(Request.cookie_name)
        return await grant_type_grant.create_token_response(request)
