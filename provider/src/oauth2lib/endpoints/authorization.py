from .base import BaseEndpoint, endpoint
from ..common import Request
from ..grant_types.base import GrantTypeBase
from .. import errors

__all__ = ["AuthorizationEndpoint"]


class AuthorizationEndpoint(BaseEndpoint):
    def __init__(self, default_response_type: str, response_types: dict[str, GrantTypeBase]):
        BaseEndpoint.__init__(self)
        self._response_types = response_types
        self._default_response_type = default_response_type
        self.redirect_errors = True

    @property
    def response_types(self):
        return self._response_types

    @property
    def default_response_type(self):
        return self._default_response_type

    @property
    def default_response_grant(self):
        return self.response_types.get(self.default_response_type)

    @endpoint
    async def create_authorization_response(self, request: Request):
        """Extract response_type and route to the designated grant."""
        # We raise error if POST request contains query component
        self._raise_on_bad_post_request(request)
        # Get authenticated End-User
        request.user = request.user_from_request
        response_type_grant = self.response_types.get(request.response_type, self.default_response_grant)
        return await response_type_grant.create_authorization_response(request)

    @endpoint
    async def validate_authorization_request(self, request: Request):
        """Extract response_type and route to the designated grant."""
        # We raise error if POST request contains query component
        self._raise_on_bad_post_request(request)
        # Get authenticated End-User
        request.user = request.user_from_request
        response_type_grant = self.response_types.get(request.response_type, self.default_response_grant)
        try:
            return await response_type_grant.validate_authorization_request(request)
        # Inform End-User about error. Send error to frontend.
        except errors.FatalClientError as e:
            return await response_type_grant._prepare_error_response(request, e, False)
        # Inform client about error. Send redirect_uri to frontend (frontend must redirect user-agent to uri).
        except errors.OAuth2Error as e:
            e.iss = Request.issuer
            return await response_type_grant._prepare_error_response(request, e, True)
