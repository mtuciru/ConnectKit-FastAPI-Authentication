from .base import GrantTypeBase
from .. import errors
from ..common import Request, aw
from ..tokens import create_bearer_token, create_dpop_token, dpop_present
from ..validators import RequestValidator

__all__ = ["RefreshTokenGrant"]


class RefreshTokenGrant(GrantTypeBase):
    """
    Refresh token grant

    https://tools.ietf.org/html/rfc6749#section-6
    """

    grant_type = 'refresh_token'

    def __init__(self, request_validator: RequestValidator = None):
        super().__init__(request_validator)
        self.register_token_modifier(self.add_id_token)

    async def create_token_response(self, request: Request):
        """
        Create a new access token from a refresh_token and optional rotate refresh_token
        """
        try:
            await self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return await self._prepare_error_response(request, e, False)

        try:
            await self._cors_preflight(request)
        except errors.OAuth2Error as e:
            # CORS preflight failed.
            # And refresh token not consumed. It's ok?
            return await self._prepare_error_response(request, e, False)

        dpop_jkt = await aw(self.request_validator.get_refresh_token_dpop_jkt(request))
        if dpop_present(request) or await aw(self.request_validator.is_client_dpop_required(request)):
            # DPoP required, but refresh_token is Bearer
            if dpop_jkt is None:
                return await self._prepare_error_response(
                    request,
                    errors.InvalidDPoPProof(description="Mismatch token types"),
                    False
                )
            # If client require DPoP type of access token (access with proof) issue DPoP
            token = await create_dpop_token(self.request_validator, request, self.refresh_token, dpop_jkt)
        else:
            # DPoP not present and not required, but refresh_token is DPoP
            if dpop_jkt is not None:
                return await self._prepare_error_response(
                    request,
                    errors.InvalidDPoPProof(description="Mismatch token types"),
                    False
                )
            token = await create_bearer_token(self.request_validator, request, self.refresh_token)

        await self._run_token_modifiers(token, request)

        await aw(self.request_validator.save_token(token, request))

        return await self._prepare_direct_response(request, token)

    async def validate_token_request(self, request: Request):
        # Duplicate parameters are always considered as invalid request.
        for param in ('grant_type', 'refresh_token', 'scope', 'client_id', 'client_secret'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestFatalError(description=f'Duplicate "{param}" parameter.', request=request)

        await self._validate_grant_type(request)

        if request.refresh_token is None:
            raise errors.InvalidRequestError(description='Missing "refresh_token" parameter.', request=request)

        if await aw(self.request_validator.client_authentication_required(request)):
            # Check that single auth scheme used, validate match basic client_id and parameter client_id
            request.validate_client_credentials()
            request.client = await aw(self.request_validator.authenticate_client(request))
            if request.client is None:
                raise errors.InvalidClientError(request=request)
        else:
            if request.client_id is None:
                raise errors.MissingClientIdError(request=request)
            request.client = await aw(self.request_validator.authenticate_client_id(request))
            if request.client is None:
                raise errors.InvalidClientIdError(request=request)

        await self._is_allowed_grant_type(request)

        if not await aw(self.request_validator.validate_refresh_token(request)):
            raise errors.InvalidGrantError(request=request)

        original_scopes = await aw(self.request_validator.get_refresh_token_scopes(request))

        if request.scope:
            if not await aw(self.request_validator.is_within_refresh_token_scopes(original_scopes, request)):
                raise errors.InvalidScopeError(request=request)
        else:
            request.scopes = original_scopes
        request._is_scope_identical = True

    async def add_id_token(self, token: dict, request: Request):
        if "openid" not in request.scopes:
            return
        if not await aw(self.request_validator.is_rotate_id_token(request)):
            return
        await super().add_id_token(token, request)
