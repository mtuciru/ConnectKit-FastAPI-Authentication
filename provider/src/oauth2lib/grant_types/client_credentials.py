from .base import GrantTypeBase
from .. import errors
from ..common import Request, aw
from ..tokens import create_bearer_token, create_dpop_token, dpop_present

__all__ = ["ClientCredentialsGrant"]


class ClientCredentialsGrant(GrantTypeBase):
    """
    Client Credentials Grant

    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner that have been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).

    The client credentials grant type MUST only be used by confidential
    clients:

        +---------+                                  +---------------+
        :         :                                  :               :
        :         :>-- A - Client Authentication --->: Authorization :
        : Client  :                                  :     Server    :
        :         :<-- B ---- Access Token ---------<:               :
        :         :                                  :               :
        +---------+                                  +---------------+

    Figure 6: Client Credentials Flow

    The flow illustrated in Figure 6 includes the following steps:

    (A)  The client authenticates with the authorization server and
            requests an access token from the token endpoint.

    (B)  The authorization server authenticates the client, and if valid,
            issues an access token.

    Client Credentials Grant: https://tools.ietf.org/html/rfc6749#section-4.4
    """

    grant_type = "client_credentials"
    refresh_token = False

    async def create_token_response(self, request: Request):
        """
        Return token or error in JSON format.
        """
        try:
            await self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return await self._prepare_error_response(request, e, False)

        try:
            # Maybe client_credentials from browser?...
            await self._cors_preflight(request)
        except errors.OAuth2Error as e:
            # CORS preflight failed.
            return await self._prepare_error_response(request, e, False)

        if dpop_present(request) or await aw(self.request_validator.is_client_dpop_required(request)):
            # If client require DPoP type of access token (access with proof) issue DPoP
            token = await create_dpop_token(self.request_validator, request, self.refresh_token)
        else:
            token = await create_bearer_token(self.request_validator, request, self.refresh_token)

        await self._run_token_modifiers(token, request)
        await aw(self.request_validator.save_token(token, request))

        return await self._prepare_direct_response(request, token)

    async def validate_token_request(self, request: Request):
        self._validate_duplicate_params(request, ('grant_type', 'scope', 'client_id', 'client_secret'))
        await self._validate_grant_type(request)
        request.client = await aw(self.request_validator.authenticate_client(request))
        if request.client is None:
            raise errors.InvalidClientError(request=request)
        await self._is_allowed_grant_type(request)
        await self._validate_scopes(request)
