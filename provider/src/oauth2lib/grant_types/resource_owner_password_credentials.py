from .base import GrantTypeBase
from .. import errors
from ..common import Request, aw
from ..tokens import create_bearer_token, create_dpop_token, dpop_present

__all__ = ["ResourceOwnerPasswordCredentialsGrant"]


class ResourceOwnerPasswordCredentialsGrant(GrantTypeBase):
    """
    Resource Owner Password Credentials Grant

    The resource owner password credentials grant type is suitable in
    cases where the resource owner has a trust relationship with the
    client, such as the device operating system or a highly privileged
    application.  The authorization server should take special care when
    enabling this grant type and only allow it when other flows are not
    viable.

    This grant type is suitable for clients capable of obtaining the
    resource owner's credentials (username and password, typically using
    an interactive form).  It is also used to migrate existing clients
    using direct authentication schemes such as HTTP Basic or Digest
    authentication to OAuth by converting the stored credentials to an
    access token::

            +----------+
            | Resource |
            |  Owner   |
            |          |
            +----------+
                 v
                 |    Resource Owner
                (A) Password Credentials
                 |
                 v
            +---------+                                  +---------------+
            |         |>--(B)---- Resource Owner ------->|               |
            |         |         Password Credentials     | Authorization |
            | Client  |                                  |     Server    |
            |         |<--(C)---- Access Token ---------<|               |
            |         |    (w/ Optional Refresh Token)   |               |
            +---------+                                  +---------------+

    Figure 5: Resource Owner Password Credentials Flow

    The flow illustrated in Figure 5 includes the following steps:

    (A)  The resource owner provides the client with its username and
            password.

    (B)  The client requests an access token from the authorization
            server's token endpoint by including the credentials received
            from the resource owner.  When making the request, the client
            authenticates with the authorization server.

    (C)  The authorization server authenticates the client and validates
            the resource owner credentials, and if valid, issues an access
            token.

    Resource Owner Password Credentials Grant: https://tools.ietf.org/html/rfc6749#section-4.3
    """

    grant_type = "password"

    async def create_token_response(self, request: Request):
        """
        Return token or error in json format.

        !!WARNING!!

        This grant type modified for self-system authentication.
        Because it is not available for other clients only for system components:
            - Frontend of provider (under the same domain)
            - Official native or mobile application with direct authentication process.
        Third-party clients not allowed to use this grant type because username and password transparent for client.
        Special client_id 'frontend_system' used for determining frontend of provider.
        In this mode:
            - CORS not allowed
            - Browser fingerprint processed
            - Secure browsers headers processed
            - Refresh token located in request.refresh_token (this token later binding to http_only cookie)
        """
        try:
            await self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return await self._prepare_error_response(request, e, False)

        try:
            await self._cors_preflight(request)
        except errors.OAuth2Error as e:
            # CORS preflight failed.
            return await self._prepare_error_response(request, e, False)

        if dpop_present(request) or await aw(self.request_validator.is_client_dpop_required(request)):
            # If client require DPoP type of access token (access with proof) issue DPoP
            token = await create_dpop_token(self.request_validator, request, self.refresh_token)
        else:
            token = await create_bearer_token(self.request_validator, request, self.refresh_token)

        await self.request_validator.save_token(token, request)
        return await self._prepare_direct_response(request, token)

    async def validate_token_request(self, request: Request):
        self._validate_duplicate_params(request, (
            'grant_type', 'username', 'password', 'scope', 'client_id', 'client_secret'
        ))

        await self._validate_grant_type(request)

        for param in ('username', 'password'):
            if getattr(request, param) is None:
                raise errors.InvalidRequestError(f'Request is missing "{param}" parameter.', request=request)

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

        await self._is_allowed_grant_type(request)

        request.user = await aw(self.request_validator.authorize_user(request))
        if request.user is None:
            raise errors.InvalidGrantError('Invalid credentials given.', request=request)

        await self._validate_scopes(request)
