from .base import GrantTypeBase
from .. import errors
from ..common import Request, aw
from ..validators import RequestValidator

__all__ = ["ImplicitGrant"]


class ImplicitGrant(GrantTypeBase):
    """
    Implicit Grant

    The implicit grant type is used to obtain access tokens (it does not
    support the issuance of refresh tokens) and is optimized for public
    clients known to operate a particular redirection URI.  These clients
    are typically implemented in a browser using a scripting language
    such as JavaScript.

    Unlike the authorization code grant type, in which the client makes
    separate requests for authorization and for an access token, the
    client receives the access token as the result of the authorization
    request.

    The implicit grant type does not include client authentication, and
    relies on the presence of the resource owner and the registration of
    the redirection URI.  Because the access token is encoded into the
    redirection URI, it may be exposed to the resource owner and other
    applications residing on the same device::

        +----------+
        | Resource |
        |  Owner   |
        |          |
        +----------+
             ^
             |
            (B)
        +----|-----+          Client Identifier     +---------------+
        |         -+----(A)-- & Redirection URI --->|               |
        |  User-   |                                | Authorization |
        |  Agent  -|----(B)-- User authenticates -->|     Server    |
        |          |                                |               |
        |          |<---(C)--- Redirection URI ----<|               |
        |          |          with Access Token     +---------------+
        |          |            in Fragment
        |          |                                +---------------+
        |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
        |          |          without Fragment      |     Client    |
        |          |                                |    Resource   |
        |     (F)  |<---(E)------- Script ---------<|               |
        |          |                                +---------------+
        +-|--------+
          |    |
         (A)  (G) Access Token
          |    |
          ^    v
        +---------+
        |         |
        |  Client |
        |         |
        +---------+

   Note: The lines illustrating steps (A) and (B) are broken into two
   parts as they pass through the user-agent.

   Figure 4: Implicit Grant Flow

   The flow illustrated in Figure 4 includes the following steps:

   (A)  The client initiates the flow by directing the resource owner's
        user-agent to the authorization endpoint.  The client includes
        its client identifier, requested scope, local state, and a
        redirection URI to which the authorization server will send the
        user-agent back once access is granted (or denied).

   (B)  The authorization server authenticates the resource owner (via
        the user-agent) and establishes whether the resource owner
        grants or denies the client's access request.

   (C)  Assuming the resource owner grants access, the authorization
        server redirects the user-agent back to the client using the
        redirection URI provided earlier.  The redirection URI includes
        the access token in the URI fragment.

   (D)  The user-agent follows the redirection instructions by making a
        request to the web-hosted client resource (which does not
        include the fragment per [RFC2616]).  The user-agent retains the
        fragment information locally.

   (E)  The web-hosted client resource returns a web page (typically an
        HTML document with an embedded script) capable of accessing the
        full redirection URI including the fragment retained by the
        user-agent, and extracting the access token (and other
        parameters) contained in the fragment.

   (F)  The user-agent executes the script provided by the web-hosted
        client resource locally, which extracts the access token.

   (G)  The user-agent passes the access token to the client.

    See `Section 10.3`_ and `Section 10.16`_ for important security considerations
    when using the implicit grant.

    Implicit Grant: https://tools.ietf.org/html/rfc6749#section-4.2
    Section 10.3: https://tools.ietf.org/html/rfc6749#section-10.3
    Section 10.16: https://tools.ietf.org/html/rfc6749#section-10.16
    """

    response_types = ['token', 'id_token', 'id_token token']
    refresh_token = False

    def __init__(self, request_validator: RequestValidator = None):
        super().__init__(request_validator)
        self.register_token_modifier(self.add_token)
        self.register_token_modifier(self.add_id_token)

    async def create_authorization_response(self, request: Request):
        """
        Implicit Grant Flow
        """
        try:
            await self.validate_authorization_request(request, return_result=False)
            await self.oidc_authorization_match_user(request)
        except errors.FatalClientError as e:
            return await self._prepare_error_response(request, e, False)
        except errors.OAuth2Error as e:
            e.iss = Request.issuer
            return await self._prepare_error_response(request, e, True)

        token_info = {
            'iss': Request.issuer
        }

        if request.state is not None:
            token_info['state'] = request.state

        # In this call may created access_token and/or id_token
        await self._run_token_modifiers(token_info, request)

        if "access_token" in token_info:
            await aw(self.request_validator.save_token(token_info, request))

        return self._prepare_redirect_response(request, token_info)

    async def validate_authorization_request(self, request: Request, return_result: bool = True):
        """
        Validate the authorization request for normal and fatal errors.

        A normal error returned to client that initiate authorization process.

        Fatal errors occur when the client_id or redirect_uri is invalid or missing.
        Because in this scenario we can't return error to client, we display this error to End-User.
        """

        # In first step we must validate client_id and redirect_uri.
        # if these parameters are valid, we can raise only normal errors.

        # Duplicate parameters are always considered as invalid request.
        for param in ('client_id', 'redirect_uri'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestFatalError(description=f'Duplicate "{param}" parameter.', request=request)

        if request.client_id is None:
            raise errors.MissingClientIdError(request=request)

        # Get minimal ClientRepresentation to process request
        request.client = await aw(self.request_validator.client_identification(request))
        if request.client is None:
            raise errors.InvalidClientIdError(request=request)

        await self._validate_redirects(request)

        # Now client_id & redirect_uri are valid, other errors will be normal

        # Now check other duplicate parameters
        # (Error will be returned to client)
        for param in ('response_type', 'scope', 'state'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description=f'Duplicate "{param}" parameter.', request=request)

        await self._validate_response_type(request)
        await self._is_allowed_response_type(request)
        await self._validate_scopes(request)

        if return_result:
            if request.user is not None:
                # This information send to frontend for displaying information for user (for consent operation, if required)
                request_info = {
                    "client_id": request.client_id,
                    "display_name": request.client.display_name,
                    "requested_scopes": request.scopes,
                    "default_scopes": await aw(self.request_validator.get_default_scopes(request)),
                    "options": await aw(self.request_validator.get_client_options(request)),
                }
            else:
                # This basic information send to frontend if user not authenticated.
                request_info = {
                    "client_id": request.client_id,
                    "display_name": request.client.display_name
                }
            request_info.update(await self.oidc_authorization_validator(request))
            return self._prepare_validation_response(request_info)
        await self.oidc_authorization_validator(request, return_result=False)
        return None
