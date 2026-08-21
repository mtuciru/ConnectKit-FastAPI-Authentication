import base64
import hashlib

from .base import GrantTypeBase
from .. import errors
from ..common import Request, safe_string_equals, aw, generate_token
from ..tokens import create_bearer_token, create_dpop_token, dpop_present
from ..validators import RequestValidator

__all__ = ["AuthorizationCodeGrant"]


def code_challenge_method_s512(verifier: str, challenge: str):
    # if common.CODE_VERIFIER_PATTERN.fullmatch(verifier) is None:
    #     return False
    verifier = base64.urlsafe_b64encode(hashlib.sha512(verifier.encode("ASCII")).digest()).decode().rstrip('=')
    return safe_string_equals(verifier, challenge)


def code_challenge_method_s256(verifier: str, challenge: str):
    # if common.CODE_VERIFIER_PATTERN.fullmatch(verifier) is None:
    #     return False
    verifier = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ASCII")).digest()).decode().rstrip('=')
    return safe_string_equals(verifier, challenge)


def code_challenge_method_plain(verifier: str, challenge: str):
    # if common.CODE_VERIFIER_PATTERN.fullmatch(verifier) is None:
    #     return False
    return safe_string_equals(verifier, challenge)


class AuthorizationCodeGrant(GrantTypeBase):
    """
    Authorization Code Grant

    The authorization code grant type is used to obtain both access
    tokens and refresh tokens and is optimized for confidential clients.
    Since this is a redirection-based flow, the client must be capable of
    interacting with the resource owner's user-agent (typically a web
    browser) and capable of receiving incoming requests (via redirection)
    from the authorization server::

        +----------+
        | Resource |
        |   Owner  |
        |          |
        +----------+
             ^
             |
            (B)
        +----|-----+          Client Identifier      +---------------+
        |         -+----(A)-- & Redirection URI ---->|               |
        |  User-   |                                 | Authorization |
        |  Agent  -+----(B)-- User authenticates --->|     Server    |
        |          |                                 |               |
        |         -+----(C)-- Authorization Code ---<|               |
        +-|----|---+                                 +---------------+
          |    |                                         ^      v
         (A)  (C)                                        |      |
          |    |                                         |      |
          ^    v                                         |      |
        +---------+                                      |      |
        |         |>---(D)-- Authorization Code ---------'      |
        |  Client |          & Redirection URI                  |
        |         |                                             |
        |         |<---(E)----- Access Token -------------------'
        +---------+       (w/ Optional Refresh Token)

    Note: The lines illustrating steps (A), (B), and (C) are broken into
    two parts as they pass through the user-agent.

    Figure 3: Authorization Code Flow

    The flow illustrated in Figure 3 includes the following steps:

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
         redirection URI provided earlier (in the request or during
         client registration).  The redirection URI includes an
         authorization code and any local state provided by the client
         earlier.

    (D)  The client requests an access token from the authorization
         server's token endpoint by including the authorization code
         received in the previous step.  When making the request, the
         client authenticates with the authorization server.  The client
         includes the redirection URI used to obtain the authorization
         code for verification.

    (E)  The authorization server authenticates the client, validates the
         authorization code, and ensures that the redirection URI
         received matches the URI used to redirect the client in
         step (C).  If valid, the authorization server responds back with
         an access token and, optionally, a refresh token.

    OAuth 2.0 public clients utilizing the Authorization Code Grant are
    susceptible to the authorization code interception attack.

    A technique to mitigate against the threat through the use of Proof Key for Code
    Exchange (PKCE, pronounced "pixy") is implemented in the current oauthlib
    implementation.

    Authorization Code Grant: https://tools.ietf.org/html/rfc6749#section-4.1
    PKCE: https://tools.ietf.org/html/rfc7636
    """

    default_response_mode = 'query'
    response_types = ['none', 'code']
    grant_type: str = "authorization_code"

    _code_challenge_methods = {
        'plain': code_challenge_method_plain,
        'S256': code_challenge_method_s256,
        'S512': code_challenge_method_s512
    }

    def __init__(self, request_validator: RequestValidator = None):
        super().__init__(request_validator)
        self.register_token_modifier(self.add_id_token)

    @staticmethod
    def _create_authorization_code(request: Request):
        code_info = {
            'code': generate_token(),
            'iss': Request.issuer
        }
        if request.state is not None:
            code_info['state'] = request.state
        if not request.is_default_redirect_uri:
            code_info['redirect_uri'] = request.redirect_uri
        if request.code_challenge is not None:
            code_info['code_challenge'] = request.code_challenge
            code_info['code_challenge_method'] = request.code_challenge_method or "plain"
        if request.nonce is not None:
            code_info['nonce'] = request.nonce
        return code_info

    async def create_authorization_response(self, request: Request):
        """
        In request must be set parameters:
            - response_type
                Allowed values are "none", "code"
            - client_id
                The client identifier as described in OAuth2 RFC in Section 2.2.
        In request may be set parameters:
            - redirect_uri
                Optional redirect URI for OAuth2 and required for OIDC.
            - scope
                Requested scopes space-delimited.
                OIDC clients must add this parameter at least with 'openid' scope value.
                'openid' scope value processed automatically and must be ignored by request_validator
            - state
                An opaque value used by the client to maintain
                state between the request and callback.  The authorization
                server includes this value when redirecting the user-agent back
                to the client.  The parameter SHOULD be used for preventing
                cross-site request forgery as described in OAuth2 RFC in Section 10.12.
        Also in request may be parameters for OIDC:
            - display
            - prompt
            - max_age
            - ui_locales
            - id_token_hint
            - login_hint
            - acr_values
            - claims_locales
            - claims

        """
        try:
            await self.validate_authorization_request(request, return_result=False)
            await self.oidc_authorization_match_user(request)
        # Inform End-User about error. Send error to frontend.
        except errors.FatalClientError as e:
            return await self._prepare_error_response(request, e, False)
        # Inform client about error. Send redirect_uri to frontend (frontend must redirect user-agent to uri).
        except errors.OAuth2Error as e:
            e.iss = Request.issuer
            return await self._prepare_error_response(request, e, True)

        if request.response_type == 'none':
            # Request type none tell no return, so, create code and save it are useless operations.
            # Simple skip other operations
            code_info = {'iss': Request.issuer}
            if request.state is not None:
                code_info['state'] = request.state
            return self._prepare_redirect_response(request, code_info)

        code_info = self._create_authorization_code(request)
        # Hybrid flow inherits this method, but add code_modifiers for adding access_token and id_token to code response
        # If it required by response_type value
        await self._run_code_modifiers(code_info, request)
        if 'access_token' in code_info:
            await aw(self.request_validator.save_token(code_info, request))
        await aw(self.request_validator.save_authorization_code(code_info, request))
        return self._prepare_redirect_response(request, code_info)

    async def create_token_response(self, request: Request):
        """
        Issue tokens by code.

        If one authorization code used several times in time window,
        Request must be rejected and, if possible, previously issued tokens must be revoked for security.
        """
        try:
            await self.validate_token_request(request)
        except errors.OAuth2Error as e:
            return await self._prepare_error_response(request, e, False)

        try:
            await self._cors_preflight(request)
        except errors.OAuth2Error as e:
            # CORS preflight failed. So, forgot used code, but not issue tokens it's not required.
            await aw(self.request_validator.forgot_authorization_code(request))
            return await self._prepare_error_response(request, e, False)

        if dpop_present(request) or await aw(self.request_validator.is_client_dpop_required(request)):
            # If client require DPoP type of access token (access with proof) issue DPoP
            dpop_jkt = await aw(self.request_validator.get_authorization_code_dpop_jkt(request))
            token = await create_dpop_token(self.request_validator, request, self.refresh_token, dpop_jkt)
        else:
            token = await create_bearer_token(self.request_validator, request, self.refresh_token)

        await self._run_token_modifiers(token, request)

        await aw(self.request_validator.save_token(token, request))
        await aw(self.request_validator.forgot_authorization_code(request))
        return await self._prepare_direct_response(request, token)

    async def validate_authorization_request(self, request: Request, return_result: bool = True):
        """
        Validate the authorization request for normal and fatal errors.

        A normal error returned to client that initiate authorization process.

        Fatal errors occur when the client_id or redirect_uri is invalid or missing.
        Because in this scenario we can't return error to client, we display this error to End-User.
        """

        # In first step we must validate client_id and redirect_uri.
        # if these parameters are valid, we can raise only normal errors.

        if not return_result and request.store.get("from_validate_authorization_request", False):
            # Skip unnecessary validation
            return None

        # Duplicate parameters are always considered as invalid request.
        self._validate_duplicate_params(request, ('client_id', 'redirect_uri'), True)

        if request.client_id is None:
            raise errors.MissingClientIdError(request=request)

        # Get minimal ClientRepresentation to process request
        request.client = await aw(self.request_validator.client_identification(request))
        if request.client is None:
            raise errors.InvalidClientIdError(request=request)

        await self._validate_redirects(request)

        # Now client_id & redirect_uri are valid, other errors will be returned to client

        # Now check other duplicate parameters
        self._validate_duplicate_params(request, (
            'response_type', 'scope', 'state', 'response_mode',
            'dpop_jkt', 'code_challenge', 'code_challenge_method'
        ))

        await self._validate_response_type(request)
        await self._is_allowed_response_type(request)

        # Optional PKCE
        if await aw(self.request_validator.is_client_pkce_required(request)):
            if request.code_challenge is None:
                raise errors.MissingCodeChallengeError(request=request)
        if request.code_challenge is not None:
            request.code_challenge_method = request.code_challenge_method or "plain"
            if request.code_challenge_method not in self._code_challenge_methods:
                raise errors.UnsupportedCodeChallengeMethodError(request=request)

        await self._validate_scopes(request)

        if return_result:
            request_info = {
                'oidc': False,
                "client_id": request.client_id,
                "display_name": request.client.display_name,
                "scopes": request.scopes,
                "options": await aw(self.request_validator.get_client_options(request)),
            }

            request_info.update(await self.oidc_authorization_validator(request))

            # One-round optimisation
            # Instead of return validation info we call 'create_authorization_response'
            # and return complete authorization response.
            # It's worked because 'none' prompt disable user interaction,
            # so we don't need to do two requests to provider.
            prompt = request_info.get("prompt")
            if prompt is not None and "none" in prompt:
                request.store["from_validate_authorization_request"] = True
                return await self.create_authorization_response(request)

            return self._prepare_validation_response(request_info)
        await self.oidc_authorization_validator(request, return_result=False)
        return None

    async def validate_token_request(self, request: Request):
        """
        Validate token request before processing if.
        """
        # In first check duplicates
        # 'client_id', 'grant_type', 'redirect_uri', 'code' from requested parameters
        # 'client_id' and 'client_secret' from client_secret_post
        self._validate_duplicate_params(request, ('client_id', 'grant_type', 'redirect_uri', 'code', 'client_secret'))

        if request.code is None:
            raise errors.InvalidRequestError(description='Missing code parameter.', request=request)

        await self._validate_grant_type(request)

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

        if not await aw(self.request_validator.restore_by_authorization_code(request)):
            raise errors.InvalidGrantError(request=request)

        # Validate PKCE code_verifier
        challenge = await aw(self.request_validator.get_authorization_code_challenge(request))
        if challenge is not None:
            if request.code_verifier is None:
                raise errors.MissingCodeVerifierError(request=request)

            challenge_method = await aw(self.request_validator.get_authorization_code_challenge_method(request))
            if challenge_method is None:
                raise errors.InvalidGrantError(request=request, description="Challenge method not found")

            if not self.validate_code_challenge(challenge, challenge_method, request.code_verifier):
                raise errors.InvalidGrantError(request=request)
        elif await aw(self.request_validator.is_client_pkce_required(request)):
            if request.code_verifier is None:
                raise errors.MissingCodeVerifierError(request=request)
            raise errors.InvalidGrantError(request=request, description="Challenge not found")

        bound_redirect_uri = await aw(self.request_validator.get_authorization_code_redirect_uri(request))
        if bound_redirect_uri is None:
            # This parameter must be omitted, but present
            # Validate by default redirect_uri, if exists
            if request.redirect_uri is not None:
                default_redirect_uri = await aw(self.request_validator.get_default_redirect_uri(request))
                if safe_string_equals(request.redirect_uri, default_redirect_uri):
                    raise errors.MismatchingRedirectURIError(request=request)
        else:
            if request.redirect_uri is None:
                raise errors.MissingRedirectURIError(request=request)
            if not safe_string_equals(request.redirect_uri, bound_redirect_uri):
                raise errors.MismatchingRedirectURIError(request=request)

    def validate_code_challenge(self, challenge: str, challenge_method: str, verifier: str):
        if challenge_method in self._code_challenge_methods:
            return self._code_challenge_methods[challenge_method](verifier, challenge)
        raise errors.ServerError(description=f'Unknown code_challenge_method "{challenge_method}"')
