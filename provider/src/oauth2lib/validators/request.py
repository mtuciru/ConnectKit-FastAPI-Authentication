from datetime import datetime
from typing import Any

from ..common import Request

__all__ = ["RequestValidator", "ClientRepresentation", "UserRepresentation"]


class ClientRepresentation:
    client_id: str = None
    display_name: str = None

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class UserRepresentation:
    id: int = None
    login: str = None
    active: bool = None

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def from_user(cls, user):
        return cls(id=user.id, login=user.login, active=user.active)


class RequestValidator:
    """
    Validator used for check request params and receive required information from datastore.

    Because all required information saved in context of request,
    usually it is the only one argument for methods.
    """

    # -*- Client processing section -*-

    async def client_identification(self, request: Request) -> ClientRepresentation | None:
        """
        This method called when required only client identification.
        Use request.client_id for determine client and return ClientRepresentation
        or None, if client not exists or not allowed

        Method is used by endpoints:
            - /authorization -- Implicit OAuth2 grant or Hybrid OIDC grant on validation stage
        """
        raise NotImplementedError("Subclasses must implement this method.")

    @staticmethod
    async def get_client_options(request: Request) -> dict[str, Any]:
        """
        This method called to create info about request to frontend.

        You can add full list of claims or other frontend parameters.

        These parameters send to frontend by library for OAuth2 if request.user is not None:
            - "client_id": request.client_id,
            - "display_name": request.client.display_name,
            - "requested_scopes": request.scopes,
            - "default_scopes": self.request_validator.get_default_scopes(request),
            - "options": await self._aw(self.request_validator.get_client_options(request)),
        And if request.user is None:
            - "client_id": request.client_id,
            - "display_name": request.client.display_name,
        Because if user is not authenticated other fields are useless.

        Method is used by endpoints:
            - /authorization -- Implicit OAuth2 grant or Hybrid OIDC grant on validation stage
        """
        return {}

    async def client_authentication_required(self, request: Request) -> bool:
        """
        This method called to determine whether authentication with client credentials is required

        According to the rfc6749, client authentication is required in the following cases:
            - Client type is Confidential
            - Client was issued client credentials
            - Client supply its client credentials (even if they are not registered on the provider)

        Method is used by endpoints:
            - /token -- Obtaining access token by specified grant (RFC6749 and OIDC Core specification)
            - /device_authorization -- Start authorization process for device (RFC 8628)
            - /introspect -- Introspect issued token by client
            - /revoke -- Revoke issued token by client
        """
        raise NotImplementedError("Subclasses must implement this method.")

    async def authenticate_client(self, request: Request) -> ClientRepresentation | None:
        """
        This method called when required client authentication by its credentials.

        This library support three methods for obtaining client credentials:
        - client_credentials_basic:
            Registered in OAuth2 HTTP Basic method where credentials send in Authorization header.
            use *request.client_credentials_basic* to obtain (client_id, client_secret) pair.
        - client_credentials_post:
            Registered in OAuth2 x-www-urlencoded form method where credentials send in body parameters.
            use *request.client_credentials_post* to obtain (client_id, client_secret) pair.

        Method is used by endpoints:
            - /token -- Obtaining access token by specified grant (RFC6749 and OIDC Core specification)
            - /device_authorization -- Start authorization process for device (RFC 8628)
            - /introspect -- Introspect issued token by client
            - /revoke -- Revoke issued token by client
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def authenticate_client_id(self, request: Request) -> ClientRepresentation | None:
        """
        This method called when client authentication by its credentials is not applicable:
        *client_authentication_required* return False

        This method must be called only if client type is Public and client credentials is not supplied.

        use *request.client_id* to access client_id

        Method is used by endpoints:
            - /token -- Obtaining access token by specified grant (RFC6749 and OIDC Core specification)
            - /device_authorization -- Start authorization process for device (RFC 8628)
            - /introspect -- Introspect issued token by client
            - /revoke -- Revoke issued token by client
        """
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    async def is_client_pkce_required(request: Request) -> bool:
        """
        This method called when extended mechanism of authentication is required.
        By default, this extension is not required, but you can require it for public or all clients.
        if client provided PKCE, this will be processed.

        RFC7636:
        OAuth 2.0 public clients utilizing the Authorization Code Grant are
        susceptible to the authorization code interception attack.  This
        specification describes the attack as well as a technique to mitigate
        against the threat through the use of Proof Key for Code Exchange
        (PKCE, pronounced "pixy").

        Method is used by endpoints:
            - /authorization -- If AuthorizationCode Grant
            - /token -- If AuthorizationCode Grant
        """
        return False

    @staticmethod
    async def get_client_origin(request: Request) -> str | bool:
        """
        This method is called to check request Origin and perform CORS header for browser-based public clients,
        that use /token and some other endpoints, because browser uses CORS for protection user.

        if return False:
            Cross-Origin checking disabled. Request will be processed, but browser will reject response in cors mode.
        if return True:
            Cross-Origin checking disabled. Any origin received in Origin header will be added to Allowed Origin header.
        if return str:
            Cross-Origin checking enabled. If origin from header not equal, request will be discarded with error.

        Method is used by endpoints:
            - /token
            - /introspect
            - /revoke
            - /userinfo
        """
        return False

    @staticmethod
    async def is_client_dpop_required(request: Request) -> bool:
        """
        This method called when DPoP tokens is required.
        By default, this extension is not required, but you can require it for clients.
        if client provided DPoP header, this method not called

        Method is used by endpoints:
            - /token
        """
        return False

    @staticmethod
    async def get_client_dpop_nonce(request: Request) -> str | None:
        """
        This method called when client used DPoP.

        This nonce must be included in DPoP token.
        Must be short-lived.

        If client not add nonce value in DPoP token, value (if is not None) from this method
        returned as required nonce. So, you must not return new value at all calls of this method.

        None if disabled nonce check
        """
        return None

    @staticmethod
    async def is_client_dpop_valid_jti(request: Request, iat: datetime, dpop_jti: str) -> bool:
        """
        This method called when client used DPoP.

        You must check than value not used before and save this value as used.

        dpop_jti value must be unique and not used before in time window of validity (in this library its 30 seconds)

        iat - issue time as datetime object in utc timezone.
        dpop_jti - DPOP JTI value to check

        return True if disabled check
        """
        return True

    # -*- redirect_uri processing section -*-

    async def get_default_redirect_uri(self, request: Request) -> str | None:
        """
        Its method called, if client not specify redirect_uri parameter.
        Its parameter is optional for OAuth2 /authorize and required in other scenarios.

        According to the rfc6749, if for client registered more than one redirect URI,
        client must set redirect_uri parameter.
        So, this method must return default redirect_uri only if default redirect_uri exists.
        Also, URI must be absolute.

        Method is used by endpoints:
            - /authorization -- Only if AuthorizationCode Grant applied, otherwise redirect_uri is required from client.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_valid_redirect_uri(self, request: Request) -> bool:
        """
        Its method called for check that redirect_uri is registered for client.

        Method is used by endpoints:
            - /authorization -- if client send redirect_uri parameter.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    # -*- scope processing section -*-

    async def get_default_scopes(self, request: Request) -> list[str]:
        """
        Its method called if client not specify scope parameter.
        it must be default (maybe minimal) scopes.
        Also, if client registered as OIDC, scopes must contain 'openid' and may contain claims scope values:
        'profile', 'email', 'address', 'phone'.

        Method is used by endpoints, that receive scope parameter.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def transform_scopes(self, request: Request) -> list[str] | None:
        """
        Validate and transform scopes from request.

        !!WARNING BEGIN!!
        You must ignore openid scope value because it's a flag to change OAuth2 flow to OIDC flow:
        don't remove this scope if present and don't add if missing.
        !!WARNING END!!

        According to the rfc6749, if client requested wrong scopes, server may return error
        or change scope value to valid.

        if we need return error this method must return None.
        if scopes modified, or unchanged this method must return scopes.

        Method is used by endpoints, that receive scope parameter.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_refresh_token_scopes(self, request: Request) -> list[str]:
        """
        This method called to receive scopes binding to refresh_token

        When we generate new access_token, requested scope must be equal or less than refresh_token store.
        If refresh token rotated, its scope may be stay same or less.

        Method is used by endpoints:
            - /token -- Obtaining access token by refresh grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    async def is_within_refresh_token_scopes(refresh_scopes: list[str], request: Request) -> bool:
        """
        This method called to check that requested scopes is within the refresh token scopes.

        default check is simple include check for all requested scopes in scopes bound to refresh token.

        Method is used by endpoints:
            - /token -- Obtaining access token by refresh grant
        """
        return not all(s in refresh_scopes for s in request.scopes)

    # -*- code processing section -*-

    @staticmethod
    async def get_authorization_code_challenge(request: Request) -> str | None:
        """
        This method called to receive code_challenge bound to code if it exists.

        If return, PKCE will be processed for request.

        Method is used by endpoints:
            - /token -- Only AuthorizationCode Grant.
        """
        return None

    async def get_authorization_code_challenge_method(self, request: Request) -> str:
        """
        This method called to receive code_challenge_method bound to code.

        Method called if method get_code_challenge return value and request has code_verifier.

        Method is used by endpoints:
            - /token -- Only AuthorizationCode Grant.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_authorization_code_nonce(self, request: Request) -> str | None:
        """
        This method called to receive nonce bound to code.

        Nonce must be included to id_token if presented.

        Method is used by endpoints:
            - /token -- Only AuthorizationCode Grant if OIDC.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_authorization_code_redirect_uri(self, request: Request) -> str | None:
        """
        This method called to receive redirect_uri bound to code.

        If it not bound (if not specified in authorization request), return None

        Method is used by endpoints:
            - /token -- Only AuthorizationCode Grant if OIDC.
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_authorization_code_dpop_jkt(self, request: Request) -> str | None:
        """
        Return bound dpop_jkt value if exists
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def save_authorization_code(self, code_info: dict, request: Request):
        """
        This method must persist authorization code and bound values.

        Bound values list:
            - client (code must be bound to client that initiate authorization.)
            - user (code must be bound to user that grant access)
            - redirect_uri (if request.is_default_redirect_uri is False)
            - scope or scopes (Optional, for later bind this value to tokens)
            - code_challenge & code_challenge_method (if PKCE enabled for request)
            - nonce (if it OIDC request and its present in request)
            - claims (if it OIDC request and its present in request)
            - state (optional, may not present in request)
            - dpop_jkt (if present in request)

        code_info contains field:
            - code
            - redirect_uri (if request.is_default_redirect_uri is False)
            - code_challenge & code_challenge_method (if PKCE enabled for request)
            - nonce (if it OIDC request and its present in request)
            - state (is present in request)

        Method is used by endpoints:
            - /authorization -- If AuthorizationCode Grant used
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def save_device_code(self, code_info: dict, request: Request):
        """
        This method must persist device authorization code, user authorization code and bound values.

        Bound values list:
            - client (codes must be bound to client that initiate authorization.)
            - scope or scopes (Optional, for later bind this value to tokens)
            - expires_in (you can change value) (it's default time for code expiration, you must check if code expired)
            - interval (you can change value) (it's default interval for pull token request, you must check if too many requests)

        code_info contains field:
            - device_code
            - user_code
            - expires_in (it's default time for code expiration, you must check if code expired)
            - interval (it's default interval for pull token request, you must check if too many requests)

        Method is used by endpoints:
            - /device_authorization -- Device authorization process
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def restore_by_authorization_code(self, request: Request) -> bool:
        """
        This method called to validate authorization code and restore bound information.

        Need operations:
            - Validate that code is valid for client (issued for it, not expired, etc.)
            - Restore user representation, bounded to code (set it in request.user)
            - Restore redirect_uri bound to code (if exists)
            - Restore scopes bound to code (set it in request.scopes) (otherwise get_default_scopes will be called)
            - Restore code_challenge & code_challenge_method (if PKCE was being enabled)
            - Restore nonce (if it OIDC request and its was being saved)
            - Restore claims (if it OIDC request and its was being saved)

        Method must return True if code is valid and restore successful otherwise return False.

        Method is used by endpoints:
            - /token -- Obtaining access token by AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_device_code_error_status(self, request: Request) -> str | None:
        """
        This method called to validate device code
        and must return None if code is valid and user grant access.

        Otherwise, method must return one of error state:
            - invalid_grant
                Device code is invalid (not existed or not bound to authenticated client)
            - authorization_pending
                Device code is valid but user still is not authorized by user_code
            - slow_down
                Device code is valid but client send too many requests and must slow down.
            - access_denied
                User authorized by user_code but rejected client, pulling session is closed.
            - expired_token
                Device code was expired, pulling session is closed.

        Method is used by endpoints:
            - /token -- Obtaining access token by DeviceCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def restore_by_device_code(self, request: Request) -> bool:
        """
        This method called to restore bound information for device code if user grant access.

        Need operations:
            - Restore user representation, bounded to code (set it in request.user)
            - Restore scopes bound to code (set it in request.scopes) (otherwise get_default_scopes will be called)

        Method must return True if restore successful otherwise return False.

        Method is used by endpoints:
            - /token -- Obtaining access token by DeviceCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def forgot_authorization_code(self, request: Request):
        """
        This method called to mark as used authorization code and forgot its bound information.

        Its method will be called after successful /token request with authorization_code grant.
        Its method will not be called if code is expired or other reasons.

        Method is used by endpoints:
            - /token -- Obtaining access token by AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def forgot_device_code(self, request: Request):
        """
        This method called to mark as used, expired or denied device code and forgot its bound information.

        Its method will be called after successful /token request with device_code grant,
        if device code is expired (expired_token error status),
        if device code is denied (access_denied error status),
        Its method will not be called for other reasons.

        Method is used by endpoints:
            - /token -- Obtaining access token by AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    # -*- grant_type processing section -*-

    async def response_type_is_allowed(self, request: Request) -> bool:
        """
        This method called to check
        that authenticated client is:
            - allowed to use AuthorizationCode, Implicit or Hybrid grants (selected by value)
            - allowed to use this response type in grant.

        Method is used by endpoints:
            - /authorization -- For AuthorizationCode, Implicit and Hybrid grants
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def grant_type_is_allowed(self, request: Request) -> bool:
        """
        This method called to check that authenticated client is allowed to use this grant type.

        Method is used by endpoints:
            - /token -- For all grant types
        """
        raise NotImplementedError('Subclasses must implement this method.')

    # -*- user processing section -*-

    async def authorize_user(self, request: Request) -> UserRepresentation | None:
        """
        This method called to authorize user by supplied username and password.

        Must return a UserRepresentation or None if user is not authorized by any reason.

        Method is used by endpoints:
            - /token -- only for ResourceOwnerPasswordCredentials grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_match(self, sub_value: str | None, request: Request) -> bool:
        """
        This method called to check match current and expected by client user sessions.

        if sub_value is presented, validate that current user session matches sub_value,
        Then if request.id_token_hint is presented, also validate that current user session matches id_token_hint.

        Only if both validation success returns True, otherwise returns False.

        sub_value extracted from request.claims.id_token.sub.value if exists, None otherwise.

        Method is used by endpoints:
            - /authorization -- only for OIDC AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_login_required(self, request: Request) -> bool:
        """
        This method called to check that current user session required reauthentication.
        This method will be called if request.user presented.

        if prompt value contains 'login' or equal 'none', this method will be called.
        If return True, that error 'login_required' or 'interaction_required' will be retuned to client.

        prompt='none' means silent authorization process without user interaction,
        so if user interaction required, error will be returned.

        prompt='login' means user must be reauthenticated, but if this method return True, reauthentication is not happen.
        so error will be returned.

        Method is used by endpoints:
            - /authorization (validation&authorization stage) -- only for OIDC AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_consent_required(self, request: Request) -> bool:
        """
        This method called to check that current user session required consent.
        This method will be called if request.user presented.

        if prompt value contains 'consent' or equal 'none', this method will be called.
        If return True, that error 'consent_required' or 'interaction_required' will be retuned to client.

        prompt='none' means silent authorization process without user interaction,
        so if user interaction required, error will be returned.

        prompt='consent' means user must be consent request, but if this method return True, consent is not happen.
        so error will be returned.

        if OAuth2, this method also will be called, for check user consent.

        Method is used by endpoints:
            - /authorization (validation stage) -- for OIDC AuthorizationCode grant
            - /authorization (validation&authorization stage) -- for OIDC and OAuth2 AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_access_denied(self, request: Request) -> bool:
        """
        This method called to check that current user denied access to client.

        return True if access denied

        Method is used by endpoints:
            - /authorization (authorization stage) -- for OIDC and OAuth2 AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    # -*- token processing section -*-

    async def save_token(self, token: dict, request: Request):
        """
        This method called to save issued access and optional refresh
        token["access_token"], token["refresh_token"].

        Method is used by endpoints:
            - /authorization -- only for Implicit and Hybrid grants
            - /token
        """
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    async def is_rotate_refresh_token(request: Request) -> bool:
        """
        This method called to determine recreate refresh token or not
        when refresh grant used.

        Default refresh token recreated, old refresh token must be invalidated.

        Method is used by endpoints:
            - /token -- Refresh grant
        """
        return True

    async def validate_refresh_token(self, request: Request) -> bool:
        """
        This method called to check refresh token exists, not expired, and associated with authenticated client.
        Also, this method can set request.user to user associated with this refresh token.

        Method is used by endpoints:
            - /token -- Refresh grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_refresh_token_dpop_jkt(self, request: Request) -> str | None:
        """
        Return bound dpop_jkt value to refresh_token if exists

        This value used for:
            - Validate that DPoP key matched with refresh_token
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def fill_id_token(self, id_token: dict, acr_required: bool, auth_time_required: bool, request: Request):
        """Finalize OpenID Connect ID token & Sign.

        TODO: rewrite

        In the OpenID Connect workflows when an ID Token is requested
        this method is called.  Subclasses should implement the
        construction, signing and optional encryption of the ID Token
        as described in the OpenID Connect spec.

        The `id_token` parameter is a dict containing a couple of OIDC
        technical fields related to the specification. Prepopulated
        attributes are:

        - `aud`, equals to `request.client_id`.
        - `iat`, equals to current time.
        - `nonce`, if present, is equals to the `nonce` from the
          authorization request.
        - `at_hash`, hash of `access_token`, if relevant.
        - `c_hash`, hash of `code`, if relevant.

        This method MUST provide required fields as below:

        - `iss`, REQUIRED. Issuer Identifier for the Issuer of the response.
        - `sub`, REQUIRED. Subject Identifier
        - `exp`, REQUIRED. Expiration time on or after which the ID
          Token MUST NOT be accepted by the RP when performing
          authentication with the OP.

        Additional claims may be added, note that `request.scope`
        should be used to determine the list of claims.

        More information can be found at `OpenID Connect Core#Claims`_

        .. _`OpenID Connect Core#Claims`: https://openid.net/specs/openid-connect-core-1_0.html#Claims

        """
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    async def is_rotate_id_token(request: Request) -> bool:
        """
        This method called to determine recreate id token or not
        when refresh grant used.

        Default id token recreated, old id token may be invalidated or saved.

        Method is used by endpoints:
            - /token -- Refresh grant
        """
        return True

    async def introspect_token(self, request: Request) -> dict[str, Any] | None:
        """
        This method called to introspect tokens.
        Use request.token and request.token_type_hint
        token_type_hint MUST be silent ignored if it is unknown or don't match with token.

        if token is "active" ("Active" will generally indicate that
            a given token has been issued by this authorization server,
            has not been revoked by the resource owner,
            and is within its given time window of validity (nbf, exp),
            also you can check that token bound to authenticated client.):
        this method MUST return a dict containing information about token (can be empty).

        According RFC7662, returned dict may contain:
            - scope
                OPTIONAL. A JSON string containing a space-separated list of
                scopes associated with this token, in the format described in
                Section 3.3 of OAuth 2.0 [RFC6749].
            - client_id
                OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
            - username
                OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
            - token_type
                OPTIONAL. Type of the token as defined in Section 5.1 of OAuth 2.0 [RFC6749].
            - exp
                OPTIONAL. Integer timestamp, measured in the number of seconds
                since January 1 1970 UTC, indicating when this token will expire, as defined in JWT [RFC7519].
            - iat
                OPTIONAL. Integer timestamp, measured in the number of seconds
                since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT [RFC7519].
            - nbf
                OPTIONAL. Integer timestamp, measured in the number of seconds
                since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT [RFC7519].
            - sub
                OPTIONAL. Subject of the token, as defined in JWT [RFC7519].
                Usually a machine-readable identifier of the resource owner who authorized this token.
            - aud
                OPTIONAL. Service-specific string identifier or list of string
                identifiers representing the intended audience for this token, as defined in JWT [RFC7519].
            - iss
                OPTIONAL. String representing the issuer of this token, as defined in JWT [RFC7519].
            - jti
                OPTIONAL. String identifier for the token, as defined in JWT [RFC7519].

        Specific implementations MAY extend this structure with their own
        service-specific response names as top-level members of this JSON
        object. Response names intended to be used across domains MUST be
        registered in the "OAuth Token Introspection Response" registry
        defined in Section 3.1.

        Method is used by endpoints:
            - /introspect
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def revoke_token(self, request: Request) -> bool:
        """
        This method called to revoke tokens.
        Use request.token and request.token_type_hint,
        token_type_hint MUST be silent ignored if it is unknown or don't match with token.

        Whenever token revoked or not this method must return True.
        Return value False raise unsupported_token_type error.

        unsupported_token_type: The authorization server does not support
            the revocation of the presented token type. That is, the
            client tried to revoke an access token on a server not
            supporting this feature.

        Method is used by endpoints:
            - /revoke
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_userinfo_claims(self, request: Request) -> dict[str, Any] | str:
        """
        TODO: rewrite
        Return the UserInfo claims in JSON or JWT.

        The UserInfo Claims MUST be returned as the members of a JSON object
         unless a signed or encrypted response was requested during Client
         Registration. The Claims defined in Section 5.1 can be returned, as can
         additional Claims not specified there.

        For privacy reasons, OpenID Providers MAY elect to not return values for
        some requested Claims.

        If a Claim is not returned, that Claim Name SHOULD be omitted from the
        JSON object representing the Claims; it SHOULD NOT be present with a
        null or empty string value.

        The sub (subject) Claim MUST always be returned in the UserInfo
        Response.

        Upon receipt of the UserInfo Request, the UserInfo Endpoint MUST return
        the JSON Serialization of the UserInfo Response as in Section 13.3 in
        the HTTP response body unless a different format was specified during
        Registration [OpenID.Registration].

        If the UserInfo Response is signed and/or encrypted, then the Claims are
        returned in a JWT and the content-type MUST be application/jwt. The
        response MAY be encrypted without also being signed. If both signing and
        encryption are requested, the response MUST be signed then encrypted,
        with the result being a Nested JWT, as defined in [JWT].

        If signed, the UserInfo Response SHOULD contain the Claims iss (issuer)
        and aud (audience) as members. The iss value SHOULD be the OP's Issuer
        Identifier URL. The aud value SHOULD be or include the RP's Client ID
        value.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: Claims as a dict OR JWT/JWS/JWE as a string

        Method is used by:
            UserInfoEndpoint
        """
        raise NotImplementedError('Subclasses must implement this method.')
