import inspect
import sys

from .base import OAuth2Error, FatalClientError
from ..common import Request

__all__ = [
    "InvalidRequestFatalError", "InvalidRedirectURIError", "InsecureRedirectURIError", "MissingRedirectURIError",
    "MismatchingRedirectURIError", "InvalidClientIdError", "MissingClientIdError", "InvalidRequestError",
    "MissingResponseTypeError", "MissingCodeChallengeError", "MissingGrantTypeError", "MissingCodeVerifierError",
    "UnauthorizedClientError", "AccessDeniedError", "UnsupportedResponseTypeError",
    "UnsupportedCodeChallengeMethodError", "InvalidScopeError", "ServerError", "TemporarilyUnavailableError",
    "InvalidClientError", "InvalidGrantError", "UnsupportedGrantTypeError", "UnsupportedTokenTypeError",
    "InvalidTokenError", "InsufficientScopeError", "InsufficientUserAuthentication", "AuthorizationPendingError",
    "SlowDownError", "ExpiredTokenError", "InteractionRequired", "LoginRequired", "AccountSelectionRequired",
    "ConsentRequired", "InvalidRequestURI", "InvalidRequestObject", "RequestNotSupported", "RequestURINotSupported",
    "RegistrationNotSupported", "InvalidDPoPProof", "UseDPoPNonce", "CustomOAuth2Error", "raise_from_error"
]

"""
This error messages declared by OAuth2 and OpenID Connect specifications
"""


class InvalidRequestFatalError(FatalClientError):
    """
    For fatal errors, the request is missing a required parameter, includes
    an invalid parameter value, includes a parameter more than once, or is
    otherwise malformed.

    this error can't be returned to client
    (because we don't know this client_id or client redirect_uri is invalid)
    """
    error = 'invalid_request'


class InvalidRedirectURIError(InvalidRequestFatalError):
    """
    redirect_uri not valid absolute uri
    """
    description = 'Invalid redirect URI.'


class InsecureRedirectURIError(InvalidRequestFatalError):
    """
    redirect_uri not secure (https) absolute uri
    """
    description = 'Insecure redirect URI.'


class MissingRedirectURIError(InvalidRequestFatalError):
    """
    redirect_uri missing
    """
    description = 'Missing redirect URI.'


class MismatchingRedirectURIError(InvalidRequestFatalError):
    """
    redirect_uri mismatched with known for client
    """
    description = 'Mismatching redirect URI.'


class InvalidClientIdError(InvalidRequestFatalError):
    """
    client_id is invalid (client is unknown)
    """
    description = 'Invalid client_id parameter value.'


class MissingClientIdError(InvalidRequestFatalError):
    """
    client_id is missing (client is unknown)
    """
    description = 'Missing client_id parameter.'


class InvalidRequestError(OAuth2Error):
    """
    The request is missing a required parameter, includes an invalid
    parameter value, includes a parameter more than once, or is
    otherwise malformed.

    in this case, we can redirect to client with error code
    """
    error = 'invalid_request'


class MissingResponseTypeError(InvalidRequestError):
    description = 'Missing response_type parameter.'


class MissingCodeChallengeError(InvalidRequestError):
    """
    If the server requires Proof Key for Code Exchange (PKCE) by OAuth
    public clients and the client does not send the "code_challenge" in
    the request, the authorization endpoint MUST return the authorization
    error response with the "error" value set to "invalid_request".  The
    "error_description" or the response of "error_uri" SHOULD explain the
    nature of error, e.g., code challenge required.
    """
    description = 'Code challenge required.'


class MissingGrantTypeError(InvalidRequestError):
    description = 'Missing grant_type parameter.'


class MissingCodeVerifierError(InvalidRequestError):
    """
    The request to the token endpoint, when PKCE is enabled, has
    the parameter `code_verifier` REQUIRED.
    """
    description = 'Code verifier required.'


class UnauthorizedClientError(OAuth2Error):
    """
    Client is not authorized to use this grand type or response type.
    """
    error = 'unauthorized_client'


class AccessDeniedError(OAuth2Error):
    """
    Access denied by resource owner.
    """
    error = 'access_denied'
    status_code = 403


class UnsupportedResponseTypeError(OAuth2Error):
    """
    The authorization server does not implement response type.
    """
    error = 'unsupported_response_type'


class UnsupportedCodeChallengeMethodError(InvalidRequestError):
    """
    If the server supporting PKCE does not support the requested
    transformation, the authorization endpoint MUST return the
    authorization error response with "error" value set to
    "invalid_request".  The "error_description" or the response of
    "error_uri" SHOULD explain the nature of error, e.g., transform
    algorithm not supported.
    """
    description = 'Transform algorithm not supported.'


class InvalidScopeError(OAuth2Error):
    """
    The requested scope is invalid, unknown, or malformed, or
    exceeds the scope granted by the resource owner.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_scope'


class ServerError(OAuth2Error):
    """
    The authorization server encountered an unexpected condition that
    prevented it from fulfilling the request.  (This error code is needed
    because a 500 Internal Server Error HTTP status code cannot be returned
    to the client via a HTTP redirect.)
    """
    error = 'server_error'


class TemporarilyUnavailableError(OAuth2Error):
    """
    The authorization server is currently unable to handle the request
    due to a temporary overloading or maintenance of the server.
    """
    error = 'temporarily_unavailable'
    status_code = 503


class InvalidClientError(FatalClientError):
    """
    Client authentication failed (e.g. unknown client, no client
    authentication included, or unsupported authentication method).
    The authorization server MAY return an HTTP 401 (Unauthorized) status
    code to indicate which HTTP authentication schemes are supported.
    If the client attempted to authenticate via the "Authorization" request
    header field, the authorization server MUST respond with an
    HTTP 401 (Unauthorized) status code, and include the "WWW-Authenticate"
    response header field matching the authentication scheme used by the
    client.
    """
    error = 'invalid_client'
    status_code = 401


class InvalidGrantError(OAuth2Error):
    """
    The provided authorization grant (e.g. authorization code, resource
    owner credentials) or refresh token is invalid, expired, revoked, does
    not match the redirection URI used in the authorization request, or was
    issued to another client.

    https://tools.ietf.org/html/rfc6749#section-5.2
    """
    error = 'invalid_grant'
    status_code = 400


class UnsupportedGrantTypeError(OAuth2Error):
    """
    The authorization grant type is not supported by the authorization
    server.
    """
    error = 'unsupported_grant_type'


class UnsupportedTokenTypeError(OAuth2Error):
    """
    The authorization server does not support the hint of the
    presented token type.  I.e. the client tried to revoke an access token
    on a server not supporting this feature.
    """
    error = 'unsupported_token_type'


class InvalidTokenError(OAuth2Error):
    """
    The access token provided is expired, revoked, malformed, or
    invalid for other reasons.  The resource SHOULD respond with
    the HTTP 401 (Unauthorized) status code.  The client MAY
    request a new access token and retry the protected resource
    request.
    """
    error = 'invalid_token'
    status_code = 401
    description = ("The access token provided is expired, revoked, malformed, "
                   "or invalid for other reasons.")


class InsufficientScopeError(OAuth2Error):
    """
    The request requires higher privileges than provided by the
    access token.  The resource server SHOULD respond with the HTTP
    403 (Forbidden) status code and MAY include the "scope"
    attribute with the scope necessary to access the protected
    resource.
    """
    error = 'insufficient_scope'
    status_code = 403
    description = ("The request requires higher privileges than provided by "
                   "the access token.")


class InsufficientUserAuthentication(OAuth2Error):
    """

    """
    error = 'insufficient_user_authentication'
    status_code = 401
    description = "Authentication requirement is not satisfied"
    acr_values: list[str]
    max_age: int

    def __init__(self, description: str = None, uri: str = None, acr_values: list[str] = None, max_age: int = None,
                 state: str = None, status_code: int = None, request: Request = None):
        super().__init__(description, uri, state, status_code, request)
        self.acr_values = acr_values
        self.max_age = max_age


## -*- Device Grant Errors -*-

class AuthorizationPendingError(OAuth2Error):
    """
    For the device authorization grant;
      The authorization request is still pending as the end user hasn't
      yet completed the user-interaction steps (Section 3.3).  The
      client SHOULD repeat the access token request to the token
      endpoint (a process known as polling).  Before each new request,
      the client MUST wait at least the number of seconds specified by
      the "interval" parameter of the device authorization response,
      or 5 seconds if none was provided, and respect any
      increase in the polling interval required by the "slow_down"
      error.
    """

    error = "authorization_pending"


class SlowDownError(OAuth2Error):
    """
    A variant of "authorization_pending", the authorization request is
    still pending and polling should continue, but the interval MUST
    be increased by 5 seconds for this and all subsequent requests.
    """

    error = "slow_down"


class ExpiredTokenError(OAuth2Error):
    """
    The "device_code" has expired, and the device authorization
    session has concluded.  The client MAY commence a new device
    authorization request but SHOULD wait for user interaction before
    restarting to avoid unnecessary polling.
    """

    error = "expired_token"


## - *- OpenID Connect Errors -*-

class InteractionRequired(OAuth2Error):
    """
    The Authorization Server requires End-User interaction to proceed.

    This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface for End-User interaction.
    """
    error = 'interaction_required'


class LoginRequired(OAuth2Error):
    """
    The Authorization Server requires End-User authentication.

    This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface for End-User authentication.
    """
    error = 'login_required'


class AccountSelectionRequired(OAuth2Error):
    """
    The End-User is REQUIRED to select a session at the Authorization Server.

    The End-User MAY be authenticated at the Authorization Server with
    different associated accounts, but the End-User did not select a session.
    This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface to prompt for a session to
    use.
    """
    error = 'account_selection_required'


class ConsentRequired(OAuth2Error):
    """
    The Authorization Server requires End-User consent.

    This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface for End-User consent.
    """
    error = 'consent_required'


# Never exists: this feature not supported
class InvalidRequestURI(OAuth2Error):
    """
    The request_uri in the Authorization Request returns an error or
    contains invalid data.
    """
    error = 'invalid_request_uri'
    description = ('The request_uri in the Authorization Request returns an '
                   'error or contains invalid data.')


# Never exists: this feature not supported
class InvalidRequestObject(OAuth2Error):
    """
    The request parameter contains an invalid Request Object.
    """
    error = 'invalid_request_object'
    description = 'The request parameter contains an invalid Request Object.'


class RequestNotSupported(OAuth2Error):
    """
    The OP does not support use of the request parameter.
    """
    error = 'request_not_supported'
    description = 'The request parameter is not supported.'


class RequestURINotSupported(OAuth2Error):
    """
    The OP does not support use of the request_uri parameter.
    """
    error = 'request_uri_not_supported'
    description = 'The request_uri parameter is not supported.'


class RegistrationNotSupported(OAuth2Error):
    """
    The OP does not support use of the registration parameter.
    """
    error = 'registration_not_supported'
    description = 'The registration parameter is not supported.'


class InvalidDPoPProof(OAuth2Error):
    """
    The DPoP token is invalid. Malformed, etc.

    By default, status_code == 400, resource server can use 401
    """
    error = 'invalid_dpop_proof'
    description = 'Invalid DPoP token'


class UseDPoPNonce(OAuth2Error):
    """
    The nonce claim required for a DPoP token. Or nonce is expired.

    By default, status_code == 400, resource server can use 401
    """
    error = 'use_dpop_nonce'
    description = 'Use "nonce" in DPoP token'
    nonce = None


class CustomOAuth2Error(OAuth2Error):
    """
    This error is a placeholder for all custom errors not described by the RFC.
    Some of the popular OAuth2 providers are using custom errors.
    """

    def __init__(self, error, *args, **kwargs):
        self.error = error
        super().__init__(*args, **kwargs)


_errors = dict()


def _form_error_list():
    global _errors
    classes = inspect.getmembers(sys.modules[__name__], lambda t: isinstance(t, OAuth2Error))
    already_has = set()

    for _, cls in classes:
        if cls.error is None:
            continue
        if cls.error in already_has:
            continue
        already_has.add(cls.error)
        _errors[cls.error] = cls


_form_error_list()


def raise_from_error(error: str, params: dict = None):
    kwargs = {
        'description': params.get('error_description'),
        'uri': params.get('error_uri'),
        'state': params.get('state'),
        'request': params.get('request')
    } if params is not None else {}
    cls = _errors.get(error, CustomOAuth2Error)
    if cls is CustomOAuth2Error:
        kwargs['error'] = error
    raise cls(**kwargs)

# def error_from_error(error: str, params: dict = None):
#     kwargs = {
#         'description': params.get('error_description'),
#         'uri': params.get('error_uri'),
#         'state': params.get('state'),
#         'request': params.get('request')
#     } if params is not None else {}
#     cls = _errors.get(error, CustomOAuth2Error)
#     if cls is CustomOAuth2Error:
#         kwargs['error'] = error
#     return cls(**kwargs)
