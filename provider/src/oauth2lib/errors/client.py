import inspect
import sys

from .base import OAuth2Error, FatalClientError


__all__ = []

#
#
# class TokenExpiredError(OAuth2Error):
#     error = 'token_expired'
#
#
# class InsecureTransportError(OAuth2Error):
#     error = 'insecure_transport'
#     description = 'OAuth 2 MUST utilize https.'
#
#
# class MismatchingStateError(OAuth2Error):
#     error = 'mismatching_state'
#     description = 'CSRF Warning! State not equal in request and response.'
#
#
# class MissingCodeError(OAuth2Error):
#     error = 'missing_code'
#
#
# class MissingTokenError(OAuth2Error):
#     error = 'missing_token'
#
#
# class MissingTokenTypeError(OAuth2Error):
#     error = 'missing_token_type'
#
#
#
# class InvalidRequestFatalError(FatalClientError):
#     """
#     For fatal errors, the request is missing a required parameter, includes
#     an invalid parameter value, includes a parameter more than once, or is
#     otherwise malformed.
#     """
#     error = 'invalid_request'
#
#
# class InvalidRedirectURIError(InvalidRequestFatalError):
#     description = 'Invalid redirect URI.'
#
#
# class MissingRedirectURIError(InvalidRequestFatalError):
#     description = 'Missing redirect URI.'
#
#
# class MismatchingRedirectURIError(InvalidRequestFatalError):
#     description = 'Mismatching redirect URI.'
#
#
# class InvalidClientIdError(InvalidRequestFatalError):
#     description = 'Invalid client_id parameter value.'
#
#
# class MissingClientIdError(InvalidRequestFatalError):
#     description = 'Missing client_id parameter.'
#
#
# class InvalidRequestError(OAuth2Error):
#     """
#     The request is missing a required parameter, includes an invalid
#     parameter value, includes a parameter more than once, or is
#     otherwise malformed.
#     """
#     error = 'invalid_request'
#
#
# class MissingResponseTypeError(InvalidRequestError):
#     description = 'Missing response_type parameter.'
#
#
# class MissingCodeChallengeError(InvalidRequestError):
#     """
#     If the server requires Proof Key for Code Exchange (PKCE) by OAuth
#     public clients and the client does not send the "code_challenge" in
#     the request, the authorization endpoint MUST return the authorization
#     error response with the "error" value set to "invalid_request".  The
#     "error_description" or the response of "error_uri" SHOULD explain the
#     nature of error, e.g., code challenge required.
#     """
#     description = 'Code challenge required.'
#
#
# class MissingCodeVerifierError(InvalidRequestError):
#     """
#     The request to the token endpoint, when PKCE is enabled, has
#     the parameter `code_verifier` REQUIRED.
#     """
#     description = 'Code verifier required.'
#
#
# class AccessDeniedError(OAuth2Error):
#     """
#     The resource owner or authorization server denied the request.
#     """
#     error = 'access_denied'
#
#
# class UnsupportedResponseTypeError(OAuth2Error):
#     """
#     The authorization server does not support obtaining an authorization
#     code using this method.
#     """
#     error = 'unsupported_response_type'
#
#
# class UnsupportedCodeChallengeMethodError(InvalidRequestError):
#     """
#     If the server supporting PKCE does not support the requested
#     transformation, the authorization endpoint MUST return the
#     authorization error response with "error" value set to
#     "invalid_request".  The "error_description" or the response of
#     "error_uri" SHOULD explain the nature of error, e.g., transform
#     algorithm not supported.
#     """
#     description = 'Transform algorithm not supported.'
#
#
# class InvalidScopeError(OAuth2Error):
#     """
#     The requested scope is invalid, unknown, or malformed, or
#     exceeds the scope granted by the resource owner.
#
#     https://tools.ietf.org/html/rfc6749#section-5.2
#     """
#     error = 'invalid_scope'
#
#
# class ServerError(OAuth2Error):
#     """
#     The authorization server encountered an unexpected condition that
#     prevented it from fulfilling the request.  (This error code is needed
#     because a 500 Internal Server Error HTTP status code cannot be returned
#     to the client via a HTTP redirect.)
#     """
#     error = 'server_error'
#
#
# class TemporarilyUnavailableError(OAuth2Error):
#     """
#     The authorization server is currently unable to handle the request
#     due to a temporary overloading or maintenance of the server.
#     (This error code is needed because a 503 Service Unavailable HTTP
#     status code cannot be returned to the client via a HTTP redirect.)
#     """
#     error = 'temporarily_unavailable'
#
#
# class InvalidClientError(FatalClientError):
#     """
#     Client authentication failed (e.g. unknown client, no client
#     authentication included, or unsupported authentication method).
#     The authorization server MAY return an HTTP 401 (Unauthorized) status
#     code to indicate which HTTP authentication schemes are supported.
#     If the client attempted to authenticate via the "Authorization" request
#     header field, the authorization server MUST respond with an
#     HTTP 401 (Unauthorized) status code, and include the "WWW-Authenticate"
#     response header field matching the authentication scheme used by the
#     client.
#     """
#     error = 'invalid_client'
#     status_code = 401
#
#
# class InvalidGrantError(OAuth2Error):
#     """
#     The provided authorization grant (e.g. authorization code, resource
#     owner credentials) or refresh token is invalid, expired, revoked, does
#     not match the redirection URI used in the authorization request, or was
#     issued to another client.
#
#     https://tools.ietf.org/html/rfc6749#section-5.2
#     """
#     error = 'invalid_grant'
#     status_code = 400
#
#
# class UnauthorizedClientError(OAuth2Error):
#     """
#     The authenticated client is not authorized to use this authorization
#     grant type.
#     """
#     error = 'unauthorized_client'
#
#
# class UnsupportedGrantTypeError(OAuth2Error):
#     """
#     The authorization grant type is not supported by the authorization
#     server.
#     """
#     error = 'unsupported_grant_type'
#
#
# class UnsupportedTokenTypeError(OAuth2Error):
#     """
#     The authorization server does not support the hint of the
#     presented token type.  I.e. the client tried to revoke an access token
#     on a server not supporting this feature.
#     """
#     error = 'unsupported_token_type'
#
#
# class InvalidTokenError(OAuth2Error):
#     """
#     The access token provided is expired, revoked, malformed, or
#     invalid for other reasons.  The resource SHOULD respond with
#     the HTTP 401 (Unauthorized) status code.  The client MAY
#     request a new access token and retry the protected resource
#     request.
#     """
#     error = 'invalid_token'
#     status_code = 401
#     description = ("The access token provided is expired, revoked, malformed, "
#                    "or invalid for other reasons.")
#
#
# class InsufficientScopeError(OAuth2Error):
#     """
#     The request requires higher privileges than provided by the
#     access token.  The resource server SHOULD respond with the HTTP
#     403 (Forbidden) status code and MAY include the "scope"
#     attribute with the scope necessary to access the protected
#     resource.
#     """
#     error = 'insufficient_scope'
#     status_code = 403
#     description = ("The request requires higher privileges than provided by "
#                    "the access token.")
#
#
# class ConsentRequired(OAuth2Error):
#     """
#     The Authorization Server requires End-User consent.
#
#     This error MAY be returned when the prompt parameter value in the
#     Authentication Request is none, but the Authentication Request cannot be
#     completed without displaying a user interface for End-User consent.
#     """
#     error = 'consent_required'
#
#
# class LoginRequired(OAuth2Error):
#     """
#     The Authorization Server requires End-User authentication.
#
#     This error MAY be returned when the prompt parameter value in the
#     Authentication Request is none, but the Authentication Request cannot be
#     completed without displaying a user interface for End-User authentication.
#     """
#     error = 'login_required'
#
#
# class CustomOAuth2Error(OAuth2Error):
#     """
#     This error is a placeholder for all custom errors not described by the RFC.
#     Some of the popular OAuth2 providers are using custom errors.
#     """
#
#     def __init__(self, error, *args, **kwargs):
#         self.error = error
#         super().__init__(*args, **kwargs)
#
#
# def raise_from_error(error, params=None):
#     kwargs = {
#         'description': params.get('error_description'),
#         'uri': params.get('error_uri'),
#         'state': params.get('state')
#     }
#     for _, cls in inspect.getmembers(sys.modules[__name__], inspect.isclass):
#         if cls.error == error:
#             raise cls(**kwargs)
#     raise CustomOAuth2Error(error=error, **kwargs)
#
#
# _errors = dict()
#
#
# def _form_error_list():
#     global _errors
#     classes = []
#     classes.extend(inspect.getmembers(rfc6749_errors, inspect.isclass))
#     classes.extend(inspect.getmembers(rfc8628_errors, inspect.isclass))
#     classes.extend(inspect.getmembers(openid_errors, inspect.isclass))
#     already_has = set()
#
#     for _, cls in classes:
#         if cls.error is None:
#             continue
#         if cls.error in already_has:
#             continue
#         already_has.add(cls.error)
#         _errors[cls.error] = cls
#
#
# _form_error_list()
#
#
# def raise_from_error(error: str, params: dict = None):
#     kwargs = {
#         'description': params.get('error_description'),
#         'uri': params.get('error_uri'),
#         'state': params.get('state'),
#         'request': params.get('request')
#     } if params is not None else {}
#
#     cls = _errors.get(error)
#
#     if cls is None:
#         custom = FatalClientError(**kwargs)
#         custom.error = error
#         raise custom
#     raise cls(**kwargs)
