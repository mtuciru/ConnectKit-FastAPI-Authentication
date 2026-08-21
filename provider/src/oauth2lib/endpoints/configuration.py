from base64 import urlsafe_b64encode
from typing import Any, Mapping, TypedDict, Callable, Coroutine

from .authorization import AuthorizationEndpoint
from .device_authorization import DeviceAuthorizationEndpoint
from .device_verification import DeviceVerificationEndpoint
from .introspection import IntrospectEndpoint
from .metadata import MetadataEndpoint, MetadataFieldsObject
from .revocation import RevocationEndpoint
from .token import TokenEndpoint
from .userinfo import UserInfoEndpoint
from ..common import Request
from ..grant_types import *
from ..validators import RequestValidator

__all__ = ["configure_endpoints", "ConfigureOptionsObject", "MetadataFieldsObject", "EndpointsObject"]

_default_options: dict[str, Any] = {
    "authorization_code_enable": False,
    "authorization_implicit_enable": False,
    "authorization_device_enable": False,
    "client_credentials_enable": False,
    "revocation_enable": False,
    "introspection_enable": False,
    "oidc_enable": False,
    "device_complete_uri": None,
}


class ConfigureOptionsObject(TypedDict, total=False):
    """
    Configure options for enabling library components

    These components enabled always and can't be disabled:
        - /oauth/token endpoint - Used for user authentification from Provider frontend.
        - 'password' grant type - Used for user authentification from Provider frontend.
        - /oauth/userinfo endpoint - Used for user authentification from Provider frontend.
    These components disabled by default and can be enabled by developers:
        - 'authorization_code' grant type - Enable grant and allow response types: 'none', 'code'
            key: authorization_code_enable
            requirements: Specify frontend 'authorize' endpoint (this endpoint used by clients to redirect users to it)
        - 'implicit' grant type - Enable grant and allow response types: 'token'
            key: authorization_implicit_enable
            requirements: Specify frontend 'authorize' endpoint (this endpoint used by clients to redirect users to it)
        - 'device_code' grant type - Enable grant and device authorization endpoint
            key: authorization_device_enable
            requirements: Provide 'device_verification_uri' function
        - revoke endpoint - Enable revoke endpoint for clients
            key: revocation_enable
        - introspect endpoint - Enable introspect endpoint for clients
            key: introspection_enable
        - OpenID Connection Extension - Enable OpenID Connection Extension for clients.
            Add response types:
                - 'id_token' for implicit grant type (if enabled)
                - 'id_token token' for implicit grant type (if enabled)
                - 'code id_token' for authorization_code, implicit grant type (if enabled)
                - 'code token' for authorization_code, implicit grant type (if enabled)
                - 'code id_token token' for authorization_code, implicit grant type (if enabled)
            key: oidc_enable
            requirements: Specify rsa key for signing id_token
        - Signed metadata - Enable signed_metadata field (for signing required rsa key (the same as for id_token))

    """
    # Enable authorization_code grant and require authorization_endpoint metafield
    authorization_code_enable: bool
    # Enable implicit grant and require authorization_endpoint metafield
    authorization_implicit_enable: bool
    # Enable device_code grant and device authorization endpoint. Required device_verification_uri function
    authorization_device_enable: bool
    # Enable client_credentials grant
    client_credentials_enable: bool
    # Enable revocation endpoint
    revocation_enable: bool
    # Enable introspection endpoint
    introspection_enable: bool
    # Enable OpenID Connection Extension
    oidc_enable: bool
    # Device verification URI function
    device_verification_uri: Callable[[Request], str | Coroutine[Any, Any, str]]
    # Device complete verification URI function
    device_complete_uri: Callable[[Request, str], str | Coroutine[Any, Any, str]]
    # Enable optional signed metadata
    use_signed_metadata: bool
    # Endpoints names from authenticate part of this library. Used for derive actual URIs after app creation finished.
    token_endpoint_name: str
    jwks_endpoint_name: str
    authorization_endpoint_name: str
    device_authorization_endpoint_name: str
    revocation_endpoint_name: str
    introspection_endpoint_name: str
    userinfo_endpoint_name: str


class ConfigureOptions(dict):
    # Enable authorization_code grant and require authorization_endpoint metafield
    authorization_code_enable: bool
    # Enable implicit grant and require authorization_endpoint metafield
    authorization_implicit_enable: bool
    # Enable device_code grant and device authorization endpoint. Required device_verification_uri function
    authorization_device_enable: bool
    # Enable client_credentials grant
    client_credentials_enable: bool
    # Enable revocation endpoint
    revocation_enable: bool
    # Enable introspection endpoint
    introspection_enable: bool
    # Enable OpenID Connection Extension
    oidc_enable: bool
    # Device verification URI function
    device_verification_uri: Callable[[Request], str | Coroutine[Any, Any, str]]
    # Device complete verification URI function
    device_complete_uri: Callable[[Request, str], str | Coroutine[Any, Any, str]]

    def __init__(self, params: Mapping[str, Any]):
        options = _default_options.copy()
        options.update(params)
        super().__init__(options)

    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(name)


class EndpointsObject(TypedDict, total=False):
    authorization: AuthorizationEndpoint
    token: TokenEndpoint
    device_authorization: DeviceAuthorizationEndpoint
    device_verification: DeviceVerificationEndpoint
    revocation: RevocationEndpoint
    introspection: IntrospectEndpoint
    userinfo: UserInfoEndpoint
    metadata: MetadataEndpoint


def configure_endpoints(request_validator: RequestValidator,
                        metadata_fields: MetadataFieldsObject,
                        options: ConfigureOptionsObject) -> EndpointsObject:
    options = ConfigureOptions(options or {})
    if metadata_fields is None:
        metadata_fields = {}
    endpoints: EndpointsObject = {}
    g_authorization_code = None
    g_hybrid = None
    g_implicit = None
    g_client_credentials = None
    g_device_code = None
    # Init cookie_name for refresh_token
    Request.issuer = metadata_fields.get("issuer", "")
    # Complete authorization endpoint with hostname
    auth_path: str = metadata_fields.get("authorization_endpoint")
    if auth_path is not None:
        iss = Request.issuer
        if not iss.endswith("/"):
            iss += "/"
        if auth_path.startswith("/"):
            auth_path = auth_path.lstrip("/")
        auth_path = iss + auth_path
        metadata_fields["authorization_endpoint"] = auth_path
    Request.cookie_name = "__" + urlsafe_b64encode(Request.issuer.encode("utf-8")).decode("utf-8").strip("=")
    # MetadataEndpoint enabled always
    # Create metadata early then all because it's validate metadata_fields
    endpoints["metadata"] = MetadataEndpoint(request_validator, metadata_fields, options)
    # Create enabled grants
    if options.authorization_code_enable:
        g_authorization_code = AuthorizationCodeGrant(request_validator)
        if options.oidc_enable:
            g_hybrid = HybridGrant(request_validator)
    if options.authorization_implicit_enable:
        g_implicit = ImplicitGrant(request_validator)
    if options.client_credentials_enable:
        g_client_credentials = ClientCredentialsGrant(request_validator)
    # Always enabled
    password_credentials = ResourceOwnerPasswordCredentialsGrant(request_validator)
    if options.authorization_device_enable:
        g_device_code = DeviceCodeGrant(
            request_validator,
            options.device_verification_uri,
            options.device_complete_uri
        )
    # Always enabled
    g_refresh_token = RefreshTokenGrant(request_validator)
    # Endpoints creation
    # AuthorizationEndpoint
    response_types: dict[str, Any] = {}
    if options.authorization_code_enable:
        response_types["code"] = g_authorization_code
        response_types["none"] = g_authorization_code
        if options.oidc_enable:
            response_types['code id_token'] = g_hybrid
            response_types['code token'] = g_hybrid
            response_types['code id_token token'] = g_hybrid
    if options.authorization_implicit_enable:
        response_types['token'] = g_implicit
        if options.oidc_enable:
            response_types['id_token'] = g_implicit
            response_types['id_token token'] = g_implicit
    if len(response_types) > 0:
        endpoints["authorization"] = AuthorizationEndpoint(
            request_validator,
            default_response_type="none",
            response_types=response_types
        )
    # DeviceAuthorizationEndpoint
    if options.authorization_device_enable:
        endpoints["device_authorization"] = DeviceAuthorizationEndpoint(request_validator,
                                                                        device_code_grant=g_device_code)
        endpoints["device_verification"] = DeviceVerificationEndpoint(request_validator)
    # TokenEndpoint
    grant_types: dict[str, Any] = {
        "password": password_credentials,
        "refresh_token": g_refresh_token
    }
    if options.authorization_code_enable:
        grant_types["authorization_code"] = g_authorization_code
    if options.client_credentials_enable:
        grant_types["client_credentials"] = g_client_credentials
    if options.authorization_device_enable:
        grant_types["urn:ietf:params:oauth:grant-type:device_code"] = g_device_code
    endpoints["token"] = TokenEndpoint(
        request_validator,
        default_grant_type="authorization_code" if "authorization_code" in grant_types else "password",
        grant_types=grant_types
    )
    # RevocationEndpoint
    if options.revocation_enable:
        endpoints["revocation"] = RevocationEndpoint(request_validator)
    # IntrospectEndpoint
    if options.introspection_enable:
        endpoints["introspection"] = IntrospectEndpoint(request_validator)
    # UserInfoEndpoint enabled always
    endpoints["userinfo"] = UserInfoEndpoint(request_validator)
    return endpoints
