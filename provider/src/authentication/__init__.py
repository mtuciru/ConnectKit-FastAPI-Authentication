from fastapi import FastAPI

from settings import FunctionParamsObject

__all__ = ["setup_as_provider", "setup_as_resource", "control", "security"]


def setup_as_provider(app: FastAPI, config: FunctionParamsObject) -> None:
    """
    Configure app to role 'Provider'.

    Perform 'setup_as_resource'
    Enable End-User authentication & authorization. (On provider)
    Enable third-party authentication & authorization. (On third-party clients)
    Enable revoke & introspect endpoints for clients.
    Enable userinfo endpoint for provider and clients.
    Enable metadata endpoint for provider and clients.
    Enable control methods (manage users, sessions, etc.)
    """
    from .settings import settings, function_settings
    from .routes.config import init_oauth2lib_endpoints
    from .routes.oauth2 import create_oauth_router
    from .routes.frontend import create_frontend_router
    from .routes.metadata import create_metadata_router
    # First setup as resource
    setup_as_resource(app, config)
    # Init OAuth2 endpoints
    init_oauth2lib_endpoints({
        "issuer": settings.issuer,
        "authorization_endpoint": function_settings.authorization_endpoint,
        "scopes_supported": function_settings.scopes_supported,
        "service_documentation": function_settings.service_documentation,
        "ui_locales_supported": function_settings.ui_locales_supported,
        "op_policy_uri": function_settings.op_policy_uri,
        "op_tos_uri": function_settings.op_tos_uri,
        "acr_values_supported": function_settings.acr_values_supported,
        "display_values_supported": function_settings.display_values_supported,
        "claims_supported": function_settings.claims_supported,
        "claims_locales_supported": function_settings.claims_locales_supported
    }, {
        "authorization_code_enable": function_settings.authorization_code_enable,
        "authorization_implicit_enable": function_settings.authorization_implicit_enable,
        "authorization_device_enable": function_settings.authorization_device_enable,
        "client_credentials_enable": function_settings.client_credentials_enable,
        "revocation_enable": function_settings.revocation_enable,
        "introspection_enable": function_settings.introspection_enable,
        "oidc_enable": function_settings.oidc_enable,
        "device_verification_uri": function_settings.device_verification_uri,
        "device_complete_uri": function_settings.device_complete_uri,
        "use_signed_metadata": function_settings.use_signed_metadata,
        "token_endpoint_name": "",
        "jwks_endpoint_name": "",
        "authorization_endpoint_name": "authorization_frontend",
        "device_authorization_endpoint_name": "",
        "revocation_endpoint_name": "",
        "introspection_endpoint_name": "",
        "userinfo_endpoint_name": ""
    })
    # Create OAuth2 routes
    app.include_router(create_oauth_router(), prefix="/api")
    # Create OAuth2 and OpenID Connect metadata locations
    app.include_router(create_metadata_router())
    # If requested, create typical frontend locations
    if function_settings.authorization_endpoint is None:
        app.include_router(create_frontend_router(), prefix="/provider")


def setup_as_resource(app: FastAPI, config: FunctionParamsObject) -> None:
    """
    Configure app to role 'Resource'.

    Create database tables if required.
    Update openapi security scheme parameter
    Add exception handler for our oauth2 errors
    """
    from .settings import configure
    from .security.handler import ExceptionContainer, oauth2_exception_handler
    from .security.security import custom_oauth2_scheme
    from .models import Base
    from database import init_default_base
    # Update inner setting by provided config
    configure(config)
    # Initiate base tables
    init_default_base(Base.metadata)
    # configure security model
    custom_oauth2_scheme.configure_openid_connect_url()
    # register oauth2 errors handler
    app.add_exception_handler(ExceptionContainer, oauth2_exception_handler)
