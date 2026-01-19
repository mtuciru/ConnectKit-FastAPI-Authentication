from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping, TypedDict

import json_adapter as json
from .base import BaseEndpoint, endpoint
from ..common import Request, is_secure_required
from ..tokens import claims_signing, get_actual_kid
from ..validators.locale import is_language_tag
from ..validators.uri import is_scheme, is_uri

__all__ = ["MetadataEndpoint", "MetadataFieldsObject", "well_known_oauth", "well_known_oidc"]

well_known_oauth = "/.well-known/oauth-authorization-server"
well_known_oidc = "/.well-known/openid-configuration"

_default_options = {
    "authorization_code_enable": False,
    "authorization_implicit_enable": False,
    "authorization_device_enable": False,
    "client_credentials_enable": False,
    "revocation_enable": False,
    "introspection_enable": False,
    "oidc_enable": False,
    "use_signed_metadata": False,
    "token_endpoint_name": "oauth_token",
    "jwks_endpoint_name": "oauth_jwks",
    "device_authorization_endpoint_name": "oauth_device_authorization",
    "revocation_endpoint_name": "oauth_revocation",
    "introspection_endpoint_name": "oauth_introspection",
    "userinfo_endpoint_name": "oauth_userinfo"
}


class MetadataOptions(dict):
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

    def __init__(self, params: Mapping[str, Any]):
        options = _default_options.copy()
        options.update(params)
        super().__init__(options)

    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(name)


class MetadataFieldsObject(TypedDict, total=False):
    issuer: str
    authorization_endpoint: str
    scopes_supported: list[str]
    service_documentation: str
    ui_locales_supported: list[str]
    op_policy_uri: str
    op_tos_uri: str
    acr_values_supported: list[str]
    display_values_supported: list[str]
    claims_supported: list[str]
    claims_locales_supported: list[str]


_metadata_template: dict[str, Any] = {
    # Issuer URL without query and fragment (Set by provider)
    "issuer": None,
    # Endpoint for End-User client authorization. Must be frontend page URL accessed by GET or POST method (Set by provider)
    "authorization_endpoint": None,
    # Basically /api/oauth/token endpoint (derived by first call to metadata endpoint)
    "token_endpoint": None,
    # Basically /api/oauth/jwks endpoint (derived by first call to metadata endpoint)
    "jwks_uri": None,
    # Subset of supported scope values (Set by provider, 'openid' appended if openid connect enabled)
    "scopes_supported": [],
    # All realized response types. May be disabled for client
    "response_types_supported": [],
    # All realized response modes. Must be supported by frontend part.
    "response_modes_supported": ["query", "fragment", "form_post"],
    # All realized and enabled by default grant types. May be disabled for client
    "grant_types_supported": ["password", "refresh_token"],
    # All realized auth client methods. May require special method for client
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
    # Supported PKCE methods
    "code_challenge_methods_supported": ["plain", "S256", "S512"],
    # DPoP signing algorithms supported
    "dpop_signing_alg_values_supported": ["RS256", "PS256", "ES256"],
    # 'iss' parameter returned in all answers from server
    "authorization_response_iss_parameter_supported": True
}

# Optional provider documentation fields
_optional_docs_fields = {
    "service_documentation": None,
    # Frontend locales supported
    "ui_locales_supported": None,
    "op_policy_uri": None,
    "op_tos_uri": None
}

# Fields used for device_authorization if enabled
_optional_device_authorization_fields = {
    "device_authorization_endpoint": None,
}

# Fields used for revocation if enabled
_optional_revocation_fields = {
    # Basically /api/oauth/revoke endpoint (derived by first call to metadata endpoint)
    "revocation_endpoint": None,
    "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none",
                                                   "client_credentials_grant"]
}

# Fields used for introspection if enabled
_optional_introspection_fields = {
    # Basically /api/oauth/introspect endpoint (derived by first call to metadata endpoint)
    "introspection_endpoint": None,
    "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none",
                                                      "client_credentials_grant"]
}

# Fields used for OIDC if enabled
_optional_oidc_fields = {
    # Basically /api/oauth/userinfo endpoint (derived by first call to metadata endpoint)
    "userinfo_endpoint": None,
    "scopes_supported": ["openid"],
    "acr_values_supported": None,
    "subject_types_supported": ["public", "pairwise"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "userinfo_signing_alg_values_supported": ["none", "RS256"],
    "display_values_supported": None,
    "claim_types_supported": ["normal"],
    "claims_supported": None,
    "claims_locales_supported": None,
    "claims_parameter_supported": True,
    "request_parameter_supported": False,
    "request_uri_parameter_supported": False
}

# This fields must or may set by provider. Need for filter params dict
_from_provider_fields = (
    # Issuer URL without query and fragment (Set by provider)
    "issuer",
    # Endpoint for End-User client authorization. Must be frontend page URL accessed by GET or POST method (Set by provider)
    "authorization_endpoint",
    # Subset of supported scope values (Set by provider, 'openid' appended if openid connect enabled)
    "scopes_supported",
    "service_documentation",
    # Frontend locales supported
    "ui_locales_supported",
    "op_policy_uri",
    "op_tos_uri",
    "acr_values_supported",
    "display_values_supported",
    "claims_supported",
    "claims_locales_supported"
)

_save_none_fields = (
    "token_endpoint",
    "jwks_uri",
    "device_authorization_endpoint",
    "revocation_endpoint",
    "introspection_endpoint",
    "userinfo_endpoint"
)


class MetadataEndpoint(BaseEndpoint):
    def __init__(self, fields: MetadataFieldsObject, options: dict[str, Any]):
        BaseEndpoint.__init__(self)
        self._options = MetadataOptions(options or {})
        if fields is None:
            raise ValueError("`fields` cannot be None")
        fields = deepcopy(fields)
        for key in list(fields.keys()):
            if key not in _from_provider_fields:
                fields.pop(key)
        self._oauth_metadata, self._oidc_metadata = self._build_metadata(fields)
        self._metadata_finalized = False
        self._metadata_signed_key = None

    @endpoint
    def create_oauth_metadata_response(self, request: Request):
        if "Origin" in request.headers:
            headers = {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': request.headers["Origin"],
                'Vary': "Origin"
            }
        else:
            headers = {
                'Content-Type': 'application/json'
            }
        if not self._metadata_finalized:
            self._finalize_metadata(request)
        else:
            self._check_need_resign()
        return headers, json.dumps(self._oauth_metadata), 200

    @endpoint
    def create_oidc_metadata_response(self, request: Request):
        if "Origin" in request.headers:
            headers = {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': request.headers["Origin"],
                'Vary': "Origin"
            }
        else:
            headers = {
                'Content-Type': 'application/json'
            }
        if not self._metadata_finalized:
            self._finalize_metadata(request)
        else:
            self._check_need_resign()
        if self._oidc_metadata is not None:
            return headers, json.dumps(self._oidc_metadata), 200
        return headers, json.dumps(self._oauth_metadata), 200

    def _validate_oauth_metadata(self, template: dict[str, Any]):
        # Issuer required always
        if "issuer" not in template or template["issuer"] is None:
            raise ValueError("`issuer` cannot be None")
        else:
            if is_secure_required():
                if not is_scheme(template["issuer"], "https"):
                    raise ValueError("`issuer` must be an URI with 'https' scheme")
        # If enabled authorization endpoint
        if self._options.authorization_code_enable or self._options.authorization_implicit_enable:
            if "authorization_endpoint" not in template or template["authorization_endpoint"] is None:
                # If not enabled derived method
                if ("authorization_endpoint_name" not in self._options
                        or self._options.authorization_endpoint_name is None):
                    raise ValueError("`authorization_endpoint` cannot be None")
            else:
                if is_secure_required():
                    if not is_scheme(template["authorization_endpoint"], "https"):
                        raise ValueError("`authorization_endpoint` must be an URI with 'https' scheme")
        # Optional params
        if "scopes_supported" in template:
            if not isinstance(template["scopes_supported"], list):
                raise ValueError("`scopes_supported` must be a list of strings")
            for scope in template["scopes_supported"]:
                if not isinstance(scope, str):
                    raise ValueError("`scopes_supported` must be a list of strings")
        if "service_documentation" in template:
            if not is_uri(template["service_documentation"]):
                raise ValueError("`service_documentation` must be an URI")
        if "ui_locales_supported" in template:
            if not isinstance(template["ui_locales_supported"], list):
                raise ValueError("`ui_locales_supported` must be a list")
            for ui_locale in template["ui_locales_supported"]:
                if not isinstance(ui_locale, str) or not is_language_tag(ui_locale):
                    raise ValueError("`ui_locales_supported` must be a list of string language tags")
        if "op_policy_uri" in template:
            if not is_uri(template["op_policy_uri"]):
                raise ValueError("`op_policy_uri` must be an URI")
        if "op_tos_uri" in template:
            if not is_uri(template["op_tos_uri"]):
                raise ValueError("`op_tos_uri` must be an URI")
        # Calculated enabled grants and response types
        if self._options.authorization_code_enable:
            template["grant_types_supported"].append("authorization_code")
            template["response_types_supported"].append("none")
            template["response_types_supported"].append("code")
        if self._options.authorization_implicit_enable:
            template["grant_types_supported"].append("implicit")
            template["response_types_supported"].append("token")
        if self._options.client_credentials_enable:
            template["grant_types_supported"].append("client_credentials")
        if self._options.authorization_device_enable:
            template["grant_types_supported"].append("urn:ietf:params:oauth:grant-type:device_code")

    def _validate_oidc_metadata(self, template: dict[str, Any]):
        if "scopes_supported" in template:
            if not isinstance(template["scopes_supported"], list):
                raise ValueError("`scopes_supported` must be a list of strings")
            for scope in template["scopes_supported"]:
                if not isinstance(scope, str):
                    raise ValueError("`scopes_supported` must be a list of strings")
            if "openid" not in template["scopes_supported"]:
                template["scopes_supported"].insert(0, "openid")
        if "acr_values_supported" in template:
            if not isinstance(template["acr_values_supported"], list):
                raise ValueError("`acr_values_supported` must be a list of strings")
            for acr_value in template["acr_values_supported"]:
                if not isinstance(acr_value, str):
                    raise ValueError("`acr_values_supported` must be a list of strings")
        if "display_values_supported" in template:
            if not isinstance(template["display_values_supported"], list):
                raise ValueError("`display_values_supported` must be a list of strings")
            for display in template["display_values_supported"]:
                if not isinstance(display, str):
                    raise ValueError("`display_values_supported` must be a list of strings")
        if "claims_supported" in template:
            if not isinstance(template["claims_supported"], list):
                raise ValueError("`claims_supported` must be a list of strings")
            for claim in template["claims_supported"]:
                if not isinstance(claim, str):
                    raise ValueError("`claims_supported` must be a list of strings")
        if "claims_locales_supported" in template:
            if not isinstance(template["claims_locales_supported"], list):
                raise ValueError("`claims_locales_supported` must be a list of strings")
            for claim_locale in template["claims_locales_supported"]:
                if not isinstance(claim_locale, str):
                    raise ValueError("`claims_locales_supported` must be a list of strings")
        if self._options.authorization_code_enable:
            template["response_types_supported"].append("code id_token")
            template["response_types_supported"].append("code token")
            template["response_types_supported"].append("code id_token token")
        if self._options.authorization_implicit_enable:
            template["response_types_supported"].append("id_token")
            template["response_types_supported"].append("id_token token")

    @staticmethod
    def _remove_none_fields(template: dict[str, Any]):
        for key in list(template.keys()):
            if key in _save_none_fields:
                continue
            if template[key] is None:
                template.pop(key)

    def _build_metadata(self, fields: MetadataFieldsObject):
        # OAuth metadata
        oauth_template = deepcopy(_metadata_template)
        oauth_template.update(_optional_docs_fields)
        if self._options.authorization_device_enable:
            oauth_template.update(deepcopy(_optional_device_authorization_fields))
        if self._options.revocation_enable:
            oauth_template.update(deepcopy(_optional_revocation_fields))
        if self._options.introspection_enable:
            oauth_template.update(deepcopy(_optional_introspection_fields))
        for key, field_value in fields.items():
            if key in oauth_template:
                oauth_template[key] = field_value
        self._validate_oauth_metadata(oauth_template)
        self._remove_none_fields(oauth_template)
        # OIDC Metadata (extended version of OAuth metadata)
        oidc_template = deepcopy(oauth_template) if self._options.oidc_enable else None
        if oidc_template is not None:
            fields = deepcopy(fields)
            oidc_template.update(deepcopy(_optional_oidc_fields))
            for key, field_value in fields.items():
                if key in oauth_template:
                    oidc_template[key] = field_value
            self._validate_oidc_metadata(oidc_template)
            self._remove_none_fields(oidc_template)
        return oauth_template, oidc_template

    def _finalize_metadata(self, request: Request):
        # We extract actual uri for required methods
        # Required:
        #   - token_endpoint: token_endpoint_name
        #   - jwks_uri: jwks_endpoint_name
        # Optional:
        #   - device_authorization_endpoint: device_authorization_endpoint_name
        #   - revocation_endpoint: revocation_endpoint_name
        #   - introspection_endpoint: introspection_endpoint_name
        #   - userinfo_endpoint: userinfo_endpoint_name
        rr = request.request
        uris = {
            "token_endpoint": str(rr.url_for(self._options.token_endpoint_name)),
            "jwks_uri": str(rr.url_for(self._options.jwks_endpoint_name)),
            "userinfo_endpoint": str(rr.url_for(self._options.userinfo_endpoint_name))
        }
        if ("authorization_endpoint" not in self._oauth_metadata
                or self._oauth_metadata["authorization_endpoint"] is None):
            uris["authorization_endpoint"] = str(rr.url_for(self._options.authorization_endpoint_name))
        if self._options.authorization_device_enable:
            uris["device_authorization_endpoint"] = str(rr.url_for(self._options.device_authorization_endpoint_name))
        if self._options.revocation_enable:
            uris["revocation_endpoint"] = str(rr.url_for(self._options.revocation_endpoint_name))
        if self._options.introspection_enable:
            uris["introspection_endpoint"] = str(rr.url_for(self._options.introspection_endpoint_name))
        self._oauth_metadata.update(uris)
        if self._options.oidc_enable:
            self._oidc_metadata.update(uris)
        self._create_signed_metadata()
        self._metadata_finalized = True

    def _check_need_resign(self):
        if not self._options.use_signed_metadata:
            return
        if self._metadata_signed_key == get_actual_kid():
            return
        self._oauth_metadata.pop("signed_metadata")
        if self._options.oidc_enable:
            self._oidc_metadata.pop("signed_metadata")
        self._create_signed_metadata()

    def _create_signed_metadata(self):
        if not self._options.use_signed_metadata:
            return
        self._metadata_signed_key = get_actual_kid()
        claims = deepcopy(self._oauth_metadata)
        claims["iss"] = claims["issuer"]
        claims["iat"] = datetime.now(tz=timezone.utc)
        signed_metadata = claims_signing(claims)
        self._oauth_metadata["signed_metadata"] = signed_metadata
        if self._options.oidc_enable:
            claims = deepcopy(self._oidc_metadata)
            claims["iss"] = claims["issuer"]
            claims["iat"] = datetime.now(tz=timezone.utc)
            signed_metadata = claims_signing(claims)
            self._oidc_metadata["signed_metadata"] = signed_metadata
