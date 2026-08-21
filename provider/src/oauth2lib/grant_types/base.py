import base64
import hashlib
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Coroutine, Any, Sequence

from json_adapter import dumps
from .. import errors
from ..common import add_params_to_uri, Request, safe_string_equals, aw
from ..tokens import create_bearer_token, claims_signing
from ..validators import RequestValidator
from ..validators.claims import (claims_validate, get_claims_sub_value,
                                 is_claims_acr_essential, is_claims_auth_time_essential,
                                 is_email, normalize_email, is_phone_number, normalize_phone_number, is_login,
                                 set_claims_auth_time_essential)
from ..validators.locale import parse_language_tags
from ..validators.uri import is_absolute_uri

__all__ = ["GrantTypeBase"]


class GrantTypeBase:
    request_validator: RequestValidator = None
    default_response_mode: str = 'fragment'
    refresh_token: bool = True
    response_types: list[str] = []
    grant_type: str = ""

    def __init__(self, request_validator: RequestValidator = None):
        self.request_validator = request_validator or RequestValidator()
        # Transforms class variables into instance variables:
        self.response_types = self.response_types
        self.grant_type = self.grant_type
        self.refresh_token = self.refresh_token
        self.default_response_mode = self.default_response_mode
        self._code_modifiers: list[Callable[[dict[str, Any], Request], None | Coroutine[Any, Any, None]]] = []
        self._token_modifiers: list[Callable[[dict[str, Any], Request], None | Coroutine[Any, Any, None]]] = []

    def register_code_modifier(self, modifier: Callable[[dict[str, Any], Request], None | Coroutine[Any, Any, None]]):
        self._code_modifiers.append(modifier)

    def register_token_modifier(self, modifier: Callable[[dict[str, Any], Request], None | Coroutine[Any, Any, None]]):
        self._token_modifiers.append(modifier)

    async def _run_code_modifiers(self, code: dict[str, Any], request: Request):
        for modifier in self._code_modifiers:
            await aw(modifier(code, request))

    async def _run_token_modifiers(self, token: dict[str, Any], request: Request):
        for modifier in self._token_modifiers:
            await aw(modifier(token, request))

    async def create_authorization_response(self, request: Request) -> tuple[dict[str, str], str, int]:
        raise NotImplementedError('Subclasses must implement this method.')

    async def validate_authorization_request(self, request: Request) -> dict[str, Any]:
        raise NotImplementedError('Subclasses must implement this method.')

    async def create_token_response(self, request: Request) -> tuple[dict[str, str], str, int]:
        raise NotImplementedError('Subclasses must implement this method.')

    async def validate_token_request(self, request: Request):
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    def _validate_duplicate_params(request: Request, params: Sequence[str], critical: bool = False):
        for param in params:
            if param in request.duplicate_params:
                if critical:
                    raise errors.InvalidRequestFatalError(description=f'Duplicate "{param}" parameter.',
                                                          request=request)
                else:
                    raise errors.InvalidRequestError(description=f'Duplicate "{param}" parameter.',
                                                     request=request)

    async def _validate_response_type(self, request: Request):
        if request.response_type is None:
            raise errors.MissingResponseTypeError(request=request)
        if request.response_type not in self.response_types:
            raise errors.UnsupportedResponseTypeError(request=request)

    async def _is_allowed_response_type(self, request: Request):
        if not await aw(self.request_validator.response_type_is_allowed(request)):
            raise errors.UnauthorizedClientError(request=request)

    async def _validate_grant_type(self, request: Request):
        if request.grant_type is None:
            raise errors.MissingGrantTypeError(request=request)
        if request.grant_type != self.grant_type:
            raise errors.UnsupportedGrantTypeError(request=request)

    async def _is_allowed_grant_type(self, request: Request):
        if not await aw(self.request_validator.grant_type_is_allowed(request)):
            raise errors.UnauthorizedClientError(request=request)

    async def _validate_scopes(self, request: Request):
        if request.scopes is None:
            request.scopes = await aw(self.request_validator.get_default_scopes(request))
            request._is_scope_identical = True
            if "openid" in request.scopes:
                # This client registered as OpenID Connect
                # By specification, scope parameter required
                raise errors.InvalidRequestError("Missing scope value")
        else:
            old_scopes = set(request.scopes)
            scopes = await aw(self.request_validator.transform_scopes(request))
            if scopes is None:
                raise errors.InvalidScopeError(request=request)
            request._is_scope_identical = old_scopes == set(scopes)
            if not request.is_scope_identical:
                request.scopes = scopes

    def _prepare_redirect_response(self, request: Request, result_data: dict):
        headers = self._get_default_headers()
        # CORS headers not required, returned to Provider frontend
        request.response_mode = request.response_mode or self.default_response_mode

        if request.response_mode not in ('query', 'fragment', 'form_post'):
            request.response_mode = self.default_response_mode

        result_items = result_data.items()

        if request.response_mode == 'query':
            return headers, dumps({
                "error": None,
                "redirect_uri": add_params_to_uri(request.redirect_uri, result_items, fragment=False)
            }), 200

        if request.response_mode == 'fragment':
            return headers, dumps({
                "error": None,
                "redirect_uri": add_params_to_uri(request.redirect_uri, result_items, fragment=True)
            }), 200

        if request.response_mode == 'form_post':
            input_template = '<input type="hidden" name="{}" value="{}"/>'
            inputs = []
            for key, value in result_items:
                inputs.append(input_template.format(str(key), str(value)))
            inputs = "".join(inputs)
            return headers, dumps({
                "error": None,
                "rewrite_html": '<html><head><title>Authorization result form</title></head>'
                                '<body onload="javascript:document.forms[0].submit()">'
                                f'<form method="POST" action="{request.redirect_uri}">{inputs}</form>'
                                '</body></html>'
            }), 200

        raise NotImplementedError('Subclasses must set a valid default_response_mode')

    async def _prepare_direct_response(self, request: Request, result_data: dict,
                                       opt_headers: dict[str, str] = None, status_code: int = 200):
        headers = self._get_default_headers()
        headers.update(await self._create_cors_headers(request))
        if opt_headers is not None:
            headers.update(opt_headers)
        return headers, dumps(result_data), status_code

    async def _prepare_error_response(self, request: Request, error: errors.OAuth2Error, redirect: bool):
        if redirect:
            return self._prepare_redirect_response(request, error.asdict)
        headers = error.headers(["Basic"], request.used_auth_schemes)
        return self._prepare_direct_response(request, error.asdict, headers, error.status_code)

    def _prepare_validation_response(self, info: dict) -> tuple[dict[str, str], str, int]:
        info = info.copy()
        info["error"] = None
        return self._get_default_headers(), dumps(info), 200

    @staticmethod
    def _get_default_headers():
        """Create default headers for grant responses."""
        return {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }

    async def _cors_preflight(self, request: Request):
        """
        If CORS is allowed return
        else error risen.

        Preflight check required for suppress token creation if not allowed client.
        Used only by browser-based clients (only browsers add Origin header)
        """
        if 'origin' not in request.headers:
            # CORS not required
            return
        origin = request.headers['origin']
        if not origin.startswith('https://'):
            raise errors.InvalidRequestError(description="CORS violation detected.", request=request)
        client_origin = await aw(self.request_validator.get_client_origin(request))
        if isinstance(client_origin, str) and safe_string_equals(origin, client_origin):
            # Origin checked and allowed
            return
        elif isinstance(client_origin, bool) and client_origin:
            # Origin not checked and all allowed
            return
        else:
            raise errors.InvalidRequestError(description="CORS violation detected.", request=request)

    async def _create_cors_headers(self, request: Request):
        """
        If CORS is allowed, create the appropriate headers.

        This method allow CORS access without preflight request.

        But if browser-based client do direct request with Authorization header, browser send OPTIONS request.
        """
        if 'origin' not in request.headers:
            # CORS not required
            return {}
        origin = request.headers['origin']
        if not origin.startswith('https://'):
            # Insecure CORS requests not allowed
            return {}
        client_origin = await aw(self.request_validator.get_client_origin(request))
        if isinstance(client_origin, str) and safe_string_equals(origin, client_origin):
            # Origin checked and allowed
            return {"Access-Control-Allow-Origin": origin,
                    "Access-Control-Expose-Headers": "DPoP-Nonce",
                    "Vary": "Origin"}
        elif isinstance(client_origin, bool) and client_origin:
            # Origin not checked and all allowed
            return {"Access-Control-Allow-Origin": "*",
                    "Access-Control-Expose-Headers": "DPoP-Nonce",
                    "Vary": "Origin"}
        else:
            # Origin not checked and not allowed
            return {}

    async def _validate_redirects(self, request: Request):
        if request.redirect_uri is not None:
            request._is_default_redirect_uri = False
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(request=request)
            if not await self.request_validator.is_valid_redirect_uri(request):
                raise errors.MismatchingRedirectURIError(request=request)
        else:
            # For OIDC redirect_uri always must be presented
            if request.scopes is not None and "openid" in request.scopes:
                raise errors.MissingRedirectURIError(request=request)
            request.redirect_uri = await aw(self.request_validator.get_default_redirect_uri(request))
            request._is_default_redirect_uri = True
            if request.redirect_uri is None:
                raise errors.MissingRedirectURIError(request=request)
            if not is_absolute_uri(request.redirect_uri):
                raise errors.InvalidRedirectURIError(request=request)

    @staticmethod
    def half_hash(value, hashfunc=hashlib.sha256):
        """
        Its value is the base64url encoding of the left-most half of the
        hash of the octets of the ASCII representation of the access_token
        value, where the hash algorithm used is the hash algorithm used in
        the alg Header Parameter of the ID Token's JOSE Header.

        For instance, if the alg is RS256, hash the access_token value
        with SHA-256, then take the left-most 128 bits and
        base64url-encode them.
        For instance, if the alg is HS512, hash the code value with
        SHA-512, then take the left-most 256 bits and base64url-encode
        them. The c_hash value is a case-sensitive string.

        Example of hash from OIDC specification (bound to a JWS using RS256):

        code:
        Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk

        c_hash:
        LDktKdoQak3Pk0cnXxCltA
        """
        digest = hashfunc(value.encode("ASCII")).digest()
        left_most = len(digest) // 2
        return base64.urlsafe_b64encode(digest[:left_most]).decode().rstrip("=")

    async def add_token(self, token: dict, request: Request):
        """
        This method modifies the token dict by added access_token without refresh_token
        if Implicit or Hybrid flow processed.
        By others, if "token" present in request.response_type
        """
        if request.response_type is None or "token" not in request.response_type_set:
            return
        token.update(await create_bearer_token(self.request_validator, request, refresh_token=False))

    async def add_id_token(self, token: dict, request: Request):
        """
        Create id_token and add it to token value.
        Fields:
            - iss
                REQUIRED. URL without query and fragment.
            - sub (must be set by request_validator)
                REQUIRED. Subject Identifier.
                A locally unique and never reassigned identifier within the Issuer for the End-User,
                which is intended to be consumed by the Client, it MUST NOT exceed 255 ASCII [RFC20] characters in length.
                The sub value is a case-sensitive string.
            - aud
                REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id
            - exp (must be set by request_validator)
                REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted by the RP when performing authentication with the OP.
                The processing of this parameter requires that the current date/time MUST be before the expiration date/time listed in the value.
                Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.
                Its value is a JSON [RFC8259] number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
                See RFC 3339 [RFC3339] for details regarding date/times in general and UTC in particular.
                NOTE: The ID Token expiration time is unrelated the lifetime of the authenticated session between the RP and the OP.
            - iat
                REQUIRED. Time at which the JWT was issued.
                Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
            - auth_time (must be set by request_validator, if required)
                Time when the End-User authentication occurred.
                Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
                When a max_age request is made or when auth_time is requested as an Essential Claim, then this Claim is REQUIRED;
                otherwise, its inclusion is OPTIONAL.
                (The auth_time Claim semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
            - nonce
                String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
                The value is passed through unmodified from the Authentication Request to the ID Token.
                If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce parameter
                sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include
                a nonce Claim in the ID Token with the Claim Value being the nonce value sent in the Authentication Request.
                Authorization Servers SHOULD perform no other processing on nonce values used. The nonce value is a case-sensitive string.
            - acr
                OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context Class Reference value
                that identifies the Authentication Context Class that the authentication performed satisfied.
                The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1.
                For historic reasons, the value "0" is used to indicate that there is no confidence that the same person is actually there.
                Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value.
                (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.)
                An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value;
                registered names MUST NOT be used with a different meaning than that which is registered.
                Parties using this claim will need to agree upon the meanings of the values used, which may be context specific.
                The acr value is a case-sensitive string.
            - amr
                OPTIONAL. Authentication Methods References.
                JSON array of strings that are identifiers for authentication methods used in the authentication.
                For instance, values might indicate that both password and OTP authentication methods were used.
                The amr value is an array of case-sensitive strings. Values used in the amr Claim SHOULD be from
                those registered in the IANA Authentication Method Reference Values registry [IANA.AMR] established by [RFC8176];
                parties using this claim will need to agree upon the meanings of any unregistered values used, which may be context specific.
            - azp
                OPTIONAL. Authorized party - the party to which the ID Token was issued.
                If present, it MUST contain the OAuth 2.0 Client ID of this party.
                The azp value is a case-sensitive string containing a StringOrURI value.
                Note that in practice, the azp Claim only occurs when extensions beyond the scope of this specification are used;
                therefore, implementations not using such extensions are encouraged to not use azp and to ignore it when it does occur.

        Setup fields by this method:
            - iss
            - aud
            - iat
            - nonce
            - at_hash
            - c_hash
        """
        # Check it is openid connect flow (openid scope must be presented, as tell specification)
        if request.scopes is None or 'openid' not in request.scopes:
            return

        # Add id_token only if response type required it. If it not token request.
        if request.response_type is not None and 'id_token' not in request.response_type_set:
            return

        id_token = {
            'iss': Request.issuer,
            'aud': request.client_id,
            'iat': datetime.now(tz=timezone.utc)
        }

        # if nonce presented in request, we must include its value
        if request.nonce is not None:
            id_token["nonce"] = request.nonce
        elif request.code is not None:
            # authorization code flow and code exists, extract saved nonce
            request.nonce = await aw(self.request_validator.get_authorization_code_nonce(request))
            id_token["nonce"] = request.nonce
        if "access_token" in token:
            id_token["at_hash"] = self.half_hash(token["access_token"])
        if "code" in token:
            id_token["c_hash"] = self.half_hash(token["code"])

        # Fill other id_token values
        acr_required = is_claims_acr_essential(request)
        auth_time_required = is_claims_auth_time_essential(request)
        await aw(self.request_validator.fill_id_token(id_token, acr_required, auth_time_required, request))
        # OIDC specification tell ruin request with error if acr required, but not present in id_token
        if acr_required:
            if "acr" not in id_token:
                raise errors.ServerError("acr claim required, but can't be provided")
        # OIDC specification tell ruin request with error if auth_time required, but not present in id_token
        if auth_time_required:
            if "auth_time" not in id_token:
                raise errors.ServerError("auth_time claim required, but can't be provided")
        # Sign id_token by specified keys
        token['id_token'] = claims_signing(id_token)

    async def oidc_authorization_validator(self, request: Request, return_result: bool = True) -> dict[str, Any] | None:
        """
        Generic pre validator for OIDC /authorization endpoint flow.
        This method normalize and validate parameters BEFORE all user interactions:
        When user not login, not consent, not select account, etc.

        "nonce", validation in part scenarios
        "display", validation not required, frontend-dependent parameter
        "prompt", validate 'none' value, other values frontend-dependent
        "max_age", validate, must be integer
        "ui_locales", validate by locale_validate
        "id_token_hint", validate not required
        "login_hint", validate not required, frontend-dependent
        "acr_values", validate not required, provider-dependent
        "claims_locales", validate by locale_validate
        "claims", validate by claims_validate

        """
        if request.scopes is None or 'openid' not in request.scopes:
            # It's classic OAuth 2.0
            # Validate only some OAuth 2.0 extensions (not OIDC)
            # https://datatracker.ietf.org/doc/html/rfc9470
            self._validate_duplicate_params(request, ("max_age", "acr_values"))
            if request.max_age is not None and not isinstance(request.max_age, int):
                try:
                    request.max_age = int(request.max_age)
                except Exception:
                    msg = "Parameter 'max_age' must be an integer."
                    raise errors.InvalidRequestError(request=request, description=msg)
            if request.acr_values is not None and isinstance(request.acr_values, str):
                request.acr_values = request.acr_values.strip().split()
            if await aw(self.request_validator.is_user_login_required(request)):
                return {
                    "prompt": ["login"]
                }
            return {
                "prompt": []
            }

        # -*- Validate parameters -*-
        self._validate_duplicate_params(request, (
            "nonce", "display", "prompt", "max_age", "ui_locales", "id_token_hint",
            "login_hint", "acr_values", "claims_locales", "claims"
        ))

        if 'id_token' in request.response_type_set and request.nonce is None:
            raise errors.InvalidRequestError(
                request=request,
                description='Request is missing mandatory nonce parameter.'
            )

        prompt = request.prompt if request.prompt is not None else set()
        if isinstance(prompt, str):
            prompt = set(map(lambda x: x.strip(), prompt.strip().split()))
            request.prompt = list(prompt)

        if request.acr_values is not None and isinstance(request.acr_values, str):
            request.acr_values = request.acr_values.strip().split()

        if request.max_age is not None and not isinstance(request.max_age, int):
            try:
                request.max_age = int(request.max_age)
            except Exception:
                msg = "Parameter 'max_age' must be an integer."
                raise errors.InvalidRequestError(request=request, description=msg)

        if request.max_age == 0:
            if 'none' in prompt:
                raise errors.InteractionRequired(request=request)
            prompt.add("login")

        if 'none' in prompt:
            if len(prompt) > 1:
                msg = "Prompt none is mutually exclusive with other values."
                raise errors.InvalidRequestError(request=request, description=msg)
            # 'none' value disable all user interaction, so, if it required, error will be raised.
            # Also check 'max_age'
            if await aw(self.request_validator.is_user_login_required(request)):
                raise errors.InteractionRequired(request=request)
            if await aw(self.request_validator.is_user_consent_required(request)):
                raise errors.InteractionRequired(request=request)

        if request.ui_locales is not None and not isinstance(request.ui_locales, list):
            request.ui_locales = parse_language_tags(request.ui_locales)

        if request.claims_locales is not None and not isinstance(request.claims_locales, list):
            request.claims_locales = parse_language_tags(request.claims_locales)

        # Guessing login_hint and normalize them
        # This hint can use frontend for insert in auth form if user not login
        # Otherwise it's value may be ignored
        if request.login_hint is not None:
            if is_email(request.login_hint):
                request.login_hint = normalize_email(request.login_hint)
            elif is_phone_number(request.login_hint):
                request.login_hint = normalize_phone_number(request.login_hint)
            elif not is_login(request.login_hint):
                # Additional constrain violation, delete hint
                request.login_hint = None

        claims_validate(request)
        if request.max_age is not None:
            set_claims_auth_time_essential(request)

        # Early EndUser matching. Require "select_account" on frontend if mismatch
        request.store["user_mismatch"] = False
        sub = get_claims_sub_value(request)
        if request.id_token_hint is not None or sub is not None:
            if not await aw(self.request_validator.is_user_match(sub, request)):
                if 'none' in prompt:
                    raise errors.InteractionRequired(request=request)
                prompt.add("select_account")
                request.store["user_mismatch"] = True
        if 'none' not in prompt and request.max_age > 0:
            if await aw(self.request_validator.is_user_login_required(request)):
                prompt.add("login")

        if return_result:
            request_info = {
                'oidc': True,
                # How frontend display user invocation
                'display': request.display.strip(),
                # Required constrains
                'prompt': list(prompt),
                # Preferred languages for frontend
                'ui_locales': request.ui_locales,
                # login_hint set by 'is_user_match' or from request
                'login_hint': request.login_hint,
            }
            return request_info
        return None

    async def oidc_authorization_match_user(self, request: Request):
        # Check explicit user deny for authentication request
        if await aw(self.request_validator.is_user_access_denied(request)):
            raise errors.AccessDeniedError(request=request)
        if request.scopes is None or 'openid' not in request.scopes:
            # https://datatracker.ietf.org/doc/html/rfc9470
            if request.max_age is not None or request.acr_values is not None:
                if await aw(self.request_validator.is_user_login_required(request)):
                    raise errors.LoginRequired(request=request)
            return
        if 'none' in request.prompt:
            # Checks below already done if prompt is 'none' (Early checks mode)
            return
        # If client expect another login user we must return error
        if request.store.get("user_mismatch", False):
            raise errors.LoginRequired(description="User session mismatch")
        if await aw(self.request_validator.is_user_login_required(request)):
            raise errors.LoginRequired(request=request)
        if await aw(self.request_validator.is_user_consent_required(request)):
            if "consent" in request.prompt:
                raise errors.ConsentRequired(request=request)
            else:
                raise errors.AccountSelectionRequired(request=request)
