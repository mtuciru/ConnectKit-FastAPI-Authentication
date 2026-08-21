"""
Validation for claim request parameter as described in specification

And some help function for specific claims:
sub - user identifier
acr - Authentication Context Class Reference
auth_time - Time when the End-User authentication occurred.

sub.value in id_token request must be used as id_token_hint, and only one of two must be specified.
sub.values is invalid variant.
if acr is essential, but not presented in id_token claims, error must be raised.
if acr is essential and acr_values presents in request parameters, error will be raised (because arc_values is voluntaries).
if auth_time is essential or max_age presents in request parameters, but not presented in id_token claims, error must be raised.

"""
import re
from typing import Any
from ..common import Request
from .. import errors
from .uri import URI_compiled
from .locale import is_language_tag
import json_adapter as json

__all__ = ["claims_validate", "get_userinfo_claim", "get_id_token_claim", "set_claims_auth_time_essential",
           "get_claims_sub_value", "get_claims_acr_values", "is_claims_acr_essential", "is_claims_auth_time_essential",
           "is_email", "normalize_email", "is_phone_number", "normalize_phone_number", "is_login"]

# time-zone-initial = ALPHA / "." / "_"
_time_zone_initial = rf"[a-zA-Z._]"

# time-zone-char    = time-zone-initial / DIGIT / "-" / "+"
_time_zone_char = rf"(?: {_time_zone_initial} | [0-9] | - | \+ )"

# time-zone-part    = time-zone-initial *13(time-zone-char)
_time_zone_part = rf"(?: {_time_zone_initial} {_time_zone_char}{{0,13}} )"

# time-zone-name    = time-zone-part *("/" time-zone-part)
_time_zone_name = rf"(?: {_time_zone_part} (?: / {_time_zone_part} )* )"

# time-hour       = 2DIGIT  ; 00-23
_time_hour = r"(?: [0-1] [0-9] | 2 [0-3] )"

# time-minute     = 2DIGIT  ; 00-59
_time_minute = r"(?: [0-5] [0-9] )"

# time-numoffset  = ("+" / "-") time-hour ":" time-minute
_time_numoffset = rf"(?: (?: \+ | - ) {_time_hour} : {_time_minute} )"

# time-zone = time-zone-name / time-numoffset
_time_zone = rf"(?: {_time_zone_name} | {_time_numoffset} )"
_timezone_pattern = re.compile(_time_zone, re.VERBOSE)

# birthdate = 4DIGIT "-" 2DIGIT "-" 2DIGIT | 4DIGIT
_birthdate = r"(?: [0-9]{4} (?: - (?: 0 [1-9] | 1 [0-2] ) - (?: 0 [1-9] | [1-2] [0-9] | 3 [0-1] ) )? )"
_birthdate_pattern = re.compile(_birthdate, re.VERBOSE)

# formatted
#   Full mailing address, formatted for display or use on a mailing label.
#   This field MAY contain multiple lines, separated by newlines.
#   Newlines can be represented either as a carriage return/line feed pair ("\r\n")
#   or as a single line feed character ("\n").
# street_address
#   Full street address component, which MAY include house number, street name, Post Office Box,
#   and multi-line extended street address information. This field MAY contain multiple lines, separated by newlines.
#   Newlines can be represented either as a carriage return/line feed pair ("\r\n")
#   or as a single line feed character ("\n").
# locality
#   City or locality component.
# region
#   State, province, prefecture, or region component.
# postal_code
#   Zip code or postal code component.
# country
#   Country name component.
_address_valid_keys = frozenset({
    "formatted",
    "street_address",
    "locality",
    "region",
    "postal_code",
    "country"
})

_login_rule = re.compile("^[a-zA-Z][-_a-zA-Z0-9]{2,31}$")


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_int(value: Any) -> bool:
    return isinstance(value, int)


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_url(value: Any) -> bool:
    if not _is_str(value):
        return False
    components = URI_compiled.fullmatch(value).groupdict()
    if components.get("scheme") not in {"https", "http"}:
        return False
    return True


def _is_timezone(value: Any) -> bool:
    if not _is_str(value):
        return False
    return _timezone_pattern.fullmatch(value) is not None


def is_login(login: str) -> bool:
    match = _login_rule.fullmatch(login)
    if match is None:
        raise False
    return True


def is_email(value: Any) -> bool:
    from email_validator import validate_email, EmailNotValidError
    try:
        _email_info = validate_email(value, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def normalize_email(value: str, check_deliverability: bool = False) -> str:
    from email_validator import validate_email, EmailNotValidError
    try:
        _email_info = validate_email(value, check_deliverability=check_deliverability)
        return _email_info.normalized
    except EmailNotValidError:
        return value


def _is_birthdate(value: Any) -> bool:
    if not _is_str(value):
        return False
    return _birthdate_pattern.fullmatch(value) is not None


def _is_locale(value: Any) -> bool:
    if not _is_str(value):
        return False
    return is_language_tag(value)


def is_phone_number(value: Any) -> bool:
    from phonenumbers import parse, NumberParseException
    try:
        parse(value)
        return True
    except NumberParseException:
        return False


def _is_address(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value.keys())
    # If presented not allowed keys, remove them
    if len(keys - _address_valid_keys) > 0:
        return False
    # presented values must be str
    for key in keys:
        status = _is_str(value[key])
        if not status:
            return False
    return True


def normalize_phone_number(value: Any) -> str:
    from phonenumbers import parse, NumberParseException, format_number, PhoneNumberFormat
    try:
        return format_number(parse(value), PhoneNumberFormat.E164)
    except NumberParseException:
        return value


def _validate_claim_value(key: str, value: Any) -> bool:
    """
    Validating value and values for registered claims
    """
    if key in ("sub", "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "gender"):
        return _is_str(value)
    elif key in ("profile", "picture", "website"):
        return _is_url(value)
    elif key in ("email_verified", "phone_number_verified"):
        return _is_bool(value)
    elif key == "email":
        return is_email(value)
    elif key == "birthdate":
        return _is_birthdate(value)
    elif key == "zoneinfo":
        return _is_timezone(value)
    elif key == "locale":
        return _is_locale(value)
    elif key == "phone_number":
        return is_phone_number(value)
    elif key == "address":
        return _is_address(value)
    elif key == "updated_at":
        return _is_int(value)
    else:
        # Unknown claim value always true, because validation pattern is not known
        return True


def _claims_arm_validate(arm: str, claims: dict[str, Any]):
    _uri = "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims"
    for key in claims.keys():
        if claims[key] is None:
            claims[key] = {
                "essential": False
            }
            continue
        norm_key = key
        if "#" in key:
            norm_key = key.split("#", maxsplit=2)[0]
        value = claims[key]
        has_value = False
        if "essential" in value and not isinstance(value["essential"], bool):
            msg = f"Malformed claims parameter '{arm}.{key}.essential'"
            raise errors.InvalidRequestError(description=msg, uri=_uri)
        if "essential" not in value:
            value["essential"] = False
        if "value" in value:
            has_value = True
            if not _validate_claim_value(norm_key, value["value"]):
                msg = f"Malformed claims parameter '{arm}.{key}.value'"
                raise errors.InvalidRequestError(description=msg, uri=_uri)
        if "values" in value:
            if has_value:
                msg = f"Malformed claims parameter '{arm}.{key}' contains 'value' and 'values' keys"
                raise errors.InvalidRequestError(description=msg, uri=_uri)
            if key == "sub":
                msg = f"Malformed claims parameter '{arm}.{key}'. 'values' is ambiguous for user identification"
                raise errors.InvalidRequestError(description=msg, uri=_uri)
            if not isinstance(value["values"], list):
                msg = f"Malformed claims parameter '{arm}.{key}.values'"
                raise errors.InvalidRequestError(description=msg, uri=_uri)
            for v in value["values"]:
                if not _validate_claim_value(norm_key, v):
                    msg = f"Malformed claims parameter '{arm}.{key}.values'"
                    raise errors.InvalidRequestError(description=msg, uri=_uri)
    if "email" in claims:
        if claims["email"].get("value") is not None:
            claims["email"]["value"] = normalize_email(claims["email"]["value"])
        if claims["email"].get("values") is not None:
            for i in range(len(claims["email"]["values"])):
                claims["email"]["values"][i] = normalize_email(claims["email"]["values"][i])
    if "phone_number" in claims:
        if claims["phone_number"].get("value") is not None:
            claims["phone_number"]["value"] = normalize_phone_number(claims["phone_number"]["value"])
        if claims["phone_number"].get("values") is not None:
            for i in range(len(claims["phone_number"]["values"])):
                claims["phone_number"]["values"][i] = normalize_phone_number(claims["phone_number"]["values"][i])


def claims_validate(request: Request):
    _uri = "https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter"
    if request.claims is not None and not isinstance(request.claims, dict):
        try:
            request.claims = json.loads(request.claims)
        except Exception:
            raise errors.InvalidRequestError(description="Malformed claims parameter", uri=_uri)
        if "userinfo" in request.claims:
            _claims_arm_validate("userinfo", request.claims["userinfo"])
        if "id_token" in request.claims:
            _claims_arm_validate("id_token", request.claims["id_token"])
            if request.id_token_hint is not None and get_claims_sub_value(request) is not None:
                _uri = "https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation"
                msg = "Malformed request. Either id_token_hint parameter or claims.id_token.sub.value must be specified"
                raise errors.InvalidRequestError(description=msg, uri=_uri)
            if request.acr_values is not None and is_claims_acr_essential(request):
                _uri = "https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics"
                msg = "Malformed request. acr_values is Voluntary, but claims.id_token.acr.essential == true"
                raise errors.InvalidRequestError(description=msg, uri=_uri)


def get_claims_sub_value(request: Request) -> str | None:
    claims: dict[str, Any] = request.claims
    if claims is None:
        return None
    if claims.get("id_token") is None:
        return None
    if claims["id_token"].get("sub") is None:
        return None
    return claims["id_token"]["sub"].get("value")


def is_claims_acr_essential(request: Request) -> bool:
    claims: dict[str, Any] = request.claims
    if claims is None:
        return False
    if claims.get("id_token") is None:
        return False
    if claims["id_token"].get("acr") is None:
        return False
    return claims["id_token"]["acr"]["essential"]


def get_claims_acr_values(request: Request) -> list[str] | None:
    claims: dict[str, Any] = request.claims
    if claims is None:
        return None
    if claims.get("id_token") is None:
        return None
    if claims["id_token"].get("acr") is None:
        return None
    value = claims["id_token"]["acr"].get("value")
    if value is not None:
        return [value]
    values = claims["id_token"]["acr"].get("values")
    if values is not None:
        return values
    return None


def is_claims_auth_time_essential(request: Request) -> bool:
    if request.max_age is not None:
        return True
    claims: dict[str, Any] = request.claims
    if claims is None:
        return False
    if claims.get("id_token") is None:
        return False
    if claims["id_token"].get("auth_time") is None:
        return False
    return claims["id_token"]["auth_time"]["essential"]


def set_claims_auth_time_essential(request: Request) -> None:
    if request.max_age is None:
        return
    claims: dict[str, Any] = request.claims
    if claims is None:
        claims = {}
        request.claims = claims
    if claims.get("id_token") is None:
        claims["id_token"] = {}
    if claims["id_token"].get("auth_time") is None:
        claims["id_token"]["auth_time"] = {
            "essential": True,
        }
    else:
        claims["id_token"]["auth_time"]["essential"] = True


def get_id_token_claim(request: Request, key: str) -> dict | None:
    claims: dict[str, Any] = request.claims
    if claims is None:
        return None
    if claims.get("id_token") is None:
        return None
    return claims["id_token"].get(key)


def get_userinfo_claim(request: Request, key: str) -> dict | None:
    claims: dict[str, Any] = request.claims
    if claims is None:
        return None
    if claims.get("userinfo") is None:
        return None
    return claims["userinfo"].get(key)
