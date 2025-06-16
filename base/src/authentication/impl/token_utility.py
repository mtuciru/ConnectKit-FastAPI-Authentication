import ipaddress
import re
from collections import OrderedDict
from functools import lru_cache
from typing import List, Dict, Any

import jwt
from ..utils import json
from fastapi import Request, Response
from starlette.requests import HTTPConnection
from ietfparse import headers
from pydantic import BaseModel, ConfigDict

from ..settings import settings

__all__ = ["UserAgent", "UserAgentExtension", "UserAgentPlatform", "ClientInfo",
           "get_real_client_ip", "get_client_fingerprint", "decode_client_fingerprint",
           "set_cookie", "reset_cookie", "encode_session_token", "decode_session_token",
           "TokenExpired", "TokenInvalid"]

#  ===== CONSTANTS =====

_user_agent = re.compile(r"^(?P<product>[^/]*)/(?P<product_version>[\S]*)(?P<comment>.*)$")
_user_agent_comment = re.compile(r"^\((?P<system_info>[^()]*)\)\s*"
                                 r"(?:(?P<platform>(?P<platform_name>[\w\d]*)/(?P<platform_version>[\d\w.]*))"
                                 r"(?:\s*\((?P<platform_detais>[^()]*)\))?\s*)?"
                                 r"(?P<extensions>(?:[\w\d]*/[\d\w.]*\s*)*)$")
_user_agent_extension = re.compile(r"(?P<extension>(?P<extension_name>[\w\d]*)/(?P<extension_version>[\d\w.]*))")


#  ===== SCHEMAS =====

class UserAgentExtension(BaseModel):
    full: str | None = None
    name: str | None = None
    version: str | None = None


class UserAgentPlatform(BaseModel):
    full: str | None = None
    name: str | None = None
    version: str | None = None
    details: str | None = None
    extensions: list[UserAgentExtension] = []


class UserAgent(BaseModel):
    product: str | None = None
    product_version: str | None = None
    comment: str | None = None
    system_info: str | None = None
    platform: UserAgentPlatform | None = None


class ClientInfo(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    client_ip: str | None = None
    user_agent: UserAgent | None = None


#  ===== FUNCTIONS =====

@lru_cache(maxsize=256)
def user_agent_parse(user_agent: str) -> OrderedDict:
    result = OrderedDict()
    components = _user_agent.fullmatch(user_agent)
    if components is None:
        result["product"] = None
        result["product_version"] = None
        result["comment"] = None
        result["error"] = "User agent is invalid"
        return result
    components = components.groupdict()
    result["product"] = components["product"]
    result["product_version"] = components["product_version"]
    components["comment"] = components["comment"].strip()
    if components["comment"] is not None and len(components["comment"]) > 0:
        comment = _user_agent_comment.fullmatch(components["comment"])
        if comment is not None:
            comment = comment.groupdict()
            result["system_info"] = comment["system_info"]
            result["platform"] = OrderedDict()
            result["platform"]["full"] = comment["platform"]
            result["platform"]["name"] = comment["platform_name"]
            result["platform"]["version"] = comment["platform_version"]
            if "platform_details" in comment:
                result["platform"]["details"] = comment["platform_details"]
            if len(comment["extensions"]) > 0:
                extensions = []
                for extension in _user_agent_extension.finditer(comment["extensions"]):
                    ext_keys = extension.groupdict()
                    data = OrderedDict()
                    data["full"] = ext_keys["extension"]
                    data["name"] = ext_keys["extension_name"]
                    data["version"] = ext_keys["extension_version"]
                    extensions.append(data)
                result["extensions"] = extensions
            else:
                result["extensions"] = []
        else:
            result["comment"] = components["comment"]
    else:
        result["comment"] = None
    return result


def extract_ip_class(ip: str) -> OrderedDict:
    result = OrderedDict()
    try:
        ip_address = ipaddress.ip_address(ip)
        result["is_address"] = True
        result["ip_address"] = ip_address
        result["version"] = ip_address.version
        result["is_global"] = ip_address.is_global
        result["is_private"] = ip_address.is_private
        result["is_unspecified"] = ip_address.is_unspecified
        result["is_loopback"] = ip_address.is_loopback
    except ValueError:
        result["is_address"] = False
    return result


def extract_ip_from_forwarded_for(header_list: List[str], return_no_ip: bool = False) -> str | None:
    target_ip = None
    private_target_ip = None
    all_ip_private = True
    for header in header_list:
        header = header.strip().lower()
        for client_ip in header.split(","):
            client_ip = client_ip.strip()
            ip_stats = extract_ip_class(client_ip)
            if not ip_stats["is_address"] and return_no_ip:
                target_ip = client_ip
                all_ip_private = False
                break
            else:
                if ip_stats["is_unspecified"] or ip_stats["is_loopback"]:
                    continue
                if ip_stats["is_private"]:
                    private_target_ip = client_ip
                elif ip_stats["is_global"]:
                    all_ip_private = False
                    target_ip = client_ip
                    break
    return target_ip if not all_ip_private else private_target_ip


def extract_ip_from_forwarded(header_list: List[str], return_no_ip: bool = False) -> str | None:
    target_ip = None
    private_target_ip = None
    all_ip_private = True
    for header in header_list:
        parsed = headers.parse_forwarded(header, only_standard_parameters=False)
        # find early valid 'for' identifier
        for proxy in parsed:
            if "for" in proxy:
                client_ip = proxy["for"].strip("[]")
                ip_stats = extract_ip_class(client_ip)
                if not ip_stats["is_address"] and return_no_ip:
                    target_ip = client_ip
                    all_ip_private = False
                    break
                else:
                    if ip_stats["is_unspecified"] or ip_stats["is_loopback"]:
                        continue
                    if ip_stats["is_private"]:
                        private_target_ip = client_ip
                    elif ip_stats["is_global"]:
                        all_ip_private = False
                        target_ip = client_ip
                        break
    return target_ip if not all_ip_private else private_target_ip


def get_real_client_ip(request: Request) -> str | None:
    ip = str(request.client[0]) if request.client is not None else None
    tmp_ip: str | None = None
    headers_keys = request.headers.keys()
    if "Forwarded" in headers_keys:
        tmp_ip = extract_ip_from_forwarded(request.headers.getlist("Forwarded"))
    elif "X-Forwarded-For" in headers_keys:
        tmp_ip = extract_ip_from_forwarded_for(request.headers.getlist("X-Forwarded-For"))
    elif "X-Real-IP" in headers_keys:
        tmp_ip = request.headers["X-Real-IP"]
    if tmp_ip is not None:
        ip = tmp_ip
    return ip


def get_client_fingerprint(request: Request | HTTPConnection) -> str:
    user_agent = request.headers["User-Agent"] if "User-Agent" in request.headers else None
    info = OrderedDict()
    info["client_ip"] = get_real_client_ip(request)
    if user_agent is not None and len(user_agent) > 0:
        info["user_agent"] = user_agent_parse(user_agent)
    else:
        info["user_agent"] = None
    return json.dumps(info)


def decode_client_fingerprint(client_fingerprint: str) -> ClientInfo:
    return ClientInfo.model_validate(json.loads(client_fingerprint))


def set_cookie(access: str, response: Response, max_age: int):
    response.set_cookie(settings.cookie_name, access,
                        httponly=True,
                        samesite="strict",
                        max_age=max_age,
                        path=settings.secure_path,
                        secure=settings.cookie_secure)


def reset_cookie(response: Response):
    response.set_cookie(settings.cookie_name, "Nope",
                        httponly=True,
                        samesite="strict",
                        max_age=0,
                        path=settings.secure_path,
                        secure=settings.cookie_secure)


def encode_session_token(payload) -> str:
    return jwt.encode(payload, settings.secret, algorithm=settings.secret_algorithm.value,
                      json_encoder=json.JSONEncoder)


class TokenInvalid(ValueError):
    def __init__(self):
        super().__init__("Invalid token specified")


class TokenExpired(ValueError):
    def __init__(self):
        super().__init__("Expired token specified")


def decode_session_token(token: str, token_type: str, suppress: bool = False) -> Dict[str, Any]:
    try:
        data = jwt.decode(token, settings.secret, algorithms=[settings.secret_algorithm.value], options={
            "require": ["iss", "sub", "sid", "aud", "jit", "exp"],
            "verify_exp": not suppress,
            "strict_aud": True
        }, issuer=settings.issuer, audience=token_type)
        return data
    except jwt.ExpiredSignatureError:
        raise TokenExpired()
    except jwt.DecodeError:
        raise TokenInvalid()
