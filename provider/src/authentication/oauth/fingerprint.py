"""
Create minimal fingerprint about browser.

It's required as soft bind for access & refresh tokens for End-User Agent
if old fingerprint (calculated on authentication) and new fingerprint (from request) not equals
sensitive operations require reauthenticate.
Reauthenticate will update fingerprint value.

as fingerprint saved:
    - client ip address
    - User-agent header -- hint header
    - Sec-CH-UA header -- brand list of web browsers
    - Sec-CH-UA-Mobile header -- flag if mobile platform
    - Sec-CH-UA-Platform header -- name of platform
"""
import hashlib
from collections import OrderedDict

from fastapi import Request
from starlette.requests import HTTPConnection

import json_adapter as json

__all__ = ["create_fingerprint"]


def create_fingerprint(request: Request | HTTPConnection):
    client = request.client
    if client is not None:
        client_ip = client.host
    else:
        client_ip = None
    user_agent = request.headers.get("User-Agent")
    sec_ch_ua = request.headers.get("Sec-CH-UA")
    sec_ch_mobile = request.headers.get("Sec-CH-UA-Mobile")
    sec_ch_platform = request.headers.get("Sec-CH-UA-Platform")
    fingerprint = OrderedDict()
    fingerprint["client_ip"] = client_ip
    fingerprint["user_agent"] = user_agent
    fingerprint["sec_ch_ua"] = sec_ch_ua
    fingerprint["sec_ch_mobile"] = sec_ch_mobile
    fingerprint["sec_ch_platform"] = sec_ch_platform
    return hashlib.sha1(json.dumps(fingerprint).encode("utf8")).hexdigest()
