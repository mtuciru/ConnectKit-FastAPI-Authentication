import uuid
from base64 import b64encode
from urllib.parse import urlencode, quote_plus

import aiohttp
from fastapi import Request, APIRouter, status, Depends, HTTPException
from oauthlib.oauth2 import WebApplicationClient
from sqlalchemy import select
from starlette.responses import RedirectResponse

from ..middleware import anonymous
from ..models import OAuthChallenge
from ..schemes.oauth2client import OAuth2Redirect
from ..schemes.responses import already_authenticated
from ..utils.common import get_database, AsyncSession, responses
from ..utils import json
from ..utils.oauth2config import oauth2config

__all__ = ['router', "set_redirect_url", "set_error_redirect_url"]

router = APIRouter(prefix="/oauth", tags=["oAuth2 or OpenID Connect client callback"])

_redirect_url: str = "/"
_error_redirect_url: str = "/"


def set_redirect_url(url: str):
    global _redirect_url
    _redirect_url = url


def set_error_redirect_url(url: str):
    global _error_redirect_url
    _error_redirect_url = url


@router.get("/from/{provider_name}", response_model=OAuth2Redirect, responses=responses(
    already_authenticated, {404: "Provider not found"}
))
@anonymous
async def oauth_redirect(
        request: Request,
        provider_name: str,
        db: AsyncSession = Depends(get_database),
):
    if provider_name not in oauth2config.providers:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    provider = oauth2config.providers[provider_name]
    web_client = WebApplicationClient(provider.client_id, scope=provider.scopes)
    state = b64encode((provider_name + "_" + uuid.uuid1().hex).encode("utf-8")).decode("utf-8")
    code_verifier = web_client.create_code_verifier(64)
    code_challenge = web_client.create_code_challenge(code_verifier, "S256")
    redirect_url = web_client.prepare_request_uri(provider.authorize_url, state=state,
                                                  code_challenge=code_challenge, code_challenge_method="S256",
                                                  redirect_uri=request.url_for("oauth_callback"))
    oauth_challenge = OAuthChallenge()
    oauth_challenge.state = state
    oauth_challenge.provider_name = provider_name
    oauth_challenge.code_verifier = code_verifier
    db.add(oauth_challenge)
    await db.commit()
    return OAuth2Redirect(url=redirect_url)


@router.get("/callback", status_code=status.HTTP_303_SEE_OTHER)
@anonymous
async def oauth_callback(
        request: Request,
        state: str, code: str,
        error: str | None = None,
        error_description: str | None = None,
        error_uri: str | None = None,
        db: AsyncSession = Depends(get_database),
):
    oauth_challenge: OAuthChallenge = await db.scalar(select(OAuthChallenge).filter_by(state=state))
    if oauth_challenge is None:
        request_qparam = urlencode({"error": "Challenge failed"})
        return RedirectResponse(f"{_error_redirect_url}?{request_qparam}", status_code=status.HTTP_303_SEE_OTHER)
    if error is not None:
        params = {"error": error}
        if error_description is not None:
            params["error_description"] = error_description
        request_qparam = urlencode(params)
        await db.delete(oauth_challenge)
        await db.commit()
        return RedirectResponse(f"{_error_redirect_url}?{request_qparam}", status_code=status.HTTP_303_SEE_OTHER)

    provider = oauth2config.providers[oauth_challenge.provider_name]
    code_verifier = oauth_challenge.code_verifier
    web_client = WebApplicationClient(provider.client_id)
    body = web_client.prepare_request_body(
        code=code,
        redirect_uri=request.url_for("oauth_callback"),
        include_client_id=False,
        code_verifier=code_verifier,
    )
    client_auth = b64encode(
        f"{quote_plus(provider.client_id)}:{quote_plus(provider.client_secret)}".encode("utf-8")
    ).decode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {client_auth}",
        "Accept": "application/json"
    }
    await db.delete(oauth_challenge)
    await db.commit()
    async with aiohttp.ClientSession() as session:
        async with session.post(provider.token_endpoint, headers=headers, data=body) as response:
            if response.status == 200:
                resp_data = json.loads(await response.text())
                access_token = resp_data.get("access_token", None)
                token_type = resp_data.get("token_type", None)
                expires_in = resp_data.get("expires_in", None)
                refresh_token = resp_data.get("refresh_token", None)
                error = resp_data.get("error", None)
                error_description = resp_data.get("error_description", None)
                if error is not None:
                    params = {"error": error}
                    if error_description is not None:
                        params["error_description"] = error_description
                    request_qparam = urlencode(params)
                    return RedirectResponse(f"{_error_redirect_url}?{request_qparam}",
                                            status_code=status.HTTP_303_SEE_OTHER)
                if access_token is None:
                    params = {"error": "invalid_response",
                              "error_description": "Unexpected state (access token not returned)"}
                    request_qparam = urlencode(params)
                    return RedirectResponse(f"{_error_redirect_url}?{request_qparam}",
                                            status_code=status.HTTP_303_SEE_OTHER)
                if token_type is None or token_type.lower() != "bearer":
                    params = {"error": "invalid_response",
                              "error_description": "Unknown access token type (only Bearer supported)"}
                    request_qparam = urlencode(params)
                    return RedirectResponse(f"{_error_redirect_url}?{request_qparam}",
                                            status_code=status.HTTP_303_SEE_OTHER)
    #             {
    #        "access_token":"2YotnFZFEjr1zCsicMWpAA",
    #        "token_type":"example",
    #        "expires_in":3600,
    #        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
    #        "example_parameter":"example_value"
    #      }
    pass
