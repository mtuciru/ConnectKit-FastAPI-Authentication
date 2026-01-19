from fastapi import Request, APIRouter, Depends, Query, HTTPException

from sqlalchemy import select
from sqlalchemy.orm import load_only

from database import AsyncSession
from ..middleware import authenticated
from ..schemes.oauth import error_response, ClientDiscoverRequest, ClientDiscoverResponse, location_response
from ..utils.common import get_database, responses
from ..models import OAuth2Client

__all__ = ["create_oauth_router"]

_authorization_validate_extra = {
    "requestBody": {
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description": "OAuth 2.0 Client Identifier",
                            "type": "string",
                            "default": ""
                        },
                        "response_type": {
                            "description": "OAuth 2.0 Response Type value"
                                           "that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": "code"
                        },
                        "redirect_uri": {
                            "description": "Redirection URI to which the response will be sent.",
                            "type": "string",
                            "default": ""
                        },
                        "scope": {
                            "description": "The scope of the access request",
                            "type": "string",
                            "default": ""
                        },
                        "state": {
                            "description": "An opaque value used by the client to maintain"
                                           "state between the request and callback.  The authorization"
                                           "server includes this value when redirecting the user-agent back"
                                           "to the client.",
                            "type": "string",
                            "default": ""
                        },
                        "response_mode": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "nonce": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": "",
                        },
                        "display": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "prompt": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "max_age": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "ui_locales": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "id_token_hint": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "login_hint": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "acr_values": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "claims_locales": {
                            "description": "End-User's preferred languages and scripts for Claims being returned, "
                                           "represented as a space-separated list of BCP47 [RFC5646] language tag values, "
                                           "ordered by preference.",
                            "type": "string",
                            "default": ""
                        },
                        "claims": {
                            "description": "This parameter is used to request that specific Claims be returned. "
                                           "The value is a JSON object listing the requested Claims.",
                            "type": "string",
                            "default": ""
                        },
                        "long": {
                            "description": "Max time session idle",
                            "type": "boolean",
                            "default": ""
                        }
                    },
                    "required": ["client_id", "response_type"]
                }
            }
        }
    },
}

_authorization_extra = {

}


def create_oauth_router() -> APIRouter:
    router = APIRouter(prefix="/oauth", tags=["oauth"])

    @router.post("/authorize_validate", openapi_extra=_authorization_validate_extra)
    async def authorization_validate(request: Request):
        pass

    @router.post("/authorize", openapi_extra=_authorization_extra)
    @authenticated
    async def authorization_process(request: Request):
        pass

    return router


# /client_info -- API method for access only from FRONTEND for discover requested client for OAuth2 /authorization
# required authorized user
# /authorization -- API method for access only from FRONTEND for realize OAuth2 authorization logic
# required authorized user
# /device -- API method for access only from FRONTEND for realize OAuth2 Device authorization logic


# @router.get("/authorize_validate", response_model=ClientDiscoverResponse, responses=responses({
#     404: "client_not_found"
# }))
# async def client_info(request: Request,
#                       params: ClientDiscoverRequest = Query(),
#                       db: AsyncSession = Depends(get_database)):


@router.post("/authorization", openapi_extra={
    "requestBody": {
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description": "OAuth 2.0 Client Identifier",
                            "type": "string",
                            "default": ""
                        },
                        "response_type": {
                            "description": "OAuth 2.0 Response Type value"
                                           "that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": "code"
                        },
                        "redirect_uri": {
                            "description": "Redirection URI to which the response will be sent.",
                            "type": "string",
                            "default": ""
                        },
                        "scope": {
                            "description": "The scope of the access request",
                            "type": "string",
                            "default": ""
                        },
                        "state": {
                            "description": "An opaque value used by the client to maintain"
                                           "state between the request and callback.  The authorization"
                                           "server includes this value when redirecting the user-agent back"
                                           "to the client.",
                            "type": "string",
                            "default": ""
                        },
                        "response_mode": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "nonce": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": "",
                        },
                        "display": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "prompt": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "max_age": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "ui_locales": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "id_token_hint": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "login_hint": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "acr_values": {
                            "description": "OAuth 2.0 Response Type value that determines the authorization processing flow to be used",
                            "type": "string",
                            "default": ""
                        },
                        "claims_locales": {
                            "description": "End-User's preferred languages and scripts for Claims being returned, "
                                           "represented as a space-separated list of BCP47 [RFC5646] language tag values, "
                                           "ordered by preference.",
                            "type": "string",
                            "default": ""
                        },
                        "claims": {
                            "description": "This parameter is used to request that specific Claims be returned. "
                                           "The value is a JSON object listing the requested Claims.",
                            "type": "string",
                            "default": ""
                        },
                        "long": {
                            "description": "Max time session idle",
                            "type": "boolean",
                            "default": ""
                        }
                    },
                    "required": ["client_id", "response_type"]
                }
            }
        }
    },
})
@authenticated()
async def authorization(request: Request, db: AsyncSession = Depends(get_database)):
    try:
        oauth2_request = await OAuth2Request.from_request(request, db)
        await oauth2_request.extract_user()
        await oauth2_request.extract_client()
        response_type = oauth2_request.response_type = normalize_response_type(oauth2_request.response_type)
        grant_type = response_types.get(response_type, oauth2_auth_grant)
        headers, body, status = grant_type.create_authorization_response(oauth2_request, bearer_token)
        await oauth2_request.await_tasks()
        return location_response(headers.get("Location"))
    except FatalClientError as e:
        return error_response(e)
    except OAuth2Error as e:
        return location_response(e.in_uri(e.redirect_uri))


@router.post("/device")
@authenticated()
async def device(request: Request, db: AsyncSession = Depends(get_database)):
    pass


@router.post("/token")
async def token(request: Request, db: AsyncSession = Depends(get_database)):
    pass


@router.post("/device_authorization")
async def device_authorization(request: Request, db: AsyncSession = Depends(get_database)):
    pass


@router.post("/revoke")
async def revoke(request: Request, db: AsyncSession = Depends(get_database)):
    pass
