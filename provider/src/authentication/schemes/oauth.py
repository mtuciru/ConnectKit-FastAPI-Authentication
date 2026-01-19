from oauthlib.oauth2 import OAuth2Error
from starlette.responses import JSONResponse

from authentication.settings import BaseModel


def error_response(error: OAuth2Error):
    return JSONResponse({'error': error.error, "description": error.description}, status_code=error.status_code)


def location_response(location: str):
    return JSONResponse({'location': location}, status_code=200)


class ClientDiscoverRequest(BaseModel):
    client_id: str


class ClientDiscoverResponse(BaseModel):
    client_id: str
    display_name: str
    min_scopes: list[str]
    max_scopes: list[str]
    options: list[str]


class AuthorizationRequest(BaseModel):
    pass


class TokenRequest(BaseModel):
    pass
