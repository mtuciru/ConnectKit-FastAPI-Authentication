import asyncio
import base64
import hashlib
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Request, Path, Response, Depends, UploadFile, File, Security, HTTPException, APIRouter
from fastapi.security import HTTPBasic, SecurityScopes
import os

from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.ext.hybrid import hybrid_method
from sqlalchemy.orm import mapped_column, Mapped
from starlette.websockets import WebSocket

import json_adapter as json

os.environ["DB_ADAPTER"] = "sqlite"
os.environ["DB_NAME"] = ":memory:"
os.environ["AUTH_ISSUER"] = "http://localhost:8000"
os.environ["AUTH_REQUIRE_SECURE"] = "FALSE"

from oauth2lib.errors.specs import OAuth2Error
from authentication import setup_as_resource, setup_as_provider
from database import async_init_default_base, Base

app = FastAPI()

setup_as_provider(app, {
    "authorization_code_enable": True,
    "authorization_implicit_enable": True,
    "oidc_enable": True,
    "authorization_device_enable": True,
    "device_verification_uri": lambda r: "https://fake.example.com/url",
    "client_credentials_enable": True,
    "revocation_enable": True,
    "introspection_enable": True,
})


async def startup():
    await async_init_default_base(Base.metadata)


# setup_app(app)

def prepare_digest(username: str, realm: str, password: str, method: str, uri: str):
    ha1 = hashlib.sha1()
    ha1.update(username.encode("utf8"))
    ha1.update(b":")
    ha1.update(realm.encode("utf8"))
    ha1.update(b":")
    ha1.update(password.encode("utf8"))
    ha1 = ha1.digest()
    ha2 = hashlib.sha1()


#     response = H(HA1:nonce:HA2)
#
# HA1 = H(username:realm:password)
#
# HA2 = H(method:digestURI)

#

async def dep_one():
    print("dep one called")
    return 1


async def dep_two():
    print("dep two called")
    return 2


class Dep:
    def __call__(self, one: Annotated[int, Depends(dep_one)], two: Annotated[int, Depends(dep_two)]):
        print("dep Dep called")
        return one + two


dep = Dep()


async def dep_three(dep_: int = Depends(dep)):
    print("dep three called")
    return dep_


@app.get("/{path:path}")
@app.post("/{path:path}")
async def test_root(one: Annotated[int, Depends(dep_one)], two: Annotated[int, Depends(dep_two)],
                    three: int = Security(dep_three, scopes=["aaa"])):
    # raise HTTPException(status_code=400, detail="Test")
    return Response(status_code=200, content=f"One: {one}, Two: {two}, Three: {three}!", media_type="text/plain")


# @app.websocket("/ws")
# async def websocket_endpoint(websocket: WebSocket):
#     await asyncio.sleep(10)
#     await websocket.accept()
#     # await websocket.close(3000, "invalid_token")


# @app.options("/no{path:path}")
# async def root_options(request: Request):
#     origin = request.headers.get("Origin") or "*"
#     print(request.headers)
#     return Response(status_code=204, headers={
#         "Access-Control-Allow-Origin": origin,
#         "Access-Control-Allow-Headers": "Authorization",
#     })
#

# @app.get("/no{path:path}")
# async def root(request: Request, path: str | None = Path()):
#     typical = 'Digest nonce="1234512345"'
#     auth = request.headers.get("Authorization")
#     # if not auth:
#     #     return Response(status_code=401, headers={"WWW-Authenticate": typical})
#     # components = auth.split(" ")
#     # print(components)
#     # if len(components) != 2:
#     #     return Response(status_code=401, headers={"WWW-Authenticate": typical})
#     # if components[0].lower() != "digest":
#     #     return Response(status_code=401, headers={"WWW-Authenticate": typical})
#     # auth = components[1]
#     print(request.headers)
#     print(request.cookies)
#     print(request.url)
#     print(request.base_url)
#     print(request.query_params)
#     print("===============================")
#     print(auth)
#     # return Response(status_code=426, headers={
#     #     "Upgrade": "sshbridge",
#     #     "Connection": "Upgrade",
#     #     "Access-Control-Allow-Origin": "https://learn.javascript.ru"
#     # })
#     return Response(content=json.dumps({
#         "headers": list(request.headers.items()),
#         "cookies": list(request.cookies.items()),
#         "url": str(request.url),
#         "base_url": str(request.base_url),
#         "query": list(request.query_params.items()),
#         "path": path,
#         # "auth": base64.b64decode(auth).decode("utf-8"),
#     }), headers={
#         "Access-Control-Allow-Origin": "https://learn.javascript.ru"
#     })
#     # return {
#     #     "headers": request.headers.items(),
#     #     "cookies": request.cookies.items(),
#     #     "url": str(request.url),
#     #     "base_url": str(request.base_url),
#     #     "query": request.query_params.items(),
#     #     "path": path,
#     #     # "auth": base64.b64decode(auth).decode("utf-8"),
#     # }


# @app.get("/.well-known/oauth-authorization-server")
# @app.get("/.well-known/oauth-authorization-server/{issuer}")
# async def well_known_authorization_server(request: Request, issuer: str | None = None):
#     return {
#         "issuer": issuer or request.base_url,
#     }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
