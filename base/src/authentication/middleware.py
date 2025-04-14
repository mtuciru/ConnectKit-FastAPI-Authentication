from fastapi import FastAPI
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.authentication import BaseUser, AuthCredentials
from starlette.middleware.cors import CORSMiddleware


class AuthenticatedUser(BaseUser):

    @property
    def is_authenticated(self) -> bool:
        pass

    @property
    def display_name(self) -> str:
        pass

    @property
    def identity(self) -> str:
        pass


class AnonymousUser(BaseUser):
    pass


class AuthenticationMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        connection = HTTPConnection(scope)


app = FastAPI()

app.add_middleware()
