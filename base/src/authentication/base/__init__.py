from fastapi import FastAPI

from .settings import settings
from .routes import router
from .middleware import *
from .utils import *
from .schemes import responses
from . import models


def setup_app(app: FastAPI):
    app.add_middleware(AuthenticationMiddleware)
    app.include_router(router, prefix=settings.secure_path)
