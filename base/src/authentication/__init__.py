from typing import Callable

from fastapi import FastAPI

from .settings import settings
from .routes import router
from .middleware import *
from .utils import *
from .schemes import responses
from . import models


def setup_app(app: FastAPI, header_processor: Callable[[str], tuple[auth_pair, auth_error]] = None):
    app.add_middleware(AuthenticationMiddleware, header_processor)
    app.include_router(router, prefix=settings.secure_path)
