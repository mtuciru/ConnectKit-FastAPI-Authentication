from fastapi import APIRouter

from .csrf import router as csrf_router
from .login import router as login_router
from .account import router as account_router

router = APIRouter(prefix="/auth")

router.include_router(csrf_router)
router.include_router(login_router)
router.include_router(account_router)

__all__ = ["router"]
