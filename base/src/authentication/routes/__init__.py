from authentication.routes.root import router
from authentication.routes.otp import router as otp_router

router.include_router(otp_router)
