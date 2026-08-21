from database.asyncio import AsyncSession
from fastapi import Request, APIRouter, Depends, Response

from oauth2lib.endpoints.metadata import well_known_oauth, well_known_oidc
from oauth2lib.tokens import get_jwks
from .config import get_endpoints
from ..schemes import oauth2_extra
from ..security import authenticated_user, EndUser
from ..settings import function_settings
from ..utils.common import get_database

__all__ = ["create_oauth_router", "create_metadata_router"]


def create_oauth_router() -> APIRouter:
    router = APIRouter(prefix="/oauth", tags=["oauth"])
    endpoints = get_endpoints()

    if function_settings.authorization_code_enable or function_settings.authorization_implicit_enable:
        auth_endpoint = endpoints["authorization"]

        @router.post("/authorize_start",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_authorization_start_extra)
        async def oauth_authorization_start(request: Request,
                                            _user: EndUser = authenticated_user(),
                                            db: AsyncSession = Depends(get_database)):
            return await auth_endpoint.validate_authorization_request(request, db)

        @router.post("/authorize_end",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_authorization_end_extra)
        async def oauth_authorization_end(request: Request,
                                          _user: EndUser = authenticated_user(),
                                          db: AsyncSession = Depends(get_database)):
            return await auth_endpoint.create_authorization_response(request, db)

    if function_settings.authorization_device_enable:
        device_endpoint = endpoints["device_authorization"]
        device_verification_endpoint = endpoints["device_verification"]

        @router.post("/device_authorize",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_device_authorization_extra)
        async def oauth_device_authorization(request: Request,
                                             db: AsyncSession = Depends(get_database)):
            return await device_endpoint.create_device_authorization_response(request, db)

        @router.post("/device_verify_start",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_device_verify_start_extra)
        async def oauth_device_authorization(request: Request,
                                             _user: EndUser = authenticated_user(),
                                             db: AsyncSession = Depends(get_database)):
            return await device_verification_endpoint.validate_device_verification_request(request, db)
            # if not user.via_provider:
            #     raise errors.AccessDeniedError()
            # device_code: models.OAuth2DeviceCode = await db.scalar(select(models.OAuth2DeviceCode).options(
            #     load_only(
            #         models.OAuth2DeviceCode.device_code, models.OAuth2DeviceCode.user_code,
            #         models.OAuth2DeviceCode.client_id, models.OAuth2DeviceCode.scope,
            #         models.OAuth2DeviceCode.approved, models.OAuth2DeviceCode.expire_at
            #     )
            # ).filter_by(user_code=user_code))
            # # All invalid states == expired code
            # # if device_code is None:
            # #     return oauth2_schemes.DeviceVerifyInfo(expired=True)
            # # if device_code.user_id is not None and device_code.user_id != user.id:
            # #     return oauth2_schemes.DeviceVerifyInfo(expired=True)
            # # now = datetime.now(tz=timezone.utc)
            # # if device_code.expire_at < now:
            # #     return oauth2_schemes.DeviceVerifyInfo(expired=True)
            # client: models.OAuth2Client = await db.scalar(select(models.OAuth2Client).options(
            #     load_only(
            #         models.OAuth2DeviceCode.device_code, models.OAuth2DeviceCode.user_code,
            #         models.OAuth2DeviceCode.client_id, models.OAuth2DeviceCode.scope,
            #         models.OAuth2DeviceCode.approved, models.OAuth2DeviceCode.expire_at
            #     )
            # ).filter_by(user_code=user_code))
            # # TODO: Add API method for user approve device via user_code
            # return Response()

        @router.post("/device_verify_end",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_device_verify_end_extra)
        async def oauth_device_authorization(request: Request,
                                             _user: EndUser = authenticated_user(),
                                             db: AsyncSession = Depends(get_database)):
            return await device_verification_endpoint.create_device_verification_response(request, db)

    if function_settings.revocation_enable:
        revoke_endpoint = endpoints["revocation"]

        @router.post("/revoke",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_revoke_extra)
        async def oauth_revoke(request: Request,
                               db: AsyncSession = Depends(get_database)):
            return await revoke_endpoint.create_revocation_response(request, db)

    if function_settings.introspection_enable:
        introspect_endpoint = endpoints["introspection"]

        @router.post("/introspect",
                     response_class=Response,
                     openapi_extra=oauth2_extra.openapi_introspect_extra)
        async def oauth_introspect(request: Request,
                                   db: AsyncSession = Depends(get_database)):
            return await introspect_endpoint.create_introspect_response(request, db)

    token_endpoint = endpoints["token"]
    userinfo_endpoint = endpoints["userinfo"]

    @router.post("/token",
                 response_class=Response,
                 openapi_extra=oauth2_extra.openapi_token_extra)
    async def oauth_token(request: Request,
                          db: AsyncSession = Depends(get_database)):
        return await token_endpoint.create_token_response(request, db)

    @router.get("/userinfo",
                response_class=Response,
                openapi_extra=oauth2_extra.openapi_userinfo_extra)
    @router.post("/userinfo",
                 response_class=Response,
                 openapi_extra=oauth2_extra.openapi_userinfo_extra)
    async def oauth_userinfo(request: Request,
                             _user: EndUser = authenticated_user(),
                             db: AsyncSession = Depends(get_database)):
        return await userinfo_endpoint.create_userinfo_response(request, db)

    @router.get("/jwks",
                response_class=Response,
                openapi_extra=oauth2_extra.openapi_jwks_extra)
    async def oauth_jwks():
        return Response(content=get_jwks(), status_code=200, media_type="application/json")

    return router


def create_metadata_router() -> APIRouter:
    router = APIRouter(tags=["oauth-metadata"])
    endpoints = get_endpoints()
    metadata_endpoint = endpoints["metadata"]

    @router.get(well_known_oauth,
                response_class=Response,
                openapi_extra=oauth2_extra.openapi_oauth_metadata_extra)
    async def oauth_metadata(request: Request,
                             db: AsyncSession = Depends(get_database)):
        return await metadata_endpoint.create_oauth_metadata_response(request, db)

    @router.get(well_known_oidc,
                response_class=Response,
                openapi_extra=oauth2_extra.openapi_oidc_metadata_extra)
    async def oidc_metadata(request: Request,
                            db: AsyncSession = Depends(get_database)):
        return await metadata_endpoint.create_oidc_metadata_response(request, db)

    return router
