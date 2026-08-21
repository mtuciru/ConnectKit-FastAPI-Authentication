from typing import Callable, Any, Coroutine

from .base import GrantTypeBase
from .. import errors
from ..common import Request, generate_token, generate_user_code, aw
from ..tokens import create_bearer_token, create_dpop_token, dpop_present
from ..validators import RequestValidator

__all__ = ["DeviceCodeGrant"]


class DeviceCodeGrant(GrantTypeBase):
    grant_type = "urn:ietf:params:oauth:grant-type:device_code"

    def __init__(self,
                 request_validator: RequestValidator,
                 verification_uri: Callable[[Request], str | Coroutine[Any, Any, str]],
                 complete_uri: Callable[[Request, str], str | Coroutine[Any, Any, str]] = None,
                 expires_in: int = 600,
                 interval: int = 5):
        super().__init__(request_validator)
        self._expires_in = expires_in
        self._interval = interval
        if verification_uri is None:
            raise ValueError("verification_uri cannot be None")
        self._verification_uri = verification_uri
        self._complete_uri = complete_uri
        self.register_token_modifier(self.add_id_token)

    def create_device_code(self):
        code_info = {
            'device_code': generate_token(68),
            'user_code': generate_user_code(),
            'expires_in': self._expires_in,
            'interval': self._interval
        }
        return code_info

    async def create_authorization_response(self, request: Request):
        try:
            await self.validate_authorization_request(request)
        except errors.OAuth2Error as e:
            return await self._prepare_error_response(request, e, False)

        code_info = self.create_device_code()

        await aw(self.request_validator.save_device_code(code_info, request))

        verification_uri = await aw(self._verification_uri(request))
        code_info["verification_uri"] = verification_uri

        if self._complete_uri is not None:
            complete_uri = await aw(self._complete_uri(request, code_info["user_code"]))
            code_info["verification_uri_complete"] = complete_uri

        return await self._prepare_direct_response(request, code_info)

    async def validate_authorization_request(self, request: Request):
        request.grant_type = self.grant_type
        self._validate_duplicate_params(request, ("client_id", "scope", "client_secret"))

        if await aw(self.request_validator.client_authentication_required(request)):
            # Check that single auth scheme used, validate match basic client_id and parameter client_id
            request.client = await aw(self.request_validator.authenticate_client(request))
            if request.client is None:
                raise errors.InvalidClientError(request=request)
        else:
            if request.client_id is None:
                raise errors.MissingClientIdError(request=request)
            request.client = await aw(self.request_validator.authenticate_client_id(request))
            if request.client is None:
                raise errors.InvalidClientIdError(request=request)

        await self._is_allowed_grant_type(request)
        await self._validate_scopes(request)

    async def create_token_response(self, request: Request):
        """
        Return token or error in json format.
        """
        try:
            await self.validate_token_request(request)
            error = await aw(self.request_validator.get_device_code_error_status(request))
            if error is not None:
                if error == "access_denied" or error == "expired_token":
                    await aw(self.request_validator.forgot_device_code(request))
                errors.raise_from_error(error)
        except errors.OAuth2Error as e:
            return await self._prepare_error_response(request, e, False)

        try:
            # Same logic as client_credentials. Why not?
            await self._cors_preflight(request)
        except errors.OAuth2Error as e:
            # CORS preflight failed. So, forgot device code, but not issue tokens it's not required.
            await aw(self.request_validator.forgot_device_code(request))
            return await self._prepare_error_response(request, e, False)

        if not await aw(self.request_validator.restore_by_device_code(request)):
            raise errors.InvalidGrantError(request=request)

        if dpop_present(request) or await aw(self.request_validator.is_client_dpop_required(request)):
            # If client require DPoP type of access token (access with proof) issue DPoP
            token = await create_dpop_token(self.request_validator, request, self.refresh_token)
        else:
            token = await create_bearer_token(self.request_validator, request, self.refresh_token)

        await self._run_token_modifiers(token, request)

        await aw(self.request_validator.save_token(token, request))
        await aw(self.request_validator.forgot_device_code(request))

        return await self._prepare_direct_response(request, token)

    async def validate_token_request(self, request: Request):
        self._validate_duplicate_params(request, ("grant_type", "device_code", "client_id", "client_secret"))

        await self._validate_grant_type(request)

        if request.device_code is None:
            raise errors.InvalidRequestError("Request is missing device_code.", request=request)

        if await aw(self.request_validator.client_authentication_required(request)):
            # Check that single auth scheme used, validate match basic client_id and parameter client_id
            request.client = await aw(self.request_validator.authenticate_client(request))
        else:
            if request.client_id is None:
                raise errors.MissingClientIdError(request=request)
            request.client = await aw(self.request_validator.authenticate_client_id(request))
        if request.client is None:
            raise errors.InvalidClientError(request=request)

        await self._is_allowed_grant_type(request)
