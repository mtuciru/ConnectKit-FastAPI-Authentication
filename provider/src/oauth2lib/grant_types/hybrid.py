from .authorization_code import AuthorizationCodeGrant
from ..common import Request
from ..validators import RequestValidator

__all__ = ["HybridGrant"]


class HybridGrant(AuthorizationCodeGrant):
    default_response_mode = 'fragment'
    response_types = ['code id_token', 'code token', 'code id_token token']
    grant_type: str = "authorization_code"

    def __init__(self, request_validator: RequestValidator = None):
        super().__init__(request_validator)
        self.register_code_modifier(self.add_token)
        self.register_code_modifier(self.add_id_token)

    async def create_token_response(self, request: Request):
        raise NotImplementedError("HybridGrant should not be used for token endpoint. Only authorize")

    async def validate_token_request(self, request: Request):
        raise NotImplementedError("HybridGrant should not be used for token endpoint. Only authorize")
