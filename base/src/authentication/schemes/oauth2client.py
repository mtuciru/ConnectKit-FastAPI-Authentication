from ..settings import BaseModel


class OAuth2Redirect(BaseModel):
    url: str
