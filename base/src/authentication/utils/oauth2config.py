import os

from ..settings import BaseModel
from ..utils import json

__all__ = ["oauth2config", "OAuth2Config", "OAuth2Provider"]

_path = "/var/opt/auth/"

try:
    os.makedirs(_path)
except OSError:
    pass


class OAuth2Provider(BaseModel):
    name: str
    client_id: str
    client_secret: str
    oidc: bool
    scopes: list[str]
    authorization_endpoint: str
    token_endpoint: str
    refresh_token_endpoint: str


class OAuth2Config(BaseModel):
    providers: dict[str, OAuth2Provider]


def config_load():
    filename = _path + "oauth2.json"
    if not os.path.exists(filename):
        return OAuth2Config.model_validate({
            "providers": {},
        })
    with open(filename) as json_file:
        data = json.load(json_file)
    providers = {}
    for d in data:
        if "name" in d:
            providers[d["name"]] = d
        else:
            raise ValueError("Bad provider syntax ('name' required)")
    config = OAuth2Config.model_validate({
        "providers": providers,
    })
    return config


oauth2config = config_load()
