"""
    oauth2lib

    This library include some mechanisms implementing some RFCs
    for OAuth2 (with some extensions) and OpenID Connect (minimal variant)
    in close integration with FastAPI library (require it for work).

    This library is inspired by oauthlib library,
    but uses coroutines for better async support, merge OAuth2 and OIDC into one inseparable solution and
    integrated with FastAPI library ao it can't be used without it
    and being a part of ConnectKit-FastAPI-OAuth2 python package.
    This library also does not implement OAuth version 1 because it is outdated.
"""
