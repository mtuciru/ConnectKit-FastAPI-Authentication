from urllib.parse import urlencode

import json_adapter as json
from ..common import add_params_to_uri, Request

__all__ = ["OAuth2Error", "FatalClientError"]


class OAuth2Error(Exception):
    error: str = None
    uri: str = None
    status_code: int = 400
    description: str = ''

    # auth_scheme: str = 'Bearer'

    def __init__(self, description: str = None, uri: str = None, state: str = None,
                 status_code: int = None, request: Request = None):

        if description is not None:
            self.description = description

        message = ' '.join([f"({self.error})", self.description])
        if request:
            message += ' ' + repr(request)
        super().__init__(message)

        if uri is not None:
            self.uri = uri
        self.state = state

        if status_code is not None:
            self.status_code = status_code

        self.iss: str | None = None

        if request:
            self.redirect_uri = request.redirect_uri
            self.client_id = request.client_id
            self.scopes = request.scopes
            self.response_type = request.response_type
            self.response_mode = request.response_mode
            self.grant_type = request.grant_type
            if state is None:
                self.state = request.state
            self.used_auth_schemes = request.used_auth_schemes
        else:
            self.redirect_uri = None
            self.client_id = None
            self.scopes = None
            self.response_type = None
            self.response_mode = None
            self.grant_type = None
            self.used_auth_schemes = []

    def update_from_request(self, request: Request | None):
        if request:
            self.redirect_uri = request.redirect_uri
            self.client_id = request.client_id
            self.scopes = request.scopes
            self.response_type = request.response_type
            self.response_mode = request.response_mode
            self.grant_type = request.grant_type
            if self.state is None:
                self.state = request.state
            self.used_auth_schemes = request.used_auth_schemes
        else:
            self.redirect_uri = None
            self.client_id = None
            self.scopes = None
            self.response_type = None
            self.response_mode = None
            self.grant_type = None
            self.used_auth_schemes = []

    def in_uri(self, uri: str = None):
        if uri is None:
            uri = self.redirect_uri
        if uri is None:
            uri = "/"
        fragment = self.response_mode == "fragment"
        return add_params_to_uri(uri, self.aslist, fragment)

    def in_post(self, uri: str = None):
        if uri is None:
            uri = self.redirect_uri
        if uri is None:
            uri = "/"
        input_template = '<input type="hidden" name="{}" value="{}"/>'
        inputs = []
        for key, value in self.aslist:
            inputs.append(input_template.format(str(key), str(value)))
        inputs = "".join(inputs)
        return (
            '<html><head><title>Authorization result form</title></head>'
            '<body onload="javascript:document.forms[0].submit()">'
            f'<form method="post" action="{uri}">{inputs}</form>'
            f'</body></html>'
        )

    @property
    def aslist(self):
        error = [('error', self.error)]
        if self.iss:
            error.append(('iss', Request.issuer))
        if self.description:
            error.append(('error_description', self.description))
        if self.uri:
            error.append(('error_uri', self.uri))
        if self.state:
            error.append(('state', self.state))
        return error

    @property
    def asdict(self):
        error = {
            "error": self.error,
        }
        if self.iss:
            error['iss'] = self.iss
        if self.description:
            error["error_description"] = self.description
        if self.uri:
            error["error_uri"] = self.uri
        if self.state:
            error["state"] = self.state
        return error

    @property
    def urlencoded(self):
        return urlencode(self.aslist)

    @property
    def json(self):
        return json.dumps(self.asdict)

    @property
    def header_values(self):
        """
        return standard fields for WWW-Authenticate scheme values.

        Used because can be more than one scheme
        (Bearer error="some_error", ...)
        """
        auth_values = [f'error="{self.error}"']
        if self.description:
            auth_values.append(f'error_description="{self.description}"')
        if self.uri:
            auth_values.append(f'error_uri="{self.uri}"')
        # Used for specific resource access error
        if getattr(self, "acr_values", None) is not None:
            auth_values.append(f'acr_values="{" ".join(getattr(self, "acr_values"))}"')
        if getattr(self, "max_age", None) is not None:
            auth_values.append(f'max_age="{getattr(self, "max_age")}"')
        return ", ".join(auth_values)

    def headers(self, schemes: list[str], used_schemes: list[str]):
        headers = {}
        if self.status_code == 401:
            """
            Basic auth-scheme used for OAuth2 endpoints with client authentification
            If client used it, add error message into Basic section
            
            Bearer auth-scheme used for OAuth2 resources endpoints & introspect (client_credentials) & revoke (client_credentials)
            If this scheme used, add error message into Bearer section
            
            DPoP auth-scheme user as Bearer but with additional token
            If this scheme used, add error message into Bearer section
            """
            values = self.header_values
            header_values = []
            for scheme in schemes:
                lower_scheme = scheme.lower()
                if lower_scheme in used_schemes:
                    if lower_scheme == "dpop":
                        v = ", ".join([values, 'algs="RS256 PS256 ES256"'])
                    else:
                        v = values
                    header_values.append(f"{scheme} " + v)
                else:
                    if lower_scheme == "dpop":
                        header_values.append(f'{scheme} algs="RS256 PS256 ES256"')
                    else:
                        header_values.append(f"{scheme}")

            headers.update({"WWW-Authenticate": ", ".join(header_values)})
        if hasattr(self, "nonce"):
            headers.update({"DPoP-Nonce": getattr(self, "nonce")})
        return headers

    @property
    def redirect_required(self):
        return True


class FatalClientError(OAuth2Error):
    """
    Errors during authorization where user should not be redirected back.

    If the request fails due to a missing, invalid, or mismatching
    redirection URI, or if the client identifier is missing or invalid,
    the authorization server SHOULD inform the resource owner of the
    error and MUST NOT automatically redirect the user-agent to the
    invalid redirection URI.

    Instead the user should be informed of the error by the provider itself.
    """

    @property
    def redirect_required(self):
        return False
