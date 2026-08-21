from copy import deepcopy

import json_adapter as json

__all__ = [
    "openapi_authorization_start_extra", "openapi_authorization_end_extra", "openapi_device_authorization_extra",
    "openapi_device_verify_start_extra", "openapi_device_verify_end_extra", "openapi_revoke_extra",
    "openapi_introspect_extra", "openapi_token_extra", "openapi_userinfo_extra", "openapi_jwks_extra",
    "openapi_oauth_metadata_extra", "openapi_oidc_metadata_extra"
]

# -*- OpenAPI Extra -*-

#
openapi_authorization_start_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description":
                                "The client identifier as described in [RFC6749, Section 2.2].\n"
                                "The client_id must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "response_type": {
                            "description":
                                "The response type as described in [RFC6749, Section 3.1.1].\n"
                                "Several response_type's may be registered for client",
                            "type": "string",
                            "default": ""
                        },
                        "redirect_uri": {
                            "description":
                                "The redirection endpoint URI as described in [RFC6749, Section 3.1.2].\n\n"
                                "If several redirect URIs registered for client, this parameter *REQUIRED*.\n\n"
                                "If OIDC extension used, this parameter *REQUIRED*.",
                            "type": "string",
                            "default": ""
                        },
                        "scope": {
                            "description":
                                "Access Token Scope as described in [RFC6749, Section 3.3].\n"
                                "If not presented, default scope of client used.\n\n"
                                '*Note*: for OpenID Connect use this parameter with scope value "openid"\n'
                                "for enable OpenID Connect logic (default scopes not enable OIDC and raise\n"
                                'error if "openid" value presented)',
                            "type": "string",
                            "default": ""
                        },
                        "state": {
                            "description":
                                "An opaque value used by the client to maintain state\n"
                                "between the request and callback. Server return this value unchanged."
                                "The parameter *SHOULD* be used for preventing cross-site request forgery\n"
                                "as described in [RFC6749, Section 10.12].",
                            "type": "string",
                            "default": ""
                        },
                        "response_mode": {
                            "description":
                                "The response mode as described in\n"
                                "[OAuth 2.0 Multiple Response Type Encoding Practices, Section 2.1].\n\n"
                                'Default value depends on grand_type and selected from "query" and "fragment".\n'
                                'You can explicit set response_mode to this two values and "form_post".',
                            "type": "string",
                            "default": ""
                        },
                        "nonce": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "Like as state, but used to associate a Client session with returned ID Token.\n"
                                "This value will be included in id_token unmodified."
                                "The nonce value is a case-sensitive string.",
                            "type": "string",
                            "default": "",
                        },
                        "display": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "ASCII string value that is a hint for the server how to display\n"
                                "the authentication and consent user interface pages to the End-User.\n"
                                "Server *MAY* ignore this hint by its reasons.\n\n"
                                "The defined values in specification are:\n\n"
                                "- page\n\n"
                                "   The Authorization Server SHOULD display the authentication and consent UI\n"
                                "   consistent with a full User Agent page view.\n"
                                "   If the display parameter is not specified, this is the default display mode.\n\n"
                                "- popup\n\n"
                                "   The Authorization Server SHOULD display the authentication and consent UI\n"
                                "   consistent with a popup User Agent window.\n"
                                "   The popup User Agent window should be of an appropriate size for a login-focused dialog\n"
                                "   and should not obscure the entire window that it is popping up over.\n\n"
                                "- touch\n\n"
                                "   The Authorization Server SHOULD display the authentication and consent UI\n"
                                "   consistent with a device that leverages a touch interface.\n\n"
                                "- wap\n\n"
                                "   The Authorization Server SHOULD display the authentication and consent UI\n"
                                '   consistent with a "feature phone" type display.',
                            "type": "string",
                            "default": ""
                        },
                        "prompt": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "Space-delimited, case-sensitive list of ASCII string values that specifies whether\n"
                                "the Authorization Server prompts the End-User for reauthentication and consent.\n"
                                "Server MAY prompts user by its reasons.\n\n"
                                "The defined in specification values are:\n\n"
                                "- none\n\n"
                                "   The Authorization Server *MUST NOT* display any authentication or consent\n"
                                '   user interface pages. The error "interaction_required" is returned\n'
                                "   if an End-User is not already authenticated\n"
                                "   or the Client does not have pre-configured consent.\n"
                                "   An other error is returned if does not fulfill other conditions for processing the request.\n"
                                "   This can be used as a method to check for existing authentication and/or consent.\n\n"
                                "- login\n\n"
                                "   The Authorization Server *SHOULD* prompt the End-User for reauthentication.\n"
                                '   If it cannot reauthenticate the End-User, it *MUST* return the error "login_required".\n\n'
                                "- consent\n\n"
                                "   The Authorization Server *SHOULD* prompt the End-User for consent\n"
                                "   before returning information to the Client. If it cannot obtain consent,\n"
                                '   it MUST return the error "consent_required".\n\n'
                                "- select_account\n\n"
                                "   The Authorization Server *SHOULD* prompt the End-User to select a user account.\n"
                                "   This enables an End-User who has multiple accounts at the Authorization Server\n"
                                "   to select amongst the multiple accounts that they might have current sessions for.\n"
                                "   If it cannot obtain an account selection choice made by the End-User,\n"
                                '   it *MUST* return the error "account_selection_required".',
                            "type": "string",
                            "default": ""
                        },
                        "max_age": {
                            "description":
                                "Maximum Authentication Age.\n"
                                "Specifies the allowable elapsed time in seconds since the last time the End-User\n"
                                "was actively authenticated by the OP. If the elapsed time is greater than this value,\n"
                                "the OP *MUST* attempt to actively re-authenticate the End-User.\n\n"
                                "*For OIDC:*\n\n"
                                "When max_age is used, the ID Token returned *MUST* include an auth_time Claim Value.\n\n"
                                "*Note:* max_age=0 is equivalent to prompt=login.",
                            "type": "integer",
                            "default": ""
                        },
                        "ui_locales": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "End-User's preferred languages and scripts for the user interface,\n"
                                "represented as a space-separated list of BCP47 [RFC5646] language tag values,\n"
                                'ordered by preference. For instance, the value "fr-CA fr en" represents a preference\n'
                                'for French as spoken in Canada, then French (without a region designation),\n'
                                'followed by English (without a region designation).\n'
                                'An error *SHOULD NOT* result if some or all of the requested locales are not supported\n'
                                'by the OpenID Provider.',
                            "type": "string",
                            "default": ""
                        },
                        "id_token_hint": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "ID Token previously issued by the Authorization Server being passed as a hint\n"
                                "about the End-User's current or past authenticated session with the Client.\n"
                                "If the End-User identified by the ID Token is already logged in or is logged in\n"
                                "as a result of the request, then the Authorization Server returns a positive response;\n"
                                'otherwise, it *MUST* return the error "login_required".\n'
                                'When possible, an id_token_hint *SHOULD* be present when prompt=none is used.',
                            "type": "string",
                            "default": ""
                        },
                        "login_hint": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "Hint to the Authorization Server about the login identifier the End-User\n"
                                "might use to log in (if necessary). This hint can be used by an RP if it first asks\n"
                                "the End-User for their e-mail address and then wants to pass that value as a hint to\n"
                                "the discovered authorization service. It is *RECOMMENDED* that the hint value match the\n"
                                "value used for discovery. This value *MAY* also be a phone number or login identifier.\n",
                            "type": "string",
                            "default": ""
                        },
                        "acr_values": {
                            "description":
                                "Requested Authentication Context Class Reference values.\n"
                                "Space-separated string that specifies the acr values that the Authorization Server\n"
                                "is being requested to use for processing this Authentication Request,\n"
                                "with the values appearing in order of preference.\n"
                                "*For OIDC:*\n\n"
                                "The Authentication Context Class satisfied by the authentication performed is returned\n"
                                "as the acr Claim Value, as specified in Section 2.\n"
                                "The acr Claim is requested as a Voluntary Claim by this parameter.",
                            "type": "string",
                            "default": ""
                        },
                        "claims_locales": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "End-User's preferred languages and scripts for Claims being returned,\n"
                                "represented as a space-separated list of BCP47 [RFC5646] language tag values,\n"
                                "ordered by preference. An error *SHOULD NOT* result if some or all of the requested\n"
                                "locales are not supported by the OpenID Provider.",
                            "type": "string",
                            "default": ""
                        },
                        "claims": {
                            "description":
                                "**This is OIDC only parameter.**\n\n"
                                "This parameter is used to request that specific Claims be returned.\n"
                                "The value is a JSON object listing the requested Claims.\n"
                                "All not understood claims will be ignored.\n"
                                "Special claims requests such id_token.sub or id_token.acr *MAY* raises errors\n"
                                "(When you request essential acr, but acr not supported).",
                            "type": "string",
                            "default": ""
                        },
                        "registration": {
                            "description":
                                "By specification, this parameter is used by the Client to provide information about\n"
                                "itself to a Self-Issued OP.\n\n"
                                'But, this parameter is forbidden and will rise "registration_not_supported" error',
                            "type": "string",
                            "default": ""
                        },
                        "request": {
                            "description":
                                "By specification this parameter enables OAuth 2.0 or OpenID Connect requests to be\n"
                                "passed in a single, self-contained parameter and to be optionally signed and/or encrypted.\n\n"
                                'But, this parameter is forbidden and will rise "request_not_supported" error',
                            "type": "string",
                            "default": ""
                        },
                        "request_uri": {
                            "description":
                                "By specification this parameter enables OAuth 2.0 and OpenID Connect requests to be\n"
                                "passed by reference, rather than by value. The request_uri value is a URL referencing\n"
                                "a resource containing a Request Object value, which is a JWT containing the request parameters.\n\n"
                                'But at this time, this parameter is forbidden and will rise "request_uri_not_supported" error\n\n'
                                "This parameter will be allowed in the future as part of PAR specification\n"
                                "and inner support for POST authorization logic.\n"
                                "Note that this param will work by OAuth2 manner\n"
                                "(from request will be used only client_id and request_uri parameter, other will be ignored).",
                            "type": "string",
                            "default": ""
                        },
                        "code_challenge": {
                            "description":
                                "Code challenge for PKCE",
                            "type": "string",
                            "default": ""
                        },
                        "code_challenge_method": {
                            "description":
                                "Code challenge method for PKCE.\n"
                                'Defaults to "plain" if not present in the request. Code verifier transformation method\n'
                                'is "S256", "S512" or "plain".',
                            "type": "string",
                            "default": ""
                        },
                        "dpop_jkt": {
                            "description":
                                "The value of the dpop_jkt authorization request parameter is the JWK Thumbprint [RFC7638]\n"
                                "of the proof-of-possession public key using the SHA-256 hash function, which is the same\n"
                                "value as used for the jkt confirmation method defined in Section 6.1 of rfc9449.",
                            "type": "string",
                            "default": ""
                        }
                    },
                    "required": ["client_id"]
                }
            }
        }
    },
    "responses": {
        "200": {
            "summary": "Successful response contains validation result, or request to redirection to client",
            "description":
                "Validation result contains basic information about authorize request\n"
                "to help frontend do all required operations.\n\n"
                "Request to redirect contains client error or successful early approved request\n"
                "(if user consent not required)",
            "content": {
                "application/json": {
                    "schema": {
                        "oneOf": [
                            {
                                "type": "object",
                                "description": "Validation result",
                                "properties": {
                                    "oidc": {
                                        "description": "Mode of request: classic OAuth 2.0 or OpenID Connect",
                                        "type": "boolean"
                                    },
                                    "client_id": {
                                        "description": "Client ID extracted from request",
                                        "type": "string"
                                    },
                                    "display_name": {
                                        "description":
                                            "Client human-readable name associated with client_id\n\n"
                                            "*Note:*\n"
                                            "This is not localized version of name. If you realize localization,\n"
                                            'localized variants stored in "options" object',
                                        "type": "string"
                                    },
                                    "scopes": {
                                        "description": "Scopes extracted from request",
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                        }
                                    },
                                    "options": {
                                        "description": "Additional client options",
                                        "type": "object",
                                        "additionalProperties": True,
                                    },
                                    "prompt": {
                                        "description": "Prompt extracted from request or requested by backend",
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                        }
                                    },
                                    "display": {
                                        "description":
                                            'Display hint from request. Present if "oidc" is true',
                                        "type": ["string", "null"]
                                    },
                                    "ui_locales": {
                                        "description":
                                            "UI preferred locales extracted from request.\n"
                                            'Present if "oidc" is true',
                                        "type": ["array", "null"],
                                        "items": {
                                            "type": "string",
                                        }
                                    },
                                    "login_hint": {
                                        "description":
                                            'Login hint extracted from request. Present if "oidc" is true. May be:\n\n'
                                            "- email\n\n"
                                            "   Standard email, validated by backend.\n\n"
                                            "- phone number\n\n"
                                            "   Standard phone number in E164 format, validated by backend.\n\n"
                                            "- login identificator\n\n"
                                            "   ASCII-set user identificator that used by server, validated by backend.",
                                        "type": ["string", "null"]
                                    }
                                },
                                "required": ["oidc", "client_id", "display_name", "scopes", "options", "prompt"],
                            },
                            {
                                "type": "object",
                                "description": "Redirection request",
                                "properties": {
                                    "error": {
                                        "description": "Flag that it is redirection request",
                                        "type": "null"
                                    },
                                    "redirect_uri": {
                                        "description": "Redirect URI.\n\n"
                                                       "If presented, frontend *MUST* navigate browser to this URI.",
                                        "type": "string"
                                    },
                                    "rewrite_html": {
                                        "description": "New HTML.\n\n"
                                                       "If presented, frontend *MUST* call document.write() with it.",
                                        "type": "string"
                                    }
                                },
                                "required": ["error"]
                            },
                        ]
                    },
                    "examples": {
                        "validation_oauth": {
                            "value": {
                                "oidc": False,
                                "client_id": "ghjgjygjygyj",
                                "display_name": "My App",
                                "scopes": [
                                    "user:read"
                                ],
                                "options": {
                                    "cool_name": "Super My App"
                                },
                                "prompt": [
                                    "login"
                                ]
                            }
                        },
                        "validation_oidc": {
                            "value": {
                                "oidc": True,
                                "client_id": "ffsefsefe",
                                "display_name": "Github sign-in",
                                "scopes": [
                                    "openid"
                                ],
                                "options": {},
                                "prompt": [
                                    "consent"
                                ],
                                "display": "popup",
                                "ui_locales": None,
                                "login_hint": None
                            }
                        },
                        "request_redirect": {
                            "value": json.dumps({
                                "error": None,
                                "redirect_uri": "https://example.com/cb?error=invalid_request",
                            })
                        },
                        "request_rewrite": {
                            "value": json.dumps({
                                "error": None,
                                "rewrite_html": "<html><head><title>Authorization result form</title></head>...</html>",
                            })
                        }
                    }
                }
            }
        },
        "400": {
            "summary": "Fatal OAuth 2.0 validation error",
            "description":
                "OAuth 2.0 error response that can't be redirected to client\n"
                "and must be displayed to EndUser.",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            },
                            "state": {
                                "description": '"state" parameter from request',
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "EndUser authorization error",
            "description":
                "EndUser access token invalid",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_token"
                            },
                            "detail": {
                                "description": "Alias for error property because FastAPI standard error response contains this field.",
                                "type": "string",
                                "default": "invalid_token"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "403": {
            "summary": "EndUser authorization error",
            "description":
                "EndUser access token invalid",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "access_denied"
                            },
                            "detail": {
                                "description": "Alias for error property because FastAPI standard error response contains this field.",
                                "type": "string",
                                "default": "access_denied"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }
                }
            }
        }
    }
}
#
openapi_authorization_end_extra = deepcopy(openapi_authorization_start_extra)
openapi_authorization_end_extra["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"][
    "properties"
]["approve"] = {
    "description":
        "If EndUser allow authorization for client, it's parameter is True",
    "type": "boolean",
    "default": False
}
openapi_authorization_end_extra["responses"]["200"]["content"]["application/json"]["schema"] = {
    "type": "object",
    "description": "Redirection request",
    "properties": {
        "error": {
            "description": "Flag that it is redirection request",
            "type": "null"
        },
        "redirect_uri": {
            "description": "Redirect URI.\n\n"
                           "If presented, frontend *MUST* navigate browser to this URI.",
            "type": "string"
        },
        "rewrite_html": {
            "description": "New HTML.\n\n"
                           "If presented, frontend *MUST* call document.write() with it.",
            "type": "string"
        }
    },
    "required": ["error"]
}
del openapi_authorization_end_extra["responses"]["200"]["content"]["application/json"]["examples"]["validation_oauth"]
del openapi_authorization_end_extra["responses"]["200"]["content"]["application/json"]["examples"]["validation_oidc"]
#
openapi_device_authorization_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description":
                                "The client identifier as described in [RFC6749, Section 2.2].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_id must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "scope": {
                            "description":
                                "Access Token Scope as described in [RFC6749, Section 3.3].\n"
                                "If not presented, default scope of client used.\n\n"
                                '*Note*: for OpenID Connect use this parameter with scope value "openid"\n'
                                '(default scopes also allowed because this flow can not receive specific OIDC parameters,\n'
                                'but id_token will be added)',
                            "type": "string",
                            "default": ""
                        },
                        "client_secret": {
                            "description":
                                "The client secret as described in [RFC6749, TODO].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_secret must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        }
                    },
                    "required": []
                }
            }
        }
    },
    "responses": {
        "200": {
            "summary": "Successful response contains generated code pair and verify_uri",
            "description":
                "As defined in specification, device_code, user_code and verification url.",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "description": "Device code response",
                        "properties": {
                            "device_code": {
                                "description": "Device code for requests on token endpoint",
                                "type": "string"
                            },
                            "user_code": {
                                "description": "User code that user must input on verification page",
                                "type": "string"
                            },
                            "expires_in": {
                                "description":
                                    "Time in second after that device code expires",
                                "type": "integer"
                            },
                            "interval": {
                                "description": "Initial pull interval in seconds on token endpoint",
                                "type": "integer"
                            },
                            "verification_uri": {
                                "description": "URI address of user code verification page",
                                "type": "string"
                            },
                            "verification_uri_complete": {
                                "description": "Optional URI address of user code verification page that include user_code.\n"
                                               "Can be used to open the page with the inserted user code.",
                                "type": "string"
                            }
                        },
                        "required": ["device_code", "user_code", "expires_in", "interval", "verification_uri"],
                    },
                    "example": {
                        "device_code": "very_long_secure_unguessable_random_string",
                        "user_code": "Eight-character ASCII letter code with a separator, user-friendly but with high entropy",
                        "expires_in": 3600,
                        "verification_uri": "https://example.com/user/verify_device"
                    }
                }
            }
        },
        "400": {
            "summary": "Any OAuth 2.0 validation error",
            "description":
                "All validation errors returned to client (because this URI called only from client)",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "Client authentication failed.",
            "description":
                "Client not send valid credentials",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_client"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        }
    }
}
#
openapi_device_verify_start_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "user_code": {
                            "description":
                                "User code returned to device that initiate authorization process",
                            "type": "string",
                            "default": ""
                        }
                    },
                    "required": ["user_code"]
                }
            }
        }
    },
    "responses": {
        "200": {
            "summary": "Successful response contains information about user_code and client",
            "description":
                "Information for EndUser about code and client",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "description": "Device code response",
                        "properties": {
                            "expired": {
                                "description": "Expiration status of user_code",
                                "type": "boolean"
                            },
                            "approved": {
                                "description": "If presented as bool its mean approved or rejected",
                                "type": ["boolean", "null"]
                            },
                            "client": {
                                "description":
                                    "Client info presented if expired is False",
                                "type": "object",
                                "properties": {
                                    "client_id": {
                                        "description": "Client ID",
                                        "type": "string",
                                    },
                                    "display_name": {
                                        "description": "Display name of Client",
                                        "type": "string",
                                    },
                                    "scopes": {
                                        "description": "Scopes requested by client",
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                        }
                                    },
                                    "options": {
                                        "description": "Additional options about client",
                                        "type": "object",
                                        "additionalProperties": True
                                    }
                                }
                            }
                        },
                        "required": ["expired"],
                    },
                    "example": {
                        "expired": False,
                        "approved": False,
                        "client": {
                            "client_id": "adsawds",
                            "display_name": "Github client",
                            "scopes": ["openid"],
                            "options": {}
                        }
                    }
                }
            }
        },
        "400": {
            "summary": "Any OAuth 2.0 validation error",
            "description":
                "All validation errors returned to client (because this URI called only from client)",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "EndUser authentication failed.",
            "description":
                "End user is not authenticated",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_token"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "403": {
            "summary": "EndUser access denied.",
            "description":
                "Access denied to this operation",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "access_denied"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        }
    }
}
#
openapi_device_verify_end_extra = deepcopy(openapi_device_verify_start_extra)
openapi_device_verify_end_extra["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"][
    "properties"
]["approve"] = {
    "description":
        "If EndUser allow authorization for client, it's parameter is True",
    "type": "boolean",
    "default": False
}
# noinspection PyTypeChecker
openapi_device_verify_end_extra["responses"]["200"]["content"]["application/json"] = {
    "schema": {
        "type": "object",
        "description": "Status of operation",
        "properties": {
            "success": {
                "type": "boolean"
            },
        },
        "required": ["success"],
    },
}
#
openapi_revoke_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description":
                                "The client identifier as described in [RFC6749, Section 2.2].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_id must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "client_secret": {
                            "description":
                                "The client secret as described in [RFC6749, TODO].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_secret must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "token": {
                            "description":
                                "Token that must be revoked",
                            "type": "string",
                            "default": ""
                        },
                        "token_type_hint": {
                            "description":
                                "Token hint to find token. Can be ignored by server or unsupported_token_type error raised",
                            "type": "string",
                            "default": ""
                        },
                        "callback": {
                            "description":
                                "Name of js function that will called with revoke result.\n\n"
                                "**Note:**\n\n"
                                "callback value not validated and returned as is with concatenation brackets",
                            "type": "string",
                            "default": ""
                        }
                    },
                    "required": ["token"]
                }
            }
        }
    },
    "responses": {
        "200": {
            "summary": "Successful revocation response",
            "description":
                "As defined in specification",
            "content": {
                "text/plain": {
                    "schema": {
                        "description": "Empty string if callback is not specified",
                        "type": "string",
                    }
                },
                "text/javascript": {
                    "schema": {
                        "description": "Callback call without arguments",
                        "type": "string",
                    }
                }
            }
        },
        "400": {
            "summary": "Any OAuth 2.0 validation error",
            "description":
                "All validation errors returned to client (because this URI called only from client)",
            "content": {
                "text/javascript": {
                    "schema": {
                        "description": "Callback call with error json as argument",
                        "type": "string",
                    }
                },
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "Client authentication failed.",
            "description":
                "Client not send valid credentials",
            "content": {
                "text/javascript": {
                    "schema": {
                        "description": "Callback call with error json as argument",
                        "type": "string",
                    }
                },
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_client"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }
                }
            }
        }
    }
}
#
openapi_introspect_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description":
                                "The client identifier as described in [RFC6749, Section 2.2].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_id must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "client_secret": {
                            "description":
                                "The client secret as described in [RFC6749, TODO].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_secret must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "token": {
                            "description":
                                "Token that must be revoked",
                            "type": "string",
                            "default": ""
                        },
                        "token_type_hint": {
                            "description":
                                "Token hint to find token. Can be ignored by server or unsupported_token_type error raised",
                            "type": "string",
                            "default": ""
                        }
                    },
                    "required": ["token"]
                }
            }
        }
    },
    "responses": {
        "200": {
            "summary": "Successful introspection response",
            "description":
                "As defined in specification",
            "content": {
                "application/json": {
                    "schema": {
                        "description": "Claims about token, 'active' is presented always",
                        "type": "object",
                        "properties": {
                            "active": {
                                "description": "Status of token, true is valid token, false otherwise"
                            }
                        },
                        "additionalProperties": True,
                        "required": ["active"]
                    }
                }
            }
        },
        "400": {
            "summary": "Any OAuth 2.0 validation error",
            "description":
                "All validation errors returned to client (because this URI called only from client)",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "Client authentication failed.",
            "description":
                "Client not send valid credentials",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_client"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }
                }
            }
        }
    }
}
#
openapi_token_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/x-www-form-urlencoded": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "client_id": {
                            "description":
                                "The client identifier as described in [RFC6749, Section 2.2].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_id must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "client_secret": {
                            "description":
                                "The client secret as described in [RFC6749, TODO].\n"
                                "This parameter required only for client_secret_post method of client authentication.\n"
                                "The client_secret must be obtained through the client registration mechanism.",
                            "type": "string",
                            "default": ""
                        },
                        "grant_type": {
                            "description":
                                "Grant type select authorization flow for obtaining tokens.",
                            "type": "string",
                            "default": ""
                        },
                        "redirect_uri": {
                            "description":
                                "The redirection endpoint URI as described in [RFC6749, Section 3.1.2].\n\n"
                                "This parameter required if in authorization request contains 'redirect_uri'.",
                            "type": "string",
                            "default": ""
                        },
                        "code": {
                            "description":
                                "",
                            "type": "string",
                            "default": ""
                        },
                        "scope": {
                            "description":
                                "Access Token Scope as described in [RFC6749, Section 3.3].\n"
                                "If not presented, default scope of client used.\n\n"
                                '*Note*: for OpenID Connect use this parameter with scope value "openid"\n'
                                "for enable OpenID Connect logic (default scopes not enable OIDC and raise\n"
                                'error if "openid" value presented)',
                            "type": "string",
                            "default": ""
                        },
                        "device_code": {
                            "description":
                                "",
                            "type": "string",
                            "default": ""
                        },
                        "refresh_token": {
                            "description":
                                "",
                            "type": "string",
                            "default": ""
                        },
                        "username": {
                            "description":
                                "",
                            "type": "string",
                            "default": ""
                        },
                        "password": {
                            "description":
                                "",
                            "type": "string",
                            "default": ""
                        },
                        "code_verifier": {
                            "description":
                                "",
                            "type": "string",
                            "default": ""
                        },
                        "long": {
                            "description":
                                "",
                            "type": "boolean",
                            "default": False
                        }
                    },
                    "required": ["grant_type"]
                }
            }
        }
    },
    "responses": {
        "200": {
            "summary": "Successful token response",
            "description":
                "As defined in specification",
            "content": {
                "application/json": {
                    "schema": {
                        "description": "Return tokens depends on 'grand_type' parameter.",
                        "type": "object",
                        "properties": {
                            "access_token": {
                                "description": "",
                                "type": "string",
                            },
                            "token_type": {
                                "description": "",
                                "type": "string",
                            },
                            "expires_in": {
                                "description": "",
                                "type": "integer",
                            },
                            "scope": {
                                "description": "",
                                "type": "string",
                            },
                            "refresh_token": {
                                "description": "",
                                "type": "string",
                            },
                            "id_token": {
                                "description": "",
                                "type": "string",
                            }
                        },
                        "required": ["access_token", "token_type"]
                    }
                }
            }
        },
        "400": {
            "summary": "Any OAuth 2.0 validation error",
            "description":
                "All validation errors returned to client (because this URI called only from client)",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "Client authentication failed.",
            "description":
                "Client not send valid credentials",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_client"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }
                }
            }
        },
        "403": {
            "summary": "Client access denied.",
            "description":
                "Client access denied",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "access_denied"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }
                }
            }
        }
    }
}
#
openapi_userinfo_extra = {
    "responses": {
        "200": {
            "summary": "Successful userinfo response",
            "description":
                "As defined in specification",
            "content": {
                "application/json": {
                    "schema": {
                        "description": "Return claims about user as described in OIDC",
                        "type": "object",
                        "additionalProperties": True,
                        "required": []
                    }
                },
                "application/jwt": {
                    "schema": {
                        "description": "Return claims about user as described in OIDC as JWT string",
                        "type": "string",
                    }
                }
            }
        },
        "400": {
            "summary": "Any OAuth 2.0 validation error",
            "description":
                "All validation errors",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_request"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }

                }
            }
        },
        "401": {
            "summary": "User authentication failed.",
            "description":
                "Specified token invalid",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "error": {
                                "description": "Error ASCII code as defined in specifications",
                                "type": "string",
                                "default": "invalid_token"
                            },
                            "error_description": {
                                "description": "Human-readable ASCII-set error description",
                                "type": "string"
                            },
                            "error_uri": {
                                "description": "URI link to page with error description (or other information)",
                                "type": "string"
                            }
                        },
                        "required": ["error"]
                    }
                }
            }
        },
    }
}
#
openapi_jwks_extra = {
    "responses": {
        "200": {
            "summary": "JWKs json with RSA public keys used by clients to validate id_token JWT and others",
            "description":
                "As defined in specification",
            "content": {
                "application/json": {
                    "schema": {
                        "description": "JSON jwks",
                        "type": "object",
                        "properties": {
                            "keys": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "kty": {
                                            "type": "string",
                                            "default": "RSA"
                                        },
                                        "kid": {
                                            "description": "Unique public key id, add in headers of id_token and others",
                                            "type": "string",
                                        },
                                        "alg": {
                                            "type": "string",
                                            "default": "RS256"
                                        },
                                        "use": {
                                            "type": "string",
                                            "default": "sig"
                                        },
                                        "n": {
                                            "description": "RSA public number n encoded",
                                            "type": "string",
                                        },
                                        "e": {
                                            "description": "RSA public number e encoded",
                                            "type": "string",
                                        }
                                    },
                                    "required": ["kty", "kid", "alg", "use", "n", "e"]
                                }
                            }
                        },
                        "required": ["keys"]
                    }
                }
            }
        }
    }
}
#
openapi_oauth_metadata_extra = {
    "responses": {
        "200": {
            "summary": "",
            "description":
                "As defined in specification.\n\nOnly required fields presented always. Other may be omitted.",
            "content": {
                "application/json": {
                    "schema": {
                        "description": "JSON jwks",
                        "type": "object",
                        "properties": {
                            "issuer": {
                                "description":
                                    "Issuer URL without query and fragment",
                                "type": "string",
                                "default": "http://localhost/"
                            },
                            "authorization_endpoint": {
                                "description":
                                    "Endpoint URL for client authorization by End-User.\n\n"
                                    "On this URL client redirect user via browser or other user-agent.",
                                "type": "string",
                                "default": "http://localhost/oauth/authorize"
                            },
                            "token_endpoint": {
                                "description":
                                    "Endpoint URL from that client take access_token.",
                                "type": "string",
                            },
                            "jwks_uri": {
                                "description":
                                    "Endpoint URL from that client take jwks.",
                                "type": "string",
                            },
                            "scopes_supported": {
                                "description":
                                    "List of supported scope values. It may be not all allowed scopes for security reasons.\n\n"
                                    "For OIDC exists special values (at least 'openid')",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["some:scope"],
                            },
                            "response_types_supported": {
                                "description":
                                    "List of supported response types for authorization flow.\n"
                                    "For each registered client supported own subset.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["code", "none", "token"],
                            },
                            "response_modes_supported": {
                                "description":
                                    "List of supported response modes for authorization flow.\n"
                                    "Client may request explicit response mode",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["query", "fragment", "form_post"],
                            },
                            "grant_types_supported": {
                                "description":
                                    "List of supported grants for token endpoint.\n"
                                    "For each registered client allowed only one method + optional 'refresh_token'",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["password", "refresh_token"],
                            },
                            "token_endpoint_auth_methods_supported": {
                                "description":
                                    "List of supported authentication methods for client.\n"
                                    "Only password-based methods are supported.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["client_secret_basic", "client_secret_post", "none"],
                            },
                            "code_challenge_methods_supported": {
                                "description":
                                    "List of supported PKCE methods for client.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["plain", "S256", "S512"],
                            },
                            "dpop_signing_alg_values_supported": {
                                "description":
                                    "List of signing algorithms supported by server for validating DPoP token from client.\n\n"
                                    "Note: RS256 & PS256 using same RSA key, but ES256 using EC key.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["RS256", "PS256", "ES256"],
                            },
                            "authorization_response_iss_parameter_supported": {
                                "description":
                                    "Extension for OAuth 2.0. In response from authorize endpoint 'iss' parameter included\n"
                                    "with issuer value from metadata.",
                                "type": "boolean",
                                "default": True,
                            },
                            "acr_values_supported": {
                                "description":
                                    "List of ACR supported by server.\n\n"
                                    "This list used for two extensions: OIDC and RFC 9470.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                }
                            },
                            "service_documentation": {
                                "description":
                                    "Endpoint URL with server documentation.",
                                "type": "string",
                            },
                            "ui_locales_supported": {
                                "description":
                                    "List of UI language tags supported by server.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                }
                            },
                            "op_policy_uri": {
                                "description":
                                    "Endpoint URL with server policy document.",
                                "type": "string",
                            },
                            "op_tos_uri": {
                                "description":
                                    "Endpoint URL with server TOS document.",
                                "type": "string",
                            },
                            "device_authorization_endpoint": {
                                "description":
                                    "Endpoint URL for device authorization flow.",
                                "type": "string",
                            },
                            "revocation_endpoint": {
                                "description":
                                    "Endpoint URL for token revoke.",
                                "type": "string",
                            },
                            "revocation_endpoint_auth_methods_supported": {
                                "description":
                                    "List of supported authentication methods for client.\n"
                                    "Only password-based methods are supported.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["client_secret_basic", "client_secret_post", "none"],
                            },
                            "introspection_endpoint": {
                                "description":
                                    "Endpoint URL for token introspect.",
                                "type": "string",
                            },
                            "introspection_endpoint_auth_methods_supported": {
                                "description":
                                    "List of supported authentication methods for client.\n"
                                    "Only password-based methods are supported.",
                                "type": "array",
                                "items": {
                                    "type": "string",
                                },
                                "default": ["client_secret_basic", "client_secret_post", "none"],
                            },
                            "userinfo_endpoint": {
                                "description":
                                    "Endpoint URL for userinfo requests.\n\n"
                                    "This endpoint used for classic OAuth 2.0 and OIDC",
                                "type": "string",
                            },
                            "signed_metadata": {
                                "description":
                                    "As described in OAuth 2.0 Metadata, signed metadata JWT",
                                "type": "string",
                            }
                        },
                        "required": [
                            "issuer", "token_endpoint", "jwks_uri", "response_types_supported",
                            "response_modes_supported", "grant_types_supported", "userinfo_endpoint",
                            "token_endpoint_auth_methods_supported", "code_challenge_methods_supported",
                            "dpop_signing_alg_values_supported", "authorization_response_iss_parameter_supported",
                        ]
                    }
                }
            }
        }
    }
}
#
openapi_oidc_metadata_extra = deepcopy(openapi_oauth_metadata_extra)
openapi_oidc_metadata_extra["responses"]["200"]["content"]["application/json"]["schema"]["properties"].update({
    "subject_types_supported": {
        "description":
            "List of supported subject types for client.\n"
            "Type of subject registered per client",
        "type": "array",
        "items": {
            "type": "string",
        },
        "default": ["public", "pairwise"],
    },
    "id_token_signing_alg_values_supported": {
        "description":
            "List of supported algorithms for signing id_token.\n"
            "Only RS256 supported",
        "type": "array",
        "items": {
            "type": "string",
        },
        "default": ["RS256"],
    },
    "userinfo_signing_alg_values_supported": {
        "description":
            "List of supported algorithms for signing userinfo if jwt result registered for client.\n"
            "Only RS256 supported",
        "type": "array",
        "items": {
            "type": "string",
        },
        "default": ["RS256"],
    },
    "display_values_supported": {
        "description":
            "List of supported values for display parameter.\n"
            "Unsupported values will be ignored",
        "type": "array",
        "items": {
            "type": "string",
        }
    },
    "claim_types_supported": {
        "description":
            "List of supported types of claims for claims parameter.\n"
            "Unsupported values will be ignored",
        "type": "array",
        "items": {
            "type": "string",
        },
        "default": ["normal"]
    },
    "claims_supported": {
        "description":
            "List of supported claims names for claims parameter.\n"
            "Unsupported values will be ignored.\n"
            "Some names may be excluded from list by security reasons",
        "type": "array",
        "items": {
            "type": "string",
        }
    },
    "claims_locales_supported": {
        "description":
            "List of supported claims UI locales for human-readable claims in id_token or userinfo.\n"
            "Unsupported values will be ignored.",
        "type": "array",
        "items": {
            "type": "string",
        }
    },
    "claims_parameter_supported": {
        "description":
            "It says whether the claims parameter is allowed in authorization request or not",
        "type": "boolean",
        "default": True,
    },
    "request_parameter_supported": {
        "description":
            "It says whether the request parameter is allowed in authorization request or not",
        "type": "boolean",
        "default": False,
    },
    "request_uri_parameter_supported": {
        "description":
            "It says whether the request_uri parameter is allowed in authorization request or not",
        "type": "boolean",
        "default": False,
    }
})
openapi_oidc_metadata_extra["responses"]["200"]["content"]["application/json"]["schema"]["required"].append([
    "scopes_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
    "userinfo_signing_alg_values_supported", "claim_types_supported", "claims_parameter_supported",
    "request_parameter_supported", "request_uri_parameter_supported"
])
#
