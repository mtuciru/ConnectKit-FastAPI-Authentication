class OAuthFrontendClient:
    id = None
    display_name = "Frontend"
    client_id = "frontend"
    client_secret = None
    enabled = True
    confidential = False
    for_user_id = None
    grant_type = "password"
    allow_credentials_grant = False
    allow_refresh_grant = True
    required_scopes = []
    redirect_uris = []
    system_client = True
    access_lifetime = None
    refresh_lifetime_short = None
    refresh_lifetime_long = None
    password_confirm_lifetime = None
