from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select
from sqlalchemy.orm import load_only
import json_adapter as json

from oauth2lib.common import Request, safe_string_equals
from oauth2lib.tokens import claims_extracting
from oauth2lib.validators import RequestValidator, ClientRepresentation, UserRepresentation
from oauth2lib.validators.claims import is_email, is_phone_number, is_login, normalize_email, normalize_phone_number
from .tokens import get_subject_id
from ..control.hooks import (get_client_authorize_options, get_nonce_by_key_hook, validate_jti_hook,
                             transform_scopes_hook, within_scopes_hook)
from .special import frontend_client_id, frontend_params

from ..models import OAuth2Client, User, OAuth2Code, OAuth2DeviceCode, GrantType, UserLock

__all__ = ["request_validator"]

from ..settings import function_settings


class MyRequestValidator(RequestValidator):
    # -*- Client processing section -*-

    async def client_identification(self, request: Request) -> ClientRepresentation | None:
        # This method called only if /authorize method called
        # But special frontend client not use this method
        if request.client_id == frontend_client_id:
            return None
        # Select from database client for perform /authorize method
        client: OAuth2Client = await request.db.scalar(select(OAuth2Client).options(load_only(
            OAuth2Client.id, OAuth2Client.display_name, OAuth2Client.enabled,
            OAuth2Client.confidential, OAuth2Client.for_user_id, OAuth2Client._redirect_uris,
            OAuth2Client._response_types, OAuth2Client.scope, OAuth2Client.max_scope, OAuth2Client.transparent
        )).filter_by(client_id=request.client_id))
        if client is None:
            return None
        if not client.enabled:
            return None
        # Transparent client acts as user-agent (as frontend, other words), so /authorise method not allowed
        if client.transparent:
            return None
        if client.for_user_id is not None:
            if client.for_user_id != request.user.id:
                return None
        request.store["client"] = client
        return ClientRepresentation(
            id=client.id,
            client_id=request.client_id,
            display_name=client.display_name
        )

    @staticmethod
    async def get_client_options(request: Request) -> dict[str, Any]:
        # Form client options for frontend to display
        client: OAuth2Client = request.store["client"]
        options = {
            "max_scopes": client.max_scopes,
            "confidential": client.confidential,
        }
        options.update(await get_client_authorize_options(request.client.id))
        return options

    async def client_authentication_required(self, request: Request) -> bool:
        # This special client not require authentication
        if request.client_id == frontend_client_id:
            # If credentials specified, must validate its
            return request.has_credentials()
        request.validate_client_credentials()
        client: OAuth2Client = await request.db.scalar(select(OAuth2Client).options(load_only(
            OAuth2Client.id, OAuth2Client._client_secret, OAuth2Client.enabled,
            OAuth2Client.confidential, OAuth2Client.transparent, OAuth2Client.dpop_bound
        )).filter_by(client_id=request.client_id))
        if client is None:
            return request.has_credentials()
        if not client.enabled:
            return request.has_credentials()
        request.store["client"] = client
        if client.confidential or client.client_secret is not None:
            return True
        return request.has_credentials()

    async def authenticate_client(self, request: Request) -> ClientRepresentation | None:
        # 'client_authentication_required' already validate credentials, now verify its
        client: OAuth2Client = request.store.get("client")
        if client is None:
            return None
        # Try extract from post
        _, client_secret = request.client_credentials_post
        if client_secret is None:
            # Otherwise extract from basic
            _, client_secret = request.client_credentials_basic
        # If not credentials specified, but required
        if client_secret is None:
            return None
        # Verify client_secret
        if not client.verify_client_secret(client_secret):
            return None
        # Return client representation
        return ClientRepresentation(
            id=client.id,
            client_id=request.client_id,
        )

    async def authenticate_client_id(self, request: Request) -> ClientRepresentation | None:
        # Authentification not required, so simple validate that client exists
        client: OAuth2Client = request.store.get("client")
        if client is None:
            if request.client_id == frontend_client_id:
                # Special frontend client
                return ClientRepresentation(
                    id=None,
                    client_id=frontend_client_id,
                )
            return None
        return ClientRepresentation(
            id=client.id,
            client_id=request.client_id,
        )

    async def is_client_pkce_required(self, request: Request) -> bool:
        return (request.code_challenge is not None or
                request.code_verifier is not None or
                not request.store["client"].confidential)

    async def get_client_origin(self, request: Request) -> str | bool:
        if request.client_id == frontend_client_id:
            # Special frontend client, origin not allowed
            return False
        client: OAuth2Client = request.store["client"]
        if client.confidential or client.transparent:
            # Confidential client not allow origin.
            return False
        _ = await client.awaitable_attrs._redirect_uris
        redirect_uris = client.redirect_uris
        requested_origin = request.headers.get("Origin", "")
        for uri in redirect_uris:
            c = urlsplit(uri)
            uri: str = urlunsplit((c[0], c[1], "", "", ""))
            if requested_origin == uri:
                return uri
        return False

    @staticmethod
    async def is_client_dpop_required(request: Request) -> bool:
        if request.client_id == frontend_client_id:
            # Special frontend client, dpop not required
            return False
        client: OAuth2Client = request.store["client"]
        return await client.awaitable_attrs.dpop_bound

    @staticmethod
    async def get_client_dpop_nonce(request: Request) -> str | None:
        # Request hook with cache key 'client_id' for nonce value
        return await get_nonce_by_key_hook(request.client_id)

    @staticmethod
    async def is_client_dpop_valid_jti(request: Request, iat: datetime, dpop_jti: str) -> bool:
        # Request hook with dpop_jti and iat for validating once use for this dpop (or several)
        return await validate_jti_hook(dpop_jti, iat)

    # -*- redirect_uri processing section -*-

    async def get_default_redirect_uri(self, request: Request) -> str | None:
        client: OAuth2Client = request.store["client"]
        _ = await client.awaitable_attrs._redirect_uris
        redirect_uris = client.redirect_uris
        if len(redirect_uris) == 1:
            return redirect_uris[0]
        return None

    async def is_valid_redirect_uri(self, request: Request) -> bool:
        client: OAuth2Client = request.store["client"]
        _ = await client.awaitable_attrs._redirect_uris
        redirect_uris = client.redirect_uris
        for uri in redirect_uris:
            if safe_string_equals(request.redirect_uri, uri):
                return True
        return False

    # -*- scope processing section -*-

    async def get_default_scopes(self, request: Request) -> list[str]:
        if request.client_id == frontend_client_id:
            # Special frontend client, dpop not required
            user: User = await request.db.scalar(select(User).options(load_only(
                User.id, User.scope
            )).filter_by(id=request.user.id))
            return user.scopes
        client: OAuth2Client = request.store["client"]
        if client.transparent:
            user: User = await request.db.scalar(select(User).options(load_only(
                User.id, User.scope
            )).filter_by(id=request.user.id))
            return user.scopes
        else:
            _ = await client.awaitable_attrs.scope
            return client.scopes

    async def transform_scopes(self, request: Request) -> list[str] | None:
        if request.client_id == frontend_client_id:
            # Frontend client worked only with full user scope, scope from request ignored
            user: User = await request.db.scalar(select(User).options(load_only(
                User.id, User.scope
            )).filter_by(id=request.user.id))
            return user.scopes
        client: OAuth2Client = request.store["client"]
        if client.transparent:
            # As frontend client
            user: User = await request.db.scalar(select(User).options(load_only(
                User.id, User.scope
            )).filter_by(id=request.user.id))
            return user.scopes
        # Call transform hook with requested scopes and maximum scopes for client
        _ = await client.awaitable_attrs.max_scope
        return await transform_scopes_hook(request.scopes, client.max_scopes)

    async def get_refresh_token_scopes(self, request: Request) -> list[str]:
        return request.store["refresh_scopes"]

    async def is_within_refresh_token_scopes(self, refresh_scopes: list[str], request: Request) -> bool:
        return await within_scopes_hook(request.scopes, refresh_scopes)

    # -*- code processing section -*-

    @staticmethod
    async def get_authorization_code_challenge(request: Request) -> str | None:
        return request.store.get("code_challenge")

    async def get_authorization_code_challenge_method(self, request: Request) -> str:
        return request.store["code_challenge_method"]

    async def get_authorization_code_nonce(self, request: Request) -> str | None:
        return request.store.get("code_nonce")

    async def get_authorization_code_redirect_uri(self, request: Request) -> str | None:
        return request.store.get("code_redirect_uri")

    async def get_authorization_code_dpop_jkt(self, request: Request) -> str | None:
        return request.store.get("code_dpop_jkt")

    async def save_authorization_code(self, code_info: dict, request: Request):
        code = OAuth2Code()
        code.code = code_info["code"]
        code.user_id = request.user.id
        code.client_id = request.client.id
        code.scope = request.scope
        code.redirect_uri = code_info.get("redirect_uri")
        code.code_challenge = code_info.get("code_challenge")
        code.code_challenge_method = code_info.get("code_challenge_method")
        code.nonce = code_info.get("nonce")
        code.claims = json.dumps(request.claims) if request.claims is not None else None
        code.dpop_jkt = request.dpop_jkt
        code.expire_at = datetime.now(tz=timezone.utc) + timedelta(minutes=2)
        request.db.add(code)
        await request.db.commit()

    async def save_device_code(self, code_info: dict, request: Request):
        code = OAuth2DeviceCode()
        code.device_code = code_info["device_code"]
        code.user_code = code_info["user_code"]
        code.client_id = request.client.id
        code.scope = request.scope
        code.interval = code_info["interval"]
        code.expire_at = datetime.now(tz=timezone.utc) + timedelta(seconds=code_info["expires_in"])
        request.db.add(code)
        await request.db.commit()

    async def restore_by_authorization_code(self, request: Request) -> bool:
        code: OAuth2Code = await request.db.scalar(select(OAuth2Code).filter_by(
            code=request.code, client_id=request.client.id)
        )
        if code is None:
            return False
        if code.expire_at < datetime.now(tz=timezone.utc):
            await request.db.delete(code)
            await request.db.commit()
            return False
        request.scope = code.scope
        request.user = UserRepresentation(id=code.user_id)
        if code.redirect_uri is not None:
            request.store["code_redirect_uri"] = code.redirect_uri
        if code.code_challenge is not None:
            request.store["code_challenge"] = code.code_challenge
            request.store["code_challenge_method"] = code.code_challenge_method
        if code.nonce is not None:
            request.store["code_nonce"] = code.nonce
        if code.claims is not None:
            request.claims = json.loads(code.claims)
        if code.dpop_jkt is not None:
            request.store["code_dpop_jkt"] = code.dpop_jkt
        return True

    async def get_device_code_error_status(self, request: Request) -> str | None:
        code: OAuth2DeviceCode = await request.db.scalar(select(OAuth2DeviceCode).filter_by(
            device_code=request.device_code, client_id=request.client.id)
        )
        if code is None:
            return "invalid_grant"
        now = datetime.now(tz=timezone.utc)
        if code.expire_at < now:
            await request.db.delete(code)
            await request.db.commit()
            return "expired_token"
        if code.last_pull + timedelta(seconds=code.interval) > now:
            return "slow_down"
        if code.approved is None:
            return "authorization_pending"
        if not code.approved:
            await request.db.delete(code)
            await request.db.commit()
            return "access_denied"
        request.store["code_scope"] = code.scope
        request.store["code_user"] = UserRepresentation(id=code.user_id)
        return None

    async def restore_by_device_code(self, request: Request) -> bool:
        request.scope = request.store.get("code_scope")
        request.user = request.store.get("code_user")
        if request.user is None:
            return False
        return True

    async def forgot_authorization_code(self, request: Request):
        code: OAuth2Code = await request.db.scalar(select(OAuth2Code).filter_by(
            code=request.code, client_id=request.client.id)
        )
        if code is not None:
            await request.db.delete(code)
            await request.db.commit()

    async def forgot_device_code(self, request: Request):
        code: OAuth2DeviceCode = await request.db.scalar(select(OAuth2DeviceCode).filter_by(
            device_code=request.device_code, client_id=request.client.id)
        )
        if code is not None:
            await request.db.delete(code)
            await request.db.commit()

    # -*- grant_type processing section -*-

    async def response_type_is_allowed(self, request: Request) -> bool:
        if request.client_id == frontend_client_id:
            # Special client allow only PasswordGrant
            return False
        client: OAuth2Client = request.store["client"]
        if client.transparent:
            return False
        _ = await client.awaitable_attrs._response_types
        if request.response_type in client.response_types:
            return True
        return False

    async def grant_type_is_allowed(self, request: Request) -> bool:
        if request.client_id == frontend_client_id:
            # Special client allow only PasswordGrant
            return request.grant_type == GrantType.Password.value
        client: OAuth2Client = request.store["client"]
        if client.transparent:
            # For transparent clients oply password allowed
            return request.grant_type == GrantType.Password.value
        if request.grant_type == "refresh_token":
            # If Refresh token emitting enabled, return True
            return await client.awaitable_attrs.emit_refresh_token
        if request.grant_type == await client.awaitable_attrs.grant_type:
            return True
        return False

    # -*- user processing section -*-

    async def authorize_user(self, request: Request) -> UserRepresentation | None:
        if is_login(request.username) and "login" in function_settings.user_login_options:
            # Login via
            user: User = await request.db.scalar(select(User).options(
                load_only(User.id, User.login, User.scope, User.active, User._password)
            ).filter_by(login=request.username))
        elif is_email(request.username) and "email" in function_settings.user_login_options:
            request.username = normalize_email(request.username)
            user: User = await request.db.scalar(select(User).options(
                load_only(User.id, User.login, User.scope, User.active, User._password)
            ).filter_by(email=request.username, email_verified=True))
        elif is_phone_number(request.username) and "phone" in function_settings.user_login_options:
            request.username = normalize_phone_number(request.username)
            user: User = await request.db.scalar(select(User).options(
                load_only(User.id, User.login, User.scope, User.active, User._password)
            ).filter_by(phone=request.username, phone_verified=True))
        else:
            return None
        if user is None:
            return None
        while True:
            user_lock: UserLock = await request.db.scalar(select(UserLock).options(
                load_only(
                    UserLock.id, UserLock.login_via, UserLock.login_attempt_count, UserLock.login_last_attempt_at,
                    UserLock.mfa_via, UserLock.block, UserLock.block_reason, UserLock.deleted
                )
            ).filter_by(id=user.id).with_for_update())

            if user_lock is None:
                user_lock = UserLock()
                user_lock.id = user.id
                request.db.add(user_lock)
                await request.db.commit()
            else:
                break
        # This method worked only with passwords
        if "pwd" not in user_lock.login_via:
            return None
        if user_lock.login_last_attempt_at + timedelta(hours=12) < datetime.now(tz=timezone.utc):
            user_lock.login_attempt_count = 0
        if function_settings.login_attempt_count != 0:
            if function_settings.login_attempt_count < 0:
                if user_lock.login_attempt_count >= (-function_settings.login_attempt_count):
                    request.additional_error_fields = {
                        "remainingAttempts": 0
                    }
                    return None
            else:
                if user_lock.login_attempt_count >= function_settings.login_attempt_count:
                    if not user_lock.block:
                        user_lock.block = True
                        user_lock.block_reason = "All attempts exceeded"
                        await request.db.commit()
                    request.additional_error_fields = {
                        "block": True,
                        "blockReason": user_lock.block_reason
                    }
                    return None
        user_lock.login_last_attempt_at = datetime.now(tz=timezone.utc)
        if user_lock.deleted:
            request.additional_error_fields = {
                "userDeleted": True
            }
            return None
        if user_lock.block:
            request.additional_error_fields = {
                "block": True,
                "blockReason": user_lock.block_reason
            }
            return None
        if not user.verify_password(request.password):
            user_lock.login_attempt_count += 1
            await request.db.commit()
            return None
        request.store["user_mfa_via"] = user_lock.mfa_via
        user_lock.login_attempt_count = 0
        await request.db.commit()
        return UserRepresentation(id=user.id, login=user.login, active=user.active)

    async def is_user_match(self, sub_value: str | None, request: Request) -> bool:
        """
        This method called to check match current and expected by client user sessions.

        sub_value and 'sub' claim from id_token must be valid plain or pairwise user id.
        plain or pairwise dependent of client configuration.

        if sub_value is presented, validate that current user session matches sub_value,
        Then if request.id_token_hint is presented, also validate that current user session matches id_token_hint.

        Only if both validation success and point to the same subject returns True, otherwise returns False.

        Also, always set request.login_hint to requested login

        sub_value extracted from request.claims.id_token.sub.value if exists, None otherwise.

        Method is used by endpoints:
            - /authorization -- only for OIDC AuthorizationCode grant
        """
        # Current user subject depends on current client
        current_sub = get_subject_id(request)
        if request.id_token_hint is not None:
            claims = claims_extracting(
                request.id_token_hint,
                require=['iss', 'aud', 'sub', 'exp', 'iat'],
                allow_expired=True
            )
            
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_login_required(self, request: Request) -> bool:
        """
        This method called to check that current user session required reauthentication.
        This method will be called if request.user presented.

        if prompt value contains 'login' or equal 'none' or max_age and/or arc_values specified, this method will be called.
        If return True, that error 'login_required' or 'interaction_required' will be retuned to client.

        prompt='none' means silent authorization process without user interaction,
        so if user interaction required, error will be returned.

        prompt='login' means user must be reauthenticated, but if this method return True, reauthentication is not happen.
        so error will be returned.

        Method is used by endpoints:
            - /authorization (validation&authorization stage) -- only for OIDC AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_consent_required(self, request: Request) -> bool:
        """
        This method called to check that current user session required consent.
        This method will be called if request.user presented.

        if prompt value contains 'consent' or contains 'select_account' or equal 'none', this method will be called.
        If return True, that error 'consent_required', 'account_selection_required' or 'interaction_required'
        will be retuned to client.

        prompt='none' means silent authorization process without user interaction,
        so if user interaction required, error will be returned.

        prompt='consent' means user must be consent request, but if this method return True, consent is not happen.
        so error will be returned.

        prompt='select_account' means user must be select account, but if this method return True, account is not selected.
        so error will be returned.

        if OAuth2, this method also will be called, for check user consent.

        Method is used by endpoints:
            - /authorization (validation stage) -- for OIDC AuthorizationCode grant
            - /authorization (validation&authorization stage) -- for OIDC and OAuth2 AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def is_user_access_denied(self, request: Request) -> bool:
        """
        This method called to check that current user denied access to client.

        return True if access denied

        Method is used by endpoints:
            - /authorization (authorization stage) -- for OIDC and OAuth2 AuthorizationCode grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    # -*- token processing section -*-

    async def save_token(self, token: dict, request: Request):
        """
        This method called to save issued access and optional refresh
        token["access_token"], token["refresh_token"].

        Method is used by endpoints:
            - /authorization -- only for Implicit and Hybrid grants
            - /token
        """
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    async def is_rotate_refresh_token(request: Request) -> bool:
        """
        This method called to determine recreate refresh token or not
        when refresh grant used.

        Default refresh token recreated, old refresh token must be invalidated.

        Method is used by endpoints:
            - /token -- Refresh grant
        """
        return True

    async def validate_refresh_token(self, request: Request) -> bool:
        """
        This method called to check refresh token exists, not expired, and associated with authenticated client.
        Also, this method can set request.user to user associated with this refresh token.

        Method is used by endpoints:
            - /token -- Refresh grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_refresh_token_dpop_jkt(self, request: Request) -> str | None:
        """
        Return bound dpop_jkt value to refresh_token if exists

        This value used for:
            - Validate that DPoP key matched with refresh_token
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def fill_id_token(self, id_token: dict, acr_required: bool, auth_time_required: bool, request: Request):
        """Finalize OpenID Connect ID token & Sign.

        TODO: rewrite

        In the OpenID Connect workflows when an ID Token is requested
        this method is called.  Subclasses should implement the
        construction, signing and optional encryption of the ID Token
        as described in the OpenID Connect spec.

        The `id_token` parameter is a dict containing a couple of OIDC
        technical fields related to the specification. Prepopulated
        attributes are:

        - `aud`, equals to `request.client_id`.
        - `iat`, equals to current time.
        - `nonce`, if present, is equals to the `nonce` from the
          authorization request.
        - `at_hash`, hash of `access_token`, if relevant.
        - `c_hash`, hash of `code`, if relevant.

        This method MUST provide required fields as below:

        - `iss`, REQUIRED. Issuer Identifier for the Issuer of the response.
        - `sub`, REQUIRED. Subject Identifier
        - `exp`, REQUIRED. Expiration time on or after which the ID
          Token MUST NOT be accepted by the RP when performing
          authentication with the OP.

        Additional claims may be added, note that `request.scope`
        should be used to determine the list of claims.

        More information can be found at `OpenID Connect Core#Claims`_

        .. _`OpenID Connect Core#Claims`: https://openid.net/specs/openid-connect-core-1_0.html#Claims

        """
        raise NotImplementedError('Subclasses must implement this method.')

    @staticmethod
    async def is_rotate_id_token(request: Request) -> bool:
        """
        This method called to determine recreate id token or not
        when refresh grant used.

        Default id token recreated, old id token may be invalidated or saved.

        Method is used by endpoints:
            - /token -- Refresh grant
        """
        return True

    async def introspect_token(self, request: Request) -> dict[str, Any] | None:
        """
        This method called to introspect tokens.
        Use request.token and request.token_type_hint
        token_type_hint MUST be silent ignored if it is unknown or don't match with token.

        if token is "active" ("Active" will generally indicate that
            a given token has been issued by this authorization server,
            has not been revoked by the resource owner,
            and is within its given time window of validity (nbf, exp),
            also you can check that token bound to authenticated client.):
        this method MUST return a dict containing information about token (can be empty).

        According RFC7662, returned dict may contain:
            - scope
                OPTIONAL. A JSON string containing a space-separated list of
                scopes associated with this token, in the format described in
                Section 3.3 of OAuth 2.0 [RFC6749].
            - client_id
                OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
            - username
                OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
            - token_type
                OPTIONAL. Type of the token as defined in Section 5.1 of OAuth 2.0 [RFC6749].
            - exp
                OPTIONAL. Integer timestamp, measured in the number of seconds
                since January 1 1970 UTC, indicating when this token will expire, as defined in JWT [RFC7519].
            - iat
                OPTIONAL. Integer timestamp, measured in the number of seconds
                since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT [RFC7519].
            - nbf
                OPTIONAL. Integer timestamp, measured in the number of seconds
                since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT [RFC7519].
            - sub
                OPTIONAL. Subject of the token, as defined in JWT [RFC7519].
                Usually a machine-readable identifier of the resource owner who authorized this token.
            - aud
                OPTIONAL. Service-specific string identifier or list of string
                identifiers representing the intended audience for this token, as defined in JWT [RFC7519].
            - iss
                OPTIONAL. String representing the issuer of this token, as defined in JWT [RFC7519].
            - jti
                OPTIONAL. String identifier for the token, as defined in JWT [RFC7519].

        Specific implementations MAY extend this structure with their own
        service-specific response names as top-level members of this JSON
        object. Response names intended to be used across domains MUST be
        registered in the "OAuth Token Introspection Response" registry
        defined in Section 3.1.

        Method is used by endpoints:
            - /introspect
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def revoke_token(self, request: Request) -> bool:
        """
        This method called to revoke tokens.
        Use request.token and request.token_type_hint,
        token_type_hint MUST be silent ignored if it is unknown or don't match with token.

        Whenever token revoked or not this method must return True.
        Return value False raise unsupported_token_type error.

        unsupported_token_type: The authorization server does not support
            the revocation of the presented token type. That is, the
            client tried to revoke an access token on a server not
            supporting this feature.

        Method is used by endpoints:
            - /revoke
        """
        raise NotImplementedError('Subclasses must implement this method.')

    # -*- resource & provider processing section -*-

    async def get_userinfo_claims(self, request: Request) -> dict[str, Any] | str:
        """
        TODO: rewrite
        Return the UserInfo claims in JSON or JWT.

        The UserInfo Claims MUST be returned as the members of a JSON object
         unless a signed or encrypted response was requested during Client
         Registration. The Claims defined in Section 5.1 can be returned, as can
         additional Claims not specified there.

        For privacy reasons, OpenID Providers MAY elect to not return values for
        some requested Claims.

        If a Claim is not returned, that Claim Name SHOULD be omitted from the
        JSON object representing the Claims; it SHOULD NOT be present with a
        null or empty string value.

        The sub (subject) Claim MUST always be returned in the UserInfo
        Response.

        Upon receipt of the UserInfo Request, the UserInfo Endpoint MUST return
        the JSON Serialization of the UserInfo Response as in Section 13.3 in
        the HTTP response body unless a different format was specified during
        Registration [OpenID.Registration].

        If the UserInfo Response is signed and/or encrypted, then the Claims are
        returned in a JWT and the content-type MUST be application/jwt. The
        response MAY be encrypted without also being signed. If both signing and
        encryption are requested, the response MUST be signed then encrypted,
        with the result being a Nested JWT, as defined in [JWT].

        If signed, the UserInfo Response SHOULD contain the Claims iss (issuer)
        and aud (audience) as members. The iss value SHOULD be the OP's Issuer
        Identifier URL. The aud value SHOULD be or include the RP's Client ID
        value.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: Claims as a dict OR JWT/JWS/JWE as a string

        Method is used by:
            UserInfoEndpoint
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def get_user_code_info(self, request: Request) -> dict[str, Any] | None:
        """
        Called when a user_code is validating

        Must return dict[str, Any] with info about the user code
        or return None (None value raise AccessDenied error)
        """
        raise NotImplementedError('Subclasses must implement this method.')

    async def approve_user_code_info(self, request: Request) -> bool | None:
        """
        Called when an EndUser approve (approve is True) or reject (approve is False) user_code.

        Must return bool approve status (True is success approve/reject or already approved/rejected,
        False is user_code invalid and other non error reasons)
        or return None (None value raise AccessDenied error)
        """
        raise NotImplementedError('Subclasses must implement this method.')


request_validator = MyRequestValidator()
