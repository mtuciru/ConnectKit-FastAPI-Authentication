from datetime import datetime

__all__ = [
    "CredentialsPlaceholder", "credentials_placeholder", "UserCredentials", "ClientCredentials",
    "UserPlaceholder", "user_placeholder", "EndUser", "ClientUser"
]


class CredentialsPlaceholder:
    """
    If Authorization header with Bearer or DPoP token not specified by client, instance of this type added to request.auth
    """

    @property
    def is_authenticated(self) -> bool:
        return False


credentials_placeholder = CredentialsPlaceholder()


class UserCredentials(CredentialsPlaceholder):
    """
    If Authorization header with Bearer or DPoP token points to End-User
    (direct-mode by user credentials or indirect-mode by authorization_code, implicit or device_code grant)
    and token successful validated, then instance of this type added to request.auth
    """

    @property
    def is_authenticated(self) -> bool:
        return True

    def __init__(self, /, **kwargs):
        # Via uid endpoint can request additional info about session.
        self._uid: str = kwargs["uid"]
        # User id on whose behalf request done
        self._user_id: int = kwargs["user_id"]
        # Client id who made request (if client used)
        self._client_id: int | None = kwargs.get("client_id")
        # External client id via that End-User was authenticated (if external client used)
        self._external_client_id: int | None = kwargs.get("external_client_id")
        # Last time when reauthentication done (used for process max_age parameter)
        self._reauthenticated_at: datetime = kwargs["reauthenticated_at"]
        # List of used auth mechanisms (used for process amr constrains)
        self._amr: list[str] = kwargs["amr"]
        # Mark that additional authentification required for complete authentification process
        # Standard decorators return error if this is True
        self._mfa_waiting: bool = kwargs["mfa_waiting"]
        # Scopes granted to session
        self._scopes: set[str] = kwargs["scopes"]

    @property
    def uid(self) -> str:
        return self._uid

    @property
    def user_id(self) -> int:
        return self._user_id

    @property
    def client_id(self) -> int | None:
        return self._client_id

    @property
    def external_client_id(self) -> int | None:
        return self._external_client_id

    @property
    def reauthenticated_at(self) -> datetime:
        return self._reauthenticated_at

    @property
    def amr(self) -> list[str]:
        return self._amr

    @property
    def mfa_waiting(self) -> bool:
        return self._mfa_waiting

    @property
    def scopes(self) -> set[str]:
        return self._scopes


class ClientCredentials(CredentialsPlaceholder):
    """
    If Authorization header with Bearer or DPoP token points to Client (client_credential grant)
    and token successful validated, then instance of this type added to request.auth
    """

    @property
    def is_authenticated(self) -> bool:
        return True

    def __init__(self, /, **kwargs):
        # Via uid endpoint can request additional info about session.
        self._uid: str = kwargs["uid"]
        # Client id who made request
        self._client_id: int = kwargs.get("client_id")
        # Scopes granted to session
        self._scopes: set[str] = kwargs["scopes"]

    @property
    def uid(self) -> str:
        return self._uid

    @property
    def client_id(self) -> int:
        return self._client_id

    @property
    def scopes(self) -> set[str]:
        return self._scopes


class UserPlaceholder:
    """
    If session is incomplete or session is None, then instance of this type added to request as request.user
    """

    @property
    def is_authenticated(self) -> bool:
        raise False

    @property
    def display_name(self) -> str:
        return ""

    @property
    def identity(self) -> str:
        return ""


user_placeholder = UserPlaceholder()


class EndUser(UserPlaceholder):
    """
    If session point to EndUser and session complete, then instance of this type added to request as request.user
    """

    @property
    def is_authenticated(self) -> bool:
        raise True

    @property
    def display_name(self) -> str:
        return self._login

    @property
    def identity(self) -> str:
        return self._login

    def __init__(self, /, **kwargs):
        self._id: int = kwargs["id"]
        self._login: str = kwargs["login"]
        self._active: bool = kwargs["active"]
        self._provider: bool = kwargs.get("provider", False)

    @property
    def id(self) -> int:
        return self._id

    @property
    def login(self) -> str:
        return self._login

    @property
    def active(self) -> bool:
        return self._active

    @property
    def via_provider(self) -> bool:
        return self._provider


class ClientUser(UserPlaceholder):
    """
    If session point to ClientUser, then instance of this type added to request as request.user
    """

    @property
    def is_authenticated(self) -> bool:
        raise True

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def identity(self) -> str:
        return self._client_id

    def __init__(self, /, **kwargs):
        self._id: int = kwargs["id"]
        self._display_name: str = kwargs["display_name"]
        self._client_id: str = kwargs["client_id"]
        self._confidential: bool = kwargs["confidential"]

    @property
    def id(self) -> int:
        return self._id

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def confidential(self) -> bool:
        return self._confidential
