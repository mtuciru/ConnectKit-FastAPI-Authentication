from datetime import timedelta

from fastapi.params import Security

from .security import (anonymous_user_dependency, AuthenticatedUserDependency,
                       AuthenticatedClientDependency, MaybeAuthenticatedUserDependency)

__all__ = ["anonymous_user", "authenticated_user", "authenticated_client", "maybe_authenticated_user"]


def anonymous_user() -> Security:
    return Security(anonymous_user_dependency)


def authenticated_user(active: bool | None = True,
                       max_age: int | timedelta | None = None,
                       required_acr: str | list[str] | None = None,
                       required_scopes: list[str] | None = None,
                       via_provider_required: bool = False) -> Security:
    return Security(AuthenticatedUserDependency(
        active=active,
        max_age=max_age,
        required_acr=required_acr,
        via_provider_required=via_provider_required
    ), scopes=required_scopes, use_cache=True)


def maybe_authenticated_user(active: bool | None = True,
                             max_age: int | timedelta | None = None,
                             required_acr: str | list[str] | None = None,
                             required_scopes: list[str] | None = None,
                             via_provider_required: bool = False) -> Security:
    return Security(MaybeAuthenticatedUserDependency(
        active=active,
        max_age=max_age,
        required_acr=required_acr,
        via_provider_required=via_provider_required
    ), scopes=required_scopes, use_cache=True)


def authenticated_client(require_confidential: bool = False,
                         required_scopes: list[str] | None = None) -> Security:
    return Security(AuthenticatedClientDependency(
        require_confidential=require_confidential
    ), scopes=required_scopes, use_cache=True)
