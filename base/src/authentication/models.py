from datetime import datetime, timezone
from typing import List

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error
from sqlalchemy import TIMESTAMP, func, ForeignKey, String
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base
from .settings import settings
from .utils import json

_hasher = PasswordHasher()

__all__ = ["Account", "AccountSession", "AccountProtection", "AccountHistory"]


class Account(AsyncAttrs, Base):
    __tablename__ = "account"
    id: Mapped[int] = mapped_column(primary_key=True)
    # Уникальный буквенно-цифровой идентификатор пользователя
    login: Mapped[str] = mapped_column(nullable=False, unique=True, index=True)
    if "email" in settings.user_login_properties:
        # Если включен email
        # Уникальный адрес электронной почты, который можно использовать вместо login для идентификации
        email: Mapped[str] = mapped_column(nullable=True, unique=True, index=True,
                                           deferred=True, deferred_group="email")
    if "phone" in settings.user_login_properties:
        # Если включен phone
        # Уникальный номер телефона (несколько одинаковых недопустимы), который можно использовать вместо login для идентификации
        phone: Mapped[str] = mapped_column(nullable=True, unique=True, index=True,
                                           deferred=True, deferred_group="phone")
    # Хеш пароля
    _password: Mapped[str] = mapped_column("password", nullable=False,
                                           deferred=True, deferred_group="sensitive")
    # Активация аккаунта. Не активированный аккаунт может залогиниться, но не может взаимодействовать с системой за рамками запроса информации о себе.
    active: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE")
    totp: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE", deferred=True, deferred_group="totp")
    _scopes: Mapped[str] = mapped_column("scopes", nullable=False, server_default="[]")
    # Дата создания аккаунта
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 server_default=func.current_timestamp(),
                                                 deferred=True, deferred_group="date")
    # Дата изменения пароля
    password_changed_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True,
                                                          server_default=func.current_timestamp(),
                                                          deferred=True, deferred_group="date")
    # Все сессии пользователя, в том числе и истекшие (но не удалённые из системы)
    sessions: Mapped[List["AccountSession"]] = relationship(back_populates="account", uselist=True,
                                                            passive_deletes=True)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = _hasher.hash(value)

    @hybrid_method
    def verify_password(self, value: str):
        try:
            _hasher.verify(self._password, value)
            if _hasher.check_needs_rehash(self._password):
                self._password = _hasher.hash(value)
            return True
        except Argon2Error:
            return False

    @hybrid_method
    async def async_verify_password(self, value: str):
        try:
            _hasher.verify(await self.awaitable_attrs._password, value)
            if _hasher.check_needs_rehash(self._password):
                self._password = _hasher.hash(value)
            return True
        except Argon2Error:
            return False

    @hybrid_property
    def scopes(self):
        decoded = json.loads(self._scopes)
        if isinstance(decoded, list):
            return decoded
        else:
            return []

    @scopes.setter
    def scopes(self, value: list[str]):
        if not isinstance(value, list):
            raise ValueError("Scopes must be a list of strings")
        valid = True
        for s in value:
            if not isinstance(s, str):
                valid = False
                break
        if not valid:
            raise ValueError("Scopes must be a list of strings")
        encoded = json.dumps(valid)
        self._scopes = encoded


class AccountSession(AsyncAttrs, Base):
    __tablename__ = "account_session"
    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("account.id", ondelete='CASCADE'),
                                            nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(nullable=False)
    """
    Отпечаток сессии пользователя:
    JSON, содержащий фактический ip пользователя и информацию заголовка user-agent.
    Токены валидны только при условии, если данная информация не изменилась.
    """
    invalid_after: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                    deferred=True, deferred_group="date")
    """
    Время, до которого сессия считается активной.
    После этого времени операция refresh закончится неудачей.
    Продлевается при каждом refresh.
    """
    confirmed_before: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                       deferred=True, deferred_group="confirmed")
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False,
                                                 deferred=True, deferred_group="login_at",
                                                 server_default=func.current_timestamp())
    """
    Время начала текущей сессии.
    """
    identity: Mapped[str] = mapped_column(nullable=False)
    """
    Идентификатор проверки подлинности токенов.
    """

    otp_success: Mapped[bool] = mapped_column(nullabel=False)
    otp_attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0",
                                                   deferred=True, deferred_group="otp")

    @hybrid_method
    def need_password_confirm(self):
        if self.confirmed_before < datetime.now(tz=timezone.utc):
            return True
        return False

    @hybrid_method
    async def async_need_password_confirm(self):
        if (await self.awaitable_attrs.confirmed_before) < datetime.now(tz=timezone.utc):
            return True
        return False

    account: Mapped["Account"] = relationship(back_populates="sessions", uselist=False, passive_deletes=True)
    """
    Ссылка на связанный аккаунт.
    При удалении аккаунта все его сессии также удаляются.
    """


class AccountProtection(AsyncAttrs, Base):
    __tablename__ = 'account_protection'
    id: Mapped[int] = mapped_column(ForeignKey("account.id", ondelete="CASCADE"), primary_key=True)
    login: Mapped[str] = mapped_column(nullable=False, unique=True, index=True,
                                       deferred=True, deferred_group="login")
    if "email" in settings.user_login_properties:
        # Если включен email
        # Уникальный адрес электронной почты, который можно использовать вместо login для идентификации
        email: Mapped[str] = mapped_column(nullable=True, unique=True, index=True,
                                           deferred=True, deferred_group="email")
    if "phone" in settings.user_login_properties:
        # Если включен phone
        # Уникальный номер телефона (несколько одинаковых недопустимы), который можно использовать вместо login для идентификации
        phone: Mapped[str] = mapped_column(nullable=True, unique=True, index=True,
                                           deferred=True, deferred_group="phone")
    # login section
    login_uuid: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="csrf")
    login_by: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="csrf")
    login_delay: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True,
                                                  deferred=True, deferred_group="csrf")
    login_attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0",
                                                     deferred=True, deferred_group="csrf")
    # confirm section
    confirm_uuid: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="confirm")
    confirm_delay: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True,
                                                    deferred=True, deferred_group="confirm")
    confirm_attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0",
                                                       deferred=True, deferred_group="confirm")
    # otp section
    otp_secret: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="otp")
    _otp_codes: Mapped[str] = mapped_column("otp_codes", String, nullable=True,
                                            deferred=True, deferred_group="otp_codes")
    otp_codes_secret: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="otp_codes")
    otp_codes_init: Mapped[int] = mapped_column(nullable=True, deferred=True, deferred_group="otp_codes")
    # block section
    block: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE", deferred=True, deferred_group="block")
    block_reason: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="block")

    @hybrid_property
    def otp_codes(self) -> list[str] | None:
        if self._otp_codes is not None:
            return json.loads(self._otp_codes)
        return None

    @otp_codes.setter
    def otp_codes(self, value: list[str] | None):
        if value is not None:
            self._otp_codes = json.dumps(value)
        else:
            self._otp_codes = None


if settings.user_save_history:
    class AccountHistory(AsyncAttrs, Base):
        __tablename__ = "account_history"
        id: Mapped[int] = mapped_column(primary_key=True)
        account_id: Mapped[int] = mapped_column(ForeignKey("account.id", ondelete='CASCADE'),
                                                nullable=False, index=True)
        date: Mapped[datetime] = mapped_column(nullable=False, server_default=func.current_timestamp())
        event_key: Mapped[str] = mapped_column(nullable=False, index=True)
        message: Mapped[str] = mapped_column(nullable=False)
else:
    class AccountHistory:
        pass
