from datetime import datetime
from typing import List, Optional

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

if settings.user_save_history:
    __all__ = ["Account", "AccountSession", "AccountProtection", "AccountHistory"]
else:
    __all__ = ["Account", "AccountSession", "AccountProtection"]


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
    __password: Mapped[str] = mapped_column("password", nullable=False,
                                            deferred=True, deferred_group="sensitive")
    # Активация аккаунта. Не активированный аккаунт может залогиниться, но не может взаимодействовать с системой за рамками запроса информации о себе.
    active: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE")
    if settings.user_has_scope:
        _scopes: Mapped[str] = mapped_column(nullable=False, server_default="[]")
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
        return self.__password

    @password.setter
    def password(self, value):
        self.__password = _hasher.hash(value)

    @hybrid_method
    def verify_password(self, value: str):
        try:
            _hasher.verify(self.__password, value)
            if _hasher.check_needs_rehash(self.__password):
                self.__password = _hasher.hash(value)
            return True
        except Argon2Error:
            return False

    if settings.user_has_scope:
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
    login_uuid: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="csrf")
    login_by: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="csrf")
    login_delay: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True,
                                                  deferred=True, deferred_group="csrf")
    login_attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0",
                                                     deferred=True, deferred_group="csrf")
    confirm_uuid: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="confirm")
    confirm_delay: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=True,
                                                    deferred=True, deferred_group="confirm")
    confirm_attempt_count: Mapped[int] = mapped_column(nullable=False, server_default="0",
                                                       deferred=True, deferred_group="confirm")
    block: Mapped[bool] = mapped_column(nullable=False, server_default="FALSE", deferred=True, deferred_group="block")
    block_reason: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="block")
    # otp_enabled: Mapped[bool] = mapped_column(server_default="FALSE", nullable=False)
    # otp_secret: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="otp")
    # otp_codes: Mapped[str] = mapped_column(String, nullable=True, deferred=True, deferred_group="otp_codes")
    # otp_codes_secret: Mapped[str] = mapped_column(nullable=True, deferred=True, deferred_group="otp_codes")
    # otp_codes_init: Mapped[int] = mapped_column(nullable=True, deferred=True, deferred_group="otp_codes")

    # @hybrid_property
    # def otp_codes_list(self) -> Optional[List[str]]:
    #     if self.otp_codes is not None:
    #         return json.loads(self.otp_codes)
    #     return None
    #
    # @otp_codes_list.setter
    # def otp_codes_list(self, value: Optional[List[str]]):
    #     if value is not None:
    #         self.otp_codes = json.dumps(value, separators=(',', ':'), indent=False, ensure_ascii=False)
    #     else:
    #         self.otp_codes = None


if settings.user_save_history:
    class AccountHistory(AsyncAttrs, Base):
        __tablename__ = "account_history"
        id: Mapped[int] = mapped_column(primary_key=True)
        account_id: Mapped[int] = mapped_column(ForeignKey("account.id", ondelete='CASCADE'),
                                                nullable=False, index=True)
        date: Mapped[datetime] = mapped_column(nullable=False, server_default=func.current_timestamp())
        event_key: Mapped[str] = mapped_column(nullable=False, index=True)
        message: Mapped[str] = mapped_column(nullable=False)
