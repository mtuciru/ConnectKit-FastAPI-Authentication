from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECURE_SECRET: str  # sign key
    SECURE_ACCESS_EXPIRE: int = 5  # In minutes
    SECURE_REFRESH_EXPIRE: int = 24  # In hours
    SECURE_REFRESH_LONG_EXPIRE: int = 720  # In hours
    SECURE_PATH: str = "/api"
    SECURE_COOKIE_NAME: str = "access"
    SECURE_ONLY: bool = True
    SECURE_BLOCK_TRIES: int = 5
    SECURE_OTP_ENABLED: bool = True
    SECURE_OTP_BLOCK_TRIES: int = 3
    SECURE_OTP_ISSUER: str = "Localhost inc."
    SECURE_STRICT_VERIFICATION: bool = True
    SECURE_LOGIN_EMAIL: bool = False


settings = Settings()
