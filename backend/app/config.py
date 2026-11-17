from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "dev"
    LOG_LEVEL: str = "INFO"

    JWT_SECRET: str = "dev-secret-change-me"
    JWT_ALGO: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 720

    DATABASE_URL: str = "postgresql+asyncpg://base:base@postgres:5432/base"
    REDIS_URL: str = "redis://redis:6379/0"

    BOOTSTRAP_ADMIN_EMAIL: str = "admin@base.local"
    BOOTSTRAP_ADMIN_PASSWORD: str = "admin"

    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    SECURITYTRAILS_API_KEY: str = ""
    GREYNOISE_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    IPINFO_TOKEN: str = ""
    URLSCAN_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    OTX_API_KEY: str = ""
    OPENCORPORATES_API_KEY: str = ""
    INTELX_API_KEY: str = ""
    TINEYE_API_USER: str = ""
    TINEYE_API_KEY: str = ""
    BING_VISUAL_API_KEY: str = ""
    FOFA_API_EMAIL: str = ""
    FOFA_API_KEY: str = ""
    ZOOMEYE_API_KEY: str = ""
    COMPANIESHOUSE_API_KEY: str = ""

    HTTP_TIMEOUT_SECONDS: int = 20
    MAX_CONCURRENT_COLLECTORS: int = 8
    RATE_LIMIT_PER_MINUTE: int = 120

    UPLOAD_DIR: str = "/data/uploads"


@lru_cache
def get_settings() -> Settings:
    return Settings()
