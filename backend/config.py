"""
Configuration — reads from .env file via pydantic-settings.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    virustotal_api_key: str = ""
    google_safe_browsing_key: str = ""
    cache_ttl: int = 3600
    ml_model_path: str = "../ml_model/model.pkl"
    suspicious_threshold: int = 10
    malicious_threshold: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
