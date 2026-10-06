from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "patchguard-dev"
    nvd_api_key: str | None = None
    api_host: str = "0.0.0.0"
    api_port: int = 8000


settings = Settings()
