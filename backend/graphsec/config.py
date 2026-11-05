from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_default_region: str = "sa-east-1"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"

    redis_url: str = "redis://localhost:6379/0"

    app_secret_key: str = "change-me"
    app_env: str = "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()
