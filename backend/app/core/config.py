from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "API Security Scanner"
    VERSION: str = "1.0.0"
    DATABASE_URL: str = "sqlite:///./scanner.db"
    MAX_CONCURRENT_SCANS: int = 5
    REQUEST_TIMEOUT: int = 10
    MAX_REQUESTS_PER_TEST: int = 20
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    class Config:
        env_file = ".env"


settings = Settings()
