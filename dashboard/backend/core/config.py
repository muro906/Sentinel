"""Application configuration settings.

Uses Pydantic Settings to load configuration from environment variables
with sensible defaults for development.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables.
    
    Attributes:
        DATABASE_URL: PostgreSQL connection string.
        REDIS_URL: Redis connection string.
        KAFKA_BOOTSTRAP_SERVERS: Comma-separated list of Kafka brokers.
        JWT_SECRET_KEY: Secret key for JWT token signing.
        ALLOWED_ORIGINS: List of allowed CORS origins.
        LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR).
        DEBUG: Enable debug mode and API documentation.
    """
    DATABASE_URL:            str       = "postgresql://sentinel:sentinel_dev@localhost:5433/sentinel"
    REDIS_URL:               str       = "redis://localhost:6380"
    KAFKA_BOOTSTRAP_SERVERS: str       = "kafka:9092"
    JWT_SECRET_KEY:          str       = "change_me_in_production"
    ALLOWED_ORIGINS:         list[str] = ["http://localhost:5173"]
    LOG_LEVEL:               str       = "INFO"
    DEBUG:                   bool      = False
    
    # Email settings (for Gmail SMTP)
    SMTP_HOST:               str       = "smtp.gmail.com"
    SMTP_PORT:               int       = 587
    SMTP_USER:               str       = "millicentwamuru@gmail.com"
    SMTP_PASSWORD:           str       = ""  # App password goes here
    FROM_EMAIL:              str       = "millicentwamuru@gmail.com"

    class Config:
        """Pydantic configuration."""
        env_file = ".env"


# Global settings instance
settings = Settings()