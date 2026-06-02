from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # -------------------------
    # 🔑 External API Keys
    # -------------------------
    GROQ_API_KEY: str = Field(..., description="Groq LLM API Key")
    TRUST_EDGE_API_KEY: str = Field("", description="Internal service API key")

    # -------------------------
    # 🤖 Telegram Config
    # -------------------------
    TELEGRAM_BOT_TOKEN: str | None = Field(None, description="Telegram Bot Token")
    TELEGRAM_CHAT_ID: str | None = Field(None, description="Telegram Chat ID")

    # -------------------------
    # 🔐 Authentication (JWT)
    # -------------------------
    JWT_SECRET_KEY: str = Field(..., description="JWT Access Token Secret")
    JWT_REFRESH_SECRET: str = Field(..., description="JWT Refresh Token Secret")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # -------------------------
    # 📧 Email Services (SMTP / Resend)
    # -------------------------
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = ""

    RESEND_API_KEY: str | None = None

    # -------------------------
    # 📱 SMS (MSG91)
    # -------------------------
    MSG91_AUTH_KEY: str | None = None
    MSG91_SENDER_ID: str = "TRUSTE"
    MSG91_TEMPLATE_ID: str | None = None

    # -------------------------
    # 🧠 Security / Rate Limiting
    # -------------------------
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_TIME_MINUTES: int = 15

    # -------------------------
    # 🗄️ Database & Redis
    # -------------------------
    DATABASE_URL: str = "sqlite:///./trust_edge.db"
    REDIS_URL: str = "redis://localhost:6379"

    # -------------------------
    # 🌍 Global Phone Validation
    # -------------------------
    ENABLE_INTERNATIONAL_NUMBERS: bool = True

    # -------------------------
    # ⚙️ Environment Config
    # -------------------------
    DEBUG: bool = True
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
