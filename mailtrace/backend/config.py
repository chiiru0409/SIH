"""
config.py — MAILTRACE application settings.

All configuration is read from environment variables, with sensible
defaults for local development.  In production, set these via a .env
file or your deployment environment — never hardcode secrets.
"""

from pydantic_settings import BaseSettings
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent  # mailtrace/


class Settings(BaseSettings):
    # ------------------------------------------------------------------ #
    #  Application                                                         #
    # ------------------------------------------------------------------ #
    APP_NAME: str = "MAILTRACE"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"          # development | production
    DEBUG: bool = True

    # ------------------------------------------------------------------ #
    #  Server & Security                                                   #
    # ------------------------------------------------------------------ #
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: str = "*"               # comma-separated list or "*" in dev

    # ------------------------------------------------------------------ #
    #  Database                                                            #
    # ------------------------------------------------------------------ #
    # SQLite by default for development; PostgreSQL (Neon) in production.
    # Accepts postgresql://, postgres://, or postgresql+asyncpg:// URLs.
    DATABASE_URL: str = ""
    POSTGRES_URL: str = ""                # Vercel / Neon alias fallback
    POSTGRES_PRISMA_URL: str = ""         # Vercel Prisma alias fallback
    POSTGRES_URL_NON_POOLING: str = ""    # Vercel non-pooling alias fallback
    NEON_DATABASE_URL: str = ""           # Neon alias fallback

    # ------------------------------------------------------------------ #
    #  File storage                                                        #
    # ------------------------------------------------------------------ #
    UPLOAD_DIR: Path = BASE_DIR / "samples"
    REPORT_DIR: Path = BASE_DIR / "reports"
    MAX_UPLOAD_SIZE_MB: int = 25            # reject .eml files larger than this

    # ------------------------------------------------------------------ #
    #  External APIs (all optional — system degrades gracefully without)  #
    # ------------------------------------------------------------------ #
    # OpenAI / compatible LLM endpoint for AI threat analysis (Phase 4)
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"

    # ip-api.com is free for non-commercial use (no key required)
    # Set to a premium endpoint or replace with ipinfo.io token if needed
    IPAPI_BASE_URL: str = "http://ip-api.com/json"
    IPINFO_TOKEN: str = ""                  # optional token for ipinfo.io

    # VirusTotal (Phase 5 — URL/domain reputation)
    VIRUSTOTAL_API_KEY: str = ""

    # AbuseIPDB (Phase 5 — IP reputation)
    ABUSEIPDB_API_KEY: str = ""

    # MaxMind GeoLite2 database path (Phase 5 — offline GeoIP)
    GEOIP_DB_PATH: str = ""

    # ------------------------------------------------------------------ #
    #  Blockchain Anchoring (Step 9)                                     #
    # ------------------------------------------------------------------ #
    BLOCKCHAIN_ENABLED: bool = False
    BLOCKCHAIN_PROVIDER: str = "mock"       # mock | null | ethereum
    BLOCKCHAIN_RPC_URL: str = ""
    BLOCKCHAIN_NETWORK: str = "local-simulated"
    BLOCKCHAIN_PRIVATE_KEY: str = ""        # NEVER expose or log
    BLOCKCHAIN_CONTRACT_ADDRESS: str = ""

    # ------------------------------------------------------------------ #
    #  Risk engine weights (Phase 6) — configurable without code changes  #
    # ------------------------------------------------------------------ #
    RISK_WEIGHT_SPF_FAIL: int = 15
    RISK_WEIGHT_DKIM_FAIL: int = 15
    RISK_WEIGHT_DMARC_FAIL: int = 15
    RISK_WEIGHT_REPLY_TO_MISMATCH: int = 10
    RISK_WEIGHT_RETURN_PATH_MISMATCH: int = 10
    RISK_WEIGHT_SUSPICIOUS_URL: int = 25
    RISK_WEIGHT_DOMAIN_ANOMALY: int = 8
    RISK_WEIGHT_IP_REPUTATION: int = 10
    RISK_WEIGHT_AI_PHISHING: int = 20       # applied proportionally to probability
    RISK_WEIGHT_AI_BEC: int = 15
    RISK_WEIGHT_AI_IMPERSONATION: int = 15
    RISK_WEIGHT_URGENCY: int = 5
    RISK_WEIGHT_HEADER_ANOMALY: int = 5

    class Config:
        env_file = str(BASE_DIR / ".env")
        env_file_encoding = "utf-8"
        case_sensitive = True


# Single shared instance imported everywhere
settings = Settings()
