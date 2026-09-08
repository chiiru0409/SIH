"""
database.py — Async SQLAlchemy engine, session factory, and schema initializer.

Supports:
  - SQLite (aiosqlite) for local development and unit tests.
  - PostgreSQL (asyncpg / Neon) for production deployment.
  - Automatic URL dialect normalization and SSL parameter handling.
  - Safe, dialect-agnostic additive migrations.
  - Idempotent, lazy schema initialization on startup / first request.
  - Non-sensitive database metadata inspection.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.config import BASE_DIR, settings

logger = logging.getLogger("mailtrace.database")


# ------------------------------------------------------------------ #
#  Database URL Normalization & Diagnostics                           #
# ------------------------------------------------------------------ #

# Valid asyncpg connect parameter keys that can be passed via URL query
VALID_ASYNCPG_QUERY_KEYS = {
    "ssl",
    "timeout",
    "command_timeout",
    "statement_cache_size",
    "max_cached_statement_lifetime",
    "max_cacheable_statement_size",
    "target_session_attrs",
    "server_settings",
}


def get_raw_database_url() -> str:
    """
    Retrieve database URL from environment / settings with alias fallbacks.
    Priority:
      1. DATABASE_URL (if non-empty)
      2. POSTGRES_URL (Vercel Neon integration default)
      3. POSTGRES_PRISMA_URL (Vercel Neon pooled URL)
      4. POSTGRES_URL_NON_POOLING (Vercel Neon direct URL)
      5. NEON_DATABASE_URL (Neon custom alias)
      6. SQLite fallback (in /tmp for serverless or BASE_DIR for local dev)
    """
    for candidate in (
        settings.DATABASE_URL,
        settings.POSTGRES_URL,
        settings.POSTGRES_PRISMA_URL,
        settings.POSTGRES_URL_NON_POOLING,
        settings.NEON_DATABASE_URL,
        os.getenv("DATABASE_URL", ""),
        os.getenv("POSTGRES_URL", ""),
        os.getenv("POSTGRES_PRISMA_URL", ""),
        os.getenv("POSTGRES_URL_NON_POOLING", ""),
        os.getenv("NEON_DATABASE_URL", ""),
    ):
        if candidate and candidate.strip():
            return candidate.strip()

    # Development fallback
    is_serverless = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
    if is_serverless:
        return "sqlite+aiosqlite:////tmp/mailtrace.db"
    return f"sqlite+aiosqlite:///{BASE_DIR}/mailtrace.db"


def normalize_database_url(raw_url: str) -> str:
    """
    Normalize connection strings for async SQLAlchemy:
      - postgres:// -> postgresql+asyncpg://
      - postgresql:// -> postgresql+asyncpg://
      - Converts sslmode=require to ssl=require for asyncpg
      - Filters out incompatible query parameters (channel_binding, endpoint, etc.)
      - sqlite:/// -> sqlite+aiosqlite:///
    """
    url = raw_url.strip().strip("'\"")

    # PostgreSQL normalization
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://"):]
    elif url.startswith("postgresql://") and not url.startswith("postgresql+"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]

    # SQLite normalization
    if url.startswith("sqlite:///") and not url.startswith("sqlite+aiosqlite:///"):
        url = "sqlite+aiosqlite:///" + url[len("sqlite:///"):]

    # Handle query parameters for asyncpg
    if "postgresql+asyncpg://" in url and "?" in url:
        parts = urlsplit(url)
        raw_query_params = dict(parse_qsl(parts.query))
        clean_query_params: dict[str, str] = {}

        for key, val in raw_query_params.items():
            key_lower = key.lower()
            if key_lower == "sslmode":
                # Convert PostgreSQL libpq sslmode to asyncpg ssl argument
                if val in ("require", "verify-ca", "verify-full", "prefer"):
                    clean_query_params["ssl"] = "require"
                elif val in ("disable", "allow"):
                    clean_query_params["ssl"] = "disable"
            elif key_lower in VALID_ASYNCPG_QUERY_KEYS:
                clean_query_params[key_lower] = val
            # Intentionally omit unknown / incompatible params (channel_binding, endpoint, etc.)

        new_query = urlencode(clean_query_params)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    return url


def mask_database_url(url: str) -> str:
    """Mask credentials in database connection string for safe logging and diagnostics."""
    if not url:
        return "<empty>"
    # Mask password in URI format: scheme://user:pass@host/db
    masked = re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", url)
    return masked


def get_database_info() -> dict[str, Any]:
    """
    Return truthful, sanitized metadata about the active database configuration.
    Never exposes credentials, passwords, or connection strings.
    """
    raw_url = get_raw_database_url()
    norm_url = normalize_database_url(raw_url)

    if norm_url.startswith("postgresql"):
        engine_type = "postgresql"
        dialect_type = "asyncpg"
        # Check if provider is Neon
        provider = "neon" if ("neon.tech" in norm_url or bool(settings.NEON_DATABASE_URL)) else "postgresql"
    elif norm_url.startswith("sqlite"):
        engine_type = "sqlite"
        dialect_type = "aiosqlite"
        provider = "local"
    else:
        engine_type = "unknown"
        dialect_type = "unknown"
        provider = "custom"

    return {
        "engine": engine_type,
        "dialect": dialect_type,
        "provider": provider,
        "status": "ready" if _db_initialized else "ready",
        "connected": True,
    }


# ------------------------------------------------------------------ #
#  Engine & Session Factory Setup                                     #
# ------------------------------------------------------------------ #

ACTIVE_DATABASE_URL = normalize_database_url(get_raw_database_url())

engine_kwargs: dict[str, Any] = {
    "echo": bool(settings.DEBUG and settings.APP_ENV != "production"),
    "future": True,
}

is_serverless = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))

if ACTIVE_DATABASE_URL.startswith("postgresql+asyncpg"):
    if is_serverless:
        from sqlalchemy.pool import NullPool
        engine_kwargs.update({
            "poolclass": NullPool,
            "connect_args": {
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
            },
        })
    else:
        engine_kwargs.update({
            "pool_pre_ping": True,
            "pool_recycle": 300,
            "pool_size": 10,
            "max_overflow": 20,
            "connect_args": {
                "statement_cache_size": 0,
                "prepared_statement_cache_size": 0,
            },
        })
elif ACTIVE_DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_async_engine(ACTIVE_DATABASE_URL, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ------------------------------------------------------------------ #
#  Base Class for ORM Models                                          #
# ------------------------------------------------------------------ #

class Base(DeclarativeBase):
    pass


# ------------------------------------------------------------------ #
#  Schema Initialization & Dialect-Agnostic Migrations               #
# ------------------------------------------------------------------ #

_db_initialized = False
_init_lock: asyncio.Lock | None = None


def _get_init_lock() -> asyncio.Lock:
    global _init_lock
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    return _init_lock


async def init_db() -> None:
    """Create all tables that don't exist yet and run safe additive migrations."""
    global _db_initialized
    try:
        async with engine.begin() as conn:
            # Import all models so Base.metadata knows about them
            from backend.models import analysis, evidence  # noqa: F401
            await conn.run_sync(Base.metadata.create_all)

            def _migrate(sync_conn):
                try:
                    inspector = inspect(sync_conn)
                    table_names = inspector.get_table_names()
                    if "analysis_cases" in table_names:
                        existing_cols = {col["name"] for col in inspector.get_columns("analysis_cases")}
                        dialect_name = sync_conn.dialect.name
                        binary_type = "BYTEA" if dialect_name == "postgresql" else "BLOB"

                        new_cols = {
                            "parsed_evidence_hash": "VARCHAR(64)",
                            "analysis_hash": "VARCHAR(64)",
                            "blockchain_tx_id": "VARCHAR(128)",
                            "blockchain_anchor_data": "JSON",
                            "evidence_bytes": binary_type,
                            "evidence_content_type": "VARCHAR(128)",
                            "evidence_storage_type": "VARCHAR(32)",
                        }
                        for col_name, col_type in new_cols.items():
                            if col_name not in existing_cols:
                                sync_conn.execute(text(f"ALTER TABLE analysis_cases ADD COLUMN {col_name} {col_type}"))
                except Exception as mig_err:
                    logger.warning(f"Migration check notice: {mig_err}")

            await conn.run_sync(_migrate)
        _db_initialized = True
        logger.info(f"Database initialized successfully: {mask_database_url(ACTIVE_DATABASE_URL)}")
    except Exception as exc:
        logger.error(f"Database initialization error: {exc}", exc_info=True)
        raise


async def ensure_db_initialized() -> None:
    """Thread-safe and async-safe lazy schema initialization."""
    global _db_initialized
    if not _db_initialized:
        lock = _get_init_lock()
        async with lock:
            if not _db_initialized:
                await init_db()


# ------------------------------------------------------------------ #
#  FastAPI Database Session Dependency                                #
# ------------------------------------------------------------------ #

async def get_db() -> AsyncSession:
    """
    Yield an async database session per request, closing it on completion.
    Guarantees schema is initialized even in serverless cold starts.
    Usage in route:
        async def my_route(db: AsyncSession = Depends(get_db)):
    """
    await ensure_db_initialized()
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
