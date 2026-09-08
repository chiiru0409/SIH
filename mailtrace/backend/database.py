"""
database.py — Async SQLAlchemy engine, session factory, and schema initializer.

Supports:
  - SQLite (aiosqlite) for local development and unit tests.
  - PostgreSQL (asyncpg / Neon) for production deployment.
  - Automatic URL dialect normalization and SSL parameter handling.
  - Safe, dialect-agnostic additive migrations.
"""

from __future__ import annotations

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

from backend.config import settings


# ------------------------------------------------------------------ #
#  Database URL Normalization & Diagnostics                           #
# ------------------------------------------------------------------ #

def get_raw_database_url() -> str:
    """Retrieve database URL from settings with aliases fallback."""
    return (
        settings.DATABASE_URL
        or settings.POSTGRES_URL
        or settings.NEON_DATABASE_URL
        or f"sqlite+aiosqlite:///{settings.BASE_DIR}/mailtrace.db"
    ).strip()


def normalize_database_url(raw_url: str) -> str:
    """
    Normalize connection strings for async SQLAlchemy:
      - postgres:// -> postgresql+asyncpg://
      - postgresql:// -> postgresql+asyncpg://
      - Converts sslmode=require to ssl=require for asyncpg
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

    # Handle query parameters (especially sslmode for asyncpg)
    if "postgresql+asyncpg://" in url and "?" in url:
        parts = urlsplit(url)
        query_params = dict(parse_qsl(parts.query))

        # asyncpg accepts ssl=require instead of sslmode=require
        if "sslmode" in query_params:
            sslmode_val = query_params.pop("sslmode")
            if sslmode_val in ("require", "verify-ca", "verify-full", "prefer"):
                query_params["ssl"] = sslmode_val if sslmode_val == "require" else "require"
            elif sslmode_val in ("disable", "allow"):
                query_params["ssl"] = "disable"

        new_query = urlencode(query_params)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))

    return url


def mask_database_url(url: str) -> str:
    """Mask credentials in database connection string for safe logging."""
    if not url:
        return "<empty>"
    # Mask password in URI format: scheme://user:pass@host/db
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", url)


# ------------------------------------------------------------------ #
#  Engine & Session Factory Setup                                     #
# ------------------------------------------------------------------ #

ACTIVE_DATABASE_URL = normalize_database_url(get_raw_database_url())

engine_kwargs: dict[str, Any] = {
    "echo": bool(settings.DEBUG and settings.APP_ENV != "production"),
    "future": True,
}

if ACTIVE_DATABASE_URL.startswith("postgresql+asyncpg"):
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_size": 10,
        "max_overflow": 20,
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
#  FastAPI Database Session Dependency                                #
# ------------------------------------------------------------------ #

async def get_db() -> AsyncSession:
    """
    Yield an async database session per request, closing it on completion.
    Usage in route:
        async def my_route(db: AsyncSession = Depends(get_db)):
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ------------------------------------------------------------------ #
#  Schema Initialization & Dialect-Agnostic Migrations               #
# ------------------------------------------------------------------ #

async def init_db() -> None:
    """Create all tables that don't exist yet and run safe additive migrations."""
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
                    new_cols = {
                        "parsed_evidence_hash": "VARCHAR(64)",
                        "analysis_hash": "VARCHAR(64)",
                        "blockchain_tx_id": "VARCHAR(128)",
                        "blockchain_anchor_data": "JSON",
                    }
                    for col_name, col_type in new_cols.items():
                        if col_name not in existing_cols:
                            sync_conn.execute(text(f"ALTER TABLE analysis_cases ADD COLUMN {col_name} {col_type}"))
            except Exception:
                pass

        await conn.run_sync(_migrate)
