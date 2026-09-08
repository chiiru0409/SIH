"""
database.py — Async SQLAlchemy engine and session factory.

Uses SQLite (aiosqlite) by default.
To switch to PostgreSQL, change DATABASE_URL in .env:
    DATABASE_URL=postgresql+asyncpg://user:pass@localhost/mailtrace
No code changes required — SQLAlchemy handles both dialects.
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from backend.config import settings


# ------------------------------------------------------------------ #
#  Engine                                                              #
# ------------------------------------------------------------------ #
# echo=True prints all SQL in development — flip to False in production
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
)

# ------------------------------------------------------------------ #
#  Session factory                                                     #
# ------------------------------------------------------------------ #
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# ------------------------------------------------------------------ #
#  Base class for ORM models                                           #
# ------------------------------------------------------------------ #
class Base(DeclarativeBase):
    pass


# ------------------------------------------------------------------ #
#  FastAPI dependency                                                  #
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


async def init_db() -> None:
    """Create all tables that don't exist yet and run safe additive migrations."""
    async with engine.begin() as conn:
        # Import all models so Base.metadata knows about them
        from backend.models import analysis, evidence  # noqa: F401
        await conn.run_sync(Base.metadata.create_all)

        def _migrate(sync_conn):
            from sqlalchemy import text
            try:
                res = sync_conn.execute(text("PRAGMA table_info(analysis_cases)"))
                cols = {row[1] for row in res.fetchall()}
                new_cols = {
                    "parsed_evidence_hash": "VARCHAR(64)",
                    "analysis_hash": "VARCHAR(64)",
                    "blockchain_tx_id": "VARCHAR(128)",
                    "blockchain_anchor_data": "JSON",
                }
                for col_name, col_type in new_cols.items():
                    if col_name not in cols:
                        sync_conn.execute(text(f"ALTER TABLE analysis_cases ADD COLUMN {col_name} {col_type}"))
            except Exception:
                pass

        await conn.run_sync(_migrate)
