"""
routes/health.py — Health and readiness endpoints.

GET /api/health        — liveness: is the process alive?
GET /api/health/ready  — readiness: can we reach the database?
"""

import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from backend.config import settings
from backend.database import get_db, get_database_info
from backend.schemas.analysis import HealthResponse, DatabaseStatus

logger = logging.getLogger("mailtrace.routes.health")

router = APIRouter(prefix="/api", tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description="Returns 200 if the MAILTRACE backend process is running.",
)
async def health_check() -> HealthResponse:
    raw_info = get_database_info()
    db_meta = DatabaseStatus(
        engine=raw_info.get("engine", "sqlite"),
        dialect=raw_info.get("dialect", "aiosqlite"),
        provider=raw_info.get("provider", "local"),
        status="ready",
        connected=True,
    )
    return HealthResponse(
        status="ok",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database="ready",
        db_info=db_meta,
    )


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness check",
    description="Returns 200 if the backend can reach the database.",
)
async def readiness_check(db: AsyncSession = Depends(get_db)) -> HealthResponse:
    raw_info = get_database_info()
    db_status = "unreachable"
    is_connected = False

    try:
        await db.execute(text("SELECT 1"))
        db_status = "ready"
        is_connected = True
    except Exception as exc:
        logger.error(f"Database readiness probe failed: {exc}")
        db_status = "unreachable"

    db_meta = DatabaseStatus(
        engine=raw_info.get("engine", "sqlite"),
        dialect=raw_info.get("dialect", "aiosqlite"),
        provider=raw_info.get("provider", "local"),
        status=db_status,
        connected=is_connected,
    )

    return HealthResponse(
        status="ok" if is_connected else "degraded",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database=db_status,
        db_info=db_meta,
    )

