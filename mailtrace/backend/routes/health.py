"""
routes/health.py — Health and readiness endpoints.

GET /api/health        — liveness: is the process alive?
GET /api/health/ready  — readiness: can we reach the database?
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from backend.config import settings
from backend.database import get_db
from backend.schemas.analysis import HealthResponse

router = APIRouter(prefix="/api", tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness check",
    description="Returns 200 if the MAILTRACE backend process is running.",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database="not_checked",
    )


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness check",
    description="Returns 200 if the backend can reach the database.",
)
async def readiness_check(db: AsyncSession = Depends(get_db)) -> HealthResponse:
    db_status = "unreachable"
    try:
        await db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        db_status = f"error: {exc}"

    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database=db_status,
    )
