"""
main.py — MAILTRACE FastAPI application entry point.

Responsibilities:
  - Create and configure the FastAPI app instance.
  - Register all routers.
  - Run startup / shutdown lifecycle events (DB init, dir creation).
  - Configure robust CORS for frontend and deployment domains.
  - Provide a root redirect to /docs.
"""

import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from backend.config import settings
from backend.database import ACTIVE_DATABASE_URL, init_db, mask_database_url
from backend.routes import health, analyze, correlation, evidence


# ------------------------------------------------------------------ #
#  Logging                                                            #
# ------------------------------------------------------------------ #
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("mailtrace")


# ------------------------------------------------------------------ #
#  Lifespan (startup / shutdown)                                      #
# ------------------------------------------------------------------ #
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---- Startup ----
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} v{settings.APP_VERSION}  [{settings.APP_ENV}]")
    logger.info("=" * 60)

    # Ensure upload and report directories exist in local dev (safely ignored in serverless)
    if not os.getenv("VERCEL") and not os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        for directory in (settings.UPLOAD_DIR, settings.REPORT_DIR):
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                logger.debug(f"  Directory ready: {directory}")
            except Exception as exc:
                logger.debug(f"  Directory check notice for {directory}: {exc}")

    # Initialize database tables
    logger.info("  Initializing database …")
    try:
        await init_db()
        logger.info(f"  Database connected: {mask_database_url(ACTIVE_DATABASE_URL)}")
    except Exception as exc:
        logger.error(f"  Database initialization warning: {exc}")
    logger.info("  Startup complete. MAILTRACE is ready.")
    logger.info("=" * 60)

    yield  # Application is running

    # ---- Shutdown ----
    logger.info("MAILTRACE shutting down …")


# ------------------------------------------------------------------ #
#  App instance                                                        #
# ------------------------------------------------------------------ #
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform.\n\n"
        "Upload `.eml` files to receive a full forensic + AI threat analysis report."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ------------------------------------------------------------------ #
#  CORS Configuration                                                 #
# ------------------------------------------------------------------ #
raw_cors = (settings.CORS_ORIGINS or "").strip()
if raw_cors == "*" or not raw_cors:
    # Open CORS (credentials False for wildcard standard compliance)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # Specific origins
    allowed_list = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_list,
        allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ------------------------------------------------------------------ #
#  Routers                                                            #
# ------------------------------------------------------------------ #
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(correlation.router)
app.include_router(evidence.router)


# ------------------------------------------------------------------ #
#  Root                                                               #
# ------------------------------------------------------------------ #
@app.get("/", include_in_schema=False)
async def root():
    """Redirect browser root to interactive API docs."""
    return RedirectResponse(url="/docs")


# ------------------------------------------------------------------ #
#  Dev server entry point                                             #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
