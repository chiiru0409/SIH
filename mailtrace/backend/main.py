"""
main.py — MAILTRACE FastAPI application entry point.

Responsibilities:
  - Create and configure the FastAPI app instance.
  - Register all routers.
  - Run startup / shutdown lifecycle events (DB init, dir creation).
  - Configure CORS for the React frontend.
  - Provide a root redirect to /docs.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from backend.config import settings
from backend.database import init_db
from backend.routes import health, analyze, correlation


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

    # Ensure upload and report directories exist
    for directory in (settings.UPLOAD_DIR, settings.REPORT_DIR):
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.info(f"  Directory ready: {directory}")

    # Initialize database tables
    logger.info("  Initializing database …")
    await init_db()
    logger.info(f"  Database: {settings.DATABASE_URL}")
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
#  CORS                                                                #
# ------------------------------------------------------------------ #
# In development allow all origins so the React dev server (port 5173
# or 3000) can call the API without proxy configuration.
# Tighten this to specific origins in production.
ALLOWED_ORIGINS = (
    ["*"]
    if settings.APP_ENV == "development"
    else [
        "https://mailtrace.yourdomain.com",  # replace before production deploy
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
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
