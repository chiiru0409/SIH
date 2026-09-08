"""
api/index.py — Vercel serverless Python entrypoint for MAILTRACE FastAPI backend.
"""

from __future__ import annotations

import logging
import sys
import traceback
from pathlib import Path

current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
mailtrace_dir = project_root / "mailtrace"

for path in (
    str(mailtrace_dir),
    str(project_root),
    str(current_dir),
    str(current_dir / "mailtrace"),
):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from backend.main import app  # noqa: F401
except Exception as exc:
    logging.exception(f"Fatal error initializing MAILTRACE FastAPI app in serverless runtime: {exc}")
    tb = traceback.format_exc()

    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    app = FastAPI(title="MAILTRACE Serverless Diagnostic Fallback")

    @app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
    async def fallback_handler(path_name: str):
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "code": "SERVERLESS_INITIALIZATION_ERROR",
                "message": str(exc),
                "traceback": tb.splitlines(),
                "sys_path": sys.path,
                "python_version": sys.version,
            },
        )
