"""
api/index.py — Vercel serverless Python entrypoint for MAILTRACE FastAPI backend.
"""

from __future__ import annotations

import json
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

# Attempt to load main application
try:
    from backend.main import app as fastapi_app
    _init_error = None
    _init_traceback = None
except Exception as exc:
    _init_error = str(exc)
    _init_traceback = traceback.format_exc()
    fastapi_app = None


class SafeServerlessASGI:
    """
    ASGI entrypoint wrapper that prevents FUNCTION_INVOCATION_FAILED crashes
    by gracefully catching all unhandled exceptions and returning structured JSON diagnostics.
    """
    def __init__(self, inner_app, init_err: str | None = None, init_tb: str | None = None):
        self.inner_app = inner_app
        self.init_err = init_err
        self.init_tb = init_tb

    async def __call__(self, scope, receive, send):
        # 1. Lifespan events
        if scope.get("type") == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    if self.inner_app is not None:
                        try:
                            # Let inner app handle startup if it has lifespan
                            pass
                        except Exception as e:
                            logging.exception(f"Lifespan startup error: {e}")
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return

        # 2. Non-HTTP scopes
        if scope.get("type") != "http":
            if self.inner_app is not None:
                await self.inner_app(scope, receive, send)
            return

        # 3. Initialization failure handler
        if self.init_err or self.inner_app is None:
            body = json.dumps({
                "status": "error",
                "code": "SERVERLESS_INIT_ERROR",
                "message": self.init_err or "Application failed to initialize",
                "traceback": (self.init_tb or "").splitlines(),
                "sys_path": sys.path,
                "python_version": sys.version,
            }).encode("utf-8")

            await send({
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        # 4. Normal HTTP execution with exception capture
        try:
            await self.inner_app(scope, receive, send)
        except Exception as exc:
            tb = traceback.format_exc()
            logging.exception(f"Unhandled serverless HTTP exception: {exc}")
            body = json.dumps({
                "status": "error",
                "code": "SERVERLESS_RUNTIME_EXCEPTION",
                "exception_class": exc.__class__.__name__,
                "message": str(exc),
                "traceback": tb.splitlines(),
            }).encode("utf-8")

            try:
                await send({
                    "type": "http.response.start",
                    "status": 500,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": body,
                })
            except Exception:
                # If headers were already sent, ignore send errors
                pass


# Export as ASGI 'app' for Vercel
app = SafeServerlessASGI(fastapi_app, _init_error, _init_traceback)
