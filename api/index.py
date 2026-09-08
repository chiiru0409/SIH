"""
api/index.py — Vercel serverless Python entrypoint for MAILTRACE FastAPI backend.
"""

import sys
from pathlib import Path

current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent
mailtrace_dir = project_root / "mailtrace"

for path in (str(mailtrace_dir), str(project_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from backend.main import app  # noqa: F401
