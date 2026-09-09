"""
routes/tenants.py — Sentaro-style Cloud Tenant Connectors & Live Stream API endpoints.

GET /api/tenants/list    — List connected Microsoft 365 / Google Workspace / Gateway tenants
GET /api/tenants/stream  — Retrieve live incoming email threat activity stream
"""

from __future__ import annotations

from fastapi import APIRouter
from backend.services.tenant_connector import get_tenants, get_live_tenant_stream

router = APIRouter(prefix="/api/tenants", tags=["tenants"])


@router.get("/list")
async def list_tenants():
    """Retrieve connected M365 and Google Workspace tenant configurations."""
    return {"tenants": get_tenants()}


@router.get("/stream")
async def live_stream():
    """Retrieve real-time incoming email event stream from connected cloud tenants."""
    return {"events": get_live_tenant_stream()}
