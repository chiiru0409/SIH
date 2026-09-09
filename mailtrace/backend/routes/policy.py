"""
routes/policy.py — Mimecast-style Policy & Quarantine API endpoints.

GET  /api/policy/rules         — List configured SOC policy rules
GET  /api/policy/quarantine    — List all quarantined items in vault
POST /api/policy/quarantine/{case_id}/remediate — Apply SOC action (RELEASE / PURGE / BLOCK_SENDER)
GET  /api/policy/blocklist     — List enterprise blocklist
POST /api/policy/blocklist     — Add entry to blocklist
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel

from backend.services.policy_engine import (
    get_active_policies,
    get_quarantine_vault,
    remediate_quarantine,
    get_blocklist,
    add_blocklist_entry,
)

router = APIRouter(prefix="/api/policy", tags=["policy"])


class RemediateRequest(BaseModel):
    action: str  # RELEASE, PURGE, BLOCK_SENDER, BLOCK_DOMAIN
    notes: Optional[str] = None


class BlocklistRequest(BaseModel):
    type: str  # DOMAIN, SENDER, IP
    value: str
    reason: Optional[str] = "Manual SOC Block"


@router.get("/rules")
async def list_policies():
    """List all active enterprise email security policies."""
    return {"policies": get_active_policies()}


@router.get("/quarantine")
async def list_quarantine():
    """List all emails currently held in the SOC Quarantine Vault."""
    return {"quarantined_items": get_quarantine_vault()}


@router.post("/quarantine/{case_id}/remediate")
async def remediate_item(case_id: str, payload: RemediateRequest):
    """Apply an analyst action (RELEASE / PURGE / BLOCK_SENDER) to a quarantined item."""
    res = remediate_quarantine(case_id, payload.action, payload.notes)
    return res


@router.get("/blocklist")
async def list_blocklist():
    """Retrieve current enterprise domain and sender blocklists."""
    return {"blocklist": get_blocklist()}


@router.post("/blocklist")
async def add_blocklist(payload: BlocklistRequest):
    """Add a new entry to the blocklist."""
    if not payload.value.strip():
        raise HTTPException(status_code=400, detail="Blocklist value cannot be empty.")
    entry = add_blocklist_entry(payload.type, payload.value, payload.reason or "Manual SOC Block")
    return {"success": True, "entry": entry}
