"""
routes/compliance.py — Sentaro-style Compliance & Governance Scorecard endpoint.

GET /api/compliance/scorecard — Retrieve NIS2, DORA, and SOC 2 email security audit scorecard
"""

from __future__ import annotations

from fastapi import APIRouter
from backend.services.compliance import get_compliance_scorecard

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("/scorecard")
async def compliance_scorecard():
    """Retrieve cybersecurity compliance and regulatory audit scorecard."""
    return get_compliance_scorecard()
