"""
routes/evidence.py — Evidence Integrity, Chain of Custody & Blockchain Anchoring Endpoints.

Endpoints:
  GET  /api/evidence/{case_id}         — Structured evidence manifest export
  GET  /api/evidence/{case_id}/verify  — Cryptographic hash & chain verification
  POST /api/evidence/{case_id}/anchor  — Blockchain anchor commitment
  GET  /api/evidence/{case_id}/chain   — Full chronological chain-of-custody log
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.analysis import AnalysisCase
from backend.models.evidence import EvidenceEvent
from backend.schemas.evidence import (
    EvidenceManifestResponse,
    EvidenceVerifyResponse,
    BlockchainAnchorResponse,
    ChainOfCustodyResponse,
    ChainOfCustodyEventResponse,
)
from backend.services.blockchain import get_blockchain_provider
from backend.services.evidence_integrity import (
    build_evidence_manifest,
    record_chain_event,
    verify_case_evidence,
    verify_chain_of_custody,
)

logger = logging.getLogger("mailtrace.routes.evidence")

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


async def _get_case_or_404(case_id: str, db: AsyncSession) -> AnalysisCase:
    res = await db.execute(select(AnalysisCase).where(AnalysisCase.id == case_id))
    case = res.scalar_one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": "error",
                "code": "CASE_NOT_FOUND",
                "message": f"No analysis case found with ID: {case_id}",
            },
        )
    return case


# ------------------------------------------------------------------ #
#  GET /api/evidence/{case_id}                                        #
# ------------------------------------------------------------------ #

@router.get(
    "/{case_id}",
    response_model=EvidenceManifestResponse,
    summary="Get structured evidence manifest for a case",
    description="Returns SHA-256 evidence commitments, chain of custody summary, and blockchain anchoring status.",
)
async def get_evidence_manifest(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> EvidenceManifestResponse:
    case = await _get_case_or_404(case_id, db)

    events_res = await db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.case_id == case_id)
        .order_by(EvidenceEvent.timestamp.asc())
    )
    events = events_res.scalars().all()

    manifest_dict = build_evidence_manifest(case, events)
    return EvidenceManifestResponse(**manifest_dict)


# ------------------------------------------------------------------ #
#  GET /api/evidence/{case_id}/verify                                 #
# ------------------------------------------------------------------ #

@router.get(
    "/{case_id}/verify",
    response_model=EvidenceVerifyResponse,
    summary="Verify cryptographic integrity of evidence and chain of custody",
    description="Recomputes raw file SHA-256, parsed evidence hash, analysis commitments, event chain, and blockchain anchors.",
)
async def verify_evidence(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> EvidenceVerifyResponse:
    case = await _get_case_or_404(case_id, db)
    verification = await verify_case_evidence(db=db, case=case, record_audit_event=True)
    return EvidenceVerifyResponse(**verification)


# ------------------------------------------------------------------ #
#  POST /api/evidence/{case_id}/anchor                                #
# ------------------------------------------------------------------ #

@router.post(
    "/{case_id}/anchor",
    response_model=BlockchainAnchorResponse,
    summary="Anchor evidence hash to blockchain ledger",
    description="Submits the case SHA-256 evidence hash to the configured blockchain provider and records an audited chain event.",
)
async def anchor_evidence(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> BlockchainAnchorResponse:
    case = await _get_case_or_404(case_id, db)
    evidence_hash = case.evidence_hash

    if not evidence_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "status": "error",
                "code": "MISSING_EVIDENCE_HASH",
                "message": f"Case {case_id} does not have a valid SHA-256 evidence hash.",
            },
        )

    provider = get_blockchain_provider()

    # Anchor hash with safe metadata
    anchor_receipt = provider.anchor_hash(
        evidence_hash=evidence_hash,
        metadata={
            "case_id": case.id,
            "original_filename": case.original_filename,
            "schema_version": "mailtrace-v1",
        },
    )

    if anchor_receipt.get("anchored"):
        tx_id = anchor_receipt.get("transaction_id")
        case.blockchain_tx_id = tx_id
        case.blockchain_anchor_data = anchor_receipt
        db.add(case)
        await db.flush()

        # Record in chain of custody
        try:
            await record_chain_event(
                db=db,
                case_id=case_id,
                event_type="BLOCKCHAIN_ANCHORED",
                evidence_hash=evidence_hash,
                metadata={
                    "transaction_id": tx_id,
                    "block_number": anchor_receipt.get("block_number"),
                    "block_timestamp": anchor_receipt.get("block_timestamp"),
                    "network": anchor_receipt.get("network"),
                    "provider": provider.get_provider_info().get("provider"),
                },
            )
            await db.flush()
        except Exception as exc:
            logger.warning(f"Could not record BLOCKCHAIN_ANCHORED chain event: {exc}")

    return BlockchainAnchorResponse(
        status=anchor_receipt.get("status", "error"),
        anchored=bool(anchor_receipt.get("anchored", False)),
        case_id=case_id,
        evidence_hash=evidence_hash,
        transaction_id=anchor_receipt.get("transaction_id"),
        block_number=anchor_receipt.get("block_number"),
        block_timestamp=anchor_receipt.get("block_timestamp"),
        network=anchor_receipt.get("network"),
        message=anchor_receipt.get("message", ""),
    )


# ------------------------------------------------------------------ #
#  GET /api/evidence/{case_id}/chain                                  #
# ------------------------------------------------------------------ #

@router.get(
    "/{case_id}/chain",
    response_model=ChainOfCustodyResponse,
    summary="Get chronological chain of custody for a case",
    description="Returns all tamper-evident events and verifies unbroken hash chaining.",
)
async def get_case_chain_of_custody(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> ChainOfCustodyResponse:
    case = await _get_case_or_404(case_id, db)

    events_res = await db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.case_id == case_id)
        .order_by(EvidenceEvent.timestamp.asc())
    )
    events = events_res.scalars().all()
    chain_valid, _ = verify_chain_of_custody(events)

    event_models = [
        ChainOfCustodyEventResponse(
            id=e.id,
            event_type=e.event_type,
            event_hash=e.event_hash,
            evidence_hash=e.evidence_hash,
            previous_event_hash=e.previous_event_hash,
            timestamp=e.timestamp.isoformat() if hasattr(e.timestamp, "isoformat") else str(e.timestamp),
            metadata=e.event_metadata or {},
        )
        for e in events
    ]

    return ChainOfCustodyResponse(
        case_id=case_id,
        evidence_hash=case.evidence_hash or "",
        total_events=len(events),
        chain_valid=chain_valid,
        events=event_models,
    )
