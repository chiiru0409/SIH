"""
routes/analyze.py — Email analysis endpoints.

POST /api/analyze/upload   — upload .eml, parse, store, return structured result
GET  /api/analyze/cases    — list all cases (paginated)
GET  /api/analyze/{id}     — get full case detail
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.database import get_db
from backend.models.analysis import AnalysisCase
from backend.schemas.analysis import CaseDetail, CaseSummary, UploadResponse
from backend.services.email_parser import parse_email
from backend.services.evidence import build_evidence_record, sha256_bytes
from backend.services.evidence_integrity import (
    compute_analysis_hash,
    compute_parsed_evidence_hash,
    record_chain_event,
)
from backend.services.forensics import run_forensic_analysis
from backend.services.intelligence import enrich_infrastructure
from backend.services.risk_engine import calculate_risk
from backend.services.threat_analyzer import analyze_threat

logger = logging.getLogger("mailtrace.routes.analyze")

router = APIRouter(prefix="/api/analyze", tags=["analyze"])

MAX_BYTES = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _safe_str(val) -> str | None:
    """Return str or None — never crash on unexpected types."""
    if val is None:
        return None
    return str(val)


def _build_upload_response(
    case: AnalysisCase,
    parsed: dict,
    evidence: dict,
    forensic: dict | None = None,
    threat: dict | None = None,
    intel: dict | None = None,
    risk: dict | None = None,
) -> dict:
    """Build the structured JSON response for POST /upload."""
    headers = parsed.get("headers", {})
    sender  = parsed.get("sender", {})
    recips  = parsed.get("recipients", {})
    auth    = parsed.get("authentication", {})
    relay   = parsed.get("received_chain", {})
    indic   = parsed.get("indicators", {})

    return {
        "case_id":  case.id,
        "status":   case.status,
        "filename": case.original_filename,
        "sha256":   evidence.get("file_sha256", ""),
        "message":  "Email successfully parsed and stored.",
        "email": {
            "from":    sender.get("email"),
            "from_display": sender.get("display_name"),
            "to":      [r.get("email") for r in recips.get("to", [])],
            "cc":      [r.get("email") for r in recips.get("cc", [])],
            "subject": headers.get("subject"),
            "date":    headers.get("date_iso") or headers.get("date_raw"),
            "message_id": headers.get("message_id"),
            "reply_to":   parsed.get("reply_to", {}).get("email") if parsed.get("reply_to") else None,
            "return_path": parsed.get("return_path", {}).get("email") if parsed.get("return_path") else None,
        },
        "authentication": {
            "spf":   auth.get("spf", {}).get("status"),
            "dkim":  auth.get("dkim", {}).get("status"),
            "dmarc": auth.get("dmarc", {}).get("status"),
        },
        "smtp_trace": {
            "hop_count":      relay.get("hop_count", 0),
            "received_chain": relay.get("chain", []),
            "public_ips":     relay.get("public_ips_observed", []),
            "earliest_node":  relay.get("earliest_observed_node"),
            "confidence_note": relay.get("confidence_note"),
        },
        "indicators": {
            "ips":         [a["ip"] for a in parsed.get("ip_addresses", [])],
            "domains":     parsed.get("domains", []),
            "urls":        [u["url"] for u in parsed.get("urls", [])],
            "attachments": [
                {
                    "filename":     a["filename"],
                    "content_type": a["content_type"],
                    "size_bytes":   a["size_bytes"],
                    "sha256":       a["sha256"],
                }
                for a in parsed.get("attachments", [])
            ],
            "flags": {
                "reply_to_mismatch":    indic.get("reply_to_mismatch", False),
                "return_path_mismatch": indic.get("return_path_mismatch", False),
                "missing_message_id":   indic.get("missing_message_id", False),
                "has_attachments":      indic.get("has_attachments", False),
            },
        },
        "evidence": {
            "file_sha256":        evidence.get("file_sha256"),
            "parsed_data_sha256": evidence.get("parsed_data_sha256"),
            "integrity_note":     evidence.get("integrity_note"),
        },
        "forensic_analysis": forensic or case.forensic_analysis,
        "threat_analysis": threat or case.ai_analysis,
        "infrastructure_intelligence": intel or {
            "ips": (case.ip_intel or {}).get("ips", []),
            "domains": (case.domain_intel or {}).get("domains", []),
            "urls": (case.url_intel or {}).get("urls", []),
            "summary": (case.ip_intel or {}).get("summary", {}),
        },
        "risk_assessment": risk or (case.risk_reasons if isinstance(case.risk_reasons, dict) else {
            "risk_score": case.risk_score,
            "severity": case.risk_label,
            "risk_factors": [],
        }),
        "parse_errors": parsed.get("parse_errors", []),
    }


# ------------------------------------------------------------------ #
#  POST /api/analyze/upload                                           #
# ------------------------------------------------------------------ #

@router.post(
    "/upload",
    summary="Upload and forensically parse a .eml file",
    description=(
        "Accepts a `.eml` file up to 25 MB. "
        "Parses MIME structure, extracts headers/auth/URLs/IPs/attachments, "
        "stores the case in the database, and returns a structured forensic report."
    ),
    status_code=status.HTTP_200_OK,
)
async def upload_eml(
    file: UploadFile = File(..., description="The .eml file to analyze"),
    db: AsyncSession = Depends(get_db),
) -> dict:

    # ---- Validate filename extension ----
    filename = file.filename or "unknown.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": "error",
                "code": "INVALID_FILE_TYPE",
                "message": "Only .eml files are accepted.",
            },
        )

    # ---- Read bytes ----
    try:
        raw_bytes = await file.read()
    except Exception as exc:
        logger.error(f"File read error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "code": "READ_ERROR", "message": "Could not read uploaded file."},
        )

    # ---- Validate size ----
    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"status": "error", "code": "EMPTY_FILE", "message": "The uploaded file is empty."},
        )

    if len(raw_bytes) > MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "status": "error",
                "code": "FILE_TOO_LARGE",
                "message": f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB} MB.",
            },
        )

    # ---- Generate case ID and store file ----
    case_id = str(uuid.uuid4())
    safe_name = f"{case_id}.eml"
    upload_path = Path(settings.UPLOAD_DIR) / safe_name

    try:
        upload_path.write_bytes(raw_bytes)
    except Exception as exc:
        logger.error(f"File storage error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "code": "STORAGE_ERROR", "message": "Could not store uploaded file."},
        )

    # ---- Parse email ----
    try:
        parsed = parse_email(raw_bytes)
    except Exception as exc:
        logger.error(f"Parser crash (should not happen): {exc}")
        parsed = {"parse_errors": [str(exc)], "fatal": True}

    # Check for fatal parse failure
    if parsed.get("fatal"):
        # Clean up stored file
        try:
            os.remove(upload_path)
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": "error",
                "code": "INVALID_EMAIL",
                "message": "The uploaded file could not be parsed as a valid email.",
                "detail": parsed.get("parse_errors", []),
            },
        )

    # ---- Build evidence record ----
    evidence = build_evidence_record(
        case_id=case_id,
        original_filename=filename,
        file_bytes=raw_bytes,
        parsed_email_dict=parsed,
    )

    # ---- Determine parse status ----
    parse_errors = parsed.get("parse_errors", [])
    case_status = "parsed_with_warnings" if parse_errors else "parsed"

    # ---- Step 3: Run forensic analysis ----
    try:
        forensic_data = run_forensic_analysis(parsed, raw_bytes)
    except Exception as exc:
        logger.error(f"Forensics error: {exc}")
        forensic_data = {
            "summary": {"status": "error", "error": str(exc)},
            "findings": [],
            "facts": [],
            "inferences": [],
            "limitations": [],
        }

    # ---- Step 4: Run AI threat analysis ----
    try:
        threat_data = analyze_threat(parsed, forensic_data)
    except Exception as exc:
        logger.error(f"Threat analysis error: {exc}")
        threat_data = {
            "primary_threat": "SUSPICIOUS",
            "secondary_threats": [],
            "confidence": 0.50,
            "signals": {},
            "indicators": [],
            "explanation": f"Threat analysis encountered an unexpected error: {exc}",
            "evidence_summary": {"facts": [], "inferences": []},
            "analysis_method": "local",
            "model_info": "fallback",
        }

    # ---- Step 5: Run infrastructure intelligence enrichment ----
    try:
        intel_data = enrich_infrastructure(parsed, forensic_data, threat_data)
    except Exception as exc:
        logger.error(f"Intelligence enrichment error: {exc}")
        intel_data = {
            "summary": {"status": "error", "error": str(exc)},
            "ips": [],
            "domains": [],
            "urls": [],
            "correlation_entities": {},
            "limitations": [],
        }

    # ---- Step 6: Run unified risk assessment ----
    try:
        risk_data = calculate_risk(forensic_data, threat_data, intel_data, parsed)
    except Exception as exc:
        logger.error(f"Risk assessment error: {exc}")
        risk_data = {
            "risk_score": 50.0,
            "severity": "MEDIUM",
            "risk_factors": [],
            "category_scores": {},
            "top_factors": [],
            "explanation": f"Risk assessment encountered an unexpected error: {exc}",
            "confidence": 0.50,
            "method": "deterministic_weighted",
            "limitations": [],
        }

    # ---- Step 9: Compute integrity commitments ----
    parsed_evidence_hash = compute_parsed_evidence_hash(parsed)
    analysis_hash = compute_analysis_hash(forensic_data, threat_data, risk_data)

    # ---- Persist to database ----
    case = AnalysisCase(
        id=case_id,
        original_filename=filename,
        stored_filename=safe_name,
        file_size_bytes=len(raw_bytes),
        parsed_email=parsed,
        forensic_analysis=forensic_data,
        ai_analysis=threat_data,
        ip_intel={"ips": intel_data.get("ips", []), "summary": intel_data.get("summary", {})},
        domain_intel={"domains": intel_data.get("domains", []), "summary": intel_data.get("summary", {})},
        url_intel={"urls": intel_data.get("urls", []), "summary": intel_data.get("summary", {})},
        risk_score=risk_data.get("risk_score"),
        risk_label=risk_data.get("severity"),
        risk_reasons=risk_data,
        status=case_status,
        evidence_hash=evidence["file_sha256"],
        parsed_evidence_hash=parsed_evidence_hash,
        analysis_hash=analysis_hash,
    )

    try:
        db.add(case)
        await db.flush()   # write to DB within this transaction

        # Record initial Chain of Custody events
        await record_chain_event(
            db=db,
            case_id=case_id,
            event_type="EVIDENCE_INGESTED",
            evidence_hash=evidence["file_sha256"],
            metadata={"original_filename": filename, "file_size_bytes": len(raw_bytes)},
        )
        await record_chain_event(
            db=db,
            case_id=case_id,
            event_type="EVIDENCE_HASHED",
            evidence_hash=evidence["file_sha256"],
            metadata={"parsed_evidence_sha256": parsed_evidence_hash, "algorithm": "SHA-256"},
        )
        await record_chain_event(
            db=db,
            case_id=case_id,
            event_type="EVIDENCE_ANALYZED",
            evidence_hash=analysis_hash,
            metadata={"risk_score": risk_data.get("risk_score"), "risk_label": risk_data.get("severity")},
        )
    except Exception as exc:
        logger.error(f"DB insert error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "code": "DB_ERROR", "message": "Could not store analysis case."},
        )

    logger.info(f"Case {case_id} stored — file={filename} status={case_status} risk={risk_data.get('risk_score')} ({risk_data.get('severity')}) sha256={evidence['file_sha256'][:16]}…")

    return _build_upload_response(case, parsed, evidence, forensic_data, threat_data, intel_data, risk_data)


# ------------------------------------------------------------------ #
#  GET /api/analyze/cases                                             #
# ------------------------------------------------------------------ #

@router.get(
    "/cases",
    response_model=list[CaseSummary],
    summary="List all analysis cases",
    description="Returns a paginated list of cases, newest first.",
)
async def list_cases(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Results per page"),
    db: AsyncSession = Depends(get_db),
) -> list[CaseSummary]:
    offset = (page - 1) * page_size
    result = await db.execute(
        select(AnalysisCase)
        .order_by(AnalysisCase.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    cases = result.scalars().all()
    return [
        CaseSummary(
            case_id=c.id,
            original_filename=c.original_filename,
            status=c.status,
            risk_score=c.risk_score,
            risk_label=c.risk_label,
            created_at=c.created_at,
        )
        for c in cases
    ]


# ------------------------------------------------------------------ #
#  GET /api/analyze/{case_id}                                         #
# ------------------------------------------------------------------ #

@router.get(
    "/{case_id}",
    response_model=CaseDetail,
    summary="Get full analysis for a case",
    description="Returns the complete forensic analysis record for the given case ID.",
)
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> CaseDetail:
    result = await db.execute(
        select(AnalysisCase).where(AnalysisCase.id == case_id)
    )
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": "error",
                "code": "CASE_NOT_FOUND",
                "message": f"No analysis case found with ID: {case_id}",
            },
        )

    return CaseDetail(
        case_id=case.id,
        original_filename=case.original_filename,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        parsed_email=case.parsed_email,
        forensic_analysis=case.forensic_analysis,
        ai_analysis=case.ai_analysis,
        ip_intel=case.ip_intel,
        domain_intel=case.domain_intel,
        url_intel=case.url_intel,
        risk_score=case.risk_score,
        risk_label=case.risk_label,
        risk_reasons=case.risk_reasons,
        campaign_id=case.campaign_id,
        correlation_data=case.correlation_data,
        report_path=case.report_path,
        evidence_hash=case.evidence_hash,
        error_detail=case.error_detail,
    )
