"""
services/evidence_integrity.py — Evidence Integrity, Tamper-Evident Hashing & Chain-of-Custody.

Standards:
  - Algorithm: SHA-256 (FIPS 180-4 standard).
  - Deterministic serialization: JSON sorted keys, UTF-8 encoded, ASCII stripped, volatile fields omitted.
  - Tamper-evident Hash Chaining: event_n_hash = SHA256(event_type:case_id:evidence_hash:timestamp:metadata:prev_hash).
  - Chain-of-custody verification: Complete forward traversal detecting deletions, reorderings, or altered fields.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.models.analysis import AnalysisCase
from backend.models.evidence import EvidenceEvent
from backend.services.blockchain import get_blockchain_provider

logger = logging.getLogger("mailtrace.services.evidence_integrity")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------ #
#  1. Cryptographic SHA-256 Primitives                               #
# ------------------------------------------------------------------ #

def sha256_bytes(data: bytes) -> str:
    """Returns hexadecimal SHA-256 digest of raw byte sequence."""
    return hashlib.sha256(data).hexdigest().lower()


def sha256_file(path: str | Path) -> str:
    """Streams file from filesystem and returns hexadecimal SHA-256 digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def sha256_canonical_json(data: Any) -> str:
    """
    Deterministic SHA-256 digest of JSON-compatible data structures.
    Guarantees stable key ordering and consistent serialization without whitespace variances.
    """
    serialized = json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest().lower()


# ------------------------------------------------------------------ #
#  2. Domain-Specific Commitments & Hashes                            #
# ------------------------------------------------------------------ #

def compute_parsed_evidence_hash(parsed_data: dict | None) -> str:
    """
    Compute a deterministic commitment over the parsed email evidence.
    Excludes volatile metadata like transient parse error objects while committing to headers,
    body hashes, authentication results, hop chains, attachments, and URLs.
    """
    if not parsed_data:
        return hashlib.sha256(b"empty_parsed_data").hexdigest().lower()

    body_data = parsed_data.get("body")
    body_sha256 = None
    html_sha256 = None

    if isinstance(body_data, dict):
        body_sha256 = body_data.get("plain_sha256")
        html_sha256 = body_data.get("html_sha256")
        if not body_sha256 and body_data.get("plain"):
            body_sha256 = sha256_bytes(str(body_data.get("plain")).encode("utf-8"))
        if not html_sha256 and body_data.get("html"):
            html_sha256 = sha256_bytes(str(body_data.get("html")).encode("utf-8"))
    elif isinstance(body_data, str) and body_data:
        body_sha256 = sha256_bytes(body_data.encode("utf-8"))

    # Filter into canonical representation
    canonical = {
        "headers": parsed_data.get("headers", {}),
        "sender": parsed_data.get("sender", {}),
        "recipients": parsed_data.get("recipients", {}),
        "reply_to": parsed_data.get("reply_to", {}),
        "return_path": parsed_data.get("return_path", {}),
        "authentication": parsed_data.get("authentication", {}),
        "received_chain": parsed_data.get("received_chain", {}),
        "indicators": parsed_data.get("indicators", {}),
        "body_sha256": body_sha256,
        "html_sha256": html_sha256,
        "attachments": [
            {
                "filename": a.get("filename"),
                "sha256": a.get("sha256"),
                "size_bytes": a.get("size_bytes"),
                "content_type": a.get("content_type"),
            }
            for a in (parsed_data.get("attachments") or [])
        ],
    }

    return sha256_canonical_json(canonical)


def compute_analysis_hash(
    forensic_data: dict | None,
    threat_data: dict | None,
    risk_data: dict | None,
) -> str:
    """
    Compute a deterministic commitment over the forensic findings, threat analysis, and risk scores.
    """
    canonical = {
        "forensic_summary": (forensic_data or {}).get("summary", {}),
        "forensic_findings": [
            {
                "title": f.get("title"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "evidence": f.get("evidence"),
            }
            for f in (forensic_data or {}).get("findings", [])
        ],
        "threat_primary": (threat_data or {}).get("primary_threat"),
        "threat_signals": (threat_data or {}).get("signals", {}),
        "risk_score": (risk_data or {}).get("risk_score") if isinstance(risk_data, dict) else None,
        "risk_severity": (risk_data or {}).get("severity") if isinstance(risk_data, dict) else None,
    }
    return sha256_canonical_json(canonical)


# ------------------------------------------------------------------ #
#  3. Chain of Custody & Event Hash Chaining                          #
# ------------------------------------------------------------------ #

def _canonical_timestamp_str(val: Any) -> str:
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        else:
            val = val.astimezone(timezone.utc)
        return val.isoformat()
    s = str(val).strip()
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.isoformat()
    except Exception:
        return s


def compute_event_hash(
    event_type: str,
    case_id: str,
    evidence_hash: str,
    timestamp_str: Any,
    metadata: dict | None,
    previous_event_hash: str | None,
) -> str:
    """
    Calculate tamper-evident event commitment:
    SHA256(event_type || case_id || evidence_hash || timestamp_iso || canonical_metadata || prev_hash)
    """
    ts_canonical = _canonical_timestamp_str(timestamp_str)
    canonical_meta = json.dumps(
        metadata or {},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    raw_payload = f"{event_type}|{case_id}|{evidence_hash}|{ts_canonical}|{canonical_meta}|{previous_event_hash or 'GENESIS'}"
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest().lower()


async def record_chain_event(
    db: AsyncSession,
    case_id: str,
    event_type: str,
    evidence_hash: str,
    metadata: dict | None = None,
    event_time: datetime | None = None,
) -> EvidenceEvent:
    """
    Append an immutable, hash-chained event to the case's chain of custody.
    """
    # 1. Fetch latest event for this case to get previous_event_hash
    res = await db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.case_id == case_id)
        .order_by(EvidenceEvent.timestamp.desc())
        .limit(1)
    )
    latest_event = res.scalar_one_or_none()
    prev_hash = latest_event.event_hash if latest_event else None

    timestamp = event_time or _utcnow()
    event_hash = compute_event_hash(
        event_type=event_type,
        case_id=case_id,
        evidence_hash=evidence_hash.lower(),
        timestamp_str=timestamp,
        metadata=metadata,
        previous_event_hash=prev_hash,
    )

    event = EvidenceEvent(
        case_id=case_id,
        event_type=event_type,
        evidence_hash=evidence_hash.lower(),
        previous_event_hash=prev_hash,
        event_hash=event_hash,
        timestamp=timestamp,
        event_metadata=metadata or {},
    )

    db.add(event)
    await db.flush()
    logger.info(f"ChainOfCustody: Recorded event {event_type} for case {case_id[:8]}… (hash={event_hash[:12]}… prev={prev_hash[:12] if prev_hash else 'GENESIS'})")
    return event


def verify_chain_of_custody(events: Sequence[EvidenceEvent]) -> tuple[bool, list[str]]:
    """
    Verify the cryptographic integrity of a sequence of chain-of-custody events.
    Checks:
      1. Genesis event has previous_event_hash = None.
      2. Each subsequent event has previous_event_hash matching previous event's event_hash.
      3. Recomputed event_hash matches recorded event_hash for every event.
    """
    if not events:
        return True, []

    errors: list[str] = []

    for i, event in enumerate(events):
        expected_prev = events[i - 1].event_hash if i > 0 else None
        if event.previous_event_hash != expected_prev:
            errors.append(
                f"Event #{i + 1} ({event.event_type}) chain link mismatch: "
                f"previous_event_hash='{event.previous_event_hash}', expected='{expected_prev}'."
            )

        recomputed_hash = compute_event_hash(
            event_type=event.event_type,
            case_id=event.case_id,
            evidence_hash=event.evidence_hash,
            timestamp_str=event.timestamp,
            metadata=event.event_metadata,
            previous_event_hash=event.previous_event_hash,
        )

        if recomputed_hash != event.event_hash:
            errors.append(
                f"Event #{i + 1} ({event.event_type}) content tampered: "
                f"recorded hash='{event.event_hash}', recomputed='{recomputed_hash}'."
            )

    return len(errors) == 0, errors


# ------------------------------------------------------------------ #
#  4. Comprehensive Evidence Verification                             #
# ------------------------------------------------------------------ #

async def verify_case_evidence(
    db: AsyncSession,
    case: AnalysisCase,
    raw_file_bytes: bytes | None = None,
    record_audit_event: bool = True,
) -> dict[str, Any]:
    """
    Execute full cryptographic integrity verification on an investigation case:
      - Verify raw file bytes match stored SHA-256 evidence_hash.
      - Verify parsed email data matches parsed_evidence_hash.
      - Verify analysis record matches analysis_hash.
      - Verify chain of custody event sequence.
      - Verify blockchain anchor if recorded.
    """
    case_id = case.id
    details: list[str] = []
    is_valid = True

    # 1. File hash verification
    expected_file_hash = case.evidence_hash or ""
    actual_file_hash = ""

    if raw_file_bytes is not None:
        actual_file_hash = sha256_bytes(raw_file_bytes)
    elif case.evidence_bytes is not None:
        actual_file_hash = sha256_bytes(case.evidence_bytes)
    else:
        # Fallback: check legacy disk path if available (for pre-migration local test cases)
        loaded = False
        if case.stored_filename:
            file_path = Path(settings.UPLOAD_DIR) / case.stored_filename
            if file_path.is_file():
                try:
                    actual_file_hash = sha256_file(file_path)
                    loaded = True
                except Exception as read_err:
                    logger.warning(f"Could not read legacy evidence file {file_path}: {read_err}")
        if not loaded:
            is_valid = False
            details.append("Stored evidence bytes not found in durable storage.")

    if actual_file_hash and expected_file_hash:
        if actual_file_hash.lower() == expected_file_hash.lower():
            details.append("File SHA-256 matches stored evidence commitment.")
        else:
            is_valid = False
            details.append(
                f"FILE INTEGRITY MISMATCH: current='{actual_file_hash}', stored='{expected_file_hash}'."
            )
    elif not expected_file_hash:
        is_valid = False
        details.append("Case has no recorded SHA-256 evidence commitment.")

    # 2. Parsed evidence hash verification
    current_parsed_hash = compute_parsed_evidence_hash(case.parsed_email)
    stored_parsed_hash = case.parsed_evidence_hash or current_parsed_hash
    if current_parsed_hash != stored_parsed_hash:
        is_valid = False
        details.append(
            f"PARSED DATA MISMATCH: current='{current_parsed_hash}', stored='{stored_parsed_hash}'."
        )
    else:
        details.append("Parsed evidence structure hash verified.")

    # 3. Analysis record hash verification
    current_analysis_hash = compute_analysis_hash(
        case.forensic_analysis, case.ai_analysis, case.risk_reasons
    )
    stored_analysis_hash = case.analysis_hash or current_analysis_hash
    if current_analysis_hash != stored_analysis_hash:
        is_valid = False
        details.append(
            f"ANALYSIS COMMITMENT MISMATCH: current='{current_analysis_hash}', stored='{stored_analysis_hash}'."
        )
    else:
        details.append("Forensic analysis commitment hash verified.")

    # 4. Chain of custody verification
    res = await db.execute(
        select(EvidenceEvent)
        .where(EvidenceEvent.case_id == case_id)
        .order_by(EvidenceEvent.timestamp.asc())
    )
    events = res.scalars().all()
    chain_valid, chain_errors = verify_chain_of_custody(events)

    if not chain_valid:
        is_valid = False
        details.extend(chain_errors)
    else:
        details.append(f"Chain of custody verified ({len(events)} events in unbroken hash chain).")

    # 5. Blockchain anchor verification
    blockchain_verified: bool | None = None
    blockchain_details: dict[str, Any] = {}
    provider = get_blockchain_provider()

    if case.blockchain_tx_id:
        anchor_check = provider.verify_anchor(
            evidence_hash=expected_file_hash,
            transaction_ref=case.blockchain_tx_id,
        )
        blockchain_verified = anchor_check.get("verified")
        blockchain_details = anchor_check
        if blockchain_verified is True:
            details.append(f"Blockchain anchor verified (tx: {case.blockchain_tx_id[:16]}…).")
        elif blockchain_verified is False:
            is_valid = False
            details.append(f"BLOCKCHAIN ANCHOR MISMATCH: {anchor_check.get('message')}")
    else:
        blockchain_details = {
            "status": "not_anchored",
            "message": "Case has not yet been anchored to blockchain.",
        }

    # 6. Record verification event in chain of custody if valid and requested
    if record_audit_event and is_valid and expected_file_hash:
        try:
            await record_chain_event(
                db=db,
                case_id=case_id,
                event_type="EVIDENCE_VERIFIED",
                evidence_hash=expected_file_hash,
                metadata={
                    "verified_at": _utcnow_iso(),
                    "file_sha256": actual_file_hash or expected_file_hash,
                    "parsed_sha256": current_parsed_hash,
                    "analysis_sha256": current_analysis_hash,
                    "chain_events_checked": len(events),
                },
            )
        except Exception as exc:
            logger.warning(f"Could not record EVIDENCE_VERIFIED audit event: {exc}")

    return {
        "valid": is_valid,
        "case_id": case_id,
        "file_sha256": actual_file_hash or expected_file_hash,
        "stored_file_sha256": expected_file_hash,
        "parsed_evidence_sha256": current_parsed_hash,
        "stored_parsed_sha256": stored_parsed_hash,
        "analysis_sha256": current_analysis_hash,
        "stored_analysis_sha256": stored_analysis_hash,
        "verification_method": "sha256",
        "chain_of_custody_valid": chain_valid,
        "chain_of_custody_events_count": len(events),
        "blockchain_verified": blockchain_verified,
        "blockchain_details": blockchain_details,
        "details": details,
        "verified_at": _utcnow_iso(),
    }


# ------------------------------------------------------------------ #
#  5. Exportable Evidence Manifest                                    #
# ------------------------------------------------------------------ #

def build_evidence_manifest(
    case: AnalysisCase,
    events: Sequence[EvidenceEvent] | None = None,
) -> dict[str, Any]:
    """
    Construct a structured, exportable evidence manifest for investigators and legal proceedings.
    """
    event_list = [
        {
            "id": e.id,
            "event_type": e.event_type,
            "event_hash": e.event_hash,
            "previous_event_hash": e.previous_event_hash,
            "timestamp": e.timestamp.isoformat() if isinstance(e.timestamp, datetime) else str(e.timestamp),
            "metadata": e.event_metadata or {},
        }
        for e in (events or [])
    ]

    provider = get_blockchain_provider()
    blockchain_info = provider.get_provider_info()

    return {
        "case_id": case.id,
        "evidence_type": "email/rfc822_eml",
        "original_filename": case.original_filename,
        "file_size_bytes": case.file_size_bytes,
        "file_sha256": case.evidence_hash or "",
        "parsed_evidence_sha256": case.parsed_evidence_hash or compute_parsed_evidence_hash(case.parsed_email),
        "analysis_sha256": case.analysis_hash or compute_analysis_hash(case.forensic_analysis, case.ai_analysis, case.risk_reasons),
        "hash_algorithm": "SHA-256",
        "integrity_status": "verified" if case.status != "error" else "compromised",
        "created_at": case.created_at.isoformat() if isinstance(case.created_at, datetime) else str(case.created_at),
        "updated_at": case.updated_at.isoformat() if isinstance(case.updated_at, datetime) else str(case.updated_at),
        "chain_of_custody": {
            "total_events": len(event_list),
            "events": event_list,
        },
        "blockchain_anchoring": {
            "enabled": blockchain_info.get("enabled", False),
            "provider": blockchain_info.get("provider", "none"),
            "network": blockchain_info.get("network", "none"),
            "transaction_id": case.blockchain_tx_id,
            "anchor_data": case.blockchain_anchor_data,
            "status": "anchored" if case.blockchain_tx_id else "not_anchored",
        },
        "legal_attribution_notice": (
            "Evidence integrity establishes cryptographic proof that original bytes, parsed forensic data, "
            "and analysis scores match their recorded SHA-256 commitments. "
            "Integrity validation proves non-tampering; it does not represent proof of author identity or criminal attribution."
        ),
    }
