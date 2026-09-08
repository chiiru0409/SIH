"""
tests/test_evidence_storage.py — Tests for Durable Evidence Storage Architecture.

Covers:
  1. EvidenceStorage save and load directly on AnalysisCase.
  2. SHA-256 exact byte commitment preservation.
  3. Evidence existence and non-sensitive metadata inspection.
  4. API upload persisting raw evidence bytes to DB with zero disk dependency.
  5. Cryptographic evidence verification directly from DB without any disk files.
  6. Tampered database bytes detection in verification.
  7. Cold start persistence simulation across independent DB sessions.
  8. Multi-case evidence isolation and unique hash guarantees.
  9. Missing evidence graceful handling (no HTTP 500).
  10. Legacy case backward compatibility without DB bytes or disk files.
  11. 25 MB max upload boundary validation.
"""

import hashlib
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from backend.config import settings
from backend.database import AsyncSessionLocal, init_db
from backend.main import app
from backend.models.analysis import AnalysisCase
from backend.services.evidence import sha256_bytes
from backend.services.evidence_integrity import (
    compute_analysis_hash,
    compute_parsed_evidence_hash,
    record_chain_event,
    verify_case_evidence,
)
from backend.services.storage import EvidenceStorage, storage

SAMPLE_EML_1 = b"""From: alerts@paypal-notification.com
To: user@example.com
Subject: Unauthorized Login Attempt
Date: Tue, 08 Sep 2026 12:00:00 +0000
Message-ID: <auth-alert-001@paypal-notification.com>

Please verify your identity at http://secure-paypal-verify.com.
"""

SAMPLE_EML_2 = b"""From: boss@company.com
To: finance@company.com
Subject: Urgent Wire Transfer Request
Date: Tue, 08 Sep 2026 12:05:00 +0000
Message-ID: <wire-req-002@company.com>

Please process the invoice attached immediately.
"""


# ------------------------------------------------------------------ #
#  1. Unit Tests for EvidenceStorage Abstraction                      #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_storage_save_and_load_direct():
    """Test 1: Save evidence bytes to case and load them back."""
    await init_db()
    case = AnalysisCase(
        id=str(uuid.uuid4()),
        original_filename="test_direct.eml",
        status="parsed",
    )
    EvidenceStorage.save_evidence_to_case(
        case=case,
        raw_bytes=SAMPLE_EML_1,
        filename="test_direct.eml",
        content_type="message/rfc822",
    )

    assert case.evidence_bytes == SAMPLE_EML_1
    assert case.file_size_bytes == len(SAMPLE_EML_1)
    assert case.evidence_content_type == "message/rfc822"
    assert case.evidence_storage_type == "db_bytea"
    assert case.evidence_hash == sha256_bytes(SAMPLE_EML_1)

    async with AsyncSessionLocal() as session:
        session.add(case)
        await session.flush()

        loaded_bytes = await EvidenceStorage.load_evidence(session, case)
        assert loaded_bytes == SAMPLE_EML_1

        exists = await EvidenceStorage.evidence_exists(session, case)
        assert exists is True

        meta = EvidenceStorage.get_metadata(case)
        assert meta["case_id"] == case.id
        assert meta["filename"] == "test_direct.eml"
        assert meta["size_bytes"] == len(SAMPLE_EML_1)
        assert meta["sha256"] == sha256_bytes(SAMPLE_EML_1)
        assert meta["storage_type"] == "db_bytea"
        assert meta["has_raw_bytes"] is True


# ------------------------------------------------------------------ #
#  2. API Upload & Zero Filesystem Dependency                         #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_api_upload_persists_evidence_bytes_to_db():
    """Test 2: API upload saves raw bytes directly into AnalysisCase row in DB."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("invoice_alert.eml", SAMPLE_EML_1, "message/rfc822")}
        res = await client.post("/api/analyze/upload", files=files)
        assert res.status_code == 200
        data = res.json()
        case_id = data["case_id"]
        expected_hash = sha256_bytes(SAMPLE_EML_1)
        assert data["sha256"] == expected_hash

        # Verify DB directly
        async with AsyncSessionLocal() as session:
            stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
            case = (await session.execute(stmt)).scalar_one_or_none()
            assert case is not None
            assert case.evidence_bytes == SAMPLE_EML_1
            assert case.evidence_hash == expected_hash
            assert case.evidence_storage_type == "db_bytea"


@pytest.mark.asyncio
async def test_verification_from_db_without_disk_file():
    """Test 3: Evidence verification re-hashes DB bytes with zero reliance on disk."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("wire_transfer.eml", SAMPLE_EML_2, "message/rfc822")}
        res_upload = await client.post("/api/analyze/upload", files=files)
        assert res_upload.status_code == 200
        case_id = res_upload.json()["case_id"]

        # Call GET /api/evidence/{case_id}/verify
        res_ver = await client.get(f"/api/evidence/{case_id}/verify")
        assert res_ver.status_code == 200
        ver_data = res_ver.json()
        assert ver_data["valid"] is True
        assert ver_data["file_sha256"] == sha256_bytes(SAMPLE_EML_2)
        assert ver_data["stored_file_sha256"] == sha256_bytes(SAMPLE_EML_2)
        assert ver_data["chain_of_custody_valid"] is True


@pytest.mark.asyncio
async def test_tampered_database_bytes_detected():
    """Test 4: If database bytes are altered, verification fails with FILE INTEGRITY MISMATCH."""
    await init_db()
    case_id = f"case-tamper-db-{uuid.uuid4()}"
    original_hash = sha256_bytes(SAMPLE_EML_1)
    parsed = {"headers": {"subject": "Test"}}

    case = AnalysisCase(
        id=case_id,
        original_filename="tamper_test.eml",
        stored_filename="",
        file_size_bytes=len(SAMPLE_EML_1),
        evidence_bytes=SAMPLE_EML_1 + b"MALICIOUS_INJECTION",  # Tampered bytes
        evidence_hash=original_hash,                            # Original recorded hash
        parsed_evidence_hash=compute_parsed_evidence_hash(parsed),
        analysis_hash=compute_analysis_hash(None, None, None),
        parsed_email=parsed,
        status="parsed",
    )

    async with AsyncSessionLocal() as session:
        session.add(case)
        await session.flush()
        await record_chain_event(session, case_id, "EVIDENCE_INGESTED", original_hash)

        result = await verify_case_evidence(db=session, case=case, record_audit_event=False)
        assert result["valid"] is False
        assert any("FILE INTEGRITY MISMATCH" in d for d in result["details"])


# ------------------------------------------------------------------ #
#  3. Cold Start & Multi-Case Isolation Simulation                   #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_cold_start_persistence_simulation():
    """Test 5: Ingest case in one session, close it, and retrieve in a fresh session."""
    await init_db()
    case_id = f"case-cold-start-{uuid.uuid4()}"
    expected_hash = sha256_bytes(SAMPLE_EML_1)

    # Session 1: Upload and persist
    async with AsyncSessionLocal() as session1:
        case = AnalysisCase(
            id=case_id,
            original_filename="cold_start.eml",
            stored_filename="",
            file_size_bytes=len(SAMPLE_EML_1),
            evidence_bytes=SAMPLE_EML_1,
            evidence_hash=expected_hash,
            status="parsed",
        )
        session1.add(case)
        await session1.commit()

    # Session 2: Cold start simulation (completely separate session / connection)
    async with AsyncSessionLocal() as session2:
        stmt = select(AnalysisCase).where(AnalysisCase.id == case_id)
        recovered_case = (await session2.execute(stmt)).scalar_one_or_none()
        assert recovered_case is not None
        assert recovered_case.evidence_bytes == SAMPLE_EML_1
        assert sha256_bytes(recovered_case.evidence_bytes) == expected_hash

        ver_result = await verify_case_evidence(db=session2, case=recovered_case, record_audit_event=False)
        assert ver_result["valid"] is True
        assert ver_result["file_sha256"] == expected_hash


@pytest.mark.asyncio
async def test_multi_case_isolation():
    """Test 6: Multiple uploads maintain distinct cases, evidence bytes, and hashes."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res1 = await client.post("/api/analyze/upload", files={"file": ("eml1.eml", SAMPLE_EML_1, "message/rfc822")})
        res2 = await client.post("/api/analyze/upload", files={"file": ("eml2.eml", SAMPLE_EML_2, "message/rfc822")})

        assert res1.status_code == 200
        assert res2.status_code == 200

        case1_id = res1.json()["case_id"]
        case2_id = res2.json()["case_id"]

        assert case1_id != case2_id
        assert res1.json()["sha256"] != res2.json()["sha256"]

        # Verify each case independently
        ver1 = (await client.get(f"/api/evidence/{case1_id}/verify")).json()
        ver2 = (await client.get(f"/api/evidence/{case2_id}/verify")).json()

        assert ver1["valid"] is True
        assert ver2["valid"] is True
        assert ver1["file_sha256"] == sha256_bytes(SAMPLE_EML_1)
        assert ver2["file_sha256"] == sha256_bytes(SAMPLE_EML_2)


# ------------------------------------------------------------------ #
#  4. Edge Cases & Boundary Handling                                 #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_legacy_case_missing_evidence_graceful():
    """Test 7: Legacy case with no evidence bytes and missing file does not raise 500 error."""
    await init_db()
    case_id = f"case-legacy-missing-{uuid.uuid4()}"
    case = AnalysisCase(
        id=case_id,
        original_filename="missing.eml",
        stored_filename="non_existent_file_12345.eml",
        evidence_bytes=None,
        evidence_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        status="parsed",
    )

    async with AsyncSessionLocal() as session:
        session.add(case)
        await session.flush()

        ver_result = await verify_case_evidence(db=session, case=case, record_audit_event=False)
        assert ver_result["valid"] is False
        assert any("not found in durable storage" in d for d in ver_result["details"])


@pytest.mark.asyncio
async def test_max_upload_size_boundary():
    """Test 8: Reject files larger than MAX_UPLOAD_SIZE_MB with 413."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create bytes larger than MAX_UPLOAD_SIZE_MB (e.g. 26 MB)
        oversized = b"A" * (settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024 + 1024)
        res = await client.post("/api/analyze/upload", files={"file": ("huge.eml", oversized, "message/rfc822")})
        assert res.status_code == 413
        assert res.json()["detail"]["code"] == "FILE_TOO_LARGE"
