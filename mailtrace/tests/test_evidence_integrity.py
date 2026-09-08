"""
tests/test_evidence_integrity.py — Tests for Step 9: Evidence Integrity & Blockchain Anchoring.

Covers:
  1. Exact file SHA-256 hash.
  2. Deterministic parsed evidence hash.
  3. Deterministic analysis record hash.
  4. Structured evidence manifest generation.
  5. Cryptographic hash verification success.
  6. Tampered file/parsed data mismatch detection.
  7. Chain-of-custody genesis event creation.
  8. Chain-of-custody sequential hash chaining (event_n -> event_n-1).
  9. Event tampering detection in chain traversal.
  10. Mock blockchain anchor generation.
  11. Blockchain verification success & mismatch detection.
  12. Blockchain disabled/unavailable mode (Null provider).
  13. Blockchain anchor idempotency (duplicate anchor detection).
  14. Invalid case 404 handling.
  15. API verification endpoint (GET /api/evidence/{case_id}/verify).
  16. API anchor endpoint (POST /api/evidence/{case_id}/anchor).
  17. Secret protection (no private keys in API, manifest, or provider responses).
  18. Existing case backward compatibility (cases without Step 9 fields).
"""

import hashlib
import json
import pytest
from httpx import ASGITransport, AsyncClient

from backend.config import settings
from backend.database import AsyncSessionLocal, init_db
from backend.main import app
from backend.models.analysis import AnalysisCase
from backend.models.evidence import EvidenceEvent
from backend.services.blockchain import (
    BlockchainProvider,
    EthereumEVMProvider,
    MockBlockchainProvider,
    NullBlockchainProvider,
    get_blockchain_provider,
)
from backend.services.evidence_integrity import (
    build_evidence_manifest,
    compute_analysis_hash,
    compute_event_hash,
    compute_parsed_evidence_hash,
    record_chain_event,
    sha256_bytes,
    sha256_canonical_json,
    verify_case_evidence,
    verify_chain_of_custody,
)

SAMPLE_EML_BYTES = b"""From: security@paypal-verify.com
To: victim@example.com
Subject: Urgent: Verify your PayPal Account
Date: Tue, 08 Sep 2026 10:00:00 +0000
Message-ID: <threat-test-001@paypal-verify.com>

Please click http://evil-paypal-login.com to confirm your password.
"""


# ------------------------------------------------------------------ #
#  1. Cryptographic SHA-256 & Deterministic Hashing                  #
# ------------------------------------------------------------------ #

def test_exact_file_hash():
    """Test 1: Exact file bytes hash produces valid 64-char SHA-256."""
    expected = hashlib.sha256(SAMPLE_EML_BYTES).hexdigest().lower()
    computed = sha256_bytes(SAMPLE_EML_BYTES)
    assert computed == expected
    assert len(computed) == 64
    assert all(c in "0123456789abcdef" for c in computed)


def test_deterministic_parsed_evidence_hash():
    """Test 2: Deterministic parsed evidence hash is stable regardless of dict key order."""
    parsed_a = {
        "headers": {"subject": "Test Subject", "date": "2026-09-08"},
        "sender": {"email": "test@example.com"},
        "attachments": [],
    }
    parsed_b = {
        "sender": {"email": "test@example.com"},
        "attachments": [],
        "headers": {"date": "2026-09-08", "subject": "Test Subject"},
    }
    hash_a = compute_parsed_evidence_hash(parsed_a)
    hash_b = compute_parsed_evidence_hash(parsed_b)
    assert hash_a == hash_b
    assert len(hash_a) == 64

    # Changing any parsed value changes the hash
    parsed_modified = dict(parsed_a)
    parsed_modified["sender"] = {"email": "attacker@example.com"}
    hash_modified = compute_parsed_evidence_hash(parsed_modified)
    assert hash_modified != hash_a


def test_deterministic_analysis_hash():
    """Test 3: Deterministic commitment over forensic, threat, and risk outputs."""
    forensic = {"summary": {"status": "analyzed"}, "findings": [{"title": "SPF Fail", "severity": "HIGH"}]}
    threat = {"primary_threat": "PHISHING", "signals": {"urgency": True}}
    risk = {"risk_score": 85.0, "severity": "CRITICAL"}

    h1 = compute_analysis_hash(forensic, threat, risk)
    h2 = compute_analysis_hash(forensic, threat, risk)
    assert h1 == h2
    assert len(h1) == 64

    # Modifying risk score modifies analysis commitment
    risk_altered = {"risk_score": 20.0, "severity": "LOW"}
    h_altered = compute_analysis_hash(forensic, threat, risk_altered)
    assert h_altered != h1


# ------------------------------------------------------------------ #
#  2. Evidence Manifest Generation                                    #
# ------------------------------------------------------------------ #

def test_evidence_manifest_generation():
    """Test 4: Generate structured manifest with legal disclaimer and zero secrets."""
    file_hash = sha256_bytes(SAMPLE_EML_BYTES)
    case = AnalysisCase(
        id="case-manifest-001",
        original_filename="urgent_invoice.eml",
        stored_filename="case-manifest-001.eml",
        file_size_bytes=len(SAMPLE_EML_BYTES),
        evidence_hash=file_hash,
        parsed_email={"headers": {"subject": "Test"}},
        forensic_analysis={"findings": []},
        ai_analysis={"primary_threat": "SUSPICIOUS"},
        risk_score=75.0,
        risk_label="HIGH",
        status="parsed",
    )

    manifest = build_evidence_manifest(case, events=[])
    assert manifest["case_id"] == "case-manifest-001"
    assert manifest["file_sha256"] == file_hash
    assert manifest["hash_algorithm"] == "SHA-256"
    assert "legal_attribution_notice" in manifest
    assert "author identity" in manifest["legal_attribution_notice"]
    assert "private_key" not in manifest
    assert "rpc_url" not in manifest


# ------------------------------------------------------------------ #
#  3. Chain of Custody & Tamper Detection                             #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_chain_of_custody_genesis_and_chaining():
    """Tests 7 & 8: Genesis event has no prev_hash, subsequent events chain cryptographically."""
    await init_db()
    case_id = "case-chain-test-01"
    ev_hash = sha256_bytes(SAMPLE_EML_BYTES)

    async with AsyncSessionLocal() as session:
        # 1. Ingested (Genesis)
        ev1 = await record_chain_event(
            db=session,
            case_id=case_id,
            event_type="EVIDENCE_INGESTED",
            evidence_hash=ev_hash,
            metadata={"filename": "sample.eml"},
        )
        assert ev1.previous_event_hash is None
        assert len(ev1.event_hash) == 64

        # 2. Hashed
        ev2 = await record_chain_event(
            db=session,
            case_id=case_id,
            event_type="EVIDENCE_HASHED",
            evidence_hash=ev_hash,
            metadata={"algo": "SHA-256"},
        )
        assert ev2.previous_event_hash == ev1.event_hash
        assert len(ev2.event_hash) == 64

        # 3. Analyzed
        ev3 = await record_chain_event(
            db=session,
            case_id=case_id,
            event_type="EVIDENCE_ANALYZED",
            evidence_hash=ev_hash,
            metadata={"threat": "PHISHING"},
        )
        assert ev3.previous_event_hash == ev2.event_hash

        # Verify unbroken chain
        events = [ev1, ev2, ev3]
        valid, errors = verify_chain_of_custody(events)
        assert valid is True
        assert len(errors) == 0


def test_chain_tamper_detection():
    """Test 9: Modifying an event in the chain triggers tamper detection."""
    case_id = "case-tamper-01"
    ts = "2026-09-08T10:00:00+00:00"

    h1 = compute_event_hash("EVIDENCE_INGESTED", case_id, "hash1", ts, {"file": "a"}, None)
    e1 = EvidenceEvent(id=1, case_id=case_id, event_type="EVIDENCE_INGESTED", evidence_hash="hash1", previous_event_hash=None, event_hash=h1, timestamp=ts, event_metadata={"file": "a"})

    h2 = compute_event_hash("EVIDENCE_HASHED", case_id, "hash1", ts, {"algo": "sha256"}, h1)
    e2 = EvidenceEvent(id=2, case_id=case_id, event_type="EVIDENCE_HASHED", evidence_hash="hash1", previous_event_hash=h1, event_hash=h2, timestamp=ts, event_metadata={"algo": "sha256"})

    # Valid check
    valid, errors = verify_chain_of_custody([e1, e2])
    assert valid is True

    # Tamper 1: Modify metadata of event 1 without updating event_hash
    e1_tampered = EvidenceEvent(id=1, case_id=case_id, event_type="EVIDENCE_INGESTED", evidence_hash="hash1", previous_event_hash=None, event_hash=h1, timestamp=ts, event_metadata={"file": "TAMPERED"})
    valid, errors = verify_chain_of_custody([e1_tampered, e2])
    assert valid is False
    assert any("tampered" in err.lower() for err in errors)

    # Tamper 2: Broken link between e1 and e2
    e2_broken_link = EvidenceEvent(id=2, case_id=case_id, event_type="EVIDENCE_HASHED", evidence_hash="hash1", previous_event_hash="FORGED_PREV_HASH", event_hash=h2, timestamp=ts, event_metadata={"algo": "sha256"})
    valid, errors = verify_chain_of_custody([e1, e2_broken_link])
    assert valid is False
    assert any("link mismatch" in err.lower() for err in errors)


# ------------------------------------------------------------------ #
#  4. Blockchain Abstraction & Providers                             #
# ------------------------------------------------------------------ #

def test_mock_blockchain_provider():
    """Test 10: MockBlockchainProvider produces valid EVM-like tx hash and block info."""
    mock_prov = MockBlockchainProvider(network="ethereum-sepolia")
    ev_hash = sha256_bytes(SAMPLE_EML_BYTES)

    receipt = mock_prov.anchor_hash(ev_hash, {"case_id": "c-123"})
    assert receipt["anchored"] is True
    assert receipt["status"] == "anchored"
    assert receipt["evidence_hash"] == ev_hash
    assert receipt["transaction_id"].startswith("0x")
    assert len(receipt["transaction_id"]) == 66
    assert receipt["block_number"] > 0
    assert receipt["network"] == "ethereum-sepolia"

    # Verify anchor
    verif = mock_prov.verify_anchor(ev_hash, receipt["transaction_id"])
    assert verif["verified"] is True
    assert verif["network"] == "ethereum-sepolia"


def test_blockchain_anchor_idempotency():
    """Test 13: Anchoring same hash twice returns already_anchored idempotently."""
    mock_prov = MockBlockchainProvider()
    ev_hash = sha256_bytes(b"idempotency_test_evidence")

    r1 = mock_prov.anchor_hash(ev_hash)
    assert r1["anchored"] is True
    assert r1["status"] == "anchored"

    r2 = mock_prov.anchor_hash(ev_hash)
    assert r2["anchored"] is True
    assert r2["status"] == "already_anchored"
    assert r2["transaction_id"] == r1["transaction_id"]


def test_blockchain_anchor_mismatch():
    """Test 11: Blockchain verify returns mismatch when verified against different hash."""
    mock_prov = MockBlockchainProvider()
    h1 = "1111111111111111111111111111111111111111111111111111111111111111"
    h2 = "2222222222222222222222222222222222222222222222222222222222222222"

    receipt = mock_prov.anchor_hash(h1)
    tx = receipt["transaction_id"]

    # Verify with wrong hash
    verif = mock_prov.verify_anchor(h2, tx)
    assert verif["verified"] is False
    assert "differ" in verif["message"].lower() or "mismatch" in verif["message"].lower()


def test_null_blockchain_provider():
    """Test 12: NullBlockchainProvider handles disabled state gracefully."""
    null_prov = NullBlockchainProvider()
    ev_hash = sha256_bytes(SAMPLE_EML_BYTES)

    receipt = null_prov.anchor_hash(ev_hash)
    assert receipt["anchored"] is False
    assert receipt["status"] == "not_configured"

    verif = null_prov.verify_anchor(ev_hash, "0x123")
    assert verif["verified"] is None
    assert verif["status"] == "not_configured"


# ------------------------------------------------------------------ #
#  5. Full Case Integrity Verification (Services)                    #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_verify_case_evidence_success():
    """Test 5: Full verification passes when hashes match."""
    await init_db()
    case_id = "case-verify-ok"
    ev_hash = sha256_bytes(SAMPLE_EML_BYTES)
    parsed = {"headers": {"subject": "Valid Subject"}}
    parsed_hash = compute_parsed_evidence_hash(parsed)
    forensic = {"findings": []}
    threat = {"primary_threat": "BENIGN"}
    risk = {"risk_score": 10.0, "severity": "LOW"}
    analysis_hash = compute_analysis_hash(forensic, threat, risk)

    case = AnalysisCase(
        id=case_id,
        original_filename="valid.eml",
        stored_filename="valid.eml",
        evidence_hash=ev_hash,
        parsed_evidence_hash=parsed_hash,
        analysis_hash=analysis_hash,
        parsed_email=parsed,
        forensic_analysis=forensic,
        ai_analysis=threat,
        risk_score=10.0,
        risk_label="LOW",
        risk_reasons=risk,
        status="parsed",
    )

    async with AsyncSessionLocal() as session:
        session.add(case)
        await session.flush()

        # Record chain event
        await record_chain_event(session, case_id, "EVIDENCE_INGESTED", ev_hash)

        result = await verify_case_evidence(
            db=session,
            case=case,
            raw_file_bytes=SAMPLE_EML_BYTES,
            record_audit_event=False,
        )

        assert result["valid"] is True
        assert result["file_sha256"] == ev_hash
        assert result["parsed_evidence_sha256"] == parsed_hash
        assert result["chain_of_custody_valid"] is True


@pytest.mark.asyncio
async def test_verify_case_evidence_file_mismatch():
    """Test 6: Hash verification detects tampered file bytes."""
    await init_db()
    case_id = "case-verify-tampered"
    ev_hash = sha256_bytes(SAMPLE_EML_BYTES)
    parsed = {"headers": {"subject": "Test"}}

    case = AnalysisCase(
        id=case_id,
        original_filename="test.eml",
        stored_filename="test.eml",
        evidence_hash=ev_hash,
        parsed_evidence_hash=compute_parsed_evidence_hash(parsed),
        analysis_hash=compute_analysis_hash(None, None, None),
        parsed_email=parsed,
        status="parsed",
    )

    async with AsyncSessionLocal() as session:
        session.add(case)
        await session.flush()

        # Pass altered file bytes
        altered_bytes = SAMPLE_EML_BYTES + b"TAMPERED_INJECTION"
        result = await verify_case_evidence(
            db=session,
            case=case,
            raw_file_bytes=altered_bytes,
            record_audit_event=False,
        )

        assert result["valid"] is False
        assert any("FILE INTEGRITY MISMATCH" in d for d in result["details"])


# ------------------------------------------------------------------ #
#  6. API Integration Tests                                           #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_api_evidence_endpoints():
    """Tests 14, 15, 16: API upload -> get evidence -> verify -> anchor -> get chain."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload email to generate real case with Step 9 integrity
        files = {"file": ("test_step9.eml", SAMPLE_EML_BYTES, "message/rfc822")}
        res_upload = await client.post("/api/analyze/upload", files=files)
        assert res_upload.status_code == 200
        data_upload = res_upload.json()
        case_id = data_upload["case_id"]

        # 2. GET /api/evidence/{case_id}
        res_ev = await client.get(f"/api/evidence/{case_id}")
        assert res_ev.status_code == 200
        ev_manifest = res_ev.json()
        assert ev_manifest["case_id"] == case_id
        assert ev_manifest["file_sha256"] == sha256_bytes(SAMPLE_EML_BYTES)
        assert ev_manifest["hash_algorithm"] == "SHA-256"
        assert ev_manifest["chain_of_custody"]["total_events"] >= 3

        # 3. GET /api/evidence/{case_id}/verify
        res_ver = await client.get(f"/api/evidence/{case_id}/verify")
        assert res_ver.status_code == 200
        ver_data = res_ver.json()
        assert ver_data["valid"] is True
        assert ver_data["verification_method"] == "sha256"
        assert ver_data["chain_of_custody_valid"] is True

        # 4. POST /api/evidence/{case_id}/anchor (Mock or configured provider)
        res_anchor = await client.post(f"/api/evidence/{case_id}/anchor")
        assert res_anchor.status_code == 200
        anchor_data = res_anchor.json()
        assert anchor_data["case_id"] == case_id
        assert anchor_data["evidence_hash"] == ev_manifest["file_sha256"]

        # 5. GET /api/evidence/{case_id}/chain
        res_chain = await client.get(f"/api/evidence/{case_id}/chain")
        assert res_chain.status_code == 200
        chain_data = res_chain.json()
        assert chain_data["chain_valid"] is True
        assert chain_data["total_events"] >= 3

        # 6. Test 14: Invalid case returns 404
        res_404 = await client.get("/api/evidence/non-existent-case-id-12345")
        assert res_404.status_code == 404


# ------------------------------------------------------------------ #
#  7. Security & Secret Protection                                    #
# ------------------------------------------------------------------ #

def test_secret_protection_and_safe_serialization():
    """Test 17: Ensure provider info, manifest, and error messages never leak secrets."""
    provider = EthereumEVMProvider(
        rpc_url="https://secret-rpc.example.com/api-key-12345",
        private_key="0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        network="ethereum-mainnet",
    )
    info = provider.get_provider_info()
    assert "0123456789abcdef" not in str(info)
    assert "secret-rpc" not in str(info)
    assert "private_key" not in info


# ------------------------------------------------------------------ #
#  8. Existing Case Backward Compatibility                           #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_existing_case_backward_compatibility():
    """Test 18: Legacy cases from Steps 1–8 without new hash fields remain verifiable."""
    await init_db()
    legacy_case_id = "legacy-case-step1"
    ev_hash = sha256_bytes(SAMPLE_EML_BYTES)

    legacy_case = AnalysisCase(
        id=legacy_case_id,
        original_filename="legacy.eml",
        stored_filename="legacy.eml",
        evidence_hash=ev_hash,
        parsed_evidence_hash=None,   # Older case before Step 9
        analysis_hash=None,          # Older case before Step 9
        blockchain_tx_id=None,
        parsed_email={"headers": {"subject": "Legacy Email"}},
        forensic_analysis={},
        ai_analysis={},
        status="parsed",
    )

    async with AsyncSessionLocal() as session:
        session.add(legacy_case)
        await session.flush()

        # Verification recomputes dynamically and handles None gracefully
        result = await verify_case_evidence(
            db=session,
            case=legacy_case,
            raw_file_bytes=SAMPLE_EML_BYTES,
            record_audit_event=False,
        )
        assert result["valid"] is True
        assert result["file_sha256"] == ev_hash
