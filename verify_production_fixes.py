"""
verify_production_fixes.py — End-to-end verification of MAILTRACE production 500 fixes,
Neon database support, schema initialization, empty database handling, and forensic pipeline.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Add project roots
sys.path.insert(0, str(Path(__file__).resolve().parent / "mailtrace"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from httpx import ASGITransport, AsyncClient
from backend.config import BASE_DIR, settings
from backend.database import (
    get_raw_database_url,
    normalize_database_url,
    mask_database_url,
    get_database_info,
    init_db,
)
from backend.main import app


async def run_verification():
    print("=" * 70)
    print("MAILTRACE — PRODUCTION 500 FIX & NEON DATABASE VERIFICATION SUITE")
    print("=" * 70)

    # Step 1: URL Normalization & Diagnostics
    print("\n[Step 1] Database URL Normalization & Masking Checks...")
    neon_sample = "postgresql://mailtrace_user:secret_neon_pass_123@ep-cool-fog-123.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=prefer"
    norm_neon = normalize_database_url(neon_sample)
    masked_neon = mask_database_url(norm_neon)

    assert norm_neon.startswith("postgresql+asyncpg://"), f"Failed protocol conversion: {norm_neon}"
    assert "ssl=require" in norm_neon, f"Failed sslmode conversion: {norm_neon}"
    assert "channel_binding" not in norm_neon, f"Incompatible param not stripped: {norm_neon}"
    assert "secret_neon_pass_123" not in masked_neon, f"Credential leaked in masked URL: {masked_neon}"
    assert "mailtrace_user:***@" in masked_neon, f"Masking format mismatch: {masked_neon}"
    print(f"  [PASS] Neon URL normalized: {norm_neon}")
    print(f"  [PASS] Masked URL safe for logs: {masked_neon}")

    db_info = get_database_info()
    print(f"  [PASS] Safe Database Info: {db_info}")
    assert "password" not in db_info and "url" not in db_info

    # Step 2: Schema Initialization
    print("\n[Step 2] Automated Schema Initialization...")
    await init_db()
    print("  [PASS] Schema initialized successfully (tables and safe additive migrations ready).")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:

        # Step 3: Health and Readiness Endpoints
        print("\n[Step 3] API Health & Readiness Probes...")
        health_res = await client.get("/api/health")
        assert health_res.status_code == 200, f"Health check failed: {health_res.status_code} {health_res.text}"
        health_data = health_res.json()
        print(f"  [PASS] GET /api/health -> 200 OK | status={health_data['status']} db={health_data.get('database')}")

        ready_res = await client.get("/api/health/ready")
        assert ready_res.status_code == 200, f"Readiness check failed: {ready_res.status_code} {ready_res.text}"
        ready_data = ready_res.json()
        print(f"  [PASS] GET /api/health/ready -> 200 OK | db_status={ready_data.get('database')} info={ready_data.get('db_info')}")

        # Step 4: Startup Requests with Empty Database State (Zero 500s)
        print("\n[Step 4] Startup Requests & Empty Database Handling (Zero 500 Errors)...")
        cases_res = await client.get("/api/analyze/cases?page=1&page_size=50")
        assert cases_res.status_code == 200, f"Empty cases list failed: {cases_res.status_code} {cases_res.text}"
        cases_data = cases_res.json()
        print(f"  [PASS] GET /api/analyze/cases (empty) -> 200 OK | returned {len(cases_data)} items")

        corr_res = await client.get("/api/correlation")
        assert corr_res.status_code == 200, f"Empty correlation overview failed: {corr_res.status_code} {corr_res.text}"
        corr_data = corr_res.json()
        print(f"  [PASS] GET /api/correlation (empty) -> 200 OK | total_cases={corr_data['total_cases']} nodes={len(corr_data['graph']['nodes'])}")

        corr_alias_res = await client.get("/api/correlation/cases")
        assert corr_alias_res.status_code == 200, f"Correlation cases alias failed: {corr_alias_res.status_code}"
        print(f"  [PASS] GET /api/correlation/cases -> 200 OK")

        # Step 5: Real Sample Ingestion & Forensics Pipeline
        print("\n[Step 5] Ingest Real Sample phishing.eml & Execute Full Forensic Pipeline...")
        sample_path = BASE_DIR / "samples" / "phishing.eml"
        assert sample_path.exists(), f"Missing sample {sample_path}"
        eml_bytes = sample_path.read_bytes()

        files = {"file": ("phishing.eml", eml_bytes, "message/rfc822")}
        upload_res = await client.post("/api/analyze/upload", files=files)
        assert upload_res.status_code == 200, f"Upload failed: {upload_res.status_code} {upload_res.text}"
        upload_data = upload_res.json()

        case_id = upload_data["case_id"]
        sha256_hash = upload_data["sha256"]
        risk_score = upload_data["risk_assessment"]["risk_score"]
        risk_label = upload_data["risk_assessment"]["severity"]
        print(f"  [PASS] POST /api/analyze/upload -> 200 OK")
        print(f"         Case ID    : {case_id}")
        print(f"         SHA-256    : {sha256_hash}")
        print(f"         Risk Score : {risk_score} ({risk_label})")
        print(f"         SPF/DKIM   : SPF={upload_data['authentication']['spf']} DKIM={upload_data['authentication']['dkim']}")

        # Step 6: Case Persistence Verification
        print("\n[Step 6] Case Persistence & Retrieval Verification...")
        detail_res = await client.get(f"/api/analyze/{case_id}")
        assert detail_res.status_code == 200, f"Fetch case failed: {detail_res.status_code} {detail_res.text}"
        detail_data = detail_res.json()

        assert detail_data["case_id"] == case_id
        assert detail_data["evidence_hash"] == sha256_hash
        assert detail_data["risk_score"] == risk_score
        assert detail_data["forensic_analysis"] is not None
        assert detail_data["ai_analysis"] is not None
        print(f"  [PASS] GET /api/analyze/{case_id} -> 200 OK | Case verified in database.")

        # Step 7: Evidence Integrity & Chain-of-Custody Verification
        print("\n[Step 7] Evidence Integrity & Cryptographic Verification...")
        manifest_res = await client.get(f"/api/evidence/{case_id}")
        assert manifest_res.status_code == 200
        manifest_data = manifest_res.json()
        print(f"  [PASS] GET /api/evidence/{case_id} -> 200 OK | Manifest retrieved.")

        verify_res = await client.get(f"/api/evidence/{case_id}/verify")
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["valid"] is True
        assert verify_data["chain_of_custody_valid"] is True
        print(f"  [PASS] GET /api/evidence/{case_id}/verify -> 200 OK | Cryptographic verification PASS.")

        chain_res = await client.get(f"/api/evidence/{case_id}/chain")
        assert chain_res.status_code == 200
        chain_data = chain_res.json()
        print(f"  [PASS] GET /api/evidence/{case_id}/chain -> 200 OK | Events count: {chain_data['total_events']}")

        anchor_res = await client.post(f"/api/evidence/{case_id}/anchor")
        assert anchor_res.status_code == 200
        anchor_data = anchor_res.json()
        print(f"  [PASS] POST /api/evidence/{case_id}/anchor -> 200 OK | Anchored: {anchor_data['anchored']}")

        # Step 8: Multi-Case Correlation & Graph Synthesis
        print("\n[Step 8] Global Correlation & Graph Verification with Persisted Case...")
        corr_active_res = await client.get("/api/correlation")
        assert corr_active_res.status_code == 200
        corr_active = corr_active_res.json()
        assert corr_active["total_cases"] >= 1
        assert len(corr_active["graph"]["nodes"]) >= 1
        print(f"  [PASS] GET /api/correlation -> 200 OK | Total Cases: {corr_active['total_cases']}, Graph Nodes: {len(corr_active['graph']['nodes'])}, Edges: {len(corr_active['graph']['edges'])}")

        # Step 9: Error Semantics & 404 Tests
        print("\n[Step 9] Error Semantics & Non-Existent ID Handling...")
        fake_res = await client.get("/api/analyze/00000000-0000-0000-0000-000000000000")
        assert fake_res.status_code == 404
        print("  [PASS] Non-existent case returned 404 (Not 500)")

    print("\n" + "=" * 70)
    print("ALL 9 VERIFICATION PHASES PASSED WITH ZERO ERRORS!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_verification())
