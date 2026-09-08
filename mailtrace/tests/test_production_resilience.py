"""
tests/test_production_resilience.py — Production resilience, PostgreSQL / Neon compatibility,
empty database handling, health/readiness endpoints, and security checks.
"""

from __future__ import annotations

import os
import pytest
from httpx import ASGITransport, AsyncClient

from backend.config import BASE_DIR, settings
from backend.database import (
    get_raw_database_url,
    normalize_database_url,
    mask_database_url,
    get_database_info,
    init_db,
    get_db,
)
from backend.main import app
from backend.schemas.analysis import HealthResponse, DatabaseStatus


# ------------------------------------------------------------------ #
#  1. Database URL Normalization & Secret Masking Tests              #
# ------------------------------------------------------------------ #

def test_normalize_database_url_postgres_variants():
    """Verify postgres:// and postgresql:// are converted to postgresql+asyncpg://"""
    raw_postgres = "postgres://user:secret_pass@ep-cool-fog-123.us-east-2.aws.neon.tech/neondb"
    norm = normalize_database_url(raw_postgres)
    assert norm.startswith("postgresql+asyncpg://")
    assert "user:secret_pass" in norm

    raw_postgresql = "postgresql://user:secret_pass@ep-cool-fog-123.us-east-2.aws.neon.tech/neondb"
    norm2 = normalize_database_url(raw_postgresql)
    assert norm2.startswith("postgresql+asyncpg://")


def test_normalize_database_url_sslmode_conversion():
    """Verify sslmode=require is translated to ssl=require for asyncpg."""
    raw_neon = "postgresql://user:secret@ep-cool-fog-123.us-east-2.aws.neon.tech/neondb?sslmode=require"
    norm = normalize_database_url(raw_neon)
    assert "ssl=require" in norm
    assert "sslmode" not in norm


def test_normalize_database_url_filters_incompatible_params():
    """Verify incompatible query parameters (channel_binding, endpoint) are safely stripped."""
    raw_complex = (
        "postgresql://user:secret@ep-cool-fog-123.us-east-2.aws.neon.tech/neondb"
        "?sslmode=require&channel_binding=prefer&endpoint=ep-cool-fog-123"
    )
    norm = normalize_database_url(raw_complex)
    assert "ssl=require" in norm
    assert "channel_binding" not in norm
    assert "endpoint=" not in norm


def test_mask_database_url_redacts_credentials():
    """Verify mask_database_url redacts passwords and auth tokens."""
    url = "postgresql+asyncpg://admin_user:super_secret_pw123@ep-xyz.aws.neon.tech/neondb?ssl=require"
    masked = mask_database_url(url)
    assert "super_secret_pw123" not in masked
    assert "admin_user:***@" in masked
    assert "ep-xyz.aws.neon.tech/neondb" in masked

    empty_masked = mask_database_url("")
    assert empty_masked == "<empty>"


def test_get_database_info_safe_structure():
    """Verify get_database_info returns safe non-sensitive metadata without secrets."""
    info = get_database_info()
    assert "engine" in info
    assert "dialect" in info
    assert "provider" in info
    assert "status" in info
    assert "connected" in info
    # Ensure no secret keys exist in the returned dictionary
    for k in ("password", "user", "url", "dsn", "secret"):
        assert k not in info


# ------------------------------------------------------------------ #
#  2. Asyncpg Availability & Engine Diagnostics                      #
# ------------------------------------------------------------------ #

def test_asyncpg_import_and_version():
    """Verify asyncpg is installed and importable in the runtime."""
    import asyncpg
    assert hasattr(asyncpg, "__version__")
    assert asyncpg.__version__


# ------------------------------------------------------------------ #
#  3. HTTP API Health and Readiness Endpoint Tests                   #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_api_health_liveness():
    """GET /api/health should return 200 OK with app info and safe database status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["app"] == settings.APP_NAME
        assert data["version"] == settings.APP_VERSION
        assert "environment" in data
        assert "db_info" in data
        assert data["db_info"]["connected"] is True


@pytest.mark.asyncio
async def test_api_health_readiness():
    """GET /api/health/ready should execute SELECT 1 and return 200 OK."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["database"] == "ready"
        assert data["db_info"]["status"] == "ready"
        assert data["db_info"]["connected"] is True


# ------------------------------------------------------------------ #
#  4. Empty Database Response Tests (Zero 500s)                       #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_empty_database_case_list():
    """GET /api/analyze/cases must return 200 OK and [] when database is initialized."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/analyze/cases?page=1&page_size=20")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)


@pytest.mark.asyncio
async def test_empty_database_correlation():
    """GET /api/correlation must return 200 OK with empty valid graph structure."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/correlation")
        assert res.status_code == 200
        data = res.json()
        assert "total_cases" in data
        assert "total_campaigns" in data
        assert "campaigns" in data
        assert "correlations" in data
        assert "graph" in data
        assert "nodes" in data["graph"]
        assert "edges" in data["graph"]
        assert isinstance(data["campaigns"], list)
        assert isinstance(data["correlations"], list)


@pytest.mark.asyncio
async def test_nonexistent_case_returns_404_not_500():
    """GET /api/analyze/{non_existent_id} must return 404 Not Found, never 500."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/analyze/00000000-0000-0000-0000-000000000000")
        assert res.status_code == 404
        data = res.json()
        assert data["detail"]["code"] == "CASE_NOT_FOUND"


@pytest.mark.asyncio
async def test_nonexistent_evidence_returns_404_not_500():
    """GET /api/evidence/{non_existent_id} must return 404 Not Found, never 500."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/evidence/00000000-0000-0000-0000-000000000000")
        assert res.status_code == 404
        data = res.json()
        assert data["detail"]["code"] == "CASE_NOT_FOUND"


# ------------------------------------------------------------------ #
#  5. End-to-End Ingest, Forensics, Risk & Evidence Verification     #
# ------------------------------------------------------------------ #

@pytest.mark.asyncio
async def test_e2e_phishing_eml_upload_and_persistence():
    """Upload real sample phishing.eml and verify full pipeline + persistence."""
    await init_db()
    phishing_path = BASE_DIR / "samples" / "phishing.eml"
    if not phishing_path.exists():
        pytest.skip("phishing.eml sample file not present")

    eml_bytes = phishing_path.read_bytes()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Upload email
        files = {"file": ("phishing.eml", eml_bytes, "message/rfc822")}
        upload_res = await client.post("/api/analyze/upload", files=files)
        assert upload_res.status_code == 200
        upload_data = upload_res.json()

        case_id = upload_data["case_id"]
        assert case_id
        assert upload_data["status"] in ("parsed", "parsed_with_warnings")
        assert upload_data["sha256"]

        # 2. Retrieve case by ID
        case_res = await client.get(f"/api/analyze/{case_id}")
        assert case_res.status_code == 200
        case_detail = case_res.json()
        assert case_detail["case_id"] == case_id
        assert case_detail["risk_score"] is not None
        assert case_detail["forensic_analysis"] is not None
        assert case_detail["evidence_hash"] == upload_data["sha256"]

        # 3. Retrieve evidence manifest
        manifest_res = await client.get(f"/api/evidence/{case_id}")
        assert manifest_res.status_code == 200
        manifest = manifest_res.json()
        assert manifest["case_id"] == case_id
        assert manifest["file_sha256"] == upload_data["sha256"]

        # 4. Verify evidence integrity
        verify_res = await client.get(f"/api/evidence/{case_id}/verify")
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["valid"] is True
        assert verify_data["chain_of_custody_valid"] is True

        # 5. Check case in list
        list_res = await client.get("/api/analyze/cases?page=1&page_size=10")
        assert list_res.status_code == 200
        cases_list = list_res.json()
        matching = [c for c in cases_list if c["case_id"] == case_id]
        assert len(matching) == 1
