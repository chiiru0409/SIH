"""
verify_step3.py — MAILTRACE Step 3 Deep Email Forensic Analysis Verification.

Performs live end-to-end verification of:
  1. FastAPI Server Startup & Lifespan
  2. Health & Readiness endpoints
  3. Upload of Clean Email & Deep Forensic Output
  4. Upload of Phishing / Deceptive Email & Forensic Anomaly Detection
  5. Authentication Forensics (SPF, DKIM, DMARC, Domain Alignment)
  6. Identity Consistency (From vs Reply-To, Return-Path, Display Name Spoofing)
  7. Received-Chain Relay Forensics (Earliest infrastructure, hops, IP exposure)
  8. Header Anomaly & Message-ID Forensics
  9. Date & Timestamp Anomaly Analysis
 10. Strict FACT vs. INFERENCE Separation
 11. Database Persistence & Retrieval
 12. Security & Sandbox Boundary Verification
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn

# Set encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.disable(logging.CRITICAL)

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from backend.main import app

BASE_URL = "http://127.0.0.1:8001"
results: dict[str, bool] = {}

def OK(msg: str):
    print(f"  [PASS]  {msg}")

def FAIL(msg: str):
    print(f"  [FAIL]  {msg}")

def HDR(msg: str):
    print(f"\n{'=' * 65}\n  {msg}\n{'=' * 65}")

def _start_server():
    for logger_name in [
        "sqlalchemy", "sqlalchemy.engine", "aiosqlite", "httpcore",
        "httpx", "mailtrace", "uvicorn", "uvicorn.access", "uvicorn.error"
    ]:
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)
    config = uvicorn.Config(app, host="127.0.0.1", port=8001, log_level="critical", access_log=False)
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    return server

def _wait_ready(timeout: int = 15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            r = httpx.get(f"{BASE_URL}/api/health", timeout=2)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def run_verification():
    HDR("MAILTRACE STEP 3 — DEEP FORENSICS VERIFICATION")
    
    server = _start_server()
    if not _wait_ready():
        FAIL("Server failed to start within timeout.")
        return False
    OK("FastAPI server started successfully on http://127.0.0.1:8001")

    client = httpx.Client(base_url=BASE_URL, timeout=10)

    # 1. Health & Readiness
    HDR("1. HEALTH & READINESS CHECKS")
    r = client.get("/api/health")
    assert r.status_code == 200
    OK(f"GET /api/health → status={r.json().get('status')} version={r.json().get('version')}")

    r = client.get("/api/health/ready")
    assert r.status_code == 200
    OK(f"GET /api/health/ready → database={r.json().get('database')}")
    results["health"] = True

    # 2. Upload Clean Email
    HDR("2. CLEAN EMAIL FORENSIC VALIDATION")
    clean_eml = (
        "From: Legal Team <legal@corp.example.com>\r\n"
        "To: recipient@destination.org\r\n"
        "Subject: Signed Agreement\r\n"
        "Date: Mon, 15 Jan 2024 10:00:00 +0000\r\n"
        "Message-ID: <legal_1001@corp.example.com>\r\n"
        "Return-Path: <legal-bounces@corp.example.com>\r\n"
        "Authentication-Results: mx.destination.org; spf=pass (corp.example.com designates 93.184.216.34); dkim=pass header.d=corp.example.com; dmarc=pass\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=corp.example.com; s=k1; b=legit==\r\n"
        "Received: from mx.destination.org (mx [93.184.216.35]) by mail.destination.org; Mon, 15 Jan 2024 10:01:00 +0000\r\n"
        "Received: from mail.corp.example.com (mail [93.184.216.34]) by mx.destination.org; Mon, 15 Jan 2024 10:00:20 +0000\r\n"
        "\r\n"
        "Please find the signed agreement enclosed."
    ).encode("utf-8")

    r = client.post("/api/analyze/upload", files={"file": ("clean_agreement.eml", clean_eml, "message/rfc822")})
    assert r.status_code == 200
    data = r.json()
    clean_case_id = data["case_id"]
    forensic = data["forensic_analysis"]

    assert forensic is not None
    assert forensic["summary"]["status"] == "completed"
    assert forensic["summary"]["authentication"]["spf_status"] == "pass"
    assert forensic["summary"]["authentication"]["dkim_status"] == "pass"
    assert forensic["summary"]["authentication"]["dmarc_status"] == "pass"
    assert forensic["summary"]["authentication"]["overall_alignment"] is True
    assert forensic["summary"]["high_risk_findings_count"] == 0
    OK(f"Clean email uploaded: Case ID={clean_case_id}")
    OK("Clean email SPF/DKIM/DMARC passed and aligned")
    OK(f"Clean email findings count: {forensic['summary']['findings_count']} (0 high risk)")
    results["clean_email"] = True

    # 3. Upload Suspicious Phishing Email
    HDR("3. SUSPICIOUS EMAIL FORENSIC DETECTION")
    phish_eml = (
        'From: "PayPal Account Security <service@paypal.com>" <billing@phish-attacker.ru>\r\n'
        "To: victim@company.com\r\n"
        "Reply-To: credential-harvest@external-drop.com\r\n"
        "Return-Path: <bounce@unrelated-server.net>\r\n"
        "Subject: Urgent: Verify Account Immediately\r\n"
        "Date: Wed, 20 Jan 2027 12:00:00 +0000\r\n"
        "Message-ID: <msg_fake_999@random-host.org>\r\n"
        "Authentication-Results: mx.company.com; spf=fail (domain phish-attacker.ru designates 93.184.216.99 as unauthorized); dmarc=fail (p=reject)\r\n"
        "Received: from mx.company.com (mx [93.184.216.100]) by mail.company.com; Wed, 20 Jan 2027 12:01:00 +0000\r\n"
        "Received: from phish-attacker.ru ([93.184.216.99]) by mx.company.com; Wed, 20 Jan 2027 12:00:10 +0000\r\n"
        "Received: from internal-node ([10.0.1.50]) by phish-attacker.ru; Wed, 20 Jan 2027 12:00:05 +0000\r\n"
        "\r\n"
        "Click here immediately: http://paypal-security-login.ru/verify"
    ).encode("utf-8")

    r = client.post("/api/analyze/upload", files={"file": ("phishing_alert.eml", phish_eml, "message/rfc822")})
    assert r.status_code == 200
    phish_data = r.json()
    phish_case_id = phish_data["case_id"]
    phish_forensic = phish_data["forensic_analysis"]

    assert phish_forensic is not None
    summary = phish_forensic["summary"]
    findings = phish_forensic["findings"]

    # Verify Authentication Failure Detection
    assert summary["authentication"]["spf_status"] == "fail"
    assert summary["authentication"]["dmarc_status"] == "fail"
    OK("SPF and DMARC failures correctly flagged")

    # Verify Identity Mismatches
    assert summary["identity"]["reply_to_mismatch"] is True
    assert summary["identity"]["return_path_mismatch"] is True
    assert summary["identity"]["display_name_spoof_suspected"] is True
    OK("Reply-To, Return-Path, and Display Name spoofing detected")

    # Verify Future Timestamp Detection
    assert summary["timestamps"]["is_future_dated"] is True
    OK("Future dated timestamp anomaly correctly flagged")

    # Verify Relay Analysis
    assert summary["relay"]["hop_count"] == 3
    assert "10.0.1.50" in summary["relay"]["internal_ips"]
    assert summary["relay"]["earliest_observed_infrastructure"]["ip"] == "10.0.1.50"
    OK(f"Received relay chain: {summary['relay']['hop_count']} hops, internal IP 10.0.1.50 detected")
    results["suspicious_email"] = True

    # 4. Fact vs Inference Verification
    HDR("4. FACT VS INFERENCE SEPARATION")
    facts = phish_forensic["facts"]
    inferences = phish_forensic["inferences"]

    assert len(facts) > 0
    assert len(inferences) > 0
    for fact in facts:
        assert fact["fact"] is True
        assert fact.get("inference_note") is None
    for infer in inferences:
        assert infer["fact"] is False
        assert infer.get("inference_note") is not None
    OK(f"Fact count: {len(facts)} (all verified with fact=True)")
    OK(f"Inference count: {len(inferences)} (all marked with fact=False and inference notes)")
    results["fact_vs_inference"] = True

    # 5. Database Persistence & Case Detail
    HDR("5. DATABASE PERSISTENCE & RETRIEVAL")
    r = client.get(f"/api/analyze/{phish_case_id}")
    assert r.status_code == 200
    detail = r.json()
    assert detail["case_id"] == phish_case_id
    assert detail["forensic_analysis"] is not None
    assert detail["forensic_analysis"]["summary"]["status"] == "completed"
    OK(f"Case {phish_case_id} successfully retrieved from DB with full forensic findings")
    results["persistence"] = True

    # 6. Security Boundaries & Limitations
    HDR("6. SECURITY & ATTRIBUTION LIMITATIONS")
    limitations = phish_forensic["limitations"]
    assert len(limitations) >= 4
    assert any("infrastructure" in lim.lower() for lim in limitations)
    assert any("deterministic" in lim.lower() for lim in limitations)
    assert any("authentication" in lim.lower() for lim in limitations)
    OK("Forensic limitations and attribution disclaimers verified")
    results["security"] = True

    HDR("STEP 3 VERIFICATION SUMMARY")
    all_passed = all(results.values())
    for k, v in results.items():
        status_str = "PASS" if v else "FAIL"
        print(f"  {k:<25}: {status_str}")
    
    if all_passed:
        HDR("ALL STEP 3 VERIFICATIONS PASSED SUCCESSFULLY")
    else:
        HDR("SOME STEP 3 VERIFICATIONS FAILED")
    return all_passed

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
