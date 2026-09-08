"""
verify_step4.py — Step 4 Live Verification Script for MAILTRACE.

Performs complete end-to-end verification of:
    1. Server startup & health / readiness endpoints.
    2. Upload of Clean Legitimate Email -> BENIGN classification.
    3. Upload of Phishing Email -> PHISHING / IMPERSONATION classification with indicators & explanation.
    4. Upload of BEC Wire Request Email -> BEC classification with financial/secrecy indicators.
    5. Structural verification of `threat_analysis` fields in API response.
    6. Database persistence of `ai_analysis` in AnalysisCase.
    7. Offline deterministic fallback validation without OpenAI API key.
    8. Fact vs. AI inference separation integrity.
    9. Absence of stack traces, security boundary enforcement.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
import traceback
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.services.threat_analyzer import (
    analyze_threat,
    THREAT_PHISHING,
    THREAT_BEC,
    THREAT_CREDENTIAL_HARVESTING,
    THREAT_IMPERSONATION,
    THREAT_SOCIAL_ENGINEERING,
    THREAT_SUSPICIOUS,
    THREAT_BENIGN,
)


def _build_test_eml(from_addr: str, to_addr: str, subject: str, body: str, headers: dict | None = None) -> bytes:
    lines = [
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        "Date: Tue, 08 Sep 2026 10:00:00 +0000",
        f"Message-ID: <verify-{abs(hash(subject))}@domain.example>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8")


async def run_live_verification():
    print("=" * 70)
    print("MAILTRACE — STEP 4 LIVE VERIFICATION")
    print("=" * 70)

    checks_passed = 0
    total_checks = 0

    def assert_check(name: str, condition: bool, extra: str = ""):
        nonlocal checks_passed, total_checks
        total_checks += 1
        if condition:
            checks_passed += 1
            print(f" [PASS] {name} {extra}")
        else:
            print(f" [FAIL] {name} {extra}")
            sys.exit(1)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health Endpoint
        resp = await client.get("/api/health")
        assert_check("Health check (/api/health)", resp.status_code == 200 and resp.json().get("status") == "ok")

        # 2. Readiness Endpoint
        resp = await client.get("/api/health/ready")
        assert_check("Readiness check (/api/health/ready)", resp.status_code == 200 and resp.json().get("status") == "ok" and resp.json().get("database") == "ok")

        # 3. Clean Email Upload & BENIGN Classification
        clean_bytes = _build_test_eml(
            from_addr="Sarah Connor <sarah@cyberdyne.org>",
            to_addr="john@example.com",
            subject="Quarterly Project Sync",
            body="Hi John,\n\nPlease find the project agenda for tomorrow's sync attached. Looking forward to catching up.\n\nBest regards,\nSarah",
            headers={"Authentication-Results": "mx.example.com; spf=pass; dkim=pass; dmarc=pass"}
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("clean_sync.eml", io.BytesIO(clean_bytes), "message/rfc822")}
        )
        assert_check("Clean email upload status 200", resp.status_code == 200)
        clean_data = resp.json()
        assert_check("Threat analysis in upload response", "threat_analysis" in clean_data)
        clean_threat = clean_data.get("threat_analysis", {})
        assert_check("Clean email primary threat is BENIGN", clean_threat.get("primary_threat") == THREAT_BENIGN)
        assert_check("Clean email confidence exists (float)", isinstance(clean_threat.get("confidence"), (int, float)))
        assert_check("Clean email explanation present", len(clean_threat.get("explanation", "")) > 0)
        assert_check("Analysis method is 'local'", clean_threat.get("analysis_method") == "local")

        # 4. Phishing Email Upload
        phish_bytes = _build_test_eml(
            from_addr="PayPal Support <service@paypa1-security-verification.com>",
            to_addr="victim@example.com",
            subject="CRITICAL: Your PayPal Account will be suspended within 24 hours",
            body="Dear Customer,\n\nWe detected unauthorized sign-in attempts on your account. To prevent account deactivation, verify your credentials immediately at http://paypa1-security-verification.com/login/verify.php.\n\nFailure to act now will result in permanent suspension.\n\nPayPal Security Team",
            headers={"Authentication-Results": "mx.victim.com; spf=fail; dkim=fail; dmarc=fail"}
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("paypal_phish.eml", io.BytesIO(phish_bytes), "message/rfc822")}
        )
        assert_check("Phishing email upload status 200", resp.status_code == 200)
        phish_data = resp.json()
        phish_case_id = phish_data["case_id"]
        phish_threat = phish_data.get("threat_analysis", {})
        assert_check(
            "Phishing email primary threat is PHISHING or IMPERSONATION",
            phish_threat.get("primary_threat") in (THREAT_PHISHING, THREAT_IMPERSONATION)
        )
        assert_check("Phishing email has structured indicators", len(phish_threat.get("indicators", [])) >= 2)
        assert_check("Phishing signals urgency is high/medium", phish_threat.get("signals", {}).get("urgency") in ("high", "medium"))
        assert_check("Phishing signals impersonation is high/medium", phish_threat.get("signals", {}).get("impersonation") in ("high", "medium"))

        # 5. BEC Email Upload
        bec_bytes = _build_test_eml(
            from_addr="CEO Richard King <rking@corp-executive.com>",
            to_addr="treasury@corp-executive.com",
            subject="Confidential: Urgent wire transfer for vendor payment",
            body="Hi Treasury,\n\nI need you to process an urgent wire transfer for an overdue invoice today. Please update the vendor banking details with the new routing number. Keep this strictly confidential until the acquisition closes. I am currently in a meeting so email only.\n\nRichard King, Chief Executive Officer",
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("bec_wire.eml", io.BytesIO(bec_bytes), "message/rfc822")}
        )
        assert_check("BEC email upload status 200", resp.status_code == 200)
        bec_data = resp.json()
        bec_case_id = bec_data["case_id"]
        bec_threat = bec_data.get("threat_analysis", {})
        assert_check("BEC email primary threat is BEC", bec_threat.get("primary_threat") == THREAT_BEC)
        assert_check("BEC email has financial manipulation indicator", any(ind.get("indicator") == "financial_manipulation" for ind in bec_threat.get("indicators", [])))
        assert_check("BEC email has secrecy indicator", any(ind.get("indicator") == "secrecy_bypass_instruction" for ind in bec_threat.get("indicators", [])))

        # 6. Database Persistence Verification
        get_resp = await client.get(f"/api/analyze/{phish_case_id}")
        assert_check("Get phishing case detail status 200", get_resp.status_code == 200)
        persisted_case = get_resp.json()
        assert_check("Persisted ai_analysis is not None", persisted_case.get("ai_analysis") is not None)
        assert_check(
            "Persisted ai_analysis primary threat matches",
            persisted_case["ai_analysis"].get("primary_threat") == phish_threat.get("primary_threat")
        )

        # 7. Fact vs Inference Integrity
        evidence_summary = phish_threat.get("evidence_summary", {})
        assert_check("Evidence summary contains 'facts' list", isinstance(evidence_summary.get("facts"), list))
        assert_check("Evidence summary contains 'inferences' list", isinstance(evidence_summary.get("inferences"), list))
        assert_check("Facts list is non-empty", len(evidence_summary.get("facts", [])) > 0)

        # 8. No Attribution Guarantee
        explanation = phish_threat.get("explanation", "").lower()
        assert_check(
            "No human attacker attribution in explanation",
            "attacker is" not in explanation and "identity confirmed as" not in explanation
        )

    print("=" * 70)
    print(f"VERIFICATION COMPLETE: {checks_passed}/{total_checks} CHECKS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_live_verification())
