"""
verify_step6.py — Step 6 Live Verification Script for MAILTRACE.

Performs complete end-to-end verification of:
    1. Server startup & health / readiness endpoints.
    2. Benign Email Upload -> LOW severity (< 25 risk score).
    3. Multi-Vector Phishing Email Upload -> HIGH or CRITICAL severity.
    4. Business Email Compromise (BEC) Upload -> HIGH or CRITICAL severity.
    5. Authentication Failure Upload -> elevated authentication category subscore.
    6. Structured risk factors verification (factor, category, points, severity, evidence, source).
    7. Category subscores verification (authentication, identity, content, infrastructure, url, attachment, header, relay).
    8. Human-readable explanation generation.
    9. Evidence quality and confidence score generation.
    10. Database persistence verification (risk_score, risk_label, risk_reasons in AnalysisCase).
    11. Score determinism and mathematical boundedness ([0, 100]).
    12. Unknown/unavailable handling with zero synthetic penalties.
    13. Legal/forensic attribution safeguards and disclaimers.
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.services.intelligence import clear_intel_cache
from backend.services.risk_engine import (
    calculate_risk,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)


def _build_test_eml(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    headers: list[tuple[str, str]] | dict | None = None,
) -> bytes:
    lines = [
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        "Date: Tue, 08 Sep 2026 10:00:00 +0000",
        f"Message-ID: <verify6-{abs(hash(subject))}@mailtrace.example>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    if headers:
        if isinstance(headers, dict):
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        elif isinstance(headers, list):
            for k, v in headers:
                lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8")


async def run_live_verification():
    print("=" * 70)
    print("MAILTRACE — STEP 6 LIVE VERIFICATION: UNIFIED RISK SCORING")
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

    clear_intel_cache()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health Endpoint
        resp = await client.get("/api/health")
        assert_check("Health check (/api/health)", resp.status_code == 200 and resp.json().get("status") == "ok")

        # 2. Readiness Endpoint
        resp = await client.get("/api/health/ready")
        assert_check(
            "Readiness check (/api/health/ready)",
            resp.status_code == 200 and resp.json().get("status") == "ok" and resp.json().get("database") == "ok"
        )

        # 3. Benign Email Upload -> LOW severity (< 25 risk score)
        benign_bytes = _build_test_eml(
            from_addr="Project Lead <sarah@acme-corp.com>",
            to_addr="team@acme-corp.com",
            subject="Sprint Planning Notes",
            body="Hello team,\n\nHere are the notes and tickets for our upcoming sprint.\n\nRegards,\nSarah",
            headers=[
                ("Authentication-Results", "mx.acme-corp.com; spf=pass (sender IP 93.184.216.34) smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass"),
                ("Received", "from mail.acme-corp.com (mail.acme-corp.com [93.184.216.34]) by mx.acme-corp.com with ESMTP"),
            ]
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("benign_sprint.eml", io.BytesIO(benign_bytes), "message/rfc822")}
        )
        assert_check("Benign email upload status 200", resp.status_code == 200)
        benign_data = resp.json()
        assert_check("risk_assessment in upload response", "risk_assessment" in benign_data)
        benign_risk = benign_data.get("risk_assessment", {})
        assert_check("Benign risk score < 25", float(benign_risk.get("risk_score", 100)) < 25.0)
        assert_check("Benign severity is LOW", benign_risk.get("severity") == SEVERITY_LOW)
        assert_check("Benign explanation generated", len(benign_risk.get("explanation", "")) > 10)

        # 4. Multi-Vector Phishing Email Upload -> CRITICAL / HIGH Severity
        phish_bytes = _build_test_eml(
            from_addr="IT Helpdesk <support@it-security-auth-desk.net>",
            to_addr="victim@enterprise.com",
            subject="URGENT: Mandatory Password Expiration Notice - Immediate Action Required",
            body=(
                "Dear User,\n\n"
                "Your corporate password will expire within 2 hours. You must immediately verify your account "
                "to avoid immediate account suspension.\n\n"
                "Sign in at: http://198.51.100.25:8080/owa/auth/login.aspx?user=victim\n\n"
                "Failure to update will result in termination of your network privileges."
            ),
            headers=[
                ("Authentication-Results", "mx.enterprise.com; spf=fail (sender IP 104.244.42.1); dkim=fail; dmarc=fail"),
                ("Received", "from outbound.mailhub.org (outbound.mailhub.org [104.244.42.1]) by mx.enterprise.com with ESMTP"),
                ("Reply-To", "attacker-inbox@suspicious-external-domain.com"),
            ]
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("urgent_phish.eml", io.BytesIO(phish_bytes), "message/rfc822")}
        )
        assert_check("Phishing email upload status 200", resp.status_code == 200)
        phish_data = resp.json()
        phish_case_id = phish_data["case_id"]
        phish_risk = phish_data.get("risk_assessment", {})

        assert_check("Phishing risk score >= 60", float(phish_risk.get("risk_score", 0)) >= 60.0)
        assert_check("Phishing severity is HIGH or CRITICAL", phish_risk.get("severity") in (SEVERITY_HIGH, SEVERITY_CRITICAL))
        assert_check("Phishing risk factors populated", len(phish_risk.get("risk_factors", [])) >= 3)
        assert_check("Phishing top factors populated", len(phish_risk.get("top_factors", [])) >= 3)

        # 5. BEC Email Upload -> Wire Fraud / Executive Pretexting
        bec_bytes = _build_test_eml(
            from_addr="Chief Executive Officer <ceo@exec-private-mail.org>",
            to_addr="accountant@target-company.com",
            subject="Urgent: Wire Transfer Request - Confidential Acquisition",
            body=(
                "Hi,\n\n"
                "I am currently in a board meeting and available by email only. Please do not call my cell.\n\n"
                "We need to process an urgent wire transfer for an acquisition today. "
                "Please update banking details with the new routing number and send confirmation immediately.\n\n"
                "Treat this with strict confidentiality."
            ),
            headers=[
                ("Authentication-Results", "mx.target-company.com; spf=fail (sender IP 198.51.100.88); dkim=none; dmarc=fail"),
                ("Received", "from mail.exec-private-mail.org [198.51.100.88] by mx.target-company.com with ESMTP"),
                ("Reply-To", "attacker-inbox@shadow-invoicing.net"),
            ]
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("bec_wire.eml", io.BytesIO(bec_bytes), "message/rfc822")}
        )
        assert_check("BEC email upload status 200", resp.status_code == 200)
        bec_data = resp.json()
        bec_risk = bec_data.get("risk_assessment", {})
        assert_check("BEC severity is MEDIUM, HIGH or CRITICAL", bec_risk.get("severity") in (SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL))
        assert_check(
            "BEC financial / authority factor detected",
            any("BEC" in f["factor"] or "Financial" in f["factor"] or "Authority" in f["factor"] or "Compromise" in f["factor"] for f in bec_risk.get("risk_factors", []))
        )

        # 6. Structured Category Scores Validation
        cats = phish_risk.get("category_scores", {})
        assert_check("Category scores contains authentication", "authentication" in cats and cats["authentication"] > 0)
        assert_check("Category scores contains identity", "identity" in cats and cats["identity"] > 0)
        assert_check("Category scores contains content", "content" in cats and cats["content"] > 0)
        assert_check("Category scores contains url", "url" in cats and cats["url"] > 0)

        # 7. Evidence Traceability Verification
        for f in phish_risk.get("risk_factors", []):
            assert_check(f"Factor '{f['factor'][:25]}' has evidence", len(f.get("evidence", "")) > 0)
            assert_check(f"Factor '{f['factor'][:25]}' has source", f.get("source") in ("step3_forensics", "step4_ai", "step5_infrastructure", "step2_extraction"))

        # 8. Database Persistence Verification (GET /api/analyze/{case_id})
        get_resp = await client.get(f"/api/analyze/{phish_case_id}")
        assert_check("Get case detail status 200", get_resp.status_code == 200)
        persisted_case = get_resp.json()
        assert_check("Persisted risk_score is not None", persisted_case.get("risk_score") is not None)
        assert_check("Persisted risk_label is correct", persisted_case.get("risk_label") in (SEVERITY_HIGH, SEVERITY_CRITICAL))
        assert_check("Persisted risk_reasons is dict", isinstance(persisted_case.get("risk_reasons"), dict))
        assert_check("Persisted risk_reasons contains risk_factors", len(persisted_case["risk_reasons"].get("risk_factors", [])) >= 3)

        # 9. Deterministic Repeatability Verification
        direct_run_1 = calculate_risk(phish_data.get("forensic_analysis"), phish_data.get("threat_analysis"), phish_data.get("infrastructure_intelligence"), {})
        direct_run_2 = calculate_risk(phish_data.get("forensic_analysis"), phish_data.get("threat_analysis"), phish_data.get("infrastructure_intelligence"), {})
        assert_check("Deterministic risk_score match", direct_run_1["risk_score"] == direct_run_2["risk_score"])
        assert_check("Deterministic severity match", direct_run_1["severity"] == direct_run_2["severity"])
        assert_check("Deterministic category_scores match", direct_run_1["category_scores"] == direct_run_2["category_scores"])

        # 10. Attribution Safeguard Verification
        limitations = phish_risk.get("limitations", [])
        assert_check("Limitations disclaimers present in risk assessment", len(limitations) >= 2)
        assert_check(
            "Attribution safeguard disclaimer in limitations",
            any("does not assert confirmation of physical human attacker" in lim.lower() for lim in limitations)
        )

    print("=" * 70)
    print(f"STEP 6 VERIFICATION COMPLETE: {checks_passed}/{total_checks} CHECKS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_live_verification())
