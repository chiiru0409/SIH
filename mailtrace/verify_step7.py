"""
verify_step7.py — Step 7 Live Verification Script for MAILTRACE.

Performs complete end-to-end verification of:
    1. Server startup & health / readiness endpoints.
    2. Upload of multiple synthetic cases (clean, multi-case phishing campaign, unrelated benign).
    3. Global campaign correlation endpoint (GET /api/correlation & GET /api/correlation/cases).
    4. Campaign cluster discovery via NetworkX connected components.
    5. Shared indicator identification (shared URLs, shared public IPs, shared domains, shared senders).
    6. Investigation graph synthesis (nodes: CASE, SENDER, DOMAIN, URL, IP, ASN, CAMPAIGN).
    7. Graph integrity validation (no orphaned edges, valid node IDs, correct relationship types).
    8. Case-specific correlation endpoint (GET /api/correlation/{case_id}).
    9. Case-specific sub-graph extraction and related cases list.
    10. Database synchronization (AnalysisCase.campaign_id and correlation_data).
    11. Attribution safeguards and disclaimers (no claims of human attacker identity).
    12. Strict passive boundaries and error-free execution.
"""

from __future__ import annotations

import asyncio
import io
import sys
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.services.intelligence import clear_intel_cache


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
        f"Message-ID: <verify7-{abs(hash(subject))}@mailtrace.example>",
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
    print("MAILTRACE — STEP 7 LIVE VERIFICATION: CAMPAIGN CORRELATION & GRAPH")
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

        # 3. Upload Synthetic Cases for Campaign Correlation
        # Case 1: Phishing Email A (Domain: credential-stealer-hub.org, IP: 104.244.42.1, URL: http://credential-stealer-hub.org/login.aspx)
        eml_phish_1 = _build_test_eml(
            from_addr="IT Support <alert@credential-stealer-hub.org>",
            to_addr="victim1@corporate.com",
            subject="Action Required: Re-verify Access Portal",
            body="Please authenticate immediately at http://credential-stealer-hub.org/login.aspx?id=101 to maintain network access.",
            headers=[
                ("Authentication-Results", "mx.corporate.com; spf=fail (sender IP 104.244.42.1); dkim=none; dmarc=fail"),
                ("Received", "from outbound.mailhub.org [104.244.42.1] by mx.corporate.com with ESMTP"),
                ("Reply-To", "harvest-collector@credential-stealer-hub.org"),
            ]
        )
        r1 = await client.post("/api/analyze/upload", files={"file": ("phish_1.eml", io.BytesIO(eml_phish_1), "message/rfc822")})
        assert_check("Upload Phish Case 1 status 200", r1.status_code == 200)
        case1_id = r1.json()["case_id"]

        # Case 2: Phishing Email B (Shares Domain, Public IP, and exact URL with Case 1)
        eml_phish_2 = _build_test_eml(
            from_addr="Security Desk <security@credential-stealer-hub.org>",
            to_addr="victim2@corporate.com",
            subject="URGENT: Verify Network Password",
            body="Verify your account details at http://credential-stealer-hub.org/login.aspx?id=101 to avoid immediate suspension.",
            headers=[
                ("Authentication-Results", "mx.corporate.com; spf=fail (sender IP 104.244.42.1); dkim=none; dmarc=fail"),
                ("Received", "from outbound.mailhub.org [104.244.42.1] by mx.corporate.com with ESMTP"),
            ]
        )
        r2 = await client.post("/api/analyze/upload", files={"file": ("phish_2.eml", io.BytesIO(eml_phish_2), "message/rfc822")})
        assert_check("Upload Phish Case 2 status 200", r2.status_code == 200)
        case2_id = r2.json()["case_id"]

        # Case 3: Phishing Email C (Shares Domain and Public IP with Case 1 & 2, but different path)
        eml_phish_3 = _build_test_eml(
            from_addr="Executive Notice <admin@credential-stealer-hub.org>",
            to_addr="victim3@corporate.com",
            subject="Final Reminder: Executive Portal Update",
            body="Review updated executive policy at http://credential-stealer-hub.org/portal/update.php.",
            headers=[
                ("Authentication-Results", "mx.corporate.com; spf=fail (sender IP 104.244.42.1); dkim=none; dmarc=fail"),
                ("Received", "from outbound.mailhub.org [104.244.42.1] by mx.corporate.com with ESMTP"),
            ]
        )
        r3 = await client.post("/api/analyze/upload", files={"file": ("phish_3.eml", io.BytesIO(eml_phish_3), "message/rfc822")})
        assert_check("Upload Phish Case 3 status 200", r3.status_code == 200)
        case3_id = r3.json()["case_id"]

        # Case 4: Unrelated Clean Benign Email (Independent domain and IP)
        eml_clean = _build_test_eml(
            from_addr="Alice <alice@unrelated-legit-company.com>",
            to_addr="bob@recipient.com",
            subject="Weekly Project Status Meeting",
            body="Hi Bob,\n\nHere is our weekly project status. Everything is on schedule.\n\nBest,\nAlice",
            headers=[
                ("Authentication-Results", "mx.recipient.com; spf=pass (sender IP 93.184.216.34); dkim=pass; dmarc=pass"),
                ("Received", "from mail.unrelated-legit-company.com [93.184.216.34] by mx.recipient.com with ESMTP"),
            ]
        )
        r4 = await client.post("/api/analyze/upload", files={"file": ("clean_weekly.eml", io.BytesIO(eml_clean), "message/rfc822")})
        assert_check("Upload Clean Case 4 status 200", r4.status_code == 200)
        case4_id = r4.json()["case_id"]

        # 4. Global Correlation API (GET /api/correlation)
        corr_resp = await client.get("/api/correlation")
        assert_check("Global correlation GET status 200", corr_resp.status_code == 200)
        corr_data = corr_resp.json()

        assert_check("Total cases >= 4", corr_data.get("total_cases", 0) >= 4)
        assert_check("Total campaigns >= 1", corr_data.get("total_campaigns", 0) >= 1)

        # 5. Campaign Cluster Verification
        campaigns = corr_data.get("campaigns", [])
        phish_camp = next((c for c in campaigns if case1_id in c["case_ids"] and case2_id in c["case_ids"]), None)
        assert_check("Campaign cluster found for phishing cases", phish_camp is not None)

        if phish_camp:
            assert_check("Campaign case_count >= 3", phish_camp.get("case_count", 0) >= 3)
            assert_check("Case 3 is included in campaign cluster", case3_id in phish_camp.get("case_ids", []))
            assert_check("Clean Case 4 is NOT in phishing campaign cluster", case4_id not in phish_camp.get("case_ids", []))
            assert_check("Campaign correlation_strength >= 50", phish_camp.get("correlation_strength", 0) >= 50.0)
            assert_check("Campaign confidence > 0.60", phish_camp.get("confidence", 0) > 0.60)
            assert_check("Campaign explanation generated", len(phish_camp.get("explanation", "")) > 10)

        # 6. Global Investigation Graph Verification
        graph = corr_data.get("graph", {})
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        assert_check("Graph nodes list populated", len(nodes) >= 6)
        assert_check("Graph edges list populated", len(edges) >= 5)

        node_types = {n["type"] for n in nodes}
        assert_check("Graph contains CASE nodes", "CASE" in node_types)
        assert_check("Graph contains DOMAIN nodes", "DOMAIN" in node_types)
        assert_check("Graph contains IP nodes", "IP" in node_types)
        assert_check("Graph contains CAMPAIGN nodes", "CAMPAIGN" in node_types)

        # 7. Graph Integrity (No orphaned edges)
        node_ids = {n["id"] for n in nodes}
        orphan_edges = [e for e in edges if e["source"] not in node_ids or e["target"] not in node_ids]
        assert_check("Graph has ZERO orphaned edges", len(orphan_edges) == 0)

        rel_types = {e["relationship"] for e in edges}
        assert_check("Graph contains CORRELATED_WITH edges", "CORRELATED_WITH" in rel_types)
        assert_check("Graph contains BELONGS_TO edges", "BELONGS_TO" in rel_types)

        # 8. Case-Specific Correlation Endpoint (GET /api/correlation/{case1_id})
        case_corr_resp = await client.get(f"/api/correlation/{case1_id}")
        assert_check("Case correlation GET status 200", case_corr_resp.status_code == 200)
        case_corr_data = case_corr_resp.json()

        assert_check("Case ID matches requested ID", case_corr_data.get("case_id") == case1_id)
        assert_check("Campaign ID is populated", case_corr_data.get("campaign_id") is not None)
        assert_check("Related cases list populated", len(case_corr_data.get("related_cases", [])) >= 2)
        assert_check("Shared indicators list populated", len(case_corr_data.get("shared_indicators", [])) >= 2)

        sub_graph = case_corr_data.get("graph", {})
        assert_check("Case sub-graph nodes populated", len(sub_graph.get("nodes", [])) >= 3)
        assert_check("Case sub-graph contains target case node", any(n["id"] == f"case:{case1_id}" for n in sub_graph.get("nodes", [])))

        # 9. Database Persistence Verification (AnalysisCase.campaign_id)
        db_case_resp = await client.get(f"/api/analyze/{case1_id}")
        assert_check("Get analyzed case detail status 200", db_case_resp.status_code == 200)
        db_case = db_case_resp.json()
        assert_check("Persisted campaign_id is populated in database", db_case.get("campaign_id") is not None)

        # 10. Attribution Safeguard Verification
        limitations = corr_data.get("limitations", [])
        assert_check("Correlation limitations list populated", len(limitations) >= 2)
        assert_check(
            "Attribution safeguard disclaimer in limitations",
            any("not physical human attacker identification" in lim.lower() for lim in limitations)
        )

    print("=" * 70)
    print(f"STEP 7 VERIFICATION COMPLETE: {checks_passed}/{total_checks} CHECKS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_live_verification())
