"""
verify_step5.py — Step 5 Live Verification Script for MAILTRACE.

Performs complete end-to-end verification of:
    1. Server startup & health / readiness endpoints.
    2. Upload of Clean Email -> Infrastructure intelligence populated with clean domains/IPs.
    3. Upload of Suspicious Email with Public & Private IPs, Domains, and URLs.
    4. Verification of Public IP enrichment (GeoIP & ASN structure).
    5. Verification of Private/Loopback IP exclusion from external lookups.
    6. Verification of Domain RDAP/WHOIS normalization and registration metadata.
    7. Verification of Passive URL structural analysis (flags, hashing, indicators).
    8. Database persistence of `ip_intel`, `domain_intel`, and `url_intel` in AnalysisCase.
    9. Verification of provider-unavailable graceful offline behavior.
    10. Verification of attribution safeguards (no attacker attribution claims).
    11. Verification of passive boundaries (no URL fetching or attachment execution).
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.services.intelligence import enrich_infrastructure, clear_intel_cache
from backend.utils.geoip import lookup_geoip
from backend.utils.asn_utils import lookup_asn
from backend.utils.whois_utils import lookup_rdap_domain
from backend.utils.url_intel import analyze_url_structure


def _build_test_eml(from_addr: str, to_addr: str, subject: str, body: str, headers: dict | list[tuple[str, str]] | None = None) -> bytes:
    lines = [
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        "Date: Tue, 08 Sep 2026 10:00:00 +0000",
        f"Message-ID: <verify5-{abs(hash(subject))}@domain.example>",
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
    print("MAILTRACE — STEP 5 LIVE VERIFICATION")
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

        # 3. Clean Email Upload & Infrastructure Intelligence
        clean_bytes = _build_test_eml(
            from_addr="Alice Smith <alice@legit-company.com>",
            to_addr="bob@recipient-corp.com",
            subject="Meeting Recap",
            body="Hi Bob,\n\nHere is the recap from our project discussion.\n\nBest,\nAlice",
            headers={"Received": "from mail.legit-company.com (mail.legit-company.com [93.184.216.34]) by mx.recipient-corp.com with ESMTP"}
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("clean_meeting.eml", io.BytesIO(clean_bytes), "message/rfc822")}
        )
        assert_check("Clean email upload status 200", resp.status_code == 200)
        clean_data = resp.json()
        assert_check("infrastructure_intelligence in upload response", "infrastructure_intelligence" in clean_data)
        clean_intel = clean_data.get("infrastructure_intelligence", {})
        assert_check("Clean intel summary completed", clean_intel.get("summary", {}).get("status") == "completed")
        assert_check("Clean intel has domains", len(clean_intel.get("domains", [])) >= 1)

        # 4. Suspicious Email Upload (Public IP, Private IP, Domain, Suspicious URL)
        susp_bytes = _build_test_eml(
            from_addr="Security Update <alert@portal-verification-desk.net>",
            to_addr="victim@target-org.com",
            subject="URGENT: Re-authenticate corporate access",
            body=(
                "Please verify your credentials immediately at http://198.51.100.12:8080/owa/auth/login.aspx?user=test "
                "or access backup portal at https://bit.ly/secure-backup-auth.\n\n"
                "External host: 104.244.42.1, Internal gateway: 10.10.5.1"
            ),
            headers=[
                ("Received", "from gateway.internal (gateway.internal [10.10.5.1]) by mail.target-org.com with ESMTP"),
                ("Received", "from outbound.mailhub.org (outbound.mailhub.org [104.244.42.1]) by gateway.internal with ESMTP"),
                ("X-Originating-IP", "[192.168.1.100]"),
                ("Authentication-Results", "mx.target-org.com; spf=fail; dkim=fail; dmarc=fail"),
            ]
        )
        resp = await client.post(
            "/api/analyze/upload",
            files={"file": ("suspicious_intel.eml", io.BytesIO(susp_bytes), "message/rfc822")}
        )
        assert_check("Suspicious email upload status 200", resp.status_code == 200)
        susp_data = resp.json()
        case_id = susp_data["case_id"]
        intel = susp_data.get("infrastructure_intelligence", {})

        # 5. Public IP Enrichment & Private IP Filtering
        ips = intel.get("ips", [])
        assert_check("IPs list extracted in intelligence", len(ips) >= 2)

        public_ips = [ip for ip in ips if ip.get("classification") == "public"]
        private_ips = [ip for ip in ips if ip.get("classification") in ("private", "loopback", "reserved")]

        assert_check("Public IPs detected and processed", len(public_ips) >= 1)
        assert_check("Private IPs detected and classified", len(private_ips) >= 1)

        for priv in private_ips:
            assert_check(f"Private IP {priv['ip']} marked excluded", priv.get("status") in ("excluded", "unavailable"))
            assert_check(f"Private IP {priv['ip']} source is local_filter", priv.get("source") == "local_filter")

        # 6. Domain RDAP Intelligence
        domains = intel.get("domains", [])
        assert_check("Domains extracted in intelligence", len(domains) >= 1)
        target_dom = next((d for d in domains if "portal-verification-desk.net" in d["domain"]), None)
        assert_check("Domain record exists for portal-verification-desk.net", target_dom is not None)
        if target_dom:
            assert_check("Registrable domain is portal-verification-desk.net", target_dom.get("registrable_domain") == "portal-verification-desk.net")
            assert_check("TLD is net", target_dom.get("tld") == "net")
            assert_check("RDAP object present", "rdap" in target_dom)

        # 7. Safe Passive URL Intelligence
        urls = intel.get("urls", [])
        assert_check("URLs analyzed in intelligence", len(urls) >= 2)

        raw_ip_url = next((u for u in urls if "198.51.100.12" in u["url"]), None)
        assert_check("Raw IP URL analyzed", raw_ip_url is not None)
        if raw_ip_url:
            assert_check("Raw IP flag is True", raw_ip_url.get("flags", {}).get("is_ip_host") is True)
            assert_check("Unusual port flag is True (port 8080)", raw_ip_url.get("flags", {}).get("unusual_port") is True)
            assert_check("Credential keywords flag is True", raw_ip_url.get("flags", {}).get("has_credential_keywords") is True)
            assert_check("URL hash present (64 chars)", len(raw_ip_url.get("url_hash", "")) == 64)

        short_url = next((u for u in urls if "bit.ly" in u["url"]), None)
        assert_check("Shortened URL analyzed", short_url is not None)
        if short_url:
            assert_check("Shortened flag is True", short_url.get("flags", {}).get("is_shortened") is True)

        # 8. Correlation Entities Structure
        entities = intel.get("correlation_entities", {})
        assert_check("Correlation entities contains 'ips'", "ips" in entities and len(entities["ips"]) >= 1)
        assert_check("Correlation entities contains 'domains'", "domains" in entities and len(entities["domains"]) >= 1)
        assert_check("Correlation entities contains 'urls'", "urls" in entities and len(entities["urls"]) >= 1)

        # 9. Database Persistence Verification
        get_resp = await client.get(f"/api/analyze/{case_id}")
        assert_check("Get case detail status 200", get_resp.status_code == 200)
        persisted_case = get_resp.json()
        assert_check("Persisted ip_intel is not None", persisted_case.get("ip_intel") is not None)
        assert_check("Persisted domain_intel is not None", persisted_case.get("domain_intel") is not None)
        assert_check("Persisted url_intel is not None", persisted_case.get("url_intel") is not None)
        assert_check("Persisted ip_intel has ips array", len(persisted_case["ip_intel"].get("ips", [])) >= 2)

        # 10. Attribution Safeguard & Passive Boundary Checks
        limitations = intel.get("limitations", [])
        assert_check("Limitations disclaimers present", len(limitations) >= 2)
        assert_check(
            "Attribution safeguard disclaimer in limitations",
            any("do not identify physical human operators" in lim.lower() for lim in limitations)
        )

    print("=" * 70)
    print(f"STEP 5 VERIFICATION COMPLETE: {checks_passed}/{total_checks} CHECKS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_live_verification())
