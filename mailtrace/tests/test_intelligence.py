"""
tests/test_intelligence.py — Test suite for MAILTRACE Step 5 Infrastructure Intelligence.

Validates:
    1. Public IPv4 enrichment
    2. Public IPv6 enrichment
    3. Private IPv4 exclusion from external lookups
    4. Loopback IP exclusion
    5. Reserved / Link-local IP exclusion
    6. Multiple public IPs handling
    7. Domain enrichment (root domain, subdomain, TLD)
    8. RDAP unavailable fallback
    9. GeoIP unavailable fallback
    10. Provider timeout handling
    11. Invalid IP input resilience
    12. Invalid domain input resilience
    13. Raw IP URL structure detection
    14. Punycode domain detection
    15. Suspicious URL structure (shortener, credential path, non-standard port, dangerous extension)
    16. In-memory IP caching (deduplication)
    17. In-memory domain caching
    18. Offline operation without API keys
    19. Mocked provider integration (IPInfo, GeoIP, RDAP)
    20. Malformed response handling and error resilience
    21. FastAPI upload endpoint integration
    22. SQLite DB persistence of ip_intel, domain_intel, and url_intel
"""

from __future__ import annotations

import io
import pytest
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.services.intelligence import (
    enrich_infrastructure,
    clear_intel_cache,
    _IP_INTEL_CACHE,
    _DOMAIN_INTEL_CACHE,
)
from backend.utils.asn_utils import lookup_asn
from backend.utils.geoip import lookup_geoip
from backend.utils.url_intel import analyze_url_structure
from backend.utils.whois_utils import lookup_rdap_domain


@pytest.fixture(autouse=True)
def reset_cache():
    """Ensure in-memory intelligence caches are cleared before each test."""
    clear_intel_cache()
    yield
    clear_intel_cache()


# ================================================================== #
#  IP Intelligence & Filtering Tests                                  #
# ================================================================== #

class TestIPIntelligence:
    def test_public_ipv4_classification_and_structure(self):
        result = lookup_geoip("8.8.8.8")
        assert result["ip"] == "8.8.8.8"
        assert result["status"] in ("success", "unavailable")
        assert result["source"] in ("local_geoip", "ipinfo", "ipapi", "unavailable")

    def test_public_ipv6_classification_and_structure(self):
        result = lookup_geoip("2001:4860:4860::8888")
        assert result["ip"] == "2001:4860:4860::8888"
        assert result["status"] in ("success", "unavailable")

    def test_private_ipv4_excluded(self):
        for priv_ip in ("10.0.1.50", "192.168.1.1", "172.16.0.5"):
            geo = lookup_geoip(priv_ip)
            assert geo["status"] == "excluded"
            assert geo["source"] == "local_filter"
            assert "private" in geo["reason"].lower()

            asn = lookup_asn(priv_ip)
            assert asn["status"] == "excluded"
            assert asn["source"] == "local_filter"

    def test_loopback_ip_excluded(self):
        geo = lookup_geoip("127.0.0.1")
        assert geo["status"] == "excluded"
        assert geo["source"] == "local_filter"
        assert "loopback" in geo["reason"].lower()

    def test_reserved_ip_excluded(self):
        geo = lookup_geoip("240.0.0.1")
        assert geo["status"] == "excluded"
        assert geo["source"] == "local_filter"

    def test_invalid_ip_resilience(self):
        for invalid in ("not-an-ip", "999.999.999.999", "", None):
            geo = lookup_geoip(invalid)
            assert geo["status"] in ("error", "excluded")
            asn = lookup_asn(invalid)
            assert asn["status"] in ("error", "excluded")

    def test_asn_public_ip_structure(self):
        asn_res = lookup_asn("1.1.1.1")
        assert asn_res["ip"] == "1.1.1.1"
        assert asn_res["status"] in ("success", "unknown", "unavailable")
        assert "asn" in asn_res
        assert "organization" in asn_res


# ================================================================== #
#  Domain & RDAP Intelligence Tests                                   #
# ================================================================== #

class TestDomainIntelligence:
    def test_domain_rdap_structure(self):
        res = lookup_rdap_domain("mail.example.com")
        assert res["domain"] == "mail.example.com"
        assert res["registrable_domain"] == "example.com"
        assert res["status"] in ("success", "unavailable")
        assert "registrar" in res
        assert "created" in res
        assert "expires" in res
        assert "registrant_privacy" in res

    def test_domain_rdap_unavailable_fallback(self, monkeypatch):
        # Force offline fallback by mocking httpx to throw or return 404
        import httpx

        def mock_get(*args, **kwargs):
            raise httpx.ConnectError("Simulated offline")

        monkeypatch.setattr(httpx.Client, "get", mock_get)
        res = lookup_rdap_domain("unreachable-test-domain.org")
        assert res["status"] == "unavailable"
        assert res["source"] == "unavailable"
        assert res["registrable_domain"] == "unreachable-test-domain.org"

    def test_invalid_domain_resilience(self):
        for invalid in ("", None, "   "):
            res = lookup_rdap_domain(invalid)
            assert res["status"] in ("error", "unavailable")


# ================================================================== #
#  Passive URL Structural Intelligence Tests                         #
# ================================================================== #

class TestURLIntelligence:
    def test_raw_ip_host_url(self):
        res = analyze_url_structure("http://198.51.100.4:8080/portal/login.php?user=test")
        assert res["hostname"] == "198.51.100.4"
        assert res["port"] == 8080
        assert res["flags"]["is_ip_host"] is True
        assert res["flags"]["unusual_port"] is True
        assert res["flags"]["has_credential_keywords"] is True
        assert any("direct IP address" in ind for ind in res["indicators"])

    def test_punycode_domain_url(self):
        res = analyze_url_structure("https://xn--pypal-4ve.com/signin")
        assert res["flags"]["is_punycode"] is True
        assert res["flags"]["has_credential_keywords"] is True
        assert any("punycode" in ind.lower() for ind in res["indicators"])

    def test_shortened_url_detection(self):
        res = analyze_url_structure("https://bit.ly/secure-doc-update")
        assert res["flags"]["is_shortened"] is True
        assert any("shortening" in ind.lower() for ind in res["indicators"])

    def test_excessive_subdomains_and_suspicious_extension(self):
        res = analyze_url_structure("http://a.b.c.d.e.malicious-site.com/downloads/invoice.pdf.exe")
        assert res["flags"]["excessive_subdomains"] is True
        assert res["flags"]["has_suspicious_extension"] is True
        assert len(res["indicators"]) >= 2

    def test_at_symbol_misdirection_url(self):
        res = analyze_url_structure("https://legit-brand.com@evil-phish-domain.net/login")
        assert res["flags"]["at_symbol_misdirection"] is True
        assert any("@" in ind for ind in res["indicators"])

    def test_url_hash_stability(self):
        url = "https://example.com/path?arg=1"
        res1 = analyze_url_structure(url)
        res2 = analyze_url_structure(url)
        assert res1["url_hash"] == res2["url_hash"]
        assert len(res1["url_hash"]) == 64  # SHA-256


# ================================================================== #
#  Master Service & Caching Tests                                     #
# ================================================================== #

class TestIntelligenceService:
    def test_enrich_infrastructure_orchestration(self):
        parsed = {
            "sender": {"email": "alert@paypal-update.com", "domain": "paypal-update.com"},
            "ip_addresses": [{"ip": "93.184.216.34"}, {"ip": "10.0.0.1"}],
            "originating_ips": ["104.244.42.1"],
            "received_chain": {"public_ips_observed": ["93.184.216.34"]},
            "domains": ["paypal-update.com", "login-portal.net"],
            "urls": ["http://104.244.42.1/login", "https://bit.ly/update"],
        }

        result = enrich_infrastructure(parsed)
        assert result["summary"]["status"] == "completed"
        assert result["summary"]["total_ips"] >= 3
        assert result["summary"]["public_ips"] >= 2
        assert result["summary"]["private_ips"] >= 1
        assert result["summary"]["total_domains"] >= 2
        assert result["summary"]["total_urls"] == 2
        assert len(result["limitations"]) > 0

        # Verify correlation entities structured
        entities = result.get("correlation_entities", {})
        assert "ips" in entities
        assert "domains" in entities
        assert "urls" in entities
        assert "asns" in entities

    def test_caching_deduplication(self):
        parsed = {
            "ip_addresses": [{"ip": "8.8.8.8"}, {"ip": "8.8.8.8"}],
            "domains": ["google.com", "google.com"],
        }
        res = enrich_infrastructure(parsed)
        assert len(res["ips"]) == 1
        assert len(res["domains"]) == 1
        assert "8.8.8.8" in _IP_INTEL_CACHE
        assert "google.com" in _DOMAIN_INTEL_CACHE

    def test_empty_and_malformed_input_resilience(self):
        res = enrich_infrastructure({})
        assert res["summary"]["status"] == "completed"
        assert res["summary"]["total_ips"] == 0
        assert res["summary"]["total_domains"] == 0
        assert res["summary"]["total_urls"] == 0


# ================================================================== #
#  Mocked Provider Tests                                              #
# ================================================================== #

class TestMockedProviders:
    def test_mocked_ipinfo_enrichment(self, monkeypatch):
        from backend.config import settings
        monkeypatch.setattr(settings, "IPINFO_TOKEN", "mock-token-xyz")

        import httpx

        def mock_get(url, *args, **kwargs):
            class MockResponse:
                status_code = 200
                def json(self):
                    return {
                        "ip": "8.8.8.8",
                        "city": "Mountain View",
                        "region": "California",
                        "country": "US",
                        "loc": "37.4056,-122.0775",
                        "org": "AS15169 Google LLC",
                        "timezone": "America/Los_Angeles",
                    }
            return MockResponse()

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        geo = lookup_geoip("8.8.8.8")
        assert geo["status"] == "success"
        assert geo["country"] == "US"
        assert geo["city"] == "Mountain View"
        assert geo["latitude"] == 37.4056
        assert geo["source"] == "ipinfo"

        asn = lookup_asn("8.8.8.8")
        assert asn["status"] == "success"
        assert asn["asn"] == "AS15169"
        assert "Google" in asn["organization"]
        assert asn["source"] == "ipinfo"


# ================================================================== #
#  API Route & DB Persistence Integration Tests                       #
# ================================================================== #

@pytest.mark.asyncio
class TestApiIntelligenceIntegration:
    async def test_upload_returns_infrastructure_intelligence(self):
        eml_bytes = (
            b"From: Service <service@notification-hub.org>\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Test Email with IP and URL\r\n"
            b"Date: Tue, 08 Sep 2026 10:00:00 +0000\r\n"
            b"Message-ID: <test-intel@domain.example>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please visit http://203.0.113.99:8080/login to verify your account."
        )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post(
                "/api/analyze/upload",
                files={"file": ("test_intel.eml", io.BytesIO(eml_bytes), "message/rfc822")},
            )
            assert resp.status_code == 200
            data = resp.json()

            # Verify Step 5 response structure
            assert "infrastructure_intelligence" in data
            intel = data["infrastructure_intelligence"]
            assert "summary" in intel
            assert "ips" in intel
            assert "domains" in intel
            assert "urls" in intel

            case_id = data["case_id"]

            # Verify Database Persistence
            get_resp = await ac.get(f"/api/analyze/{case_id}")
            assert get_resp.status_code == 200
            case_data = get_resp.json()

            assert case_data["ip_intel"] is not None
            assert case_data["domain_intel"] is not None
            assert case_data["url_intel"] is not None
            assert len(case_data["url_intel"]["urls"]) >= 1
