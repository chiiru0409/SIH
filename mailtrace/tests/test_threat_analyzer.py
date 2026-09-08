"""
tests/test_threat_analyzer.py — Test suite for MAILTRACE Step 4 AI-Powered Threat Detection.

Validates:
    - 12 Test fixtures across all required threat archetypes:
        1. Clean legitimate personal email (BENIGN)
        2. Basic phishing email (PHISHING)
        3. Credential harvesting email (CREDENTIAL_HARVESTING)
        4. BEC wire transfer / payment request (BEC)
        5. Executive / CEO impersonation (IMPERSONATION / BEC)
        6. Account suspension security scam (PHISHING / SOCIAL_ENGINEERING)
        7. Urgent social engineering coercion (SOCIAL_ENGINEERING)
        8. Suspicious IP-host link email (PHISHING / SUSPICIOUS)
        9. Dangerous attachment-based email (SUSPICIOUS / PHISHING)
        10. Benign corporate business email (BENIGN)
        11. Ambiguous / low-signal email (SUSPICIOUS)
        12. Missing / empty body email (BENIGN / SUSPICIOUS graceful handling)
    - Primary and secondary threat classification
    - Confidence scoring (0.0 to 1.0)
    - Structured indicator generation & weight scoring
    - Signals mapping
    - Explainable reasoning and evidence citations
    - Strict Fact vs. AI Inference separation
    - Deterministic local operation without API key
    - Optional LLM mock integration and fallback resilience
    - Full FastAPI upload endpoint integration & SQLite DB persistence
"""

from __future__ import annotations

import io
import json
import pytest
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.services.email_parser import parse_email
from backend.services.forensics import run_forensic_analysis
from backend.services.threat_analyzer import (
    analyze_threat,
    THREAT_PHISHING,
    THREAT_BEC,
    THREAT_CREDENTIAL_HARVESTING,
    THREAT_IMPERSONATION,
    THREAT_SOCIAL_ENGINEERING,
    THREAT_SUSPICIOUS,
    THREAT_BENIGN,
    _call_llm_analyzer,
)


# ================================================================== #
#  Synthetic Email Builders (Raw RFC-822 formatted)                   #
# ================================================================== #

def _build_eml(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    headers: dict[str, str] | None = None,
    attachments: list[tuple[str, str, bytes]] | None = None,
) -> bytes:
    """Build a valid raw RFC-822 email byte stream."""
    lines = [
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        f"Date: Tue, 08 Sep 2026 10:00:00 +0000",
        f"Message-ID: <test-{abs(hash(subject))}@domain.example>",
        "MIME-Version: 1.0",
    ]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")

    if not attachments:
        lines.append("Content-Type: text/plain; charset=utf-8")
        lines.append("")
        lines.append(body)
        return "\r\n".join(lines).encode("utf-8")

    # Multipart with attachments
    boundary = "----=_Part_MailTrace_Test_123"
    lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
    lines.append("")
    lines.append(f"--{boundary}")
    lines.append("Content-Type: text/plain; charset=utf-8")
    lines.append("")
    lines.append(body)

    for fname, ctype, fbytes in attachments:
        lines.append(f"--{boundary}")
        lines.append(f'Content-Type: {ctype}; name="{fname}"')
        lines.append(f'Content-Disposition: attachment; filename="{fname}"')
        lines.append("Content-Transfer-Encoding: base64")
        lines.append("")
        import base64
        lines.append(base64.b64encode(fbytes).decode("ascii"))

    lines.append(f"--{boundary}--")
    return "\r\n".join(lines).encode("utf-8")


# ================================================================== #
#  12 Fixture Scenarios                                               #
# ================================================================== #

@pytest.fixture
def clean_personal_email() -> bytes:
    """Fixture 1: Clean legitimate personal email."""
    return _build_eml(
        from_addr="Alice Smith <alice@example.com>",
        to_addr="bob@example.com",
        subject="Weekend lunch plans",
        body="Hi Bob,\n\nAre we still on for lunch this Saturday at 1 PM?\nLet me know if that time works for you.\n\nBest,\nAlice",
        headers={
            "Authentication-Results": "mx.google.com; spf=pass (google.com: domain of alice@example.com designates 198.51.100.1 as permitted sender) smtp.mailfrom=alice@example.com; dkim=pass header.i=@example.com; dmarc=pass",
        },
    )


@pytest.fixture
def basic_phishing_email() -> bytes:
    """Fixture 2: Basic phishing email with fake security alert & suspicious link."""
    return _build_eml(
        from_addr="PayPal Security <service@paypa1-security-alert.com>",
        to_addr="victim@example.com",
        subject="URGENT: Unauthorized login detected on your PayPal account",
        body="Dear Customer,\n\nWe detected an unauthorized sign-in attempt from an unrecognized device.\nYour account will be suspended within 24 hours unless you verify your identity.\n\nClick the link below to verify your account immediately:\nhttp://paypa1-security-alert.com/login/verify.php\n\nThank you,\nPayPal Support Team",
        headers={
            "Authentication-Results": "mx.victim.com; spf=fail (domain of paypa1-security-alert.com does not designate sender); dkim=fail; dmarc=fail",
        },
    )


@pytest.fixture
def credential_harvesting_email() -> bytes:
    """Fixture 3: Credential harvesting email prompting password submission."""
    return _build_eml(
        from_addr="IT Helpdesk <support@corporate-internal.com>",
        to_addr="user@corporate.com",
        subject="Action Required: Password Expiring Today",
        body="Hello,\n\nYour corporate password expires today. Please confirm your login credentials and enter your password at the portal below to keep your account active:\n\nhttp://192.168.1.50/owa/auth/login.aspx\n\nEnter your username and password to prevent account termination.",
        headers={
            "Reply-To": "harvest@evil-attacker.com",
        },
    )


@pytest.fixture
def bec_wire_request_email() -> bytes:
    """Fixture 4: BEC wire transfer / banking detail modification."""
    return _build_eml(
        from_addr="CEO John Doe <ceo@company-holdings.com>",
        to_addr="finance@company-holdings.com",
        subject="Confidential: Urgent Wire Transfer Request",
        body="Hi Jane,\n\nI need you to process an urgent wire transfer for an overdue invoice today. Please update the vendor banking details with the new routing number provided below.\n\nKeep this strictly confidential until the acquisition closes. I am currently in a meeting so email only.\n\nThanks,\nJohn Doe, CEO",
    )


@pytest.fixture
def executive_impersonation_email() -> bytes:
    """Fixture 5: Executive impersonation with gift card request."""
    return _build_eml(
        from_addr="Managing Director Robert Smith <exec-desk@external-mailservice.org>",
        to_addr="assistant@mycompany.com",
        subject="Quick assistance needed - Robert",
        body="Hi,\n\nI am in a board meeting and need you to purchase 5 Apple gift cards for a client presentation immediately. Email the card codes directly to me as soon as possible. Do not call my cell.\n\nRegards,\nRobert Smith\nChief Executive Officer",
        headers={
            "Reply-To": "robert.smith.private123@mail-drop.net",
        },
    )


@pytest.fixture
def account_suspension_scam_email() -> bytes:
    """Fixture 6: Account suspension warning scam."""
    return _build_eml(
        from_addr="Netflix Billing <billing@stream-account-notice.net>",
        to_addr="subscriber@example.com",
        subject="Final Warning: Your Netflix subscription has been suspended",
        body="Your recent payment failed. Your account will be closed in 24 hours to avoid service interruption.\n\nUpdate your account details and billing information now: http://stream-account-notice.net/billing\n\nFailure to act promptly will result in permanent deactivation.",
    )


@pytest.fixture
def urgent_social_engineering_email() -> bytes:
    """Fixture 7: Urgent social engineering coercion."""
    return _build_eml(
        from_addr="Legal Notice Office <notifications@court-summons-portal.com>",
        to_addr="citizen@example.com",
        subject="CRITICAL: Legal summons - Immediate action required",
        body="URGENT ATTENTION: A legal complaint has been filed against you. You must act immediately within 12 hours. Failure to respond will result in immediate penalty and law enforcement action. Review the legal notice attached or face severe consequences.",
    )


@pytest.fixture
def suspicious_link_ip_email() -> bytes:
    """Fixture 8: Suspicious email using raw IP host URL."""
    return _build_eml(
        from_addr="Notice <alert@notification-hub.org>",
        to_addr="user@example.com",
        subject="Document shared with you",
        body="Please view the shared document at http://203.0.113.88/sharepoint/doc10294.pdf and confirm receipt.",
    )


@pytest.fixture
def dangerous_attachment_email() -> bytes:
    """Fixture 9: Suspicious email with dangerous executable attachment."""
    return _build_eml(
        from_addr="Shipping Vendor <dispatch@freight-tracker-intl.com>",
        to_addr="logistics@company.com",
        subject="Updated Shipping Manifest & Customs Clearance",
        body="Please find the attached shipping manifest and customs declaration for your pending container shipment.",
        attachments=[
            ("Customs_Manifest_Invoice.pdf.exe", "application/octet-stream", b"MZ\x90\x00\x03\x00\x00\x00PE\x00\x00"),
        ],
    )


@pytest.fixture
def benign_business_email() -> bytes:
    """Fixture 10: Benign corporate business email."""
    return _build_eml(
        from_addr="Project Manager Sarah <sarah.jenkins@acmecorp.com>",
        to_addr="team@acmecorp.com",
        subject="Q3 Sprint Review & Retrospective Notes",
        body="Hi team,\n\nAttached are the sprint review notes from today's retrospective. Thank you all for the great work on delivering the milestones.\nOur next sprint planning session is scheduled for Tuesday at 10 AM.\n\nBest regards,\nSarah Jenkins\nProject Manager | Acme Corp",
        headers={
            "Authentication-Results": "mail.acmecorp.com; spf=pass; dkim=pass header.i=@acmecorp.com; dmarc=pass",
        },
    )


@pytest.fixture
def ambiguous_suspicious_email() -> bytes:
    """Fixture 11: Ambiguous email with minor header / structural anomaly."""
    return _build_eml(
        from_addr="info@unknown-marketing-site.com",
        to_addr="user@example.com",
        subject="Newsletter Issue #42",
        body="Check out the latest tech trends and updates from our quarterly technology digest.",
        headers={
            "Reply-To": "different-domain@external-bounce.com",
        },
    )


@pytest.fixture
def empty_body_email() -> bytes:
    """Fixture 12: Missing / empty body email."""
    return _build_eml(
        from_addr="sender@example.com",
        to_addr="recipient@example.com",
        subject="Ping",
        body="",
    )


# ================================================================== #
#  Unit Tests for Threat Analyzer Logic                               #
# ================================================================== #

class TestThreatClassificationFixtures:
    """Test classification on all 12 fixtures."""

    def test_clean_personal_email(self, clean_personal_email: bytes):
        parsed = parse_email(clean_personal_email)
        forensic = run_forensic_analysis(parsed, clean_personal_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] == THREAT_BENIGN
        assert result["confidence"] >= 0.70
        assert "standard communication patterns" in result["explanation"].lower() or "benign" in result["explanation"].lower()
        assert result["analysis_method"] == "local"

    def test_basic_phishing_email(self, basic_phishing_email: bytes):
        parsed = parse_email(basic_phishing_email)
        forensic = run_forensic_analysis(parsed, basic_phishing_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_PHISHING, THREAT_IMPERSONATION)
        assert result["confidence"] >= 0.75
        assert result["signals"]["urgency"] in ("high", "medium")
        assert result["signals"]["impersonation"] in ("high", "medium")
        assert any(ind["indicator"] == "urgency_language" for ind in result["indicators"])
        assert any(ind["indicator"] == "brand_display_name_spoofing" for ind in result["indicators"])

    def test_credential_harvesting_email(self, credential_harvesting_email: bytes):
        parsed = parse_email(credential_harvesting_email)
        forensic = run_forensic_analysis(parsed, credential_harvesting_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_CREDENTIAL_HARVESTING, THREAT_PHISHING)
        assert result["signals"]["credential_request"] in ("high", "medium")
        assert any(ind["indicator"] == "credential_request" for ind in result["indicators"])
        assert result["confidence"] >= 0.75

    def test_bec_wire_request_email(self, bec_wire_request_email: bytes):
        parsed = parse_email(bec_wire_request_email)
        forensic = run_forensic_analysis(parsed, bec_wire_request_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] == THREAT_BEC
        assert result["signals"]["financial_request"] == "high"
        assert result["signals"]["authority_pressure"] in ("high", "medium")
        assert any(ind["indicator"] == "financial_manipulation" for ind in result["indicators"])
        assert any(ind["indicator"] == "secrecy_bypass_instruction" for ind in result["indicators"])
        assert "bec" in result["explanation"].lower() or "compromise" in result["explanation"].lower()

    def test_executive_impersonation_email(self, executive_impersonation_email: bytes):
        parsed = parse_email(executive_impersonation_email)
        forensic = run_forensic_analysis(parsed, executive_impersonation_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_BEC, THREAT_IMPERSONATION, THREAT_SOCIAL_ENGINEERING)
        assert result["signals"]["financial_request"] in ("high", "medium")
        assert result["confidence"] >= 0.70
        assert any(ind["indicator"] == "financial_manipulation" for ind in result["indicators"])

    def test_account_suspension_scam_email(self, account_suspension_scam_email: bytes):
        parsed = parse_email(account_suspension_scam_email)
        forensic = run_forensic_analysis(parsed, account_suspension_scam_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_PHISHING, THREAT_SOCIAL_ENGINEERING, THREAT_CREDENTIAL_HARVESTING)
        assert result["signals"]["urgency"] in ("high", "medium")
        assert result["confidence"] >= 0.70

    def test_urgent_social_engineering_email(self, urgent_social_engineering_email: bytes):
        parsed = parse_email(urgent_social_engineering_email)
        forensic = run_forensic_analysis(parsed, urgent_social_engineering_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_SOCIAL_ENGINEERING, THREAT_PHISHING, THREAT_SUSPICIOUS)
        assert result["signals"]["urgency"] in ("high", "medium")
        assert result["confidence"] >= 0.65

    def test_suspicious_link_ip_email(self, suspicious_link_ip_email: bytes):
        parsed = parse_email(suspicious_link_ip_email)
        forensic = run_forensic_analysis(parsed, suspicious_link_ip_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_PHISHING, THREAT_SUSPICIOUS)
        assert result["signals"]["suspicious_link"] == "high"
        assert any(ind["indicator"] == "ip_host_url" for ind in result["indicators"])

    def test_dangerous_attachment_email(self, dangerous_attachment_email: bytes):
        parsed = parse_email(dangerous_attachment_email)
        forensic = run_forensic_analysis(parsed, dangerous_attachment_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_SUSPICIOUS, THREAT_PHISHING)
        assert result["signals"]["attachment_threat"] == "high"
        assert any(ind["indicator"] == "dangerous_attachment_type" for ind in result["indicators"])

    def test_benign_business_email(self, benign_business_email: bytes):
        parsed = parse_email(benign_business_email)
        forensic = run_forensic_analysis(parsed, benign_business_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] == THREAT_BENIGN
        assert result["confidence"] >= 0.70
        assert result["signals"]["urgency"] in ("none", "low")
        assert result["signals"]["credential_request"] in ("none", "low")

    def test_ambiguous_suspicious_email(self, ambiguous_suspicious_email: bytes):
        parsed = parse_email(ambiguous_suspicious_email)
        forensic = run_forensic_analysis(parsed, ambiguous_suspicious_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_SUSPICIOUS, THREAT_BENIGN, THREAT_IMPERSONATION)
        assert isinstance(result["confidence"], float)

    def test_empty_body_email(self, empty_body_email: bytes):
        parsed = parse_email(empty_body_email)
        forensic = run_forensic_analysis(parsed, empty_body_email)
        result = analyze_threat(parsed, forensic)

        assert result["primary_threat"] in (THREAT_BENIGN, THREAT_SUSPICIOUS)
        assert isinstance(result["explanation"], str)
        assert result["confidence"] > 0.0


# ================================================================== #
#  Explainability, Indicators, Evidence, and Boundaries               #
# ================================================================== #

class TestThreatExplainability:
    """Test explainability details, weights, evidence separation, and safety."""

    def test_indicator_structure_and_weights(self, basic_phishing_email: bytes):
        parsed = parse_email(basic_phishing_email)
        forensic = run_forensic_analysis(parsed, basic_phishing_email)
        result = analyze_threat(parsed, forensic)

        indicators = result.get("indicators", [])
        assert len(indicators) > 0

        for ind in indicators:
            assert "indicator" in ind
            assert "category" in ind
            assert "weight" in ind
            assert 0.0 <= ind["weight"] <= 1.0
            assert ind["severity"] in ("high", "medium", "low", "info")
            assert "description" in ind
            assert "evidence" in ind

    def test_fact_vs_inference_separation(self, basic_phishing_email: bytes):
        parsed = parse_email(basic_phishing_email)
        forensic = run_forensic_analysis(parsed, basic_phishing_email)
        result = analyze_threat(parsed, forensic)

        evidence_summary = result.get("evidence_summary", {})
        assert "facts" in evidence_summary
        assert "inferences" in evidence_summary
        assert isinstance(evidence_summary["facts"], list)
        assert isinstance(evidence_summary["inferences"], list)
        assert len(evidence_summary["facts"]) > 0

    def test_no_attacker_attribution_claim(self, bec_wire_request_email: bytes):
        parsed = parse_email(bec_wire_request_email)
        forensic = run_forensic_analysis(parsed, bec_wire_request_email)
        result = analyze_threat(parsed, forensic)

        explanation = result["explanation"].lower()
        # Ensure no attribution claims
        assert "attacker is" not in explanation
        assert "hacker located at" not in explanation
        assert "identity confirmed as" not in explanation

    def test_resilience_on_none_and_empty_inputs(self):
        result = analyze_threat({}, None)
        assert result["primary_threat"] == THREAT_BENIGN
        assert result["confidence"] > 0.0
        assert result["analysis_method"] == "local"

    def test_signals_mapping_complete(self, basic_phishing_email: bytes):
        parsed = parse_email(basic_phishing_email)
        result = analyze_threat(parsed)

        signals = result.get("signals", {})
        expected_signals = [
            "urgency", "credential_request", "financial_request",
            "impersonation", "suspicious_link", "attachment_threat",
            "fear_manipulation", "authority_pressure"
        ]
        for key in expected_signals:
            assert key in signals
            assert signals[key] in ("high", "medium", "low", "none")


# ================================================================== #
#  LLM Provider Mock & Fallback Tests                                 #
# ================================================================== #

class TestLLMFallback:
    """Test deterministic local fallback when API key is missing or invalid."""

    @pytest.mark.asyncio
    async def test_llm_analyzer_skips_when_no_api_key(self, monkeypatch):
        from backend.config import settings
        monkeypatch.setattr(settings, "OPENAI_API_KEY", "")

        res = await _call_llm_analyzer({"sender": {}}, None)
        assert res is None

    @pytest.mark.asyncio
    async def test_llm_analyzer_graceful_on_network_failure(self, monkeypatch):
        from backend.config import settings
        monkeypatch.setattr(settings, "OPENAI_API_KEY", "sk-mock-key-12345")

        # LLM call will fail or be handled gracefully without crashing
        res = await _call_llm_analyzer({"sender": {}}, None)
        # Should return None and fallback smoothly
        assert res is None or isinstance(res, dict)


# ================================================================== #
#  FastAPI Integration & DB Persistence Tests                         #
# ================================================================== #

@pytest.mark.asyncio
class TestApiThreatIntegration:
    """Test upload endpoint returning Step 4 threat analysis and DB persistence."""

    async def test_upload_returns_threat_analysis(self, basic_phishing_email: bytes):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            resp = await ac.post(
                "/api/analyze/upload",
                files={"file": ("phishing_test.eml", io.BytesIO(basic_phishing_email), "message/rfc822")},
            )
            assert resp.status_code == 200
            data = resp.json()

            # Existing Step 1-3 fields intact
            assert "case_id" in data
            assert "email" in data
            assert "authentication" in data
            assert "forensic_analysis" in data

            # Step 4 Threat analysis present
            assert "threat_analysis" in data
            threat = data["threat_analysis"]
            assert threat is not None
            assert threat["primary_threat"] in (THREAT_PHISHING, THREAT_IMPERSONATION)
            assert isinstance(threat["confidence"], float)
            assert "indicators" in threat
            assert "explanation" in threat
            assert "signals" in threat
            assert threat["analysis_method"] == "local"

    async def test_case_detail_persists_ai_analysis(self, bec_wire_request_email: bytes):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            upload_resp = await ac.post(
                "/api/analyze/upload",
                files={"file": ("bec_case.eml", io.BytesIO(bec_wire_request_email), "message/rfc822")},
            )
            assert upload_resp.status_code == 200
            case_id = upload_resp.json()["case_id"]

            # Query GET /api/analyze/{case_id}
            get_resp = await ac.get(f"/api/analyze/{case_id}")
            assert get_resp.status_code == 200
            case_data = get_resp.json()

            assert case_data["case_id"] == case_id
            assert case_data["ai_analysis"] is not None
            assert case_data["ai_analysis"]["primary_threat"] == THREAT_BEC
            assert "indicators" in case_data["ai_analysis"]
            assert "evidence_summary" in case_data["ai_analysis"]
