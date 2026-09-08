"""
tests/test_forensic_consistency.py — Comprehensive Forensic Logic, AI Consistency & Data-Integrity Test Matrix.

Implements the 15-Scenario Test Matrix (A through O) + Real Regression Cases:
    A. Completely benign email
    B. Urgent but legitimate email (e.g., casual_test.eml pattern)
    C. Credential phishing email
    D. BEC-style email
    E. Financial fraud email
    F. Impersonation email
    G. Social engineering email
    H. Malformed / minimal email
    I. Multipart email
    J. Attachment email
    K. Email with URLs
    L. Email with authentication results (SPF/DKIM/DMARC PASS)
    M. Email without authentication results (UNKNOWN, never FAIL)
    N. Email without Received headers (Cautious relay wording)
    O. Email with multiple Received headers (Hop chronology & attribution safety)

Additional Verifications:
    - Zero contradiction between signals_map, threat indicators, risk factors, and rationale
    - UNKNOWN vs FAIL semantics in authentication
    - Evidence tamper detection (byte alteration causes verification failure)
    - Multi-case correlation with identical filenames and distinct case_ids
"""

from __future__ import annotations

import hashlib
import json
import pytest

from backend.services.email_parser import parse_email
from backend.services.forensics import run_forensic_analysis
from backend.services.threat_analyzer import (
    analyze_threat,
    validate_threat_consistency,
    THREAT_PHISHING,
    THREAT_BEC,
    THREAT_CREDENTIAL_HARVESTING,
    THREAT_IMPERSONATION,
    THREAT_SOCIAL_ENGINEERING,
    THREAT_SUSPICIOUS,
    THREAT_BENIGN,
)
from backend.services.risk_engine import calculate_risk
from backend.services.correlation import build_campaign_correlation
from backend.services.evidence_integrity import sha256_bytes, compute_event_hash, verify_chain_of_custody


# ================================================================== #
#  Helper: Build RFC-822 EML bytes                                    #
# ================================================================== #

def _make_eml(
    from_addr: str = "alice@example.com",
    to_addr: str = "bob@example.com",
    subject: str = "Meeting notes",
    body: str = "Here are the notes from our sync.",
    headers: dict[str, str] | None = None,
    received_hops: list[str] | None = None,
) -> bytes:
    received_lines = [f"Received: {hop}" for hop in (received_hops or [])]
    header_lines = [
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        "Date: Mon, 08 Sep 2026 10:00:00 +0000",
        "Message-ID: <test-consistency-001@example.com>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    if headers:
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")

    all_lines = received_lines + header_lines + ["", body]
    return "\r\n".join(all_lines).encode("utf-8")


def _run_full_pipeline(raw_bytes: bytes) -> tuple[dict, dict, dict, dict]:
    parsed = parse_email(raw_bytes)
    forensic = run_forensic_analysis(parsed)
    threat = analyze_threat(parsed, forensic)
    risk = calculate_risk(
        forensic_analysis=forensic,
        threat_analysis=threat,
        infrastructure_intelligence={},
        parsed_email=parsed,
    )
    return parsed, forensic, threat, risk


# ================================================================== #
#  SCENARIO A: Completely Benign Email                                #
# ================================================================== #

def test_scenario_a_completely_benign():
    """Scenario A: Standard email with no urgency, no links, no credentials."""
    raw = _make_eml(
        from_addr="colleague@company.com",
        subject="Project Status Update",
        body="Hi Bob, attaching the weekly status summary for your review when you have time. Best regards.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["primary_threat"] == THREAT_BENIGN
    assert threat["signals"]["urgency"] == "none"
    assert threat["signals"]["credential_request"] == "none"
    assert threat["signals"]["financial_request"] == "none"
    assert "No credential solicitation" in threat["explanation"]

    # Automated consistency cross-check
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO B: Urgent but Legitimate Email (casual_test.eml pattern)  #
# ================================================================== #

def test_scenario_b_urgent_legitimate_casual_test():
    """
    Scenario B: Casual email containing urgency words ('ASAP', 'urgent')
    Signals engine detects urgency=medium, risk factor awards +4 pts,
    threat classification remains BENIGN, explanation acknowledges urgency.
    ZERO contradiction allowed!
    """
    raw = _make_eml(
        from_addr="manager@company.com",
        subject="Urgent: Quick sync needed ASAP",
        body="Hi Team, please review the latest slide deck immediately before our 2pm call. Urgent attention required.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    # Urgency must be detected
    assert threat["signals"]["urgency"] in ("medium", "high")
    assert threat["primary_threat"] == THREAT_BENIGN
    assert THREAT_SOCIAL_ENGINEERING not in threat.get("secondary_threats", [])

    # The explanation MUST acknowledge the urgency and MUST NOT claim 'no urgency'
    assert "urgency" in threat["explanation"].lower()
    assert "no significant urgency" not in threat["explanation"].lower()
    assert "no urgency" not in threat["explanation"].lower()
    
    # Risk factor must match signal
    urgency_factor = next((f for f in risk.get("risk_factors", []) if "Urgent" in f.get("factor", "")), None)
    assert urgency_factor is not None, "Urgency risk factor must be present"
    assert urgency_factor["points"] == 4.0

    # Automated consistency cross-check
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO C: Credential Phishing Email                              #
# ================================================================== #

def test_scenario_c_credential_phishing():
    """Scenario C: Password reset / credential prompt with link."""
    raw = _make_eml(
        from_addr="security@service-login-portal.com",
        subject="Important: Verify your login password immediately",
        body="Your account was locked. Please click here to enter your current password and restore access: http://192.168.1.1/login",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["primary_threat"] in (THREAT_CREDENTIAL_HARVESTING, THREAT_PHISHING)
    assert threat["signals"]["credential_request"] in ("medium", "high")
    assert "credential" in threat["explanation"].lower()

    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO D: BEC Wire Transfer Email                                #
# ================================================================== #

def test_scenario_d_bec_wire_transfer():
    """Scenario D: Executive authority + wire transfer request."""
    raw = _make_eml(
        from_addr="ceo-exec@company-corp.com",
        subject="Strictly Confidential: Urgent wire transfer request",
        body="I am in an executive board meeting. Process a wire transfer payment of $45,000 to the attached vendor immediately. Keep this confidential.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["primary_threat"] in (THREAT_BEC, THREAT_SOCIAL_ENGINEERING)
    assert threat["signals"]["financial_request"] in ("medium", "high")

    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO E: Financial Fraud / Gift Card Scam                       #
# ================================================================== #

def test_scenario_e_financial_fraud():
    """Scenario E: Gift card purchase fraud."""
    raw = _make_eml(
        from_addr="director@external-mail.com",
        subject="Task: Purchase Apple gift cards for client rewards",
        body="Please purchase 5 Apple gift cards worth $200 each right away and email me the redemption codes.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["signals"]["financial_request"] in ("medium", "high")
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO F: Impersonation Email                                    #
# ================================================================== #

def test_scenario_f_brand_impersonation():
    """Scenario F: Display name says Microsoft Support from gmail.com."""
    raw = _make_eml(
        from_addr='"Microsoft Account Team" <random123@gmail.com>',
        subject="Security Notice regarding your Microsoft 365 Subscription",
        body="Your Microsoft Office 365 license has expired. Renew your credentials.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["signals"]["impersonation"] in ("medium", "high")
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO G: Social Engineering / Coercion                          #
# ================================================================== #

def test_scenario_g_social_engineering_fear():
    """Scenario G: Fear of negative consequence / legal penalty."""
    raw = _make_eml(
        from_addr="legal@compliance-notice.org",
        subject="URGENT: Legal action pending against your organization",
        body="Failure to respond within 1 hour will result in immediate termination of service, legal lawsuit, and regulatory penalties.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["signals"]["fear_manipulation"] in ("medium", "high")
    assert threat["signals"]["urgency"] in ("medium", "high")
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO H: Malformed / Minimal Email                              #
# ================================================================== #

def test_scenario_h_malformed_minimal():
    """Scenario H: Minimal / empty body email gracefully handled."""
    raw = b"From: test@example.com\r\nSubject: Empty\r\n\r\n"
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert threat["primary_threat"] in (THREAT_BENIGN, THREAT_SUSPICIOUS)
    assert isinstance(risk["risk_score"], (int, float))
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO I: Multipart Email                                        #
# ================================================================== #

def test_scenario_i_multipart_email():
    """Scenario I: Multipart alternative MIME structure."""
    raw = (
        b"From: info@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Multipart Newsletter\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=\"BOUNDARY123\"\r\n\r\n"
        b"--BOUNDARY123\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Plain text content here.\r\n"
        b"--BOUNDARY123\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>HTML content here.</p>\r\n"
        b"--BOUNDARY123--\r\n"
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert parsed["body"]["plain"] == "Plain text content here."
    assert "<p>HTML content here.</p>" in parsed["body"]["html"]
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO J: Attachment Email                                       #
# ================================================================== #

def test_scenario_j_attachment_email():
    """Scenario J: Email with dangerous executable / archive attachment."""
    raw = (
        b"From: billing@vendor-corp.com\r\n"
        b"To: accounts@client.com\r\n"
        b"Subject: Overdue Invoice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY_ATT\"\r\n\r\n"
        b"--BOUNDARY_ATT\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please see attached invoice.\r\n"
        b"--BOUNDARY_ATT\r\n"
        b"Content-Type: application/x-msdownload\r\n"
        b"Content-Disposition: attachment; filename=\"invoice_document.exe\"\r\n\r\n"
        b"MZ999fakebinary\r\n"
        b"--BOUNDARY_ATT--"
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "invoice_document.exe"
    assert threat["signals"]["attachment_threat"] in ("medium", "high")
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO K: Email with URLs                                        #
# ================================================================== #

def test_scenario_k_url_intelligence():
    """Scenario K: Raw IP host URL detection."""
    raw = _make_eml(
        from_addr="notify@service.com",
        subject="Account Check",
        body="Access your dashboard at http://203.0.113.15:8080/secure/portal",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert len(parsed["urls"]) == 1
    assert threat["signals"]["suspicious_link"] in ("medium", "high")
    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO L: Authentication Results (PASS)                          #
# ================================================================== #

def test_scenario_l_authentication_pass():
    """Scenario L: Valid SPF, DKIM, DMARC passing headers."""
    raw = _make_eml(
        from_addr="sender@trusted-domain.com",
        subject="Authenticated email",
        body="Everything is properly signed.",
        headers={
            "Authentication-Results": "mx.google.com; dkim=pass header.i=@trusted-domain.com; spf=pass (google.com: domain of sender@trusted-domain.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=sender@trusted-domain.com; dmarc=pass (p=REJECT) header.from=trusted-domain.com",
            "DKIM-Signature": "v=1; a=rsa-sha256; d=trusted-domain.com; s=s2023; b=abc;",
        },
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    auth = parsed["authentication"]
    assert auth["spf"]["status"] == "pass"
    assert auth["dkim"]["status"] == "pass"
    assert auth["dmarc"]["status"] == "pass"

    # Forensics must show passed findings
    spf_f = next(f for f in forensic["findings"] if f["type"] == "spf_status")
    assert spf_f["status"] == "passed"
    dkim_f = next(f for f in forensic["findings"] if f["type"] == "dkim_status")
    assert dkim_f["status"] == "passed"
    dmarc_f = next(f for f in forensic["findings"] if f["type"] == "dmarc_status")
    assert dmarc_f["status"] == "passed"

    contradictions = validate_threat_consistency(threat, risk, parsed)
    assert contradictions == [], f"Contradictions found: {contradictions}"


# ================================================================== #
#  SCENARIO M: Authentication Unobserved (UNKNOWN != FAIL)            #
# ================================================================== #

def test_scenario_m_authentication_unobserved():
    """Scenario M: Missing auth headers must be recorded as UNKNOWN, NOT FAIL."""
    raw = _make_eml(
        from_addr="internal@intranet.local",
        subject="Internal note",
        body="Internal transfer without auth headers.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    auth_summary = forensic["summary"]["authentication"]
    assert auth_summary["spf_status"] == "unknown"
    assert auth_summary["dkim_status"] == "unknown"
    assert auth_summary["dmarc_status"] == "unknown"

    # Risk score must NOT add high DMARC or SPF failure penalties
    dmarc_fail_factor = next((f for f in risk.get("risk_factors", []) if "DMARC Policy Rejection" in f.get("factor", "")), None)
    assert dmarc_fail_factor is None, "UNKNOWN DMARC must not be penalized as Policy Rejection Failure"


# ================================================================== #
#  SCENARIO N: Relay Timeline Without Received Headers                #
# ================================================================== #

def test_scenario_n_no_received_headers():
    """Scenario N: Absence of Received headers must not assert single hop."""
    raw = _make_eml(
        from_addr="direct@example.com",
        subject="Direct test",
        body="Directly ingested message.",
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    assert parsed["received_chain"]["hop_count"] == 0
    assert parsed["received_chain"]["chain"] == []


# ================================================================== #
#  SCENARIO O: Multiple Received Hops Chronology                      #
# ================================================================== #

def test_scenario_o_multiple_received_hops():
    """Scenario O: Received hops ordered oldest -> newest."""
    hops = [
        "from mail-final.relay.com ([198.51.100.20]) by mx.dest.com with ESMTP id xyz; Mon, 08 Sep 2026 10:02:00 +0000",
        "from initial-sender.origin.com ([203.0.113.50]) by mail-final.relay.com with ESMTP id abc; Mon, 08 Sep 2026 10:00:00 +0000",
    ]
    raw = _make_eml(
        from_addr="traveler@example.com",
        subject="Multi-hop trace",
        body="Routed message.",
        received_hops=hops,
    )
    parsed, forensic, threat, risk = _run_full_pipeline(raw)

    relay = parsed["received_chain"]
    assert relay["hop_count"] == 2
    assert relay["earliest_observed_node"]["from_ip"] == "203.0.113.50"
    assert "headers can be forged" in relay["confidence_note"].lower()


# ================================================================== #
#  EVIDENCE TAMPER DETECTION                                          #
# ================================================================== #

def test_evidence_tamper_detection():
    """Ensure SHA-256 evidence integrity detects modified bytes."""
    original_bytes = b"Authentic email byte payload for forensic case 123."
    original_hash = sha256_bytes(original_bytes)

    # Recomputed hash matches exactly
    assert sha256_bytes(original_bytes) == original_hash

    # Tampered bytes must fail validation
    tampered_bytes = b"Tampered email byte payload for forensic case 123."
    tampered_hash = sha256_bytes(tampered_bytes)
    assert tampered_hash != original_hash


# ================================================================== #
#  MULTI-CASE CORRELATION WITH DUPLICATE FILENAMES                    #
# ================================================================== #

def test_multi_case_correlation_duplicate_filenames():
    """Ensure correlation distinguishes cases by case_id, not filename."""
    case_a = {
        "id": "case-alpha-001",
        "original_filename": "casual_test.eml",
        "parsed_email": {
            "sender": {"email": "shared-threat@badactor.com"},
            "domains": ["badactor.com"],
            "urls": [{"url": "http://badactor.com/login"}],
        },
        "ip_intel": {
            "ips": [{"ip": "198.51.100.99", "classification": "public", "asn": {"number": "AS12345"}}]
        },
        "domain_intel": {"domains": [{"domain": "badactor.com"}]},
        "url_intel": {"urls": [{"url": "http://badactor.com/login"}]},
    }
    case_b = {
        "id": "case-beta-002",
        "original_filename": "casual_test.eml",  # Identical filename
        "parsed_email": {
            "sender": {"email": "billing@badactor.com"},
            "domains": ["badactor.com"],
            "urls": [{"url": "http://badactor.com/invoice"}],
        },
        "ip_intel": {
            "ips": [{"ip": "198.51.100.99", "classification": "public", "asn": {"number": "AS12345"}}]
        },
        "domain_intel": {"domains": [{"domain": "badactor.com"}]},
        "url_intel": {"urls": [{"url": "http://badactor.com/invoice"}]},
    }

    # Correlate across cases
    overview = build_campaign_correlation([case_a, case_b])

    assert overview is not None
    # Correlation must link case_a and case_b by their distinct case_ids
    correlations = overview.get("correlations", [])
    assert len(correlations) >= 1
    corr = correlations[0]
    assert {corr["case_a"], corr["case_b"]} == {"case-alpha-001", "case-beta-002"}
