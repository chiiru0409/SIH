"""
tests/test_risk_engine.py — Step 6 Unit and Integration Tests for Unified Risk Engine.

Tests:
    1. Completely benign email produces LOW risk (< 25).
    2. Clean authenticated email with SPF/DKIM/DMARC pass receives benign mitigation.
    3. SPF failure contributes authentication risk points.
    4. DKIM failure contributes authentication risk points.
    5. DMARC failure contributes high authentication risk points.
    6. Reply-To mismatch contributes identity risk points.
    7. Return-Path mismatch contributes identity risk points.
    8. Phishing AI classification contributes content risk.
    9. BEC AI classification contributes content risk.
    10. Credential harvesting AI classification contributes content risk.
    11. Impersonation / display name brand spoof contributes identity risk.
    12. Suspicious URL indicators (raw IP host, unusual port, credential keyword, shortener, punycode).
    13. Attachment threats (dangerous executable extensions, double extensions).
    14. Multiple simultaneous threat signals produce CRITICAL / HIGH risk (>= 75).
    15. Unknown authentication data contributes 0 penalty points.
    16. Unavailable infrastructure data contributes 0 penalty points.
    17. High-confidence AI classification scales points proportionally.
    18. Low-confidence AI classification produces lower weighted points.
    19. Double-counting protection limits category runaway subscores.
    20. Score lower bound is strictly >= 0.0.
    21. Score upper bound is strictly <= 100.0.
    22. Severity boundary classifications (LOW, MEDIUM, HIGH, CRITICAL).
    23. Evidence traceability: all risk factors contain valid factor, category, severity, evidence, source.
    24. Deterministic repeated scoring: identical inputs produce identical scores and explanations.
    25. Empty / malformed input resilience without exceptions.
"""

from __future__ import annotations

import pytest
from backend.services.risk_engine import (
    calculate_risk,
    get_severity_label,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
    CATEGORY_CAPS,
)


# ------------------------------------------------------------------ #
#  Fixtures / Helpers                                                #
# ------------------------------------------------------------------ #

def _mock_forensic(
    spf_status: str = "pass",
    dkim_status: str = "pass",
    dmarc_status: str = "pass",
    findings: list[dict] | None = None,
) -> dict:
    return {
        "summary": {
            "authentication": {
                "spf_status": spf_status,
                "dkim_status": dkim_status,
                "dmarc_status": dmarc_status,
            },
            "identity": {},
            "relay": {},
            "headers": {},
        },
        "findings": findings or [],
        "facts": [],
        "inferences": [],
        "limitations": [],
    }


def _mock_threat(
    primary_threat: str = "BENIGN",
    confidence: float = 0.90,
    signals: dict | None = None,
    indicators: list[dict] | None = None,
) -> dict:
    return {
        "primary_threat": primary_threat,
        "secondary_threats": [],
        "confidence": confidence,
        "signals": signals or {},
        "indicators": indicators or [],
        "explanation": "Threat analysis evaluation.",
    }


def _mock_intel(
    ips: list[dict] | None = None,
    domains: list[dict] | None = None,
    urls: list[dict] | None = None,
) -> dict:
    return {
        "ips": ips or [],
        "domains": domains or [],
        "urls": urls or [],
        "summary": {"status": "completed"},
        "limitations": [],
    }


# ------------------------------------------------------------------ #
#  Test Cases                                                        #
# ------------------------------------------------------------------ #

def test_1_completely_benign_email():
    """Benign email with passing auth and no threat signals produces LOW risk (< 25)."""
    forensic = _mock_forensic(spf_status="pass", dkim_status="pass", dmarc_status="pass")
    threat = _mock_threat(primary_threat="BENIGN", confidence=0.95)
    intel = _mock_intel()
    parsed = {"attachments": []}

    res = calculate_risk(forensic, threat, intel, parsed)
    assert res["risk_score"] < 25.0
    assert res["severity"] == SEVERITY_LOW
    assert "conforms to expected" in res["explanation"] or "Low overall risk" in res["explanation"]


def test_2_clean_authenticated_email_mitigation():
    """Passing SPF, DKIM, and DMARC applies benign mitigation dampening."""
    forensic_pass = _mock_forensic(spf_status="pass", dkim_status="pass", dmarc_status="pass")
    forensic_neutral = _mock_forensic(spf_status="neutral", dkim_status="neutral", dmarc_status="neutral")

    threat = _mock_threat(primary_threat="SUSPICIOUS", confidence=0.60)

    res_pass = calculate_risk(forensic_pass, threat, _mock_intel(), {})
    res_neutral = calculate_risk(forensic_neutral, threat, _mock_intel(), {})

    assert res_pass["risk_score"] < res_neutral["risk_score"]


def test_3_spf_failure():
    """SPF validation failure produces authentication risk factor."""
    forensic = _mock_forensic(spf_status="fail", dkim_status="pass", dmarc_status="pass")
    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})

    spf_factors = [f for f in res["risk_factors"] if f["factor"] == "SPF Validation Failure"]
    assert len(spf_factors) == 1
    assert spf_factors[0]["category"] == "authentication"
    assert spf_factors[0]["points"] > 0
    assert res["category_scores"]["authentication"] > 0


def test_4_dkim_failure():
    """DKIM signature failure produces authentication risk factor."""
    forensic = _mock_forensic(spf_status="pass", dkim_status="fail", dmarc_status="pass")
    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})

    dkim_factors = [f for f in res["risk_factors"] if f["factor"] == "DKIM Signature Verification Failure"]
    assert len(dkim_factors) == 1
    assert dkim_factors[0]["category"] == "authentication"
    assert dkim_factors[0]["points"] > 0


def test_5_dmarc_failure():
    """DMARC policy failure contributes high authentication risk points."""
    forensic = _mock_forensic(spf_status="fail", dkim_status="fail", dmarc_status="reject")
    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})

    dmarc_factors = [f for f in res["risk_factors"] if "DMARC Policy" in f["factor"]]
    assert len(dmarc_factors) == 1
    assert dmarc_factors[0]["severity"] == "high"
    assert res["category_scores"]["authentication"] >= 14.0


def test_6_reply_to_mismatch():
    """Reply-To domain mismatch contributes identity risk points."""
    findings = [{
        "type": "reply_to_mismatch",
        "status": "failed",
        "severity": "medium",
        "description": "Reply-To domain attacker.net does not match From domain corp.com",
    }]
    forensic = _mock_forensic(findings=findings)
    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})

    ident_factors = [f for f in res["risk_factors"] if f["factor"] == "Sender / Reply-To Domain Discrepancy"]
    assert len(ident_factors) == 1
    assert ident_factors[0]["category"] == "identity"
    assert res["category_scores"]["identity"] >= 10.0


def test_7_return_path_mismatch():
    """Return-Path mismatch contributes identity risk points."""
    findings = [{
        "type": "return_path_mismatch",
        "status": "failed",
        "severity": "low",
        "description": "Return-Path envelope domain differs from From header",
    }]
    forensic = _mock_forensic(findings=findings)
    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})

    factors = [f for f in res["risk_factors"] if f["factor"] == "Sender / Return-Path Domain Discrepancy"]
    assert len(factors) == 1
    assert factors[0]["category"] == "identity"


def test_8_phishing_classification():
    """Primary threat PHISHING generates significant content risk."""
    threat = _mock_threat(primary_threat="PHISHING", confidence=0.92, signals={"urgency": "detected"})
    res = calculate_risk(_mock_forensic(), threat, _mock_intel(), {})

    content_factors = [f for f in res["risk_factors"] if f["category"] == "content"]
    assert len(content_factors) >= 1
    assert any("Phishing Attack" in f["factor"] for f in content_factors)
    assert res["category_scores"]["content"] >= 20.0


def test_9_bec_classification():
    """Primary threat BEC with financial signals generates content risk."""
    threat = _mock_threat(
        primary_threat="BEC",
        confidence=0.90,
        signals={"financial_request": "detected", "authority_pressure": "detected"}
    )
    res = calculate_risk(_mock_forensic(), threat, _mock_intel(), {})

    bec_factors = [f for f in res["risk_factors"] if "Business Email Compromise" in f["factor"]]
    assert len(bec_factors) == 1
    assert res["category_scores"]["content"] >= 20.0


def test_10_credential_harvesting():
    """Primary threat CREDENTIAL_HARVESTING produces high content score."""
    threat = _mock_threat(
        primary_threat="CREDENTIAL_HARVESTING",
        confidence=0.95,
        signals={"credential_request": "detected", "fear_manipulation": "detected"}
    )
    res = calculate_risk(_mock_forensic(), threat, _mock_intel(), {})

    cred_factors = [f for f in res["risk_factors"] if "Credential Harvesting" in f["factor"]]
    assert len(cred_factors) >= 1
    assert res["category_scores"]["content"] >= 25.0


def test_11_impersonation_and_brand_spoof():
    """Display name brand spoofing contributes high identity risk points."""
    findings = [{
        "type": "display_name_brand_spoof",
        "status": "failed",
        "severity": "high",
        "description": "Display name 'Microsoft Security' on external domain alert.com",
    }]
    forensic = _mock_forensic(findings=findings)
    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})

    spoof_factors = [f for f in res["risk_factors"] if "Brand Impersonation" in f["factor"]]
    assert len(spoof_factors) == 1
    assert spoof_factors[0]["points"] >= 15.0
    assert res["category_scores"]["identity"] >= 15.0


def test_12_suspicious_url_indicators():
    """URLs with raw IP, unusual port, credential paths, and shorteners generate URL subscores."""
    intel = _mock_intel(urls=[
        {
            "url": "http://198.51.100.12:8080/owa/auth/login.aspx?user=test",
            "flags": {
                "is_ip_host": True,
                "unusual_port": True,
                "has_credential_keywords": True,
                "is_shortened": False,
                "is_punycode": False,
            },
            "port": 8080,
        },
        {
            "url": "https://bit.ly/secure-backup",
            "flags": {
                "is_ip_host": False,
                "unusual_port": False,
                "has_credential_keywords": False,
                "is_shortened": True,
                "is_punycode": False,
            },
            "port": 443,
        }
    ])
    res = calculate_risk(_mock_forensic(), _mock_threat(), intel, {})

    url_factors = [f for f in res["risk_factors"] if f["category"] == "url"]
    assert len(url_factors) >= 3
    assert any("Raw IP Host" in f["factor"] for f in url_factors)
    assert any("Non-Standard URL Port" in f["factor"] for f in url_factors)
    assert any("Credential Harvesting Path" in f["factor"] for f in url_factors)
    assert res["category_scores"]["url"] > 0


def test_13_attachment_threats():
    """Dangerous executable/script extensions and double extensions contribute attachment risk."""
    parsed = {
        "attachments": [
            {"filename": "quarterly_bonus.pdf.exe", "content_type": "application/x-msdownload", "size_bytes": 45000},
            {"filename": "setup_script.vbs", "content_type": "text/vbscript", "size_bytes": 1200},
        ]
    }
    res = calculate_risk(_mock_forensic(), _mock_threat(), _mock_intel(), parsed)

    attach_factors = [f for f in res["risk_factors"] if f["category"] == "attachment"]
    assert len(attach_factors) >= 2
    assert any("Executable / Script Attachment" in f["factor"] for f in attach_factors)
    assert any("Double Extension" in f["factor"] for f in attach_factors)
    assert res["category_scores"]["attachment"] >= 16.0


def test_14_multiple_simultaneous_threats_critical():
    """Multi-vector attack (auth fail + brand spoof + phishing + raw IP URL + dangerous attachment) produces CRITICAL."""
    findings = [
        {"type": "display_name_brand_spoof", "status": "failed", "severity": "high", "description": "Spoofed Brand"},
        {"type": "reply_to_mismatch", "status": "failed", "severity": "medium", "description": "Reply-To Mismatch"},
    ]
    forensic = _mock_forensic(spf_status="fail", dkim_status="fail", dmarc_status="reject", findings=findings)
    threat = _mock_threat(
        primary_threat="PHISHING",
        confidence=0.95,
        signals={"urgency": "detected", "credential_request": "detected", "fear_manipulation": "detected"}
    )
    intel = _mock_intel(urls=[{
        "url": "http://198.51.100.12:8080/login.aspx",
        "flags": {"is_ip_host": True, "unusual_port": True, "has_credential_keywords": True, "is_shortened": False, "is_punycode": False},
        "port": 8080,
    }])
    parsed = {
        "attachments": [{"filename": "invoice_update.pdf.exe", "content_type": "application/octet-stream", "size_bytes": 50000}]
    }

    res = calculate_risk(forensic, threat, intel, parsed)
    assert res["risk_score"] >= 75.0
    assert res["severity"] == SEVERITY_CRITICAL
    assert len(res["top_factors"]) >= 3


def test_15_unknown_authentication_zero_penalty():
    """Unknown or unconfigured authentication contributes 0 risk penalty points."""
    forensic = _mock_forensic(spf_status="unknown", dkim_status="unknown", dmarc_status="unknown")
    res = calculate_risk(forensic, _mock_threat(primary_threat="BENIGN"), _mock_intel(), {})

    assert res["category_scores"]["authentication"] == 0.0
    auth_factors = [f for f in res["risk_factors"] if f["category"] == "authentication"]
    assert len(auth_factors) == 0


def test_16_unavailable_infrastructure_zero_penalty():
    """Unavailable GeoIP or RDAP contributes 0 risk penalty points."""
    intel = {
        "ips": [{"ip": "8.8.8.8", "status": "unavailable", "geo": {"status": "unavailable"}, "asn": {"status": "unknown"}}],
        "domains": [{"domain": "example.com", "status": "unavailable", "rdap": {"status": "unavailable"}}],
        "urls": [],
    }
    res = calculate_risk(_mock_forensic(), _mock_threat(), intel, {})
    assert res["category_scores"]["infrastructure"] == 0.0


def test_17_high_vs_low_confidence_scaling():
    """Higher AI confidence yields higher proportional points for the same primary threat."""
    threat_high = _mock_threat(primary_threat="PHISHING", confidence=0.95)
    threat_low = _mock_threat(primary_threat="PHISHING", confidence=0.55)

    res_high = calculate_risk(_mock_forensic(), threat_high, _mock_intel(), {})
    res_low = calculate_risk(_mock_forensic(), threat_low, _mock_intel(), {})

    assert res_high["category_scores"]["content"] > res_low["category_scores"]["content"]


def test_18_double_counting_protection_category_caps():
    """Excessive duplicate findings within a single category are capped at the category ceiling."""
    findings = [
        {"type": "dmarc_spf_alignment", "status": "failed", "severity": "low", "description": "fail"},
        {"type": "dmarc_dkim_alignment", "status": "failed", "severity": "low", "description": "fail"},
    ]
    # DMARC reject (14) + SPF fail (8) + DKIM fail (8) + alignment (4+4) = 38 raw points
    forensic = _mock_forensic(spf_status="fail", dkim_status="fail", dmarc_status="reject", findings=findings)

    res = calculate_risk(forensic, _mock_threat(), _mock_intel(), {})
    assert res["category_scores"]["authentication"] <= CATEGORY_CAPS["authentication"]
    assert res["category_scores"]["authentication"] == 25.0


def test_19_score_lower_bound_zero():
    """Risk score is strictly clamped to >= 0.0 under heavy benign mitigations."""
    forensic = _mock_forensic(spf_status="pass", dkim_status="pass", dmarc_status="pass")
    threat = _mock_threat(primary_threat="BENIGN", confidence=1.0)
    res = calculate_risk(forensic, threat, _mock_intel(), {})

    assert res["risk_score"] >= 0.0
    assert isinstance(res["risk_score"], (int, float))


def test_20_score_upper_bound_hundred():
    """Risk score is strictly clamped to <= 100.0 even under massive multi-category penalties."""
    findings = [
        {"type": "display_name_brand_spoof", "status": "failed", "severity": "high"},
        {"type": "reply_to_mismatch", "status": "failed", "severity": "medium"},
        {"type": "return_path_mismatch", "status": "failed", "severity": "low"},
        {"type": "missing_message_id", "status": "failed", "severity": "low"},
        {"type": "duplicate_headers", "status": "failed", "severity": "low"},
        {"type": "future_timestamp", "status": "failed", "severity": "medium"},
        {"type": "relay_chronology", "status": "failed", "severity": "medium"},
    ]
    forensic = _mock_forensic(spf_status="fail", dkim_status="fail", dmarc_status="reject", findings=findings)
    threat = _mock_threat(
        primary_threat="CREDENTIAL_HARVESTING",
        confidence=1.0,
        signals={
            "urgency": "detected",
            "credential_request": "detected",
            "financial_request": "detected",
            "impersonation": "detected",
            "fear_manipulation": "detected",
            "authority_pressure": "detected",
        }
    )
    intel = _mock_intel(urls=[
        {
            "url": "http://198.51.100.12:8080/login.aspx",
            "flags": {"is_ip_host": True, "unusual_port": True, "has_credential_keywords": True, "is_shortened": True, "is_punycode": True},
            "port": 8080,
        }
    ])
    parsed = {
        "attachments": [
            {"filename": "payload.exe", "content_type": "application/octet-stream", "size_bytes": 10000},
            {"filename": "report.pdf.vbs", "content_type": "text/vbscript", "size_bytes": 5000},
        ]
    }

    res = calculate_risk(forensic, threat, intel, parsed)
    assert res["risk_score"] <= 100.0
    assert res["risk_score"] == 100.0
    assert res["severity"] == SEVERITY_CRITICAL


def test_21_severity_boundary_thresholds():
    """Verify get_severity_label boundary points."""
    assert get_severity_label(0.0) == SEVERITY_LOW
    assert get_severity_label(24.0) == SEVERITY_LOW
    assert get_severity_label(24.9) == SEVERITY_MEDIUM
    assert get_severity_label(25.0) == SEVERITY_MEDIUM
    assert get_severity_label(49.0) == SEVERITY_MEDIUM
    assert get_severity_label(49.9) == SEVERITY_HIGH
    assert get_severity_label(50.0) == SEVERITY_HIGH
    assert get_severity_label(74.0) == SEVERITY_HIGH
    assert get_severity_label(74.9) == SEVERITY_CRITICAL
    assert get_severity_label(75.0) == SEVERITY_CRITICAL
    assert get_severity_label(100.0) == SEVERITY_CRITICAL


def test_22_evidence_traceability():
    """Every generated risk factor contains factor, category, points, severity, evidence, and source."""
    forensic = _mock_forensic(spf_status="fail", dkim_status="fail", dmarc_status="reject")
    threat = _mock_threat(primary_threat="PHISHING", confidence=0.90, signals={"urgency": "detected"})
    res = calculate_risk(forensic, threat, _mock_intel(), {})

    assert len(res["risk_factors"]) > 0
    for factor in res["risk_factors"]:
        assert isinstance(factor["factor"], str) and len(factor["factor"]) > 0
        assert factor["category"] in CATEGORY_CAPS
        assert isinstance(factor["points"], (int, float)) and factor["points"] > 0
        assert factor["severity"] in ("low", "medium", "high", "critical")
        assert isinstance(factor["evidence"], str) and len(factor["evidence"]) > 0
        assert factor["source"] in ("step3_forensics", "step4_ai", "step5_infrastructure", "step2_extraction")


def test_23_deterministic_repeated_scoring():
    """The risk engine produces exact identical results across repeated invocations."""
    forensic = _mock_forensic(spf_status="fail", dkim_status="pass", dmarc_status="softfail")
    threat = _mock_threat(primary_threat="BEC", confidence=0.88, signals={"financial_request": "detected"})
    intel = _mock_intel(urls=[{"url": "https://bit.ly/test", "flags": {"is_shortened": True}}])

    run1 = calculate_risk(forensic, threat, intel, {})
    run2 = calculate_risk(forensic, threat, intel, {})
    run3 = calculate_risk(forensic, threat, intel, {})

    assert run1["risk_score"] == run2["risk_score"] == run3["risk_score"]
    assert run1["severity"] == run2["severity"] == run3["severity"]
    assert run1["category_scores"] == run2["category_scores"] == run3["category_scores"]
    assert run1["explanation"] == run2["explanation"] == run3["explanation"]
    assert len(run1["risk_factors"]) == len(run2["risk_factors"]) == len(run3["risk_factors"])


def test_24_empty_malformed_input_resilience():
    """Risk engine handles None, empty dicts, or unexpected types without crashing."""
    res_none = calculate_risk(None, None, None, None)
    assert res_none["risk_score"] == 0.0
    assert res_none["severity"] == SEVERITY_LOW
    assert isinstance(res_none["risk_factors"], list)
    assert isinstance(res_none["category_scores"], dict)

    res_empty = calculate_risk({}, {}, {}, {})
    assert res_empty["risk_score"] == 0.0
    assert res_empty["severity"] == SEVERITY_LOW
