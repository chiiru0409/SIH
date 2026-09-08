"""
tests/test_forensics.py — Comprehensive unit & integration tests for MAILTRACE Step 3.

Covers all 20 required forensic fixture scenarios and deep forensic validation:
  1. SPF PASS + aligned
  2. SPF FAIL + misaligned
  3. DKIM PASS + verified
  4. DKIM FAIL
  5. DMARC PASS
  6. DMARC FAIL
  7. From / Reply-To mismatch
  8. From / Return-Path mismatch
  9. DKIM / From domain mismatch
  10. Message-ID domain mismatch
  11. Missing authentication headers (produces UNKNOWN, not false FAIL)
  12. Multiple Received hops (chronological sequence)
  13. Private/internal IP in Received chain
  14. Malformed Received header
  15. Future timestamp (>24h)
  16. Chronological timestamp anomaly in Received chain
  17. Missing Message-ID
  18. Missing Date
  19. Normal clean email
  20. Malformed email / edge cases
  21. Duplicate single-instance headers (RFC-5322 violation)
  22. Display name spoofing (VIP impersonation)
  23. Fact vs Inference separation
  24. Full forensic pipeline & API integration
"""

from __future__ import annotations

import email.message
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.services.email_parser import parse_email
from backend.services.forensics import (
    analyze_authentication,
    analyze_identity_consistency,
    analyze_received_chain,
    analyze_headers,
    analyze_timestamps,
    run_forensic_analysis,
    is_domain_aligned,
    _get_base_domain,
)


# ================================================================== #
#  Synthetic EML Builders                                             #
# ================================================================== #

def _build_eml(
    headers: dict[str, str | list[str]] | list[tuple[str, str]],
    body: str = "This is a test email body.",
) -> bytes:
    """Helper to synthesize an RFC-5322 byte payload."""
    lines = []
    if isinstance(headers, dict):
        for k, v in headers.items():
            if isinstance(v, list):
                for item in v:
                    lines.append(f"{k}: {item}")
            else:
                lines.append(f"{k}: {v}")
    else:
        for k, v in headers:
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8")


# ================================================================== #
#  1. Alignment Helpers Tests                                         #
# ================================================================== #

class TestDomainAlignmentHelpers:
    def test_base_domain_simple(self):
        assert _get_base_domain("example.com") == "example.com"
        assert _get_base_domain("mail.example.com") == "example.com"
        assert _get_base_domain("a.b.c.example.com") == "example.com"

    def test_base_domain_two_level_tld(self):
        assert _get_base_domain("corp.example.co.uk") == "example.co.uk"
        assert _get_base_domain("mail.service.gov.in") == "service.gov.in"
        assert _get_base_domain("sub.bank.com.au") == "bank.com.au"

    def test_domain_aligned_strict(self):
        assert is_domain_aligned("example.com", "example.com", strict=True) is True
        assert is_domain_aligned("mail.example.com", "example.com", strict=True) is False

    def test_domain_aligned_relaxed(self):
        assert is_domain_aligned("mail.example.com", "example.com", strict=False) is True
        assert is_domain_aligned("auth.example.com", "smtp.example.com", strict=False) is True
        assert is_domain_aligned("attacker.com", "paypal.com", strict=False) is False
        assert is_domain_aligned(None, "paypal.com") is False
        assert is_domain_aligned("paypal.com", None) is False


# ================================================================== #
#  2. Authentication Tests (Scenarios 1-6 & 11)                       #
# ================================================================== #

class TestAuthenticationForensics:
    def test_scenario_1_spf_pass_aligned(self):
        raw = _build_eml({
            "From": "Security <security@company.com>",
            "Return-Path": "<bounces@company.com>",
            "Received-SPF": "pass (mail.company.com: domain of bounces@company.com designates 198.51.100.1 as permitted sender)",
            "Authentication-Results": "mx.google.com; spf=pass (google.com: domain of bounces@company.com designates 198.51.100.1 as permitted sender)",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["spf_status"] == "pass"
        assert summary["spf_aligned"] is True
        spf_findings = [f for f in findings if f["type"] == "spf_status"]
        assert len(spf_findings) == 1
        assert spf_findings[0]["status"] == "passed"
        assert spf_findings[0]["fact"] is True

    def test_scenario_2_spf_fail_misaligned(self):
        raw = _build_eml({
            "From": "Support <support@paypal.com>",
            "Return-Path": "<attacker@evil.com>",
            "Received-SPF": "fail (domain of attacker@evil.com does not designate 203.0.113.50 as permitted sender)",
            "Authentication-Results": "mx.google.com; spf=fail (google.com: domain of attacker@evil.com does not designate 203.0.113.50 as permitted sender)",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["spf_status"] == "fail"
        assert summary["spf_aligned"] is False
        spf_fail_fact = [f for f in findings if f["type"] == "spf_status" and f["fact"] is True]
        assert len(spf_fail_fact) == 1
        assert spf_fail_fact[0]["status"] == "failed"
        
        spf_fail_inference = [f for f in findings if f["type"] == "spf_fail_inference"]
        assert len(spf_fail_inference) == 1
        assert spf_fail_inference[0]["fact"] is False

    def test_scenario_3_dkim_pass(self):
        raw = _build_eml({
            "From": "Billing <billing@stripe.com>",
            "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=stripe.com; s=s1; t=1600000000; bh=abc=; b=xyz=",
            "Authentication-Results": "mx.google.com; dkim=pass header.i=@stripe.com header.s=s1 header.b=xyz;",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["dkim_status"] == "pass"
        assert summary["dkim_aligned"] is True
        dkim_pass_fact = [f for f in findings if f["type"] == "dkim_status" and f["status"] == "passed"]
        assert len(dkim_pass_fact) == 1
        assert dkim_pass_fact[0]["fact"] is True

    def test_scenario_4_dkim_fail(self):
        raw = _build_eml({
            "From": "Bank <alerts@bank.com>",
            "DKIM-Signature": "v=1; a=rsa-sha256; d=bank.com; s=k1; b=badsignature",
            "Authentication-Results": "mx.google.com; dkim=fail (bad signature) header.d=bank.com;",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["dkim_status"] == "fail"
        assert summary["dkim_aligned"] is False
        dkim_fail = [f for f in findings if f["type"] == "dkim_status"]
        assert len(dkim_fail) == 1
        assert dkim_fail[0]["status"] == "failed"
        
        dkim_inference = [f for f in findings if f["type"] == "dkim_fail_inference"]
        assert len(dkim_inference) == 1
        assert dkim_inference[0]["fact"] is False

    def test_scenario_5_dmarc_pass(self):
        raw = _build_eml({
            "From": "News <news@github.com>",
            "Authentication-Results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass (p=REJECT sp=REJECT) header.from=github.com",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["dmarc_status"] == "pass"
        assert summary["dmarc_aligned"] is True
        dmarc_pass = [f for f in findings if f["type"] == "dmarc_status" and f["status"] == "passed"]
        assert len(dmarc_pass) == 1

    def test_scenario_6_dmarc_fail(self):
        raw = _build_eml({
            "From": "Spoofed <admin@microsoft.com>",
            "Authentication-Results": "mx.google.com; spf=fail; dkim=none; dmarc=fail (p=REJECT) header.from=microsoft.com",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["dmarc_status"] == "fail"
        assert summary["dmarc_aligned"] is False
        dmarc_fail = [f for f in findings if f["type"] == "dmarc_status" and f["status"] == "failed"]
        assert len(dmarc_fail) == 1
        
        dmarc_infer = [f for f in findings if f["type"] == "dmarc_fail_inference"]
        assert len(dmarc_infer) == 1
        assert dmarc_infer[0]["fact"] is False

    def test_scenario_11_missing_auth_headers_produces_unknown(self):
        raw = _build_eml({
            "From": "User <user@example.com>",
            "To": "Friend <friend@example.org>",
            "Subject": "Hello",
            "Date": "Mon, 01 Jan 2024 10:00:00 +0000",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_authentication(parsed)
        
        assert summary["spf_status"] == "unknown"
        assert summary["dkim_status"] == "unknown"
        assert summary["dmarc_status"] == "unknown"
        
        # Verify that all 3 are recorded as status='unknown' and fact=True without fabricating failures
        unknown_findings = [f for f in findings if f["status"] == "unknown"]
        assert len(unknown_findings) >= 3
        for uf in unknown_findings:
            assert uf["severity"] == "info"
            assert uf["fact"] is True


# ================================================================== #
#  3. Identity Consistency Tests (Scenarios 7, 8, 9, 22)              #
# ================================================================== #

class TestIdentityConsistency:
    def test_scenario_7_reply_to_mismatch(self):
        raw = _build_eml({
            "From": "Help Desk <support@mybank.com>",
            "Reply-To": "Harvest <collector@phish-redirect.com>",
            "Subject": "Account Update",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_identity_consistency(parsed)
        
        assert summary["reply_to_mismatch"] is True
        mismatch_fact = [f for f in findings if f["type"] == "reply_to_mismatch"]
        assert len(mismatch_fact) == 1
        assert mismatch_fact[0]["fact"] is True
        assert mismatch_fact[0]["severity"] == "medium"
        
        mismatch_infer = [f for f in findings if f["type"] == "reply_to_mismatch_inference"]
        assert len(mismatch_infer) == 1
        assert mismatch_infer[0]["fact"] is False

    def test_scenario_8_return_path_mismatch(self):
        raw = _build_eml({
            "From": "CEO <ceo@company.com>",
            "Return-Path": "<bounce@external-relay.net>",
            "Subject": "Urgent wire",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_identity_consistency(parsed)
        
        assert summary["return_path_mismatch"] is True
        rp_fact = [f for f in findings if f["type"] == "return_path_mismatch"]
        assert len(rp_fact) == 1
        assert rp_fact[0]["fact"] is True

    def test_scenario_9_dkim_domain_mismatch(self):
        raw = _build_eml({
            "From": "Notifications <alerts@bank.com>",
            "Authentication-Results": "mx.google.com; dkim=pass header.d=bulkmailer365.net header.s=s1;",
            "DKIM-Signature": "v=1; a=rsa-sha256; d=bulkmailer365.net; s=s1; b=abc=",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_identity_consistency(parsed)
        
        dkim_mismatch = [f for f in findings if f["type"] == "dkim_domain_mismatch"]
        assert len(dkim_mismatch) == 1
        assert dkim_mismatch[0]["fact"] is True
        assert "bulkmailer365.net" in dkim_mismatch[0]["description"]

    def test_scenario_22_display_name_spoofing(self):
        raw = _build_eml({
            "From": '"CEO Tim <tim.cook@apple.com>" <fraudster99@disposable.org>',
            "Subject": "Urgent Request",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_identity_consistency(parsed)
        
        assert summary["display_name_spoof_suspected"] is True
        spoof_fact = [f for f in findings if f["type"] == "display_name_spoof"]
        assert len(spoof_fact) == 1
        assert spoof_fact[0]["severity"] == "high"
        assert spoof_fact[0]["fact"] is True
        
        spoof_infer = [f for f in findings if f["type"] == "display_name_spoof_inference"]
        assert len(spoof_infer) == 1
        assert spoof_infer[0]["fact"] is False


# ================================================================== #
#  4. Received Chain Tests (Scenarios 12, 13, 14, 16)                 #
# ================================================================== #

class TestReceivedChainForensics:
    def test_scenario_12_multiple_received_hops_chronological(self):
        raw = _build_eml([
            ("From", "alice@sender.org"),
            ("Received", "from mail.destination.com (mail.destination.com [93.184.216.20]) by mx.google.com with ESMTP id abc; Mon, 01 Jan 2024 10:02:00 +0000"),
            ("Received", "from relay.intermediate.net (relay.intermediate.net [93.184.216.10]) by mail.destination.com with ESMTP id def; Mon, 01 Jan 2024 10:01:00 +0000"),
            ("Received", "from mail.sender.org (mail.sender.org [93.184.216.5]) by relay.intermediate.net with ESMTP id ghi; Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Subject", "Multi-hop relay"),
        ])
        parsed = parse_email(raw)
        findings, summary = analyze_received_chain(parsed)
        
        assert summary["hop_count"] == 3
        assert len(summary["public_ips"]) >= 1
        assert summary["earliest_observed_infrastructure"]["ip"] == "93.184.216.5"
        
        # Chronology should be clean (no inconsistency finding)
        chrono_findings = [f for f in findings if f["type"] == "hop_timestamp_inconsistency"]
        assert len(chrono_findings) == 0

    def test_scenario_13_private_internal_ip_exposure(self):
        raw = _build_eml([
            ("From", "staff@internal.corp"),
            ("Received", "from edge.corp.com (edge.corp.com [93.184.216.25]) by mx.destination.com; Mon, 01 Jan 2024 10:01:00 +0000"),
            ("Received", "from workstation.corp.local (workstation [10.0.4.15]) by edge.corp.com; Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Subject", "Internal IP check"),
        ])
        parsed = parse_email(raw)
        findings, summary = analyze_received_chain(parsed)
        
        assert "10.0.4.15" in summary["internal_ips"]
        internal_findings = [f for f in findings if f["type"] == "internal_ip_exposure"]
        assert len(internal_findings) == 1
        assert internal_findings[0]["fact"] is True

    def test_scenario_14_malformed_received_header(self):
        raw = _build_eml([
            ("From", "sender@test.com"),
            ("Received", "corrupted garbage received header with no tokens"),
            ("Received", "from mail.example.com [93.184.216.1] by mx.test.com; Mon, 01 Jan 2024 10:00:00 +0000"),
            ("Subject", "Malformed header test"),
        ])
        parsed = parse_email(raw)
        findings, summary = analyze_received_chain(parsed)
        
        malformed_findings = [f for f in findings if f["type"] == "malformed_received_header"]
        assert len(malformed_findings) == 1
        assert malformed_findings[0]["fact"] is True

    def test_scenario_16_chronological_timestamp_anomaly(self):
        raw = _build_eml([
            ("From", "sender@test.com"),
            # Newest header recorded at 09:00:00
            ("Received", "from relay.second.com (relay [93.184.216.2]) by mx.dest.com; Mon, 01 Jan 2024 09:00:00 +0000"),
            # Older hop claimed 12:00:00 (3 hours in the future)
            ("Received", "from relay.first.com (relay [93.184.216.1]) by relay.second.com; Mon, 01 Jan 2024 12:00:00 +0000"),
            ("Subject", "Timestamp anomaly"),
        ])
        parsed = parse_email(raw)
        findings, summary = analyze_received_chain(parsed)
        
        chrono_findings = [f for f in findings if f["type"] == "hop_timestamp_inconsistency"]
        assert len(chrono_findings) == 1
        assert chrono_findings[0]["fact"] is True


# ================================================================== #
#  5. Header Anomaly & Message-ID Tests (Scenarios 10, 17, 21)        #
# ================================================================== #

class TestHeaderAndMessageIdForensics:
    def test_scenario_10_message_id_domain_mismatch(self):
        raw = _build_eml({
            "From": "Accounts <accounts@chase.com>",
            "Message-ID": "<abc123xyz@newsletter-blaster.org>",
            "Subject": "Statement",
            "Date": "Mon, 01 Jan 2024 10:00:00 +0000",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_headers(parsed)
        
        assert summary["message_id_domain"] == "newsletter-blaster.org"
        mismatch_findings = [f for f in findings if f["type"] == "message_id_domain_mismatch"]
        assert len(mismatch_findings) == 1
        assert mismatch_findings[0]["fact"] is True

    def test_scenario_17_missing_message_id(self):
        raw = _build_eml({
            "From": "sender@example.com",
            "Subject": "No Message-ID",
            "Date": "Mon, 01 Jan 2024 10:00:00 +0000",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_headers(parsed)
        
        missing_findings = [f for f in findings if f["type"] == "missing_message_id"]
        assert len(missing_findings) == 1
        assert missing_findings[0]["status"] == "info"
        assert missing_findings[0]["severity"] == "low"

    def test_scenario_21_duplicate_single_instance_headers(self):
        raw = _build_eml([
            ("From", "Attacker <attacker@evil.com>"),
            ("From", "Victim <victim@trusted.com>"),
            ("Subject", "First Subject"),
            ("Subject", "Second Subject"),
            ("Date", "Mon, 01 Jan 2024 10:00:00 +0000"),
        ])
        parsed = parse_email(raw)
        findings, summary = analyze_headers(parsed)
        
        assert "From" in summary["duplicate_headers"] or "Subject" in summary["duplicate_headers"]
        dup_findings = [f for f in findings if f["type"] == "duplicate_header"]
        assert len(dup_findings) >= 1
        for df in dup_findings:
            assert df["severity"] == "high"
            assert df["status"] == "failed"
            assert df["fact"] is True


# ================================================================== #
#  6. Date & Timestamp Tests (Scenarios 15, 18)                       #
# ================================================================== #

class TestDateTimestampForensics:
    def test_scenario_15_future_timestamp(self):
        # 30 days in the future
        future_dt = datetime.now(timezone.utc) + timedelta(days=30)
        future_str = future_dt.strftime("%a, %d %b %Y %H:%M:%S +0000")
        
        raw = _build_eml({
            "From": "spammer@spam.org",
            "Date": future_str,
            "Subject": "Future spam",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_timestamps(parsed)
        
        assert summary["is_future_dated"] is True
        future_facts = [f for f in findings if f["type"] == "future_dated_email"]
        assert len(future_facts) == 1
        assert future_facts[0]["fact"] is True
        assert future_facts[0]["severity"] == "high"
        
        future_infer = [f for f in findings if f["type"] == "future_date_inference"]
        assert len(future_infer) == 1
        assert future_infer[0]["fact"] is False

    def test_scenario_18_missing_date(self):
        raw = _build_eml({
            "From": "sender@test.com",
            "Subject": "No date header",
        })
        parsed = parse_email(raw)
        findings, summary = analyze_timestamps(parsed)
        
        missing_date = [f for f in findings if f["type"] == "missing_date_header"]
        assert len(missing_date) == 1
        assert missing_date[0]["fact"] is True


# ================================================================== #
#  7. Clean & Malformed End-to-End Tests (Scenarios 19, 20, 23)        #
# ================================================================== #

class TestMasterForensicAnalysis:
    def test_scenario_19_normal_clean_email(self):
        raw = _build_eml({
            "From": "Alice Smith <alice@example.com>",
            "To": "Bob Jones <bob@example.org>",
            "Subject": "Quarterly Report",
            "Date": "Mon, 15 Jan 2024 14:30:00 +0000",
            "Message-ID": "<msg_20240115@example.com>",
            "Return-Path": "<alice@example.com>",
            "Received-SPF": "pass (mail.example.com: domain of alice@example.com designates 93.184.216.34 as permitted sender)",
            "Authentication-Results": "mx.example.org; spf=pass; dkim=pass header.i=@example.com; dmarc=pass header.from=example.com",
            "DKIM-Signature": "v=1; a=rsa-sha256; d=example.com; s=s2024; b=valid==",
            "Received": [
                "from mx.example.org (mx.example.org [93.184.216.35]) by destination.org; Mon, 15 Jan 2024 14:31:00 +0000",
                "from mail.example.com (mail.example.com [93.184.216.34]) by mx.example.org; Mon, 15 Jan 2024 14:30:10 +0000",
            ],
        })
        parsed = parse_email(raw)
        forensic_data = run_forensic_analysis(parsed, raw)
        
        summary = forensic_data["summary"]
        assert summary["status"] == "completed"
        assert summary["failed_count"] == 0
        assert summary["high_risk_findings_count"] == 0
        assert summary["authentication"]["overall_alignment"] is True
        assert len(forensic_data["limitations"]) >= 4

    def test_scenario_20_malformed_email_handling(self):
        # Extremely truncated/malformed bytes
        raw = b"Invalid Garbage :::: None \n\n Empty MIME payload"
        parsed = parse_email(raw)
        forensic_data = run_forensic_analysis(parsed, raw)
        
        assert forensic_data["summary"]["status"] == "completed"
        assert isinstance(forensic_data["findings"], list)
        assert isinstance(forensic_data["facts"], list)
        assert isinstance(forensic_data["inferences"], list)

    def test_scenario_23_fact_vs_inference_strict_separation(self):
        raw = _build_eml({
            "From": '"PayPal Support <service@paypal.com>" <phisher@evil-domain.com>',
            "Reply-To": "collector@harvest-creds.com",
            "Subject": "Account Suspended",
            "Date": "Mon, 01 Jan 2024 10:00:00 +0000",
            "Authentication-Results": "mx.google.com; spf=fail; dmarc=fail (p=reject) header.from=evil-domain.com",
        })
        parsed = parse_email(raw)
        forensic_data = run_forensic_analysis(parsed, raw)
        
        facts = forensic_data["facts"]
        inferences = forensic_data["inferences"]
        
        # All items in facts must have fact == True and no inference_note required
        for fact in facts:
            assert fact["fact"] is True
            assert fact["inference_note"] is None
            
        # All items in inferences must have fact == False and contain an inference_note
        for infer in inferences:
            assert infer["fact"] is False
            assert infer["inference_note"] is not None
            assert len(infer["inference_note"]) > 5


# ================================================================== #
#  8. API Integration Tests                                           #
# ================================================================== #

class TestApiIntegration:
    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_upload_returns_forensic_analysis(self, client):
        eml_bytes = _build_eml({
            "From": "Support <support@legit.com>",
            "Subject": "API Test",
            "Date": "Mon, 01 Jan 2024 10:00:00 +0000",
            "Message-ID": "<api_test_123@legit.com>",
        })
        
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("test_upload.eml", eml_bytes, "message/rfc822")},
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify Step 2 keys still exist
        assert "case_id" in data
        assert "status" in data
        assert "email" in data
        assert "authentication" in data
        assert "smtp_trace" in data
        assert "indicators" in data
        assert "evidence" in data
        
        # Verify Step 3 forensic findings are integrated
        assert "forensic_analysis" in data
        forensic = data["forensic_analysis"]
        assert "summary" in forensic
        assert "findings" in forensic
        assert "facts" in forensic
        assert "inferences" in forensic
        assert "limitations" in forensic
        assert forensic["summary"]["findings_count"] == len(forensic["findings"])
        
        # Verify GET /api/analyze/{case_id} retrieves full persisted case
        case_id = data["case_id"]
        get_resp = client.get(f"/api/analyze/{case_id}")
        assert get_resp.status_code == 200
        detail = get_resp.json()
        assert detail["case_id"] == case_id
        assert detail["forensic_analysis"] is not None
        assert detail["forensic_analysis"]["summary"]["status"] == "completed"
