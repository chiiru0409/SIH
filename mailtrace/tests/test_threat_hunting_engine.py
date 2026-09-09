"""
tests/test_threat_hunting_engine.py — Test Suite for Threat Hunting, Funnel of Fidelity & Detection Engineering.
"""

import pytest
from backend.services.threat_analyzer import (
    analyze_threat,
    detect_saas_abuse,
    evaluate_compound_rules,
    map_mitre_attack,
    build_funnel_of_fidelity,
)
from backend.services.correlation import (
    execute_threat_hunt,
    export_case_iocs,
    build_campaign_correlation,
)
from backend.services.policy_engine import generate_incident_playbook


def test_funnel_of_fidelity_structure():
    """Verify that the Funnel of Fidelity produces a clean 4-tier distillation."""
    mock_parsed = {
        "sender": {"email": "attacker@evil-domain.com", "display_name": "CEO John Doe"},
        "from_address": "CEO John Doe <attacker@evil-domain.com>",
        "headers": {"subject": "Urgent Wire Transfer Request"},
        "authentication": {
            "spf": {"status": "fail"},
            "dkim": {"status": "fail"},
            "dmarc": {"status": "fail"},
        },
        "urls": [{"url": "https://docs.google.com/forms/d/e/sample/viewform"}],
        "ip_addresses": [{"ip": "185.220.101.5"}],
    }

    mock_forensics = {
        "facts": ["DKIM signature failed validation", "SPF record returned hardfail"],
        "inferences": ["Possible VIP display name spoofing"],
        "findings": [
            {"category": "authentication", "type": "dmarc", "status": "failed", "title": "DMARC Failure", "severity": "HIGH"},
            {"category": "identity", "type": "display_name_spoofing", "status": "failed", "title": "Display-Name Impersonation", "severity": "HIGH"},
        ],
    }

    result = analyze_threat(mock_parsed, mock_forensics)

    assert "funnel_of_fidelity" in result
    funnel = result["funnel_of_fidelity"]

    assert "tier_1_observed_facts" in funnel
    assert "tier_2_behavioral_signals" in funnel
    assert "tier_3_compound_detections" in funnel
    assert "tier_4_actionable_verdict" in funnel

    # Tier 1 should contain technical facts
    assert len(funnel["tier_1_observed_facts"]) >= 1
    # Tier 4 should contain confidence and verdict
    assert funnel["tier_4_actionable_verdict"]["confidence"] >= 0.70
    assert "verdict" in funnel["tier_4_actionable_verdict"]


def test_saas_cloud_abuse_detection():
    """Verify detection of Living-off-Legitimate-Services (Google Forms, Canva, Notion)."""
    urls_google = [{"url": "https://docs.google.com/forms/d/e/1FAIpQLSc/viewform"}]
    abuse = detect_saas_abuse(urls_google, "Please submit your password here")
    assert len(abuse) > 0
    assert any("Google" in a["platform"] for a in abuse)

    urls_canva = [{"url": "https://www.canva.com/design/DAFxxx/view"}]
    abuse_canva = detect_saas_abuse(urls_canva, "View your secure invoice")
    assert len(abuse_canva) > 0
    assert any("Canva" in a["platform"] for a in abuse_canva)

    urls_clean = [{"url": "https://internal.company.com/portal"}]
    abuse_clean = detect_saas_abuse(urls_clean, "General update")
    assert len(abuse_clean) == 0


def test_compound_rules_matrix():
    """Verify multi-signal compounding rules eliminate single-signal false alarms."""
    # Scenario: VIP spoof + External freemail + Financial demand
    signals_high_risk = {
        "impersonation": "high",
        "financial_request": "high",
        "urgency": "high",
    }
    parsed_vip = {
        "sender": {"email": "ceo.urgent@gmail.com", "display_name": "CEO John Doe", "domain": "gmail.com"}
    }
    rules = evaluate_compound_rules(
        signals_map=signals_high_risk,
        indicators=[],
        parsed_email=parsed_vip,
        forensic_analysis=None,
        saas_abuse=[],
    )
    rule_ids = [r["rule_id"] for r in rules]
    assert "CR-001" in rule_ids  # VIP_IMPERSONATION_WITH_FREEMAIL

    # Scenario: Low risk email with benign signals
    signals_benign = {
        "impersonation": "none",
        "financial_request": "none",
        "urgency": "low",
    }
    parsed_clean = {
        "sender": {"email": "newsletter@acme.com", "display_name": "Acme News", "domain": "acme.com"}
    }
    rules_benign = evaluate_compound_rules(
        signals_map=signals_benign,
        indicators=[],
        parsed_email=parsed_clean,
        forensic_analysis=None,
        saas_abuse=[],
    )
    assert len(rules_benign) == 0


def test_mitre_attack_mapping():
    """Verify MITRE ATT&CK enterprise email mapping."""
    mitre = map_mitre_attack(
        primary_threat="CREDENTIAL_HARVESTING",
        signals_map={"credential_request": "high", "impersonation": "high"},
        indicators=[{"category": "link", "indicator": "call_to_action_link"}],
        compound_rules=[{"mitre_technique": "T1566.002"}],
        saas_abuse=[{"platform": "Google Docs / Forms"}],
    )
    assert len(mitre) >= 2
    technique_ids = [m["technique_id"] for m in mitre]
    assert "T1566.002" in technique_ids  # Spearphishing Link


def test_hypothesis_driven_threat_hunt():
    """Verify threat hunt engine executes hypotheses across multiple cases."""
    mock_cases = [
        {
            "id": "case-001",
            "original_filename": "phish1.eml",
            "risk_score": 85.0,
            "risk_label": "CRITICAL",
            "parsed_email": {
                "sender": {"email": "attacker1@evil.com", "display_name": "Support"},
                "ip_addresses": [{"ip": "185.220.101.5"}],
                "urls": [{"url": "https://evil.com/login"}],
            },
            "ai_analysis": {
                "primary_intent": "CREDENTIAL_HARVESTING",
                "saas_abuse": [],
                "compound_rules": [],
            },
            "forensic_analysis": {
                "findings": [{"category": "CREDENTIAL", "title": "Credential Harvesting", "severity": "CRITICAL"}],
            },
        },
        {
            "id": "case-002",
            "original_filename": "phish2.eml",
            "risk_score": 90.0,
            "risk_label": "CRITICAL",
            "parsed_email": {
                "sender": {"email": "attacker2@another-domain.com", "display_name": "Helpdesk"},
                "ip_addresses": [{"ip": "185.220.101.5"}],  # Shared public IP!
                "urls": [{"url": "https://evil.com/login"}],
            },
            "ai_analysis": {
                "primary_intent": "CREDENTIAL_HARVESTING",
                "saas_abuse": [],
                "compound_rules": [],
            },
            "forensic_analysis": {
                "findings": [{"category": "CREDENTIAL", "title": "Credential Harvesting", "severity": "CRITICAL"}],
            },
        },
    ]

    hunt_res = execute_threat_hunt(mock_cases, hypothesis_type="ALL")
    assert hunt_res["status"] == "COMPLETED"
    assert hunt_res["total_cases_analyzed"] == 2

    # Check that SHARED_INFRASTRUCTURE caught the shared IP 185.220.101.5
    shared_infra = next((r for r in hunt_res["results"] if r["hypothesis_id"] == "SHARED_INFRASTRUCTURE"), None)
    assert shared_infra is not None
    assert shared_infra["total_matches"] == 2
    assert any("185.220.101.5" in str(ind) for ind in shared_infra["matched_indicators"])

    # Check that CREDENTIAL_CAMPAIGNS caught both cases
    cred_hunt = next((r for r in hunt_res["results"] if r["hypothesis_id"] == "CREDENTIAL_CAMPAIGNS"), None)
    assert cred_hunt is not None
    assert cred_hunt["total_matches"] == 2


def test_ioc_export_capabilities():
    """Verify structured IoC exporter generates JSON, CSV, and STIX patterns."""
    mock_case = {
        "id": "case-ioc-123",
        "original_filename": "threat.eml",
        "risk_label": "HIGH",
        "parsed_email": {
            "sender": {"email": "malicious@badactor.xyz"},
            "domains": ["badactor.xyz"],
            "ip_addresses": [{"ip": "185.220.101.5"}],
            "urls": [{"url": "https://badactor.xyz/harvest"}],
            "attachments": [{"filename": "invoice.pdf.exe", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
        },
    }

    ioc_export = export_case_iocs(mock_case)
    assert ioc_export["case_id"] == "case-ioc-123"
    assert ioc_export["total_iocs"] >= 4

    # CSV validation
    csv_text = ioc_export["csv_export"]
    assert "Type,Value,Context,Confidence,MITRE_Tactic,Case_ID" in csv_text
    assert "185.220.101.5" in csv_text
    assert "badactor.xyz" in csv_text

    # STIX Pattern validation
    stix_list = ioc_export["stix_patterns"]
    assert any("[ipv4-addr:value = '185.220.101.5']" in s for s in stix_list)
    assert any("[domain-name:value = 'badactor.xyz']" in s for s in stix_list)


def test_incident_playbook_generation():
    """Verify generation of Palantir ADS-aligned SOC incident playbooks."""
    playbook = generate_incident_playbook(
        case_id="case-999",
        threat_intent="CREDENTIAL_HARVESTING",
        risk_score=95.0,
        sender_email="phisher@external.com",
        sender_domain="external.com",
        has_auth_fail=True,
        has_display_spoof=True,
        saas_abuse={"detected": True, "services": ["Google Docs/Forms"]},
    )

    assert "phases" in playbook
    phases = playbook["phases"]
    assert "phase1_containment" in phases
    assert "phase2_preservation" in phases
    assert "phase3_hunting" in phases
    assert "phase4_eradication" in phases

    # Verify actions contain high severity containment
    containment = phases["phase1_containment"]["actions"]
    assert any("quarantine" in a.lower() for a in containment)
    assert any("defang" in a.lower() for a in containment)

    # Verify LOLServices note was added
    hunting = phases["phase3_hunting"]["actions"]
    assert any("Living-off-Legitimate-Services" in a for a in hunting)
