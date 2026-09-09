"""
tests/test_enterprise_ecosystem.py — Test suite for Sentaro, GreatHorn, and Mimecast enterprise capabilities.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app
from backend.services.behavioral_graph import evaluate_behavioral_relationship
from backend.services.policy_engine import (
    evaluate_policies,
    get_quarantine_vault,
    remediate_quarantine,
    get_blocklist,
    add_blocklist_entry,
    get_active_policies,
)
from backend.services.tenant_connector import get_tenants, get_live_tenant_stream
from backend.services.compliance import get_compliance_scorecard


class TestBehavioralGraphAndWarningBanners:
    """Tests for GreatHorn-style relationship scoring and dynamic warning banners."""

    def test_executive_impersonation_generates_critical_banner(self):
        result = evaluate_behavioral_relationship(
            sender_email="attacker@freemail.com",
            sender_display="Satya Nadella",
            sender_domain="freemail.com",
            recipients=["cfo@company.com"],
            risk_score=90.0,
            forensic_findings=[
                {"category": "IDENTITY", "title": "Display-Name Spoofing", "severity": "CRITICAL"}
            ],
            threat_classification={"primary_intent": "BEC / Wire Fraud", "tactics": ["WIRE_TRANSFER", "URGENCY"]},
        )
        assert result["relationship_tier"] == "IMPERSONATION_ANOMALY"
        assert result["warning_banner"]["severity"] == "CRITICAL"
        assert "SUSPECTED EXECUTIVE IMPERSONATION" in result["warning_banner"]["title"]
        assert "IMPERSONATION" in result["warning_banner"]["tags"]
        assert "<div style=" in result["warning_banner"]["html_injected"]

    def test_clean_external_email_generates_info_banner(self):
        result = evaluate_behavioral_relationship(
            sender_email="partner@trusted-vendor.com",
            sender_display="Trusted Partner",
            sender_domain="trusted-vendor.com",
            recipients=["team@company.com"],
            risk_score=15.0,
            forensic_findings=[],
            threat_classification={"primary_intent": "Benign", "tactics": []},
        )
        assert result["warning_banner"]["severity"] == "INFO"
        assert "EXTERNAL COMMUNICATION" in result["warning_banner"]["title"]


class TestMimecastPolicyEngine:
    """Tests for Mimecast-style automated policy rules and Quarantine Vault."""

    def test_critical_risk_triggers_auto_quarantine(self):
        res = evaluate_policies(
            case_id="case-test-999",
            original_filename="malicious.eml",
            sender_email="bad@phish.com",
            sender_display="Evil Corp",
            sender_domain="phish.com",
            subject="Invoice Overdue",
            risk_score=85.0,
            threat_classification={"primary_intent": "Phishing"},
        )
        assert res["recommended_action"] == "QUARANTINE"
        assert res["is_quarantined"] is True

        # Verify present in vault
        vault = get_quarantine_vault()
        found = [v for v in vault if v.get("case_id") == "case-test-999"]
        assert len(found) > 0

    def test_quarantine_remediation_and_blocklist(self):
        rem = remediate_quarantine("case-test-999", "BLOCK_SENDER", "Analyst confirmed malware")
        assert rem["success"] is True
        assert rem["new_status"] == "BLOCK_SENDER"

        # Verify blocklist addition
        add_blocklist_entry("DOMAIN", "evil-attack-node.com", "Confirmed C2 domain")
        blocklist = get_blocklist()
        assert any(b["value"] == "evil-attack-node.com" for b in blocklist)


class TestSentaroComplianceScorecard:
    """Tests for Sentaro-style compliance posture mapping."""

    def test_compliance_scorecard_structure(self):
        scorecard = get_compliance_scorecard()
        assert scorecard["overall_compliance_score"] >= 90
        assert scorecard["overall_status"] == "EXCELLENT"
        assert len(scorecard["frameworks"]) >= 3
        framework_ids = [f["id"] for f in scorecard["frameworks"]]
        assert "NIS2" in framework_ids
        assert "DORA" in framework_ids
        assert "SOC2_ISO" in framework_ids


@pytest.mark.asyncio
class TestEnterpriseApiEndpoints:
    """Tests for all newly registered enterprise REST endpoints."""

    async def test_policy_rules_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/policy/rules")
            assert res.status_code == 200
            data = res.json()
            assert "policies" in data
            assert len(data["policies"]) >= 4

    async def test_quarantine_vault_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/policy/quarantine")
            assert res.status_code == 200
            data = res.json()
            assert "quarantined_items" in data

    async def test_tenants_and_stream_endpoints(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res1 = await ac.get("/api/tenants/list")
            assert res1.status_code == 200
            assert len(res1.json().get("tenants", [])) >= 2

            res2 = await ac.get("/api/tenants/stream")
            assert res2.status_code == 200
            assert len(res2.json().get("events", [])) >= 2

    async def test_compliance_scorecard_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/compliance/scorecard")
            assert res.status_code == 200
            data = res.json()
            assert data["overall_compliance_score"] >= 90
