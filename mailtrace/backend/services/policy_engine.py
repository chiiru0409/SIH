"""
services/policy_engine.py — Automated SOC Policy Enforcement, Quarantine Vault & Incident Playbooks.
Inspired by Mimecast Targeted Threat Protection & Palantir Alerting & Detection Strategy (ADS).

Evaluates security policy rules against analyzed cases and manages the SOC
Quarantine Vault, domain/sender blocklists, and automated remediation action playbooks.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mailtrace.services.policy")

# In-memory store for SOC policies, quarantine vault, and blocklists
_DEFAULT_POLICIES = [
    {
        "id": "POL-001",
        "name": "Auto-Quarantine Critical Threats",
        "enabled": True,
        "condition": "risk_score >= 80",
        "action": "QUARANTINE",
        "description": "Automatically isolate high-severity malware, credential harvest, and phishing emails.",
    },
    {
        "id": "POL-002",
        "name": "Executive BEC & Wire Fraud Shield",
        "enabled": True,
        "condition": "has_bec_intent == True or has_display_spoof == True",
        "action": "QUARANTINE_AND_ALERT",
        "description": "Quarantine executive impersonation attacks and alert SOC incident responders.",
    },
    {
        "id": "POL-003",
        "name": "Authentication Failure Defanging",
        "enabled": True,
        "condition": "has_auth_fail == True and risk_score >= 50",
        "action": "DEFANG_URLS",
        "description": "Defang all hyperlinks and disable active elements for unauthenticated external emails.",
    },
    {
        "id": "POL-004",
        "name": "External Sender Warning Banner",
        "enabled": True,
        "condition": "risk_score >= 30",
        "action": "INJECT_BANNER",
        "description": "Inject warning banners onto suspicious external messages to alert recipients.",
    },
]

_QUARANTINE_VAULT: Dict[str, Dict[str, Any]] = {}
_BLOCKLIST: List[Dict[str, Any]] = [
    {
        "id": "BLK-001",
        "type": "DOMAIN",
        "value": "phish-portal-secure.com",
        "reason": "Known credential harvesting infrastructure",
        "added_at": "2026-09-01T08:00:00Z",
        "added_by": "SOC_ANALYST_AUTO",
    },
    {
        "id": "BLK-002",
        "type": "IP",
        "value": "185.220.101.5",
        "reason": "Bulletproof hoster TOR relay origin",
        "added_at": "2026-09-02T14:30:00Z",
        "added_by": "SOC_ANALYST_AUTO",
    },
]


def generate_incident_playbook(
    case_id: str,
    threat_intent: str,
    risk_score: float,
    sender_email: Optional[str],
    sender_domain: Optional[str],
    has_auth_fail: bool,
    has_display_spoof: bool,
    saas_abuse: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generates a Palantir Alerting & Detection Strategy (ADS)-aligned SOC Incident Playbook.
    Provides structured 4-phase containment, eradication, and hunting actions.
    """
    intent_up = (threat_intent or "").upper()
    saas_info = saas_abuse or {}

    containment_steps: List[str] = []
    preservation_steps: List[str] = [
        "Cryptographically seal RFC-822 evidence payload (SHA-256) into local audit log.",
        "Export parsed IoC manifest (JSON/CSV) for SIEM ingest.",
    ]
    hunting_steps: List[str] = [
        f"Execute threat hunt across tenant mailboxes for sender domain '{sender_domain or 'unknown'}'.",
        "Check correlation graph for related campaign clusters and shared public sending IPs.",
    ]
    eradication_steps: List[str] = []

    if risk_score >= 80 or "CREDENTIAL" in intent_up or "MALWARE" in intent_up:
        containment_steps.extend([
            "Execute immediate quarantine on message across all recipient mailboxes via API.",
            "Defang all embedded hyperlinks and disable active HTML execution.",
            "Trigger automated password reset and session revocation if any user clicked embedded links.",
        ])
        eradication_steps.extend([
            f"Add domain '{sender_domain}' and sending IPs to perimeter email gateway blocklist.",
            "Purge quarantined copy from user spam/trash folders after evidence hash verification.",
        ])
    elif "BEC" in intent_up or has_display_spoof:
        containment_steps.extend([
            "Quarantine message and alert internal finance/payroll teams of active VIP impersonation lure.",
            "Notify target recipients via out-of-band channel (phone/Slack) to verify any pending payment requests.",
        ])
        eradication_steps.extend([
            "Configure executive display name exact-match rule in gateway policy engine.",
            f"Add sender email '{sender_email}' to VIP fraud blocklist.",
        ])
    elif has_auth_fail:
        containment_steps.extend([
            "Defang external links and append HIGH-RISK EXTERNAL SPOOF warning banner.",
            "Route subsequent unauthenticated inbound messages from this domain to quarantine review.",
        ])
        eradication_steps.extend([
            f"Contact domain owner of '{sender_domain}' to review missing/misconfigured SPF & DMARC records.",
        ])
    else:
        containment_steps.extend([
            "Inject cautionary external sender banner if message is delivered to user inbox.",
        ])
        eradication_steps.extend([
            "No immediate blocklist addition required; monitor for repeat anomalies.",
        ])

    if saas_info.get("detected"):
        services = ", ".join(saas_info.get("services", []))
        hunting_steps.append(f"Living-off-Legitimate-Services detected ({services}): audit all outbound traffic to cloud lure links.")
        containment_steps.append(f"Submit abuse takedown report to {services} trust & safety teams.")

    return {
        "playbook_id": f"PB-{intent_up or 'GENERIC'}-{case_id[:8]}",
        "threat_category": intent_up or "SUSPICIOUS_EMAIL",
        "phases": {
            "phase1_containment": {
                "title": "Phase 1: Immediate Containment & Isolation",
                "actions": containment_steps,
            },
            "phase2_preservation": {
                "title": "Phase 2: Evidence Integrity & Chain of Custody",
                "actions": preservation_steps,
            },
            "phase3_hunting": {
                "title": "Phase 3: Threat Hunting & Scope Assessment",
                "actions": hunting_steps,
            },
            "phase4_eradication": {
                "title": "Phase 4: Eradication & Hardening",
                "actions": eradication_steps,
            },
        },
        "soc_readiness_level": "L2_ANALYST_ACTIONABLE",
    }


def evaluate_policies(
    case_id: str,
    original_filename: str,
    sender_email: Optional[str],
    sender_display: Optional[str],
    sender_domain: Optional[str],
    subject: Optional[str],
    risk_score: float,
    threat_classification: Optional[Dict[str, Any]] = None,
    forensic_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Evaluates enterprise policy rules against an analyzed case, applies automated remediation,
    and attaches an ADS-aligned Incident Playbook.
    """
    threat_info = threat_classification or {}
    primary_intent = str(threat_info.get("primary_intent", "")).upper()
    findings = forensic_findings or []
    saas_abuse = threat_info.get("saas_abuse") or {}

    has_bec = "BEC" in primary_intent or "WIRE" in primary_intent
    has_display_spoof = any("DISPLAY-NAME" in str(f.get("category", "")).upper() or "SPOOF" in str(f.get("title", "")).upper() for f in findings)
    has_auth_fail = any(f.get("severity") in ("CRITICAL", "HIGH") and "AUTHENTICATION" in str(f.get("category", "")).upper() for f in findings)
    
    # Check blocklist
    is_blocked = any(
        (b["type"] == "DOMAIN" and sender_domain and b["value"].lower() == sender_domain.lower()) or
        (b["type"] == "SENDER" and sender_email and b["value"].lower() == sender_email.lower())
        for b in _BLOCKLIST
    )

    triggered_rules = []
    recommended_action = "ALLOW"
    action_reason = "No high-severity policy thresholds violated."

    if is_blocked:
        triggered_rules.append({
            "policy_id": "POL-BLK",
            "name": "Blocklist Match",
            "action": "BLOCK_AND_PURGE",
            "severity": "CRITICAL",
        })
        recommended_action = "BLOCK_AND_PURGE"
        action_reason = f"Sender or domain matches enterprise blocklist."

    elif risk_score >= 80:
        triggered_rules.append({
            "policy_id": "POL-001",
            "name": "Auto-Quarantine Critical Threats",
            "action": "QUARANTINE",
            "severity": "CRITICAL",
        })
        recommended_action = "QUARANTINE"
        action_reason = f"Risk score ({risk_score}/100) exceeds Critical threshold (80)."

    elif has_bec or (has_display_spoof and risk_score >= 60):
        triggered_rules.append({
            "policy_id": "POL-002",
            "name": "Executive BEC & Wire Fraud Shield",
            "action": "QUARANTINE_AND_ALERT",
            "severity": "HIGH",
        })
        recommended_action = "QUARANTINE"
        action_reason = "Suspected Business Email Compromise or VIP Display Name Impersonation."

    elif has_auth_fail and risk_score >= 50:
        triggered_rules.append({
            "policy_id": "POL-003",
            "name": "Authentication Failure Defanging",
            "action": "DEFANG_URLS",
            "severity": "MEDIUM",
        })
        recommended_action = "DEFANG_URLS"
        action_reason = "SPF/DKIM authentication failed on external sender."

    elif risk_score >= 30:
        triggered_rules.append({
            "policy_id": "POL-004",
            "name": "External Sender Warning Banner",
            "action": "INJECT_BANNER",
            "severity": "LOW",
        })
        recommended_action = "INJECT_BANNER"
        action_reason = "External message with elevated risk signals."

    # Automatically add to Quarantine Vault if action is QUARANTINE
    if recommended_action in ("QUARANTINE", "QUARANTINE_AND_ALERT"):
        _QUARANTINE_VAULT[case_id] = {
            "case_id": case_id,
            "filename": original_filename,
            "sender_email": sender_email,
            "sender_display": sender_display,
            "sender_domain": sender_domain,
            "subject": subject or "(No Subject)",
            "risk_score": risk_score,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "status": "QUARANTINED",
            "reason": action_reason,
            "triggered_rules": [r["name"] for r in triggered_rules],
            "analyst_notes": None,
        }

    # Generate ADS-aligned incident playbook
    playbook = generate_incident_playbook(
        case_id=case_id,
        threat_intent=primary_intent,
        risk_score=risk_score,
        sender_email=sender_email,
        sender_domain=sender_domain,
        has_auth_fail=has_auth_fail,
        has_display_spoof=has_display_spoof,
        saas_abuse=saas_abuse,
    )

    return {
        "status": "EVALUATED",
        "recommended_action": recommended_action,
        "action_reason": action_reason,
        "is_quarantined": recommended_action in ("QUARANTINE", "QUARANTINE_AND_ALERT"),
        "triggered_rules": triggered_rules,
        "incident_playbook": playbook,
    }


def get_quarantine_vault() -> List[Dict[str, Any]]:
    """Returns all items currently in the SOC Quarantine Vault."""
    return list(_QUARANTINE_VAULT.values())


def remediate_quarantine(case_id: str, action: str, notes: Optional[str] = None) -> Dict[str, Any]:
    """
    Applies SOC analyst remediation to a quarantined item.
    Actions: 'RELEASE', 'PURGE', 'BLOCK_SENDER'
    """
    item = _QUARANTINE_VAULT.get(case_id)
    if not item:
        # Create ad-hoc record if needed
        item = {
            "case_id": case_id,
            "status": "QUARANTINED",
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
        }
        _QUARANTINE_VAULT[case_id] = item

    action_upper = action.upper()
    item["status"] = action_upper
    item["remediated_at"] = datetime.now(timezone.utc).isoformat()
    item["analyst_notes"] = notes or f"Action {action_upper} applied by SOC analyst."

    if action_upper == "BLOCK_SENDER" and item.get("sender_email"):
        add_blocklist_entry("SENDER", item["sender_email"], f"Quarantined in case {case_id}")
    elif action_upper == "BLOCK_DOMAIN" and item.get("sender_domain"):
        add_blocklist_entry("DOMAIN", item["sender_domain"], f"Quarantined in case {case_id}")

    return {
        "success": True,
        "case_id": case_id,
        "new_status": action_upper,
        "updated_item": item,
    }


def get_blocklist() -> List[Dict[str, Any]]:
    """Returns the current enterprise blocklist."""
    return _BLOCKLIST


def add_blocklist_entry(entry_type: str, value: str, reason: str = "SOC Manual Block") -> Dict[str, Any]:
    """Adds a new domain, sender, or IP to the blocklist."""
    new_entry = {
        "id": f"BLK-{len(_BLOCKLIST) + 1:03d}",
        "type": entry_type.upper(),
        "value": value.strip(),
        "reason": reason,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "added_by": "SOC_ANALYST",
    }
    _BLOCKLIST.append(new_entry)
    return new_entry


def get_active_policies() -> List[Dict[str, Any]]:
    """Returns all configured enterprise policies."""
    return _DEFAULT_POLICIES
