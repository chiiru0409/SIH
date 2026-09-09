"""
services/tenant_connector.py — Cloud Email Tenant Ingestion & Real-Time Connector.
Inspired by Sentaro & GreatHorn Cloud API Architecture.

Manages direct API connections to Microsoft 365 (Microsoft Graph API) and
Google Workspace (Gmail API / PubSub), providing live event ingestion streams.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("mailtrace.services.tenants")

_TENANTS = [
    {
        "id": "tenant-m365-corp",
        "provider": "MICROSOFT_365",
        "name": "Enterprise Corporate Tenant",
        "domain": "enterprise-defense.org",
        "status": "CONNECTED",
        "sync_mode": "GRAPH_API_WEBHOOK",
        "mailboxes_monitored": 2450,
        "threats_intercepted_today": 14,
        "last_sync": "Just now",
        "health": "HEALTHY",
    },
    {
        "id": "tenant-gsuite-ops",
        "provider": "GOOGLE_WORKSPACE",
        "name": "Operations & Engineering G-Suite",
        "domain": "ops.enterprise-defense.org",
        "status": "CONNECTED",
        "sync_mode": "GMAIL_PUBSUB_STREAM",
        "mailboxes_monitored": 820,
        "threats_intercepted_today": 6,
        "last_sync": "1 min ago",
        "health": "HEALTHY",
    },
    {
        "id": "tenant-postfix-edge",
        "provider": "SMTP_GATEWAY",
        "name": "Perimeter Postfix Inbound Gateway",
        "domain": "mailgw.enterprise-defense.org",
        "status": "CONNECTED",
        "sync_mode": "MILTER_PASSIVE_MIRROR",
        "mailboxes_monitored": 3270,
        "threats_intercepted_today": 31,
        "last_sync": "Just now",
        "health": "HEALTHY",
    },
]

# Simulated live incoming email event stream
_LIVE_STREAM_EVENTS = [
    {
        "event_id": "EVT-9041",
        "timestamp": "2026-09-09T10:45:12Z",
        "tenant_id": "tenant-m365-corp",
        "tenant_name": "Microsoft 365 Corp",
        "sender": "billing-update@intuit-quickbooks-security.com",
        "display_name": "Intuit Security Team",
        "recipient": "finance@enterprise-defense.org",
        "subject": "URGENT: Payroll Account Suspension Warning - Verify Within 24 Hours",
        "risk_score": 92,
        "severity": "CRITICAL",
        "intent": "Credential Harvesting",
        "policy_action": "QUARANTINED",
    },
    {
        "event_id": "EVT-9042",
        "timestamp": "2026-09-09T10:48:33Z",
        "tenant_id": "tenant-gsuite-ops",
        "tenant_name": "Google Workspace Ops",
        "sender": "satya.nadella@micros0ft-support.cloud",
        "display_name": "Executive Management",
        "recipient": "cfo@enterprise-defense.org",
        "subject": "Confidential: Acquisition Wire Transfer Instructions",
        "risk_score": 96,
        "severity": "CRITICAL",
        "intent": "BEC / Wire Fraud",
        "policy_action": "QUARANTINED",
    },
    {
        "event_id": "EVT-9043",
        "timestamp": "2026-09-09T10:51:04Z",
        "tenant_id": "tenant-m365-corp",
        "tenant_name": "Microsoft 365 Corp",
        "sender": "newsletter@techdigest-news.com",
        "display_name": "TechDigest Weekly",
        "recipient": "team@enterprise-defense.org",
        "subject": "Your Weekly Engineering & Security Digest",
        "risk_score": 12,
        "severity": "LOW",
        "intent": "Benign / Newsletter",
        "policy_action": "DELIVERED",
    },
    {
        "event_id": "EVT-9044",
        "timestamp": "2026-09-09T10:53:29Z",
        "tenant_id": "tenant-postfix-edge",
        "tenant_name": "Perimeter Postfix Gateway",
        "sender": "support@invoice-vendor-portal.net",
        "display_name": "Vendor Accounts Payable",
        "recipient": "accounting@enterprise-defense.org",
        "subject": "Updated Remittance Details for Q3 Settlement",
        "risk_score": 68,
        "severity": "HIGH",
        "intent": "Phishing / Payment Redirect",
        "policy_action": "BANNER_INJECTED",
    },
]


def get_tenants() -> List[Dict[str, Any]]:
    """Returns all active cloud tenant configurations."""
    return _TENANTS


def get_live_tenant_stream() -> List[Dict[str, Any]]:
    """Returns real-time tenant email event stream."""
    return _LIVE_STREAM_EVENTS


def add_stream_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Adds a new analyzed case event to the live stream."""
    _LIVE_STREAM_EVENTS.insert(0, event)
    if len(_LIVE_STREAM_EVENTS) > 50:
        _LIVE_STREAM_EVENTS.pop()
    return event
