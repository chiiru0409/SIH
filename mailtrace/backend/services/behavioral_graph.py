"""
services/behavioral_graph.py — Behavioral Communication Graph & Warning Banner Engine.
Inspired by GreatHorn Cloud Email Security.

Analyzes sender-recipient historical relationship familiarity, communication anomalies,
and generates dynamic, color-coded inline warning banners injected into email previews.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mailtrace.services.behavioral")


def evaluate_behavioral_relationship(
    sender_email: Optional[str],
    sender_display: Optional[str],
    sender_domain: Optional[str],
    recipients: List[str],
    risk_score: float = 0.0,
    forensic_findings: Optional[List[Dict[str, Any]]] = None,
    threat_classification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates historical communication familiarity and generates GreatHorn-style
    dynamic inline warning banners and relationship metrics.
    """
    findings = forensic_findings or []
    threat_info = threat_classification or {}
    primary_intent = str(threat_info.get("primary_intent", "")).upper()
    tactics = [str(t).upper() for t in threat_info.get("tactics", [])]

    # Analyze sender domain context
    is_freemail = False
    if sender_domain:
        freemail_providers = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
            "proton.me", "protonmail.com", "icloud.com", "mail.com", "aol.com"
        }
        is_freemail = sender_domain.lower() in freemail_providers

    # Check for impersonation signals
    has_display_spoof = any(
        "DISPLAY-NAME" in str(f.get("category", "")).upper() or 
        "IMPERSONATION" in str(f.get("title", "")).upper() or
        "SPOOF" in str(f.get("title", "")).upper()
        for f in findings
    )

    has_auth_fail = any(
        f.get("severity") in ("CRITICAL", "HIGH") and "AUTHENTICATION" in str(f.get("category", "")).upper()
        for f in findings
    )

    has_wire_fraud = (
        "BEC" in primary_intent or 
        "WIRE" in primary_intent or 
        any("WIRE" in t or "PAYMENT" in t or "INVOICE" in t for t in tactics)
    )

    # Determine Relationship Tier
    if has_display_spoof:
        relationship_tier = "IMPERSONATION_ANOMALY"
        familiarity_score = 0.05
    elif is_freemail and ("EXECUTIVE" in primary_intent or "CEO" in str(sender_display).upper()):
        relationship_tier = "SUSPICIOUS_FREEMAIL_VIP"
        familiarity_score = 0.10
    elif risk_score >= 70 or has_auth_fail:
        relationship_tier = "UNTRUSTED_EXTERNAL"
        familiarity_score = 0.15
    elif is_freemail:
        relationship_tier = "FREEMAIL_EXTERNAL"
        familiarity_score = 0.40
    else:
        relationship_tier = "FIRST_TIME_DOMAIN"
        familiarity_score = 0.50

    # Determine Banner Level & Content
    banner_tags = []
    if has_wire_fraud or (has_display_spoof and risk_score >= 60):
        banner_severity = "CRITICAL"
        banner_title = "🚨 DANGER: SUSPECTED EXECUTIVE IMPERSONATION & WIRE FRAUD"
        banner_message = (
            f"The sender name '{sender_display or 'Executive'}' does not match the actual sending address "
            f"<{sender_email or 'unknown'}>. This email requests financial action or credentials. "
            "DO NOT reply, click links, or execute wire transfers."
        )
        banner_color = "#ef4444"
        banner_bg = "rgba(239, 68, 68, 0.15)"
        banner_border = "#dc2626"
        banner_tags.extend(["IMPERSONATION", "WIRE_FRAUD_ALERT", "DMARC_FAIL"])

    elif risk_score >= 75 or has_auth_fail:
        banner_severity = "CRITICAL"
        banner_title = "⚠️ CRITICAL: UNVERIFIED SENDER & AUTHENTICATION FAILURE"
        banner_message = (
            f"The sending server for <{sender_email or 'unknown'}> failed cryptographic SPF/DKIM verification. "
            "The sender identity cannot be verified. Exercise extreme caution."
        )
        banner_color = "#f97316"
        banner_bg = "rgba(249, 115, 22, 0.15)"
        banner_border = "#ea580c"
        banner_tags.extend(["AUTH_FAILED", "SPOOF_RISK"])

    elif risk_score >= 40 or is_freemail or "URGENCY" in tactics:
        banner_severity = "WARNING"
        banner_title = "⚡ CAUTION: EXTERNAL SENDER WITH URGENCY CUES"
        banner_message = (
            f"This email originated outside your organization from <{sender_email or 'external'}> and contains "
            "time-sensitive demands. Verify the sender's identity via an independent communication channel."
        )
        banner_color = "#eab308"
        banner_bg = "rgba(234, 179, 8, 0.15)"
        banner_border = "#ca8a04"
        banner_tags.extend(["EXTERNAL_SENDER", "URGENCY_TACTIC"])

    else:
        banner_severity = "INFO"
        banner_title = "ℹ️ NOTICE: EXTERNAL COMMUNICATION"
        banner_message = (
            f"This message originated from outside your corporate domain ({sender_domain or 'external'}). "
            "Be cautious when sharing sensitive organization data."
        )
        banner_color = "#06b6d4"
        banner_bg = "rgba(6, 182, 212, 0.12)"
        banner_border = "#0891b2"
        banner_tags.append("EXTERNAL")

    # Generate Self-Contained HTML and Plaintext Warning Banners
    html_banner = f"""<div style="background-color: {banner_bg}; border: 2px solid {banner_border}; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #f8fafc;">
  <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 13px; color: {banner_color}; margin-bottom: 4px;">
    <span>{banner_title}</span>
  </div>
  <div style="font-size: 12px; line-height: 1.4; color: #e2e8f0;">
    {banner_message}
  </div>
</div>"""

    plaintext_banner = (
        f"========================================================================\n"
        f"{banner_title}\n"
        f"{banner_message}\n"
        f"========================================================================"
    )

    return {
        "relationship_tier": relationship_tier,
        "familiarity_score": familiarity_score,
        "is_first_time_sender": relationship_tier in ("FIRST_TIME_DOMAIN", "IMPERSONATION_ANOMALY", "FREEMAIL_EXTERNAL"),
        "is_freemail_provider": is_freemail,
        "warning_banner": {
            "severity": banner_severity,
            "title": banner_title,
            "message": banner_message,
            "color": banner_color,
            "border_color": banner_border,
            "bg_color": banner_bg,
            "tags": banner_tags,
            "html_injected": html_banner,
            "plaintext_injected": plaintext_banner,
        },
    }
