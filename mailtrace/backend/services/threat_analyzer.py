"""
services/threat_analyzer.py — MAILTRACE AI-Powered Threat Detection & Explainable Classification.

Primary Entry Point:
    analyze_threat(parsed_email: dict, forensic_analysis: dict | None = None) -> dict[str, Any]

Architecture:
    1. Content & Intent Extraction (Urgency, Credential Harvesting, Financial manipulation, Authority/Secrecy, Fear).
    2. Forensic Evidence Correlation (SPF/DKIM/DMARC status, Identity mismatches, Display name brand spoofing).
    3. Multi-Category Threat Classification:
       - PHISHING
       - BEC (Business Email Compromise)
       - CREDENTIAL_HARVESTING
       - IMPERSONATION
       - SOCIAL_ENGINEERING
       - SUSPICIOUS
       - BENIGN
    4. Multi-Label Indicator Generation & Weight Scoring.
    5. Explainable Reasoning (Structured indicators + Evidence citations + Concise explanation).
    6. Strict Fact vs. AI Inference Separation.
    7. 100% Offline / Deterministic Local Capability with Optional LLM Provider Fallback.

Design Rules:
    - Never replace deterministic forensic evidence.
    - Never claim confirmation of physical human attacker identity or attribution.
    - Treat all input as untrusted.
    - Zero external network dependency for standard operation.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from backend.config import settings
from backend.utils.ip_utils import classify_ip
from backend.utils.url_utils import normalize_domain

logger = logging.getLogger("mailtrace.threat_analyzer")


# ================================================================== #
#  Threat Category Constants                                          #
# ================================================================== #

THREAT_PHISHING = "PHISHING"
THREAT_BEC = "BEC"
THREAT_CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
THREAT_IMPERSONATION = "IMPERSONATION"
THREAT_SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
THREAT_SUSPICIOUS = "SUSPICIOUS"
THREAT_BENIGN = "BENIGN"

ALL_THREAT_CATEGORIES = [
    THREAT_PHISHING,
    THREAT_BEC,
    THREAT_CREDENTIAL_HARVESTING,
    THREAT_IMPERSONATION,
    THREAT_SOCIAL_ENGINEERING,
    THREAT_SUSPICIOUS,
    THREAT_BENIGN,
]


# ================================================================== #
#  Pattern Dictionaries for NLP / Intent Extraction                  #
# ================================================================== #

# 1. Urgency and Coercion Patterns
URGENCY_PATTERNS = [
    (r"\b(?:within|in)\s+(?:24|48|12|2|1)\s+(?:hours?|hrs?|days?)\b", 0.85, "Strict deadline pressure"),
    (r"\bimmediate(?:ly)?\s+(?:action|attention|verification|response|update|penalty)\b", 0.80, "Immediate action demanded"),
    (r"\baccount\s+(?:will\s+be|has\s+been)\s+(?:suspended|closed|terminated|locked|deactivated|disabled)\b", 0.90, "Account suspension warning"),
    (r"\bact\s+(?:now|promptly|immediately|fast)\b", 0.70, "Pressure to act immediately"),
    (r"\bfinal\s+(?:notice|warning|reminder)\b", 0.85, "Final warning coercive language"),
    (r"\burgent(?:\s+attention|\s+request|\s+matter|\s+notification)?\b", 0.75, "Urgent notification flag"),
    (r"\bto\s+avoid\s+(?:service\s+interruption|account\s+closure|suspension|deactivation|penalty|legal)\b", 0.85, "Avoidance of negative consequence"),
    (r"\baccess\s+(?:will\s+be|is)\s+restricted\b", 0.80, "Access restriction threat"),
    (r"\btime[-\s]sensitive\b", 0.70, "Time-sensitive framing"),
]

# 2. Credential Harvesting Patterns
CREDENTIAL_PATTERNS = [
    (r"\b(?:verify|confirm|update|validate|review)\s+(?:your\s+)?(?:account|credentials?|password|passcode|login|identity|details|billing)\b", 0.90, "Request to verify account credentials"),
    (r"\b(?:enter|input|provide|submit)\s+(?:your\s+)?(?:password|pin|security\s+key|credentials?|otp|2fa\s+code|username\s+and\s+password)\b", 0.95, "Direct credential submission prompt"),
    (r"\b(?:click\s+here|follow\s+link|sign\s+in)\s+to\s+(?:verify|reactivate|keep|unlock)\s+(?:your\s+)?account\b", 0.90, "Link to re-authenticate account"),
    (r"\bpassword\s+(?:expires?|expiring|expired|reset|change\s+required)\b", 0.85, "Password expiration notice"),
    (r"\blogin\s+(?:to\s+view|to\s+access|portal|verification)\b", 0.80, "Login required to access message/content"),
    (r"\b(?:microsoft|office\s*365|google|workspace|apple\s*id|icloud|outlook|webmail|owa)\s+(?:login|credential|authentication|portal|auth)\b", 0.90, "Brand-specific credential portal language"),
    (r"\bfill\s+out\s+(?:the|this)\s+(?:form|attached\s+form)\s+with\s+your\s+details\b", 0.85, "Request to fill details into form"),
]

# 3. Financial & BEC (Business Email Compromise) Patterns
FINANCIAL_BEC_PATTERNS = [
    (r"\b(?:wire|bank|electronic)\s+transfer\b", 0.85, "Wire transfer reference"),
    (r"\b(?:update|change|new)\s+(?:our\s+|my\s+|the\s+)?(?:banking|bank|remittance|account|routing)\s+details\b", 0.95, "Bank detail alteration request"),
    (r"\b(?:invoice|payment)\s+(?:is\s+)?(?:overdue|pending|due\s+today|attached|updated|process)\b", 0.80, "Urgent invoice payment request"),
    (r"\bnew\s+routing\s+number\b", 0.90, "Bank routing number update"),
    (r"\b(?:process|execute|send|approve)\s+(?:the|this)\s+(?:payment|transfer|transaction|urgent\s+wire)\b", 0.85, "Transaction execution request"),
    (r"\b(?:purchase|buy|need)\s+(?:\d+\s+)?(?:apple|google\s*play|amazon|itunes|steam)\s+gift\s*cards?\b", 0.95, "Gift card purchase request (classic scam)"),
    (r"\bupdate\s+(?:direct\s+deposit|payroll|w-?2|tax\s+info)\b", 0.90, "Payroll / Direct deposit redirection request"),
    (r"\bremittance\s+advice\b", 0.70, "Remittance advice reference"),
    (r"\bswift(?:\s+code|\s+transfer|\s+payment)?\b", 0.75, "SWIFT international transfer reference"),
]

# 4. Executive Authority & Pretexting
EXECUTIVE_AUTHORITY_PATTERNS = [
    (r"\b(?:ceo|cfo|coo|cto|chief\s+executive|chief\s+financial|managing\s+director|president|executive\s+director|board\s+of\s+directors)\b", 0.80, "Executive title invoked"),
    (r"\b(?:i\s+am|i\'m)\s+(?:currently\s+)?in\s+a\s+(?:board\s+)?meeting\b", 0.85, "Meeting pretext (inability to verify via voice)"),
    (r"\b(?:i\s+am|i\'m)\s+traveling\b", 0.75, "Travel pretext"),
    (r"\bavailable\s+(?:by|via)\s+email\s+only|email\s+only\b", 0.85, "Email-only communication restriction"),
    (r"\bhandle\s+this\s+(?:personally|urgently|discreetly)\b", 0.80, "Pressure for personal/urgent handling"),
    (r"\bneed\s+you\s+to\s+(?:help\s+me\s+with\s+a\s+task|purchase|process)\b", 0.75, "Executive favor pretext"),
    (r"\bdo\s+not\s+call\s+(?:my\s+cell|me)\b", 0.85, "Voice verification evasion"),
]

# 5. Secrecy & Procedure Bypass Patterns
SECRECY_PATTERNS = [
    (r"\b(?:keep\s+this|strictly)\s+confidential\b", 0.85, "Explicit request for secrecy"),
    (r"\bdo\s+not\s+(?:tell|contact|call|discuss\s+with)\s+(?:anyone|the\s+team|accounting|finance|colleagues|my\s+cell)\b", 0.95, "Instruction to bypass team/accounting verification"),
    (r"\bdiscreet\s+(?:handling|transaction|matter)\b", 0.85, "Request for discreet handling"),
    (r"\bbypass\s+(?:standard|the\s+usual)\s+proc(?:edure|ess)\b", 0.90, "Instruction to bypass standard approval procedures"),
    (r"\bwithout\s+(?:informing|notifying)\b", 0.80, "Avoidance of notification"),
]

# 6. Security Alert & Fear Manipulation Patterns
SECURITY_FEAR_PATTERNS = [
    (r"\b(?:unauthorized|unusual|suspicious)\s+(?:login|activity|sign-?in|access|attempt)\b", 0.85, "Suspicious login/activity alert"),
    (r"\bsecurity\s+(?:alert|breach|incident|warning|notice)\b", 0.80, "Security alert framing"),
    (r"\baccount\s+(?:compromised|hacked|at\s+risk)\b", 0.85, "Account compromise claim"),
    (r"\bdetected\s+(?:from|in)\s+(?:an\s+unrecognized|a\s+new)\s+device\b", 0.80, "New device login pretext"),
    (r"\bif\s+this\s+was\s+not\s+you\b", 0.75, "Call-to-action for non-recognized activity"),
    (r"\b(?:legal\s+action|law\s+enforcement|court\s+summons|legal\s+complaint|subpoena|police|arrest)\b", 0.90, "Legal threat / Law enforcement intimidation"),
    (r"\b(?:severe\s+consequences|penalty|prosecution|legal\s+notice)\b", 0.85, "Intimidation / penalty threat"),
]

# 7. Call to Action / Link Phrasing
CTA_PATTERNS = [
    (r"\b(?:click\s+here|click\s+the\s+link|follow\s+this\s+link|tap\s+here|visit\s+the\s+link|view\s+the\s+shared\s+document)\b", 0.70, "Click link call-to-action"),
    (r"\b(?:open|view|download|review)\s+(?:the\s+)?attached\s+(?:file|document|invoice|pdf|spreadsheet|notice)\b", 0.75, "Open attachment call-to-action"),
    (r"\bclick\s+below\s+to\s+(?:proceed|continue|confirm|update)\b", 0.70, "Button/link action prompt"),
]

# High risk attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".cpl", ".jar", ".ps1", ".iso", ".img", ".dmg", ".pif", ".docm", ".xlsm", ".pptm"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".img"}

# Major high-target brand names for impersonation detection
HIGH_TARGET_BRANDS = [
    "paypal", "microsoft", "office365", "office 365", "google", "apple", "amazon",
    "netflix", "chase", "bank of america", "wells fargo", "citibank", "dhl", "fedex",
    "ups", "irs", "docu sign", "docusign", "adobe", "dropbox", "facebook", "meta",
    "linkedin", "zoom", "stripe", "coinbase", "binance", "metamask", "it support", "helpdesk"
]


# ================================================================== #
#  Signal Extraction Helpers                                          #
# ================================================================== #

def _match_patterns(text: str, pattern_list: list[tuple[str, float, str]]) -> list[dict[str, Any]]:
    """Search text against a list of (regex, weight, description) patterns."""
    if not text:
        return []

    matches = []
    seen_descriptions = set()

    for pattern, weight, description in pattern_list:
        found = re.search(pattern, text, re.IGNORECASE)
        if found and description not in seen_descriptions:
            matched_snippet = found.group(0)
            # Find surrounding context (~60 chars)
            start = max(0, found.start() - 25)
            end = min(len(text), found.end() + 25)
            snippet = text[start:end].strip().replace("\n", " ")

            matches.append({
                "description": description,
                "weight": weight,
                "matched_text": matched_snippet,
                "context_snippet": snippet,
                "pattern": pattern,
            })
            seen_descriptions.add(description)

    return matches


def _severity_from_weight(weight: float) -> str:
    """Map numeric weight to human readable severity."""
    if weight >= 0.85:
        return "high"
    elif weight >= 0.70:
        return "medium"
    elif weight >= 0.40:
        return "low"
    return "info"


def _signal_level(score: float) -> str:
    """Map aggregate score to signal level label."""
    if score >= 0.70:
        return "high"
    elif score >= 0.35:
        return "medium"
    elif score >= 0.15:
        return "low"
    return "none"


# ================================================================== #
#  Core Threat Analysis Logic                                         #
# ================================================================== #

def _extract_content_signals(
    subject: str,
    body_text: str,
    parsed_email: dict,
    forensic_analysis: dict | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Extract linguistic, structural, and forensic threat indicators.
    Returns:
        signals_map: dict of category -> level ("high"|"medium"|"low"|"none")
        indicators: list of structured indicator dicts
    """
    sender_info = parsed_email.get("sender", {})
    from_display = sender_info.get("display_name", "") or ""
    from_domain = sender_info.get("domain", "") or ""

    combined_text = f"{from_display}\n{subject or ''}\n{body_text or ''}"

    # 1. Linguistic pattern matching
    urgency_matches = _match_patterns(combined_text, URGENCY_PATTERNS)
    credential_matches = _match_patterns(combined_text, CREDENTIAL_PATTERNS)
    financial_matches = _match_patterns(combined_text, FINANCIAL_BEC_PATTERNS)
    executive_matches = _match_patterns(combined_text, EXECUTIVE_AUTHORITY_PATTERNS)
    secrecy_matches = _match_patterns(combined_text, SECRECY_PATTERNS)
    security_matches = _match_patterns(combined_text, SECURITY_FEAR_PATTERNS)
    cta_matches = _match_patterns(combined_text, CTA_PATTERNS)

    indicators: list[dict[str, Any]] = []

    # Process Urgency
    for m in urgency_matches:
        indicators.append({
            "indicator": "urgency_language",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Urgency indicator detected: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # Process Credentials
    for m in credential_matches:
        indicators.append({
            "indicator": "credential_request",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Credential prompt detected: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # Process Financial / BEC
    for m in financial_matches:
        indicators.append({
            "indicator": "financial_manipulation",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Financial / payment manipulation signal: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # Process Executive Authority
    for m in executive_matches:
        indicators.append({
            "indicator": "executive_authority_pretext",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Executive authority / pretexting language: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # Process Secrecy
    for m in secrecy_matches:
        indicators.append({
            "indicator": "secrecy_bypass_instruction",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Instruction to maintain secrecy or bypass standard process: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # Process Security Alerts / Fear
    for m in security_matches:
        indicators.append({
            "indicator": "security_fear_manipulation",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Security alert / fear manipulation detected: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # Process Call to Action
    for m in cta_matches:
        indicators.append({
            "indicator": "suspicious_call_to_action",
            "category": "content",
            "weight": m["weight"],
            "severity": _severity_from_weight(m["weight"]),
            "description": f"Call to action: {m['description']}.",
            "evidence": m["context_snippet"],
        })

    # 2. Attachment Analysis
    attachments = parsed_email.get("attachments", [])
    has_dangerous_ext = False
    has_archive = False
    dangerous_filenames = []

    for att in attachments:
        fname = att.get("filename", "").lower()
        if any(fname.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            has_dangerous_ext = True
            dangerous_filenames.append(att.get("filename", "unknown"))
        elif any(fname.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
            has_archive = True
            dangerous_filenames.append(att.get("filename", "unknown"))
        elif "." in fname and any(f".{part}" in DANGEROUS_EXTENSIONS for part in fname.split(".")[1:]):
            # Double extension detection (e.g. file.pdf.exe)
            has_dangerous_ext = True
            dangerous_filenames.append(att.get("filename", "unknown"))

    if has_dangerous_ext:
        indicators.append({
            "indicator": "dangerous_attachment_type",
            "category": "attachment",
            "weight": 0.90,
            "severity": "high",
            "description": "Email contains attachment with potentially executable or dangerous file extension.",
            "evidence": f"Attachments: {', '.join(dangerous_filenames)}",
        })
    elif has_archive:
        indicators.append({
            "indicator": "archive_attachment_present",
            "category": "attachment",
            "weight": 0.50,
            "severity": "medium",
            "description": "Email contains an archive file (.zip/.rar/.7z) which may conceal payload files.",
            "evidence": f"Attachments: {', '.join(dangerous_filenames)}",
        })

    # 3. URL & Link Analysis
    urls = parsed_email.get("urls", [])
    ip_host_urls = []
    suspicious_urls = []

    for u in urls:
        u_str = u.get("url", "") if isinstance(u, dict) else str(u)
        domain = u.get("domain", "") if isinstance(u, dict) else ""
        if not domain and "://" in u_str:
            domain = u_str.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        
        is_ip = (classify_ip(domain) != "unknown") if domain else False
        if is_ip or (isinstance(u, dict) and u.get("is_ip_host")):
            ip_host_urls.append(u_str)
        elif isinstance(u, dict) and u.get("suspicious_flags"):
            suspicious_urls.append(u_str)

    if ip_host_urls:
        indicators.append({
            "indicator": "ip_host_url",
            "category": "link",
            "weight": 0.85,
            "severity": "high",
            "description": "Message contains URL using raw IP address host instead of registered domain.",
            "evidence": f"URLs: {', '.join(ip_host_urls[:3])}",
        })
    elif suspicious_urls:
        indicators.append({
            "indicator": "suspicious_url_characteristics",
            "category": "link",
            "weight": 0.70,
            "severity": "medium",
            "description": "Message contains URLs with suspicious characteristics.",
            "evidence": f"URLs: {', '.join(suspicious_urls[:3])}",
        })
    elif len(urls) > 0 and (credential_matches or urgency_matches):
        indicators.append({
            "indicator": "call_to_action_link",
            "category": "link",
            "weight": 0.60,
            "severity": "medium",
            "description": "Message contains links in combination with urgent or credential-related requests.",
            "evidence": f"URLs present: {len(urls)} link(s)",
        })

    # 4. Forensic Signals Integration (from Step 3)
    auth_failures = 0
    impersonation_evidence = []
    reply_to_mismatch = False
    sender_brand_mismatch = False

    # Brand impersonation in display name check
    for brand in HIGH_TARGET_BRANDS:
        if brand in from_display.lower() and brand.replace(" ", "") not in from_domain.lower():
            sender_brand_mismatch = True
            impersonation_evidence.append(
                f"Display name '{from_display}' references '{brand.title()}' while sending domain is '{from_domain}'"
            )
            break

    if sender_brand_mismatch:
        indicators.append({
            "indicator": "brand_display_name_spoofing",
            "category": "identity",
            "weight": 0.90,
            "severity": "high",
            "description": "Display name impersonates a trusted brand while sending domain belongs to an unrelated entity.",
            "evidence": "; ".join(impersonation_evidence),
        })

    # Check forensic analysis findings if present
    if forensic_analysis:
        findings = forensic_analysis.get("findings", [])
        for f in findings:
            cat = f.get("category", "")
            ftype = f.get("type", "")
            status = f.get("status", "")

            if cat == "authentication" and status == "failed":
                auth_failures += 1
                indicators.append({
                    "indicator": f"auth_failure_{ftype}",
                    "category": "authentication",
                    "weight": 0.75,
                    "severity": "high",
                    "description": f"Authentication check failed: {f.get('title')}",
                    "evidence": f.get("description", ""),
                })
            elif cat == "identity" and status in ("warning", "failed"):
                if "reply_to" in ftype:
                    reply_to_mismatch = True
                indicators.append({
                    "indicator": f"identity_anomaly_{ftype}",
                    "category": "identity",
                    "weight": 0.80,
                    "severity": "high",
                    "description": f"Identity inconsistency: {f.get('title')}",
                    "evidence": f.get("description", ""),
                })
            elif cat == "headers" and status == "warning":
                indicators.append({
                    "indicator": f"header_anomaly_{ftype}",
                    "category": "headers",
                    "weight": 0.50,
                    "severity": "medium",
                    "description": f"Header anomaly: {f.get('title')}",
                    "evidence": f.get("description", ""),
                })
    else:
        # Fallback to parser indicators
        flags = parsed_email.get("indicators", {})
        if flags.get("reply_to_mismatch"):
            reply_to_mismatch = True
            indicators.append({
                "indicator": "identity_anomaly_reply_to_mismatch",
                "category": "identity",
                "weight": 0.75,
                "severity": "medium",
                "description": "Reply-To address domain differs from From header domain.",
                "evidence": f"From: {sender_info.get('email')} vs Reply-To: {parsed_email.get('reply_to', {}).get('email')}",
            })

    # Compute aggregate signal strengths
    urgency_score = min(1.0, sum(m["weight"] for m in urgency_matches) * 0.7)
    credential_score = min(1.0, sum(m["weight"] for m in credential_matches) * 0.8)
    financial_score = min(1.0, sum(m["weight"] for m in financial_matches) * 0.8)
    executive_score = min(1.0, sum(m["weight"] for m in executive_matches) * 0.7)
    secrecy_score = min(1.0, sum(m["weight"] for m in secrecy_matches) * 0.85)
    fear_score = min(1.0, sum(m["weight"] for m in security_matches) * 0.75)
    
    impersonation_score = 0.0
    if sender_brand_mismatch:
        impersonation_score += 0.85
    if reply_to_mismatch:
        impersonation_score += 0.40
    if auth_failures > 0:
        impersonation_score += 0.35 * auth_failures
    impersonation_score = min(1.0, impersonation_score)

    link_score = 0.0
    if ip_host_urls:
        link_score = 0.90
    elif suspicious_urls:
        link_score = 0.75
    elif len(urls) > 0:
        link_score = 0.35

    attachment_score = 0.90 if has_dangerous_ext else (0.50 if has_archive else (0.20 if attachments else 0.0))

    signals_map = {
        "urgency": _signal_level(urgency_score),
        "credential_request": _signal_level(credential_score),
        "financial_request": _signal_level(financial_score),
        "impersonation": _signal_level(impersonation_score),
        "suspicious_link": _signal_level(link_score),
        "attachment_threat": _signal_level(attachment_score),
        "fear_manipulation": _signal_level(fear_score),
        "authority_pressure": _signal_level(executive_score + secrecy_score),
    }

    return signals_map, indicators


def _classify_threat(
    signals_map: dict[str, str],
    indicators: list[dict[str, Any]],
    parsed_email: dict,
    forensic_analysis: dict | None = None,
) -> tuple[str, list[str], float]:
    """
    Determine primary threat, secondary threats, and classification confidence.
    """
    is_high = lambda sig: signals_map.get(sig) == "high"
    is_med_or_high = lambda sig: signals_map.get(sig) in ("medium", "high")

    scores: dict[str, float] = {
        THREAT_PHISHING: 0.0,
        THREAT_BEC: 0.0,
        THREAT_CREDENTIAL_HARVESTING: 0.0,
        THREAT_IMPERSONATION: 0.0,
        THREAT_SOCIAL_ENGINEERING: 0.0,
        THREAT_SUSPICIOUS: 0.0,
        THREAT_BENIGN: 0.0,
    }

    # 1. Evaluate CREDENTIAL_HARVESTING
    if is_high("credential_request"):
        scores[THREAT_CREDENTIAL_HARVESTING] += 0.88
        if is_med_or_high("urgency"):
            scores[THREAT_CREDENTIAL_HARVESTING] += 0.05
        if is_med_or_high("suspicious_link"):
            scores[THREAT_CREDENTIAL_HARVESTING] += 0.05
    elif is_med_or_high("credential_request"):
        scores[THREAT_CREDENTIAL_HARVESTING] += 0.65

    # 2. Evaluate PHISHING
    phish_score = 0.0
    if is_high("impersonation") and (is_high("credential_request") or is_high("fear_manipulation") or is_high("urgency")):
        phish_score += 0.99
    elif is_high("impersonation") and (is_med_or_high("urgency") or is_med_or_high("credential_request") or is_med_or_high("fear_manipulation")):
        phish_score += 0.95
    elif is_high("fear_manipulation") and (is_med_or_high("suspicious_link") or is_med_or_high("urgency")):
        phish_score += 0.92
    elif is_high("credential_request") and is_high("impersonation"):
        phish_score += 0.98
    elif is_high("credential_request") and (is_med_or_high("suspicious_link") or is_med_or_high("urgency")):
        phish_score += 0.88
    elif is_high("suspicious_link") and (is_med_or_high("urgency") or is_med_or_high("credential_request") or is_med_or_high("fear_manipulation")):
        phish_score += 0.88
    elif is_high("suspicious_link"):
        phish_score += 0.80
    elif is_med_or_high("credential_request") and is_med_or_high("urgency"):
        phish_score += 0.78
    elif is_med_or_high("fear_manipulation") and is_med_or_high("urgency"):
        phish_score += 0.75
    elif is_high("attachment_threat") and (is_med_or_high("urgency") or is_med_or_high("impersonation")):
        phish_score += 0.80

    scores[THREAT_PHISHING] = min(1.0, phish_score)

    # 3. Evaluate BEC (Business Email Compromise)
    bec_score = 0.0
    if is_high("financial_request") and (is_med_or_high("authority_pressure") or is_med_or_high("impersonation")):
        bec_score += 0.95
    elif is_high("financial_request") and is_med_or_high("urgency"):
        bec_score += 0.90
    elif is_high("financial_request"):
        bec_score += 0.82
    elif is_high("authority_pressure") and is_med_or_high("urgency") and not is_high("credential_request"):
        bec_score += 0.75
    elif is_med_or_high("financial_request") and is_med_or_high("authority_pressure"):
        bec_score += 0.75

    scores[THREAT_BEC] = min(1.0, bec_score)

    # 4. Evaluate IMPERSONATION
    imp_score = 0.0
    if is_high("impersonation"):
        imp_score += 0.85
    elif is_med_or_high("impersonation"):
        imp_score += 0.65
    if is_med_or_high("authority_pressure"):
        imp_score += 0.20

    scores[THREAT_IMPERSONATION] = min(1.0, imp_score)

    # 5. Evaluate SOCIAL_ENGINEERING
    soc_score = 0.0
    if is_high("fear_manipulation") and is_med_or_high("urgency"):
        soc_score += 0.90
    elif is_high("urgency") and is_high("fear_manipulation"):
        soc_score += 0.90
    elif is_high("urgency") and is_med_or_high("authority_pressure"):
        soc_score += 0.82
    elif is_high("urgency") and not is_high("financial_request") and not is_high("credential_request"):
        soc_score += 0.75
    elif is_med_or_high("fear_manipulation"):
        soc_score += 0.60
    elif is_med_or_high("urgency") and is_med_or_high("authority_pressure"):
        soc_score += 0.65
    elif signals_map.get("urgency") == "medium":
        soc_score += 0.40
    elif signals_map.get("urgency") == "low":
        soc_score += 0.20

    scores[THREAT_SOCIAL_ENGINEERING] = min(1.0, soc_score)

    # 6. Evaluate SUSPICIOUS (Anomalies present but inconclusive for full Phishing/BEC)
    susp_score = 0.0
    total_high_indicators = sum(1 for ind in indicators if ind.get("severity") == "high")
    total_med_indicators = sum(1 for ind in indicators if ind.get("severity") == "medium")

    if is_high("attachment_threat") and not (is_high("credential_request") or is_high("financial_request")):
        susp_score += 0.80
    elif is_high("suspicious_link") and not (is_high("credential_request") or is_high("financial_request")):
        susp_score += 0.75
    elif total_high_indicators >= 1 or total_med_indicators >= 2:
        susp_score += 0.65
    elif total_med_indicators == 1:
        susp_score += 0.45

    scores[THREAT_SUSPICIOUS] = min(1.0, susp_score)

    # 7. Evaluate BENIGN
    if total_high_indicators == 0 and total_med_indicators == 0:
        scores[THREAT_BENIGN] = 0.95
    elif total_high_indicators == 0 and total_med_indicators <= 1 and susp_score < 0.50:
        scores[THREAT_BENIGN] = 0.75
    else:
        scores[THREAT_BENIGN] = 0.05

    # Priority order for classification ties
    priority_order = [
        THREAT_PHISHING,
        THREAT_BEC,
        THREAT_CREDENTIAL_HARVESTING,
        THREAT_SOCIAL_ENGINEERING,
        THREAT_IMPERSONATION,
        THREAT_SUSPICIOUS,
        THREAT_BENIGN,
    ]

    sorted_categories = sorted(
        priority_order,
        key=lambda cat: (scores[cat], -priority_order.index(cat)),
        reverse=True,
    )

    primary = sorted_categories[0]
    primary_score = scores[primary]

    # If the highest score is too low (< 0.50), default to BENIGN or SUSPICIOUS
    if primary_score < 0.50:
        if total_med_indicators > 0 or total_high_indicators > 0:
            primary = THREAT_SUSPICIOUS
            primary_score = max(0.55, susp_score)
        else:
            primary = THREAT_BENIGN
            primary_score = 0.90

    # Secondary threats: any other category with score >= 0.60
    secondaries = [
        cat for cat in priority_order
        if cat != primary and cat != THREAT_BENIGN and scores[cat] >= 0.60
    ]

    # Calculate final confidence
    confidence = round(max(0.50, min(0.99, primary_score)), 2)

    return primary, secondaries, confidence


def _generate_explanation(
    primary_threat: str,
    secondary_threats: list[str],
    signals_map: dict[str, str],
    indicators: list[dict[str, Any]],
    parsed_email: dict,
    forensic_analysis: dict | None = None,
) -> str:
    """
    Generate an explainable, fact-grounded human-readable summary.
    Dynamically derived from observed structured signals with zero contradictions.
    """
    sender = parsed_email.get("sender", {})
    from_addr = sender.get("email") or "Unknown sender"
    subject = parsed_email.get("headers", {}).get("subject") or "No subject"

    urgency_val = str(signals_map.get("urgency", "none")).lower()
    cred_val = str(signals_map.get("credential_request", "none")).lower()
    fin_val = str(signals_map.get("financial_request", "none")).lower()
    imp_val = str(signals_map.get("impersonation", "none")).lower()
    link_val = str(signals_map.get("suspicious_link", "none")).lower()
    att_val = str(signals_map.get("attachment_threat", "none")).lower()
    fear_val = str(signals_map.get("fear_manipulation", "none")).lower()
    auth_val = str(signals_map.get("authority_pressure", "none")).lower()

    explanation_parts: list[str] = []

    # 1. Primary Classification Clause
    if primary_threat == THREAT_BENIGN:
        explanation_parts.append(
            f"The email from '{from_addr}' with subject '{subject}' exhibits standard communication patterns with low aggregate risk."
        )
    elif primary_threat == THREAT_PHISHING:
        explanation_parts.append(
            "Potential phishing indicators detected. The message employs deceptive lures designed to induce the recipient into performing sensitive actions."
        )
    elif primary_threat == THREAT_BEC:
        explanation_parts.append(
            "Potential Business Email Compromise (BEC) indicators detected. The communication involves financial manipulation, payment redirection, or executive authority pretexting."
        )
    elif primary_threat == THREAT_CREDENTIAL_HARVESTING:
        explanation_parts.append(
            "Potential credential harvesting activity detected. The message explicitly prompts the recipient to enter, verify, or re-authenticate sensitive account credentials."
        )
    elif primary_threat == THREAT_IMPERSONATION:
        explanation_parts.append(
            "Potential sender or brand impersonation detected. Discrepancies exist between visible sender identity headers and actual sending infrastructure."
        )
    elif primary_threat == THREAT_SOCIAL_ENGINEERING:
        explanation_parts.append(
            "Potential social engineering indicators detected. The message uses coercive psychological framing, such as high urgency or fear of negative consequences, to bypass critical verification."
        )
    elif primary_threat == THREAT_SUSPICIOUS:
        explanation_parts.append(
            "Suspicious anomalies detected. While inconclusive for a specific attack taxonomy, multiple irregular structural, attachment, or header signals warrant caution."
        )

    # 2. Detected Signal Affirmations (Truthful attribution of observed signals)
    detected_signals: list[str] = []
    if urgency_val in ("low", "medium", "high"):
        urg_ind = next((i for i in indicators if "urgency" in str(i.get("category", "")).lower() or "urgency" in str(i.get("indicator", "")).lower()), None)
        ev = f" ('{urg_ind.get('evidence')}')" if urg_ind and urg_ind.get("evidence") else ""
        detected_signals.append(f"{urgency_val}-level urgency language{ev}")

    if fear_val in ("low", "medium", "high"):
        fear_ind = next((i for i in indicators if "fear" in str(i.get("category", "")).lower() or "fear" in str(i.get("indicator", "")).lower()), None)
        ev = f" ('{fear_ind.get('evidence')}')" if fear_ind and fear_ind.get("evidence") else ""
        detected_signals.append(f"{fear_val}-level fear/consequence framing{ev}")

    if auth_val in ("low", "medium", "high"):
        auth_ind = next((i for i in indicators if "authority" in str(i.get("category", "")).lower() or "authority" in str(i.get("indicator", "")).lower() or "secrecy" in str(i.get("category", "")).lower()), None)
        ev = f" ('{auth_ind.get('evidence')}')" if auth_ind and auth_ind.get("evidence") else ""
        detected_signals.append(f"{auth_val}-level authority/secrecy pressure{ev}")

    if cred_val in ("low", "medium", "high") and primary_threat != THREAT_CREDENTIAL_HARVESTING:
        cred_ind = next((i for i in indicators if "credential" in str(i.get("category", "")).lower() or "credential" in str(i.get("indicator", "")).lower()), None)
        ev = f" ('{cred_ind.get('evidence')}')" if cred_ind and cred_ind.get("evidence") else ""
        detected_signals.append(f"{cred_val}-level credential prompt language{ev}")

    if fin_val in ("low", "medium", "high") and primary_threat != THREAT_BEC:
        fin_ind = next((i for i in indicators if "financial" in str(i.get("category", "")).lower() or "financial" in str(i.get("indicator", "")).lower()), None)
        ev = f" ('{fin_ind.get('evidence')}')" if fin_ind and fin_ind.get("evidence") else ""
        detected_signals.append(f"{fin_val}-level financial/payment request{ev}")

    if imp_val in ("low", "medium", "high") and primary_threat != THREAT_IMPERSONATION:
        imp_ind = next((i for i in indicators if "impersonation" in str(i.get("category", "")).lower() or "impersonation" in str(i.get("indicator", "")).lower()), None)
        ev = f" ('{imp_ind.get('evidence')}')" if imp_ind and imp_ind.get("evidence") else ""
        detected_signals.append(f"{imp_val}-level identity/brand pretexting{ev}")

    if primary_threat == THREAT_BENIGN:
        if detected_signals:
            explanation_parts.append(
                f"Isolated minor observations were identified ({'; '.join(detected_signals)}), but remain below actionable malicious thresholds in isolation."
            )
        else:
            explanation_parts.append(
                "No significant urgency indicators or coercive psychological framing were detected."
            )
    else:
        if detected_signals:
            explanation_parts.append(
                f"Contributing behavioral signals: {'; '.join(detected_signals)}."
            )

    # 3. Explicit Statement of Absent Threats (Truthful negation)
    absent_categories: list[str] = []
    if cred_val == "none" and primary_threat != THREAT_CREDENTIAL_HARVESTING:
        absent_categories.append("credential solicitation")
    if fin_val == "none" and primary_threat != THREAT_BEC:
        absent_categories.append("financial fraud patterns")
    if link_val == "none":
        absent_categories.append("deceptive links")
    if att_val == "none":
        absent_categories.append("dangerous attachments")

    if primary_threat == THREAT_BENIGN and absent_categories:
        explanation_parts.append(f"No {', '.join(absent_categories)} were detected.")

    # 4. Key Contributing Forensic Findings
    if primary_threat != THREAT_BENIGN:
        key_evidence = []
        high_inds = [ind for ind in indicators if ind.get("severity") == "high"]
        med_inds = [ind for ind in indicators if ind.get("severity") == "medium"]
        for ind in (high_inds + med_inds)[:3]:
            key_evidence.append(f"{ind.get('description')} ({ind.get('evidence', '')})")
        if key_evidence:
            explanation_parts.append("Key forensic findings: " + "; ".join(key_evidence) + ".")

    # 5. Secondary Threats
    if secondary_threats:
        sec_str = ", ".join(secondary_threats)
        explanation_parts.append(f"Associated secondary threat categories: {sec_str}.")

    # 6. Attribution Safeguard
    explanation_parts.append(
        "Note: Classification is an algorithmic assessment based on observed message content and header metadata, and does not assert physical attacker attribution."
    )

    return " ".join(explanation_parts)


def _separate_facts_and_inferences(
    indicators: list[dict[str, Any]],
    parsed_email: dict,
    forensic_analysis: dict | None = None,
) -> dict[str, list[str]]:
    """
    Strictly separate verified forensic facts from AI inferences.
    """
    facts: list[str] = []
    inferences: list[str] = []

    sender = parsed_email.get("sender", {})
    from_addr = sender.get("email")
    if from_addr:
        facts.append(f"Sender From header address is '{from_addr}'.")

    if sender.get("display_name"):
        facts.append(f"Sender display name is '{sender.get('display_name')}'.")

    # Step 3 facts if available
    if forensic_analysis:
        for f in forensic_analysis.get("facts", []):
            facts.append(f.get("description") or f.get("title", ""))
    else:
        # Basic parser facts
        auth = parsed_email.get("authentication", {})
        if auth.get("spf", {}).get("status"):
            facts.append(f"SPF authentication status is recorded as '{auth.get('spf', {}).get('status')}'.")
        if auth.get("dkim", {}).get("status"):
            facts.append(f"DKIM authentication status is recorded as '{auth.get('dkim', {}).get('status')}'.")
        if auth.get("dmarc", {}).get("status"):
            facts.append(f"DMARC authentication status is recorded as '{auth.get('dmarc', {}).get('status')}'.")

    urls = parsed_email.get("urls", [])
    if urls:
        facts.append(f"Email contains {len(urls)} extracted URL(s).")

    attachments = parsed_email.get("attachments", [])
    if attachments:
        facts.append(f"Email contains {len(attachments)} attachment(s): {', '.join(a.get('filename', 'unnamed') for a in attachments)}.")

    # Inferences derived from indicators
    for ind in indicators:
        inferences.append(f"Inference: {ind.get('description')} [Evidence: {ind.get('evidence', 'N/A')}]")

    return {
        "facts": facts[:10],
        "inferences": inferences[:10],
    }


# ================================================================== #
#  Optional LLM Provider Integration                                 #
# ================================================================== #

async def _call_llm_analyzer(
    parsed_email: dict,
    forensic_analysis: dict | None,
) -> dict[str, Any] | None:
    """
    Optionally invoke an external LLM API if OPENAI_API_KEY is configured.
    Enforces strict structured JSON output and schema validation.
    Returns None on any error or missing key to trigger local fallback.
    """
    api_key = settings.OPENAI_API_KEY
    if not api_key:
        return None

    try:
        import httpx  # type: ignore
    except ImportError:
        logger.warning("httpx not installed; skipping LLM call.")
        return None

    # Prepare sanitized context for LLM
    sender = parsed_email.get("sender", {})
    headers = parsed_email.get("headers", {})
    body_obj = parsed_email.get("body", {})
    body = ""
    if isinstance(body_obj, dict):
        body = body_obj.get("normalized") or body_obj.get("plain") or body_obj.get("html") or ""
    elif isinstance(body_obj, str):
        body = body_obj
    body_snippet = body[:2000]

    forensic_summary = {}
    if forensic_analysis:
        forensic_summary = {
            "status": forensic_analysis.get("summary", {}).get("status"),
            "failed_count": forensic_analysis.get("summary", {}).get("failed_count", 0),
            "high_risk_findings": forensic_analysis.get("summary", {}).get("high_risk_findings_count", 0),
            "key_findings": [f.get("title") for f in forensic_analysis.get("findings", [])[:5]],
        }

    prompt = (
        "You are an explainable email threat intelligence system. Analyze the following email metadata and content.\n"
        "Classify the threat into one primary threat category: PHISHING, BEC, CREDENTIAL_HARVESTING, IMPERSONATION, SOCIAL_ENGINEERING, SUSPICIOUS, or BENIGN.\n"
        "Return ONLY valid JSON matching this schema:\n"
        "{\n"
        '  "primary_threat": "PHISHING|BEC|CREDENTIAL_HARVESTING|IMPERSONATION|SOCIAL_ENGINEERING|SUSPICIOUS|BENIGN",\n'
        '  "secondary_threats": ["optional other threat strings"],\n'
        '  "confidence": 0.85,\n'
        '  "signals": {"urgency": "none|low|medium|high", "credential_request": "none|low|medium|high", "financial_request": "none|low|medium|high", "impersonation": "none|low|medium|high", "suspicious_link": "none|low|medium|high", "attachment_threat": "none|low|medium|high", "fear_manipulation": "none|low|medium|high", "authority_pressure": "none|low|medium|high"},\n'
        '  "indicators": [{"indicator": "string", "category": "content|identity|authentication|link|attachment", "weight": 0.8, "severity": "low|medium|high", "description": "string", "evidence": "string"}],\n'
        '  "explanation": "concise grounded explanation"\n'
        "}\n\n"
        "CRITICAL RULES:\n"
        "1. Do not invent facts or claims not supported by the supplied metadata.\n"
        "2. Do not attempt physical attacker attribution or name specific individuals.\n"
        "3. Phrasing for BEC must be 'Potential BEC indicators detected'.\n\n"
        f"EMAIL DATA:\n"
        f"From: {sender.get('email')} (Display Name: {sender.get('display_name')})\n"
        f"Subject: {headers.get('subject')}\n"
        f"Body Preview:\n{body_snippet}\n"
        f"Forensic Context: {json.dumps(forensic_summary)}\n"
    )

    headers_req = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.OPENAI_MODEL or "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a specialized email security classifier that outputs strict JSON."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("https://api.openai.com/v1/chat/completions", headers=headers_req, json=payload)
            if resp.status_code != 200:
                logger.warning(f"LLM request returned status {resp.status_code}: {resp.text}")
                return None

            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            result = json.loads(content)

            # Validate basic structure
            if "primary_threat" in result and result["primary_threat"] in ALL_THREAT_CATEGORIES:
                result["analysis_method"] = "llm"
                result["model_info"] = settings.OPENAI_MODEL or "gpt-4o-mini"
                return result
            else:
                logger.warning(f"LLM returned invalid category: {result.get('primary_threat')}")
                return None
    except Exception as exc:
        logger.warning(f"LLM analysis failed, falling back to local engine: {exc}")
        return None


# ================================================================== #
#  Public Entry Point                                                 #
# ================================================================== #

def analyze_threat(
    parsed_email: dict[str, Any],
    forensic_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform explainable AI threat analysis on parsed email content and forensic evidence.

    Returns a structured dictionary containing:
        - primary_threat: str
        - secondary_threats: list[str]
        - confidence: float (0.0 to 1.0)
        - signals: dict
        - indicators: list[dict]
        - explanation: str
        - evidence_summary: dict (facts and inferences)
        - analysis_method: 'local' | 'llm'
        - model_info: str
    """
    if not isinstance(parsed_email, dict):
        parsed_email = {}

    headers = parsed_email.get("headers", {})
    subject = headers.get("subject") or ""

    body_obj = parsed_email.get("body", {})
    if isinstance(body_obj, dict):
        body_text = (
            body_obj.get("normalized")
            or body_obj.get("plain")
            or body_obj.get("html")
            or body_obj.get("normalized_text")
            or body_obj.get("plain_text")
            or body_obj.get("html_text")
            or ""
        )
    elif isinstance(body_obj, str):
        body_text = body_obj
    else:
        body_text = ""

    # 1. Extract signals and indicators deterministically
    signals_map, indicators = _extract_content_signals(
        subject=subject,
        body_text=body_text,
        parsed_email=parsed_email,
        forensic_analysis=forensic_analysis,
    )

    # 2. Classify threat
    primary_threat, secondary_threats, confidence = _classify_threat(
        signals_map=signals_map,
        indicators=indicators,
        parsed_email=parsed_email,
        forensic_analysis=forensic_analysis,
    )

    # 3. Generate explainable explanation
    explanation = _generate_explanation(
        primary_threat=primary_threat,
        secondary_threats=secondary_threats,
        signals_map=signals_map,
        indicators=indicators,
        parsed_email=parsed_email,
        forensic_analysis=forensic_analysis,
    )

    # 4. Separate facts and inferences
    evidence_summary = _separate_facts_and_inferences(
        indicators=indicators,
        parsed_email=parsed_email,
        forensic_analysis=forensic_analysis,
    )

    result = {
        "primary_threat": primary_threat,
        "secondary_threats": secondary_threats,
        "confidence": confidence,
        "signals": signals_map,
        "indicators": indicators,
        "explanation": explanation,
        "evidence_summary": evidence_summary,
        "analysis_method": "local",
        "model_info": "rule-nlp-engine-v1",
    }

    return result


def validate_threat_consistency(
    threat_analysis: dict[str, Any],
    risk_assessment: dict[str, Any] | None = None,
    parsed_email: dict[str, Any] | None = None,
) -> list[str]:
    """
    Automated consistency validator to detect internal contradictions across:
    - Signals vs. Explanation narrative
    - Signals vs. Risk factors
    - Threat classification vs. Supporting evidence
    - Confidence sanity

    Returns a list of contradiction error strings (empty list [] if fully consistent).
    """
    contradictions: list[str] = []

    if not isinstance(threat_analysis, dict):
        return ["Threat analysis is missing or not a dictionary."]

    primary = threat_analysis.get("primary_threat", "")
    secondaries = threat_analysis.get("secondary_threats", []) or []
    confidence = float(threat_analysis.get("confidence", 0.0))
    signals = threat_analysis.get("signals", {}) or {}
    explanation = threat_analysis.get("explanation", "") or ""
    exp_lower = explanation.lower()

    # 1. Check Signal vs. Explanation Contradictions
    urgency_level = signals.get("urgency", "none")
    if urgency_level in ("medium", "high") and ("no significant urgency" in exp_lower or "no urgency" in exp_lower):
        contradictions.append(f"Urgency signal is '{urgency_level}' but explanation claims no urgency indicators were detected.")

    cred_level = signals.get("credential_request", "none")
    if cred_level in ("medium", "high") and ("no credential solicitation" in exp_lower or "no credential" in exp_lower):
        contradictions.append(f"Credential request signal is '{cred_level}' but explanation claims no credential solicitation was detected.")

    fin_level = signals.get("financial_request", "none")
    if fin_level in ("medium", "high") and ("no financial fraud" in exp_lower or "no financial manipulation" in exp_lower or "no financial" in exp_lower):
        contradictions.append(f"Financial request signal is '{fin_level}' but explanation claims no financial patterns were detected.")

    link_level = signals.get("suspicious_link", "none")
    if link_level in ("medium", "high") and "no deceptive links" in exp_lower:
        contradictions.append(f"Suspicious link signal is '{link_level}' but explanation claims no deceptive links were detected.")

    att_level = signals.get("attachment_threat", "none")
    if att_level in ("medium", "high") and "no dangerous attachments" in exp_lower:
        contradictions.append(f"Attachment threat signal is '{att_level}' but explanation claims no dangerous attachments were detected.")

    # 2. Check Classification vs. Supporting Evidence
    if primary == THREAT_BENIGN:
        # Benign classification should not have critical signals or high urgency+fear
        if urgency_level == "high" and signals.get("fear_manipulation") == "high":
            contradictions.append("Primary classification is BENIGN despite high urgency and high fear manipulation signals.")
        if cred_level == "high" and link_level == "high":
            contradictions.append("Primary classification is BENIGN despite high credential request and high suspicious link signals.")

    if primary == THREAT_CREDENTIAL_HARVESTING and cred_level == "none":
        contradictions.append("Primary classification is CREDENTIAL_HARVESTING but credential_request signal is 'none'.")

    if primary == THREAT_BEC and fin_level == "none" and signals.get("authority_pressure") == "none":
        contradictions.append("Primary classification is BEC but neither financial_request nor authority_pressure signals were observed.")

    if primary == THREAT_PHISHING and all(signals.get(k) == "none" for k in ("impersonation", "credential_request", "suspicious_link", "attachment_threat", "fear_manipulation")):
        contradictions.append("Primary classification is PHISHING but no supporting phishing signals were observed.")

    if THREAT_SOCIAL_ENGINEERING in secondaries and all(signals.get(k) in ("none", "") for k in ("urgency", "fear_manipulation", "authority_pressure")):
        contradictions.append("Secondary threats include SOCIAL_ENGINEERING but no urgency, fear, or authority pressure signals were detected.")

    # 3. Check Risk Assessment Factors vs. Signals
    if risk_assessment and isinstance(risk_assessment, dict):
        risk_factors = risk_assessment.get("top_risk_factors", []) or []
        for factor in risk_factors:
            f_name = factor.get("factor", "")
            f_pts = float(factor.get("points", 0.0))
            if f_pts > 0:
                if "Urgent Coercion Language" in f_name and urgency_level == "none":
                    contradictions.append("Risk assessment awarded points for Urgent Coercion Language, but urgency threat signal is 'none'.")
                if "Credential Prompt Language" in f_name and cred_level == "none":
                    contradictions.append("Risk assessment awarded points for Credential Prompt Language, but credential_request signal is 'none'.")
                if "Financial / Wire Transfer Request" in f_name and fin_level == "none":
                    contradictions.append("Risk assessment awarded points for Financial / Wire Transfer Request, but financial_request signal is 'none'.")
                if "Fear & Intimidation Language" in f_name and signals.get("fear_manipulation", "none") == "none":
                    contradictions.append("Risk assessment awarded points for Fear & Intimidation Language, but fear_manipulation signal is 'none'.")

    return contradictions

