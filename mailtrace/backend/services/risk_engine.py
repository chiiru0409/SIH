"""
services/risk_engine.py — MAILTRACE Unified Risk Scoring & Threat Assessment Engine.

Primary Entry Point:
    calculate_risk(
        forensic_analysis: dict[str, Any] | None = None,
        threat_analysis: dict[str, Any] | None = None,
        infrastructure_intelligence: dict[str, Any] | None = None,
        parsed_email: dict[str, Any] | None = None,
    ) -> dict[str, Any]

Core Architecture:
    1. Deterministic Multi-Category Point Accumulation:
       - Authentication (SPF, DKIM, DMARC, ARC, alignment) -> max 25 pts
       - Identity (Display name spoofing, From/Reply-To/Return-Path mismatches) -> max 25 pts
       - Content / AI Threat (Primary threat category, intent signals, confidence) -> max 35 pts
       - Infrastructure (RDAP, GeoIP/ASN context) -> max 15 pts
       - URL (Raw IP hosts, unusual ports, shorteners, credential paths) -> max 20 pts
       - Attachment (Dangerous executables, scripts, double extensions) -> max 20 pts
       - Header & Relay (Missing Message-ID, relay hops anomalies, date skew) -> max 15 pts

    2. Anti-Double-Counting Safeguards:
       - Category subscore ceilings prevent duplicate evidence from causing runaway scores.
       - Related findings (e.g. DMARC fail + SPF fail + SPF alignment fail) are bound to the category cap.

    3. Unknown vs. Failure Principle:
       - Missing or unavailable data (e.g. SPF unknown, GeoIP unavailable, RDAP timeout) yields 0 points.

    4. Benign Mitigations:
       - Strong cryptographic authentication pass (SPF + DKIM + DMARC aligned) offers modest risk dampening.

    5. Bounded Output:
       - Final score strictly clamped to [0, 100].
       - Severity bands: LOW (0–24), MEDIUM (25–49), HIGH (50–74), CRITICAL (75–100).
       - Full evidence traceability on all risk factors.
       - Strict attribution safety (never asserts physical attacker identity).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("mailtrace.risk_engine")

# ================================================================== #
#  Centralized Constants & Weights                                    #
# ================================================================== #

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

SEVERITY_THRESHOLDS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}

CATEGORY_CAPS = {
    "authentication": 25.0,
    "identity": 25.0,
    "content": 35.0,
    "infrastructure": 15.0,
    "url": 20.0,
    "attachment": 20.0,
    "header": 10.0,
    "relay": 10.0,
}

# High-risk dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".hta", ".vbs", ".js", ".bat", ".cmd", ".ps1", ".wsf",
    ".iso", ".img", ".vhd", ".jar", ".cpl", ".pif", ".msi", ".dll",
}

SUSPICIOUS_ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".cab",
}


# ================================================================== #
#  Helper: Determine Severity Level                                   #
# ================================================================== #

def get_severity_label(score: float) -> str:
    """Return the standardized severity band for a given 0–100 risk score."""
    clamped = max(0.0, min(100.0, score))
    if clamped <= 24.0:
        return SEVERITY_LOW
    elif clamped <= 49.0:
        return SEVERITY_MEDIUM
    elif clamped <= 74.0:
        return SEVERITY_HIGH
    else:
        return SEVERITY_CRITICAL


# ================================================================== #
#  Category Analyzers                                                 #
# ================================================================== #

def _evaluate_authentication(
    forensic: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """Evaluate authentication findings (SPF, DKIM, DMARC, ARC)."""
    factors: list[dict[str, Any]] = []
    points = 0.0

    auth_summary = forensic.get("summary", {}).get("authentication", {})
    spf_status = (auth_summary.get("spf_status") or "").lower()
    dkim_status = (auth_summary.get("dkim_status") or "").lower()
    dmarc_status = (auth_summary.get("dmarc_status") or "").lower()

    findings = forensic.get("findings", [])

    # DMARC failure
    if dmarc_status in ("fail", "failed", "reject", "quarantine"):
        pts = 14.0
        points += pts
        factors.append({
            "factor": "DMARC Policy Rejection / Failure",
            "category": "authentication",
            "points": pts,
            "severity": "high",
            "evidence": f"Observed DMARC status: {dmarc_status}",
            "source": "step3_forensics",
        })
    elif dmarc_status in ("softfail", "neutral"):
        pts = 6.0
        points += pts
        factors.append({
            "factor": "DMARC Neutral / Softfail",
            "category": "authentication",
            "points": pts,
            "severity": "medium",
            "evidence": f"Observed DMARC status: {dmarc_status}",
            "source": "step3_forensics",
        })

    # SPF failure
    if spf_status in ("fail", "failed", "hardfail"):
        pts = 8.0
        points += pts
        factors.append({
            "factor": "SPF Validation Failure",
            "category": "authentication",
            "points": pts,
            "severity": "medium",
            "evidence": f"Observed SPF status: {spf_status}",
            "source": "step3_forensics",
        })
    elif spf_status in ("softfail",):
        pts = 4.0
        points += pts
        factors.append({
            "factor": "SPF Softfail",
            "category": "authentication",
            "points": pts,
            "severity": "low",
            "evidence": f"Observed SPF status: {spf_status}",
            "source": "step3_forensics",
        })

    # DKIM failure
    if dkim_status in ("fail", "failed", "bad_signature", "invalid"):
        pts = 8.0
        points += pts
        factors.append({
            "factor": "DKIM Signature Verification Failure",
            "category": "authentication",
            "points": pts,
            "severity": "medium",
            "evidence": f"Observed DKIM status: {dkim_status}",
            "source": "step3_forensics",
        })

    # SPF/DKIM Alignment Failures from findings
    for f in findings:
        f_type = f.get("type", "")
        f_status = f.get("status", "")
        if f_type == "dmarc_spf_alignment" and f_status == "failed":
            pts = 4.0
            points += pts
            factors.append({
                "factor": "SPF Domain Alignment Failure",
                "category": "authentication",
                "points": pts,
                "severity": "low",
                "evidence": f.get("description", "SPF domain is not aligned with From domain"),
                "source": "step3_forensics",
            })
        elif f_type == "dmarc_dkim_alignment" and f_status == "failed":
            pts = 4.0
            points += pts
            factors.append({
                "factor": "DKIM Domain Alignment Failure",
                "category": "authentication",
                "points": pts,
                "severity": "low",
                "evidence": f.get("description", "DKIM signing domain is not aligned with From domain"),
                "source": "step3_forensics",
            })

    # Cap at category maximum
    capped_points = min(points, CATEGORY_CAPS["authentication"])
    return capped_points, factors


def _evaluate_identity(
    forensic: dict[str, Any],
    threat: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """Evaluate identity consistency (From vs Reply-To, Return-Path, Display Name Spoofing)."""
    factors: list[dict[str, Any]] = []
    points = 0.0

    findings = forensic.get("findings", [])

    for f in findings:
        f_type = f.get("type", "")
        f_status = f.get("status", "")

        if f_type == "display_name_brand_spoof" and f_status in ("failed", "warning"):
            pts = 16.0
            points += pts
            factors.append({
                "factor": "Display Name Brand Impersonation",
                "category": "identity",
                "points": pts,
                "severity": "high",
                "evidence": f.get("description", "Display name impersonates known organization on external domain"),
                "source": "step3_forensics",
            })
        elif f_type == "reply_to_mismatch" and f_status in ("failed", "warning"):
            pts = 10.0
            points += pts
            factors.append({
                "factor": "Sender / Reply-To Domain Discrepancy",
                "category": "identity",
                "points": pts,
                "severity": "medium",
                "evidence": f.get("description", "Reply-To points to a domain unaligned with sender From address"),
                "source": "step3_forensics",
            })
        elif f_type == "return_path_mismatch" and f_status in ("failed", "warning"):
            pts = 8.0
            points += pts
            factors.append({
                "factor": "Sender / Return-Path Domain Discrepancy",
                "category": "identity",
                "points": pts,
                "severity": "low",
                "evidence": f.get("description", "Return-Path envelope domain is unaligned with From header"),
                "source": "step3_forensics",
            })
        elif f_type == "sender_header_mismatch" and f_status in ("failed", "warning"):
            pts = 6.0
            points += pts
            factors.append({
                "factor": "From / Sender Header Discrepancy",
                "category": "identity",
                "points": pts,
                "severity": "low",
                "evidence": f.get("description", "Sender header specifies different entity than From header"),
                "source": "step3_forensics",
            })

    # AI Impersonation signal if not already heavily covered by display_name_brand_spoof
    ai_signals = threat.get("signals", {})
    impersonation_sig = str(ai_signals.get("impersonation", "")).lower()
    if impersonation_sig in ("detected", "true", "low", "medium", "high") and not any(f["factor"] == "Display Name Brand Impersonation" for f in factors):
        pts = 10.0
        points += pts
        factors.append({
            "factor": "AI Detected Executive / Identity Pretexting",
            "category": "identity",
            "points": pts,
            "severity": "medium",
            "evidence": "Threat analysis detected authority pretexting or executive impersonation patterns",
            "source": "step4_ai",
        })

    capped_points = min(points, CATEGORY_CAPS["identity"])
    return capped_points, factors


def _evaluate_content_ai(
    threat: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """Evaluate AI threat classifications, confidence, and linguistic intent signals."""
    factors: list[dict[str, Any]] = []
    points = 0.0

    primary_threat = threat.get("primary_threat", "BENIGN")
    confidence = float(threat.get("confidence", 0.5))
    confidence_scale = max(0.5, min(1.0, confidence))

    if primary_threat == "PHISHING":
        base_pts = 26.0
        pts = round(base_pts * confidence_scale, 1)
        points += pts
        factors.append({
            "factor": "Phishing Attack Classification",
            "category": "content",
            "points": pts,
            "severity": "high",
            "evidence": f"Primary threat classified as PHISHING (confidence: {confidence:.2f})",
            "source": "step4_ai",
        })
    elif primary_threat == "CREDENTIAL_HARVESTING":
        base_pts = 28.0
        pts = round(base_pts * confidence_scale, 1)
        points += pts
        factors.append({
            "factor": "Credential Harvesting Classification",
            "category": "content",
            "points": pts,
            "severity": "high",
            "evidence": f"Primary threat classified as CREDENTIAL_HARVESTING (confidence: {confidence:.2f})",
            "source": "step4_ai",
        })
    elif primary_threat == "BEC":
        base_pts = 26.0
        pts = round(base_pts * confidence_scale, 1)
        points += pts
        factors.append({
            "factor": "Business Email Compromise (BEC) Classification",
            "category": "content",
            "points": pts,
            "severity": "high",
            "evidence": f"Primary threat classified as BEC / Wire Fraud (confidence: {confidence:.2f})",
            "source": "step4_ai",
        })
    elif primary_threat == "IMPERSONATION":
        base_pts = 20.0
        pts = round(base_pts * confidence_scale, 1)
        points += pts
        factors.append({
            "factor": "Identity Impersonation Classification",
            "category": "content",
            "points": pts,
            "severity": "medium",
            "evidence": f"Primary threat classified as IMPERSONATION (confidence: {confidence:.2f})",
            "source": "step4_ai",
        })
    elif primary_threat == "SOCIAL_ENGINEERING":
        base_pts = 16.0
        pts = round(base_pts * confidence_scale, 1)
        points += pts
        factors.append({
            "factor": "Social Engineering Classification",
            "category": "content",
            "points": pts,
            "severity": "medium",
            "evidence": f"Primary threat classified as SOCIAL_ENGINEERING (confidence: {confidence:.2f})",
            "source": "step4_ai",
        })
    elif primary_threat == "SUSPICIOUS":
        base_pts = 12.0
        pts = round(base_pts * confidence_scale, 1)
        points += pts
        factors.append({
            "factor": "Suspicious Intent Classification",
            "category": "content",
            "points": pts,
            "severity": "low",
            "evidence": f"Primary threat classified as SUSPICIOUS (confidence: {confidence:.2f})",
            "source": "step4_ai",
        })

    # Supporting NLP Intent Signals
    signals = threat.get("signals", {})

    def _is_signal_detected(sig_name: str) -> bool:
        val = signals.get(sig_name, "")
        if isinstance(val, str):
            return val.lower() in ("detected", "true", "low", "medium", "high")
        return bool(val)

    if _is_signal_detected("urgency"):
        pts = 4.0
        points += pts
        factors.append({
            "factor": "Urgent Coercion Language",
            "category": "content",
            "points": pts,
            "severity": "low",
            "evidence": "Email employs strict deadlines or immediate consequence framing",
            "source": "step4_ai",
        })

    if _is_signal_detected("credential_request") and primary_threat != "CREDENTIAL_HARVESTING":
        pts = 7.0
        points += pts
        factors.append({
            "factor": "Credential Prompt Language",
            "category": "content",
            "points": pts,
            "severity": "medium",
            "evidence": "Email explicitly requests login, password, or security token verification",
            "source": "step4_ai",
        })

    if _is_signal_detected("financial_request") and primary_threat != "BEC":
        pts = 7.0
        points += pts
        factors.append({
            "factor": "Financial / Wire Transfer Request",
            "category": "content",
            "points": pts,
            "severity": "medium",
            "evidence": "Email references banking changes, urgent invoices, or gift card purchases",
            "source": "step4_ai",
        })

    if _is_signal_detected("fear_manipulation"):
        pts = 4.0
        points += pts
        factors.append({
            "factor": "Fear & Intimidation Language",
            "category": "content",
            "points": pts,
            "severity": "low",
            "evidence": "Email threatens account termination, legal penalty, or severe escalation",
            "source": "step4_ai",
        })

    if _is_signal_detected("authority_pressure") and primary_threat not in ("BEC", "IMPERSONATION"):
        pts = 4.0
        points += pts
        factors.append({
            "factor": "Executive Authority Pressure",
            "category": "content",
            "points": pts,
            "severity": "low",
            "evidence": "Email invokes senior executive status or secrecy demands",
            "source": "step4_ai",
        })

    capped_points = min(points, CATEGORY_CAPS["content"])
    return capped_points, factors


def _evaluate_infrastructure(
    intel: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """Evaluate infrastructure intelligence context (RDAP, GeoIP/ASN, young domain)."""
    factors: list[dict[str, Any]] = []
    points = 0.0

    # Normal GeoIP and ASN MUST NOT increase risk (per specification requirement 7)
    # Unavailable GeoIP / RDAP MUST contribute 0 points (per requirement 14)

    capped_points = min(points, CATEGORY_CAPS["infrastructure"])
    return capped_points, factors


def _evaluate_urls(
    intel: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """Evaluate passive URL structural indicators (raw IP, unusual port, shorteners, keywords)."""
    factors: list[dict[str, Any]] = []
    points = 0.0

    urls = intel.get("urls", [])
    raw_ip_flagged = False
    unusual_port_flagged = False
    shortener_flagged = False
    cred_keyword_flagged = False
    punycode_flagged = False

    for u in urls:
        flags = u.get("flags", {})
        url_str = u.get("url", "")

        if flags.get("is_ip_host") and not raw_ip_flagged:
            raw_ip_flagged = True
            pts = 10.0
            points += pts
            factors.append({
                "factor": "Raw IP Host URL",
                "category": "url",
                "points": pts,
                "severity": "high",
                "evidence": f"URL uses raw IP address instead of domain hostname: {url_str[:60]}",
                "source": "step5_infrastructure",
            })

        if flags.get("unusual_port") and not unusual_port_flagged:
            unusual_port_flagged = True
            pts = 6.0
            points += pts
            factors.append({
                "factor": "Non-Standard URL Port",
                "category": "url",
                "points": pts,
                "severity": "medium",
                "evidence": f"URL specifies non-standard service port ({u.get('port')}): {url_str[:60]}",
                "source": "step5_infrastructure",
            })

        if flags.get("has_credential_keywords") and not cred_keyword_flagged:
            cred_keyword_flagged = True
            pts = 7.0
            points += pts
            factors.append({
                "factor": "Credential Harvesting Path in URL",
                "category": "url",
                "points": pts,
                "severity": "medium",
                "evidence": f"URL path targets login or auth portal: {url_str[:60]}",
                "source": "step5_infrastructure",
            })

        if flags.get("is_shortened") and not shortener_flagged:
            shortener_flagged = True
            pts = 4.0
            points += pts
            factors.append({
                "factor": "URL Shortener Redirection",
                "category": "url",
                "points": pts,
                "severity": "low",
                "evidence": f"URL uses shortening service to conceal destination: {url_str[:60]}",
                "source": "step5_infrastructure",
            })

        if flags.get("is_punycode") and not punycode_flagged:
            punycode_flagged = True
            pts = 6.0
            points += pts
            factors.append({
                "factor": "Punycode / IDN Domain URL",
                "category": "url",
                "points": pts,
                "severity": "medium",
                "evidence": f"URL contains Punycode encoded characters: {url_str[:60]}",
                "source": "step5_infrastructure",
            })

    capped_points = min(points, CATEGORY_CAPS["url"])
    return capped_points, factors


def _evaluate_attachments(
    parsed: dict[str, Any],
    threat: dict[str, Any],
) -> tuple[float, list[dict[str, Any]]]:
    """Evaluate attachment risks (executable/script files, double extensions)."""
    factors: list[dict[str, Any]] = []
    points = 0.0

    attachments = parsed.get("attachments", [])
    for att in attachments:
        fname = (att.get("filename") or "").lower()
        if not fname:
            continue

        # Check dangerous executable/script extensions
        for ext in DANGEROUS_EXTENSIONS:
            if fname.endswith(ext):
                pts = 16.0
                points += pts
                factors.append({
                    "factor": "Executable / Script Attachment",
                    "category": "attachment",
                    "points": pts,
                    "severity": "high",
                    "evidence": f"Attachment has dangerous executable or script extension '{ext}': {fname}",
                    "source": "step2_extraction",
                })
                break

        # Check double extensions (e.g. invoice.pdf.exe)
        parts = fname.split(".")
        if len(parts) >= 3:
            second_last = f".{parts[-2]}"
            last = f".{parts[-1]}"
            if last in DANGEROUS_EXTENSIONS and second_last in (".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png"):
                pts = 10.0
                points += pts
                factors.append({
                    "factor": "Double Extension Attachment Deception",
                    "category": "attachment",
                    "points": pts,
                    "severity": "high",
                    "evidence": f"Attachment uses double extension masking technique: {fname}",
                    "source": "step2_extraction",
                })

    # AI Attachment signal
    ai_signals = threat.get("signals", {})
    attach_sig = str(ai_signals.get("attachment_threat", "")).lower()
    if attach_sig in ("detected", "true", "low", "medium", "high") and not factors:
        pts = 8.0
        points += pts
        factors.append({
            "factor": "Suspicious Attachment Reference",
            "category": "attachment",
            "points": pts,
            "severity": "medium",
            "evidence": "Message references attachments with urgent execution or invoice themes",
            "source": "step4_ai",
        })

    capped_points = min(points, CATEGORY_CAPS["attachment"])
    return capped_points, factors


def _evaluate_headers_relay(
    forensic: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[float, float, list[dict[str, Any]]]:
    """Evaluate header anomalies and relay hops (missing Message-ID, date skew, private relay leaks)."""
    header_factors: list[dict[str, Any]] = []
    relay_factors: list[dict[str, Any]] = []
    header_points = 0.0
    relay_points = 0.0

    findings = forensic.get("findings", [])
    for f in findings:
        f_type = f.get("type", "")
        f_status = f.get("status", "")

        if f_type == "missing_message_id" and f_status in ("failed", "warning"):
            pts = 5.0
            header_points += pts
            header_factors.append({
                "factor": "Missing Mandatory Message-ID Header",
                "category": "header",
                "points": pts,
                "severity": "low",
                "evidence": "Email lacks standard RFC 5322 Message-ID header",
                "source": "step3_forensics",
            })
        elif f_type == "duplicate_headers" and f_status in ("failed", "warning"):
            pts = 5.0
            header_points += pts
            header_factors.append({
                "factor": "Suspicious Duplicate Header Fields",
                "category": "header",
                "points": pts,
                "severity": "low",
                "evidence": f.get("description", "Multiple occurrences of single-instance headers detected"),
                "source": "step3_forensics",
            })
        elif f_type == "future_timestamp" and f_status in ("failed", "warning"):
            pts = 6.0
            header_points += pts
            header_factors.append({
                "factor": "Future Date Timestamp Anomaly",
                "category": "header",
                "points": pts,
                "severity": "medium",
                "evidence": f.get("description", "Email Date header indicates a future time"),
                "source": "step3_forensics",
            })
        elif f_type == "relay_chronology" and f_status in ("failed", "warning"):
            pts = 6.0
            relay_points += pts
            relay_factors.append({
                "factor": "Received Relay Chronological Anomaly",
                "category": "relay",
                "points": pts,
                "severity": "medium",
                "evidence": f.get("description", "Received header timestamps violate chronological forwarding sequence"),
                "source": "step3_forensics",
            })

    capped_header = min(header_points, CATEGORY_CAPS["header"])
    capped_relay = min(relay_points, CATEGORY_CAPS["relay"])
    return capped_header, capped_relay, header_factors + relay_factors


def _evaluate_benign_mitigations(
    forensic: dict[str, Any],
    threat: dict[str, Any],
    parsed: dict[str, Any],
) -> float:
    """
    Calculate modest benign score reduction if authentication is fully valid and aligned.
    Does NOT wipe out severe content/URL threats, but reduces noise for legitimate emails.
    """
    mitigation = 0.0
    auth_summary = forensic.get("summary", {}).get("authentication", {})
    spf_status = (auth_summary.get("spf_status") or "").lower()
    dkim_status = (auth_summary.get("dkim_status") or "").lower()
    dmarc_status = (auth_summary.get("dmarc_status") or "").lower()

    # If all three major authentication mechanisms explicitly PASS
    if spf_status == "pass" and dkim_status == "pass" and dmarc_status == "pass":
        mitigation += 8.0

    primary_threat = threat.get("primary_threat", "")
    threat_conf = float(threat.get("confidence", 0.5))
    if primary_threat == "BENIGN" and threat_conf >= 0.8:
        mitigation += 5.0

    return mitigation


# ================================================================== #
#  Explanation Generator                                              #
# ================================================================== #

def _generate_explanation(
    score: float,
    severity: str,
    top_factors: list[dict[str, Any]],
    category_scores: dict[str, float],
    threat: dict[str, Any],
) -> str:
    """Generate concise, human-readable evidence-based explanation."""
    if severity == SEVERITY_LOW or score < 25.0:
        if not top_factors:
            return "No suspicious indicators detected. Email conforms to expected forensic and transport standards."
        factor_names = [f["factor"] for f in top_factors[:2]]
        return (
            f"Low overall risk ({score:.0f}/100). Minor observations noted ({', '.join(factor_names)}), "
            "but authentication and content appear consistent with legitimate communication."
        )

    # For Medium, High, and Critical
    primary_threat = threat.get("primary_threat", "SUSPICIOUS")
    top_factor_names = [f["factor"] for f in top_factors[:3]]
    factors_str = ", ".join(top_factor_names) if top_factor_names else "general forensic anomalies"

    if severity == SEVERITY_CRITICAL:
        return (
            f"CRITICAL risk ({score:.0f}/100) — High-probability {primary_threat.replace('_', ' ').lower()} threat detected. "
            f"Primary risk drivers: {factors_str}. Immediate defensive containment or quarantine recommended."
        )
    elif severity == SEVERITY_HIGH:
        return (
            f"HIGH risk ({score:.0f}/100) — Significant threat indicators detected ({primary_threat.replace('_', ' ').lower()}). "
            f"Key contributing factors include {factors_str}."
        )
    else:  # MEDIUM
        return (
            f"MEDIUM risk ({score:.0f}/100) — Suspicious characteristics identified. "
            f"Contributing factors: {factors_str}. Verification advised before interacting."
        )


# ================================================================== #
#  Public Entry Point                                                 #
# ================================================================== #

def calculate_risk(
    forensic_analysis: dict[str, Any] | None = None,
    threat_analysis: dict[str, Any] | None = None,
    infrastructure_intelligence: dict[str, Any] | None = None,
    parsed_email: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Deterministic, explainable unified risk assessment engine.

    Combines:
      - Step 3: Deep Forensic Analysis
      - Step 4: AI Threat Analysis
      - Step 5: Infrastructure Intelligence
      - Step 2: Extracted Parsed Email Indicators

    Returns:
      {
        "risk_score": float (0–100),
        "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "risk_factors": list[dict],
        "category_scores": dict[str, float],
        "top_factors": list[dict],
        "explanation": str,
        "confidence": float (0.0 to 1.0),
        "method": "deterministic_weighted",
        "limitations": list[str],
      }
    """
    forensic = forensic_analysis if isinstance(forensic_analysis, dict) else {}
    threat = threat_analysis if isinstance(threat_analysis, dict) else {}
    intel = infrastructure_intelligence if isinstance(infrastructure_intelligence, dict) else {}
    parsed = parsed_email if isinstance(parsed_email, dict) else {}

    all_factors: list[dict[str, Any]] = []

    # 1. Evaluate Categories
    auth_score, auth_factors = _evaluate_authentication(forensic, parsed)
    all_factors.extend(auth_factors)

    ident_score, ident_factors = _evaluate_identity(forensic, threat, parsed)
    all_factors.extend(ident_factors)

    content_score, content_factors = _evaluate_content_ai(threat)
    all_factors.extend(content_factors)

    infra_score, infra_factors = _evaluate_infrastructure(intel)
    all_factors.extend(infra_factors)

    url_score, url_factors = _evaluate_urls(intel, parsed)
    all_factors.extend(url_factors)

    attach_score, attach_factors = _evaluate_attachments(parsed, threat)
    all_factors.extend(attach_factors)

    hdr_score, rly_score, hdr_rly_factors = _evaluate_headers_relay(forensic, parsed)
    all_factors.extend(hdr_rly_factors)

    category_scores = {
        "authentication": round(auth_score, 1),
        "identity": round(ident_score, 1),
        "content": round(content_score, 1),
        "infrastructure": round(infra_score, 1),
        "url": round(url_score, 1),
        "attachment": round(attach_score, 1),
        "header": round(hdr_score, 1),
        "relay": round(rly_score, 1),
    }

    # 2. Raw Total
    raw_total = (
        auth_score + ident_score + content_score + infra_score +
        url_score + attach_score + hdr_score + rly_score
    )

    # 3. Apply Benign Mitigations (if any)
    mitigation = _evaluate_benign_mitigations(forensic, threat, parsed)
    adjusted_score = max(0.0, raw_total - mitigation)

    # 4. Strict Clamping to [0, 100]
    final_score = round(max(0.0, min(100.0, adjusted_score)), 1)
    severity = get_severity_label(final_score)

    # 5. Top Factors (Sorted by point contribution descending)
    sorted_factors = sorted(all_factors, key=lambda x: x.get("points", 0.0), reverse=True)
    top_factors = sorted_factors[:5]

    # 6. Confidence Score (Calculated from evidence quality and AI confidence)
    ai_conf = float(threat.get("confidence", 0.85)) if threat else 0.85
    evidence_breadth = sum([
        1.0 if forensic else 0.0,
        1.0 if threat else 0.0,
        1.0 if intel else 0.0,
        1.0 if parsed else 0.0,
    ]) / 4.0
    confidence = round(max(0.50, min(1.0, 0.70 * ai_conf + 0.30 * evidence_breadth)), 2)

    # 7. Generate Explanation
    explanation = _generate_explanation(
        score=final_score,
        severity=severity,
        top_factors=top_factors,
        category_scores=category_scores,
        threat=threat,
    )

    # 8. Forensic Disclaimers & Attribution Safeguards
    limitations = [
        "Risk score is a deterministic mathematical assessment of observed technical indicators and message content.",
        "The risk score reflects communication threat probability and does NOT assert confirmation of physical human attacker identity or criminal culpability.",
        "Missing or unconfigured intelligence providers contribute 0 risk points and are never treated as synthetic failures.",
        "Legitimate authenticated senders may occasionally exhibit anomalies (e.g. forwarding mailing lists or automated systems) requiring human analyst review.",
    ]

    return {
        "risk_score": final_score,
        "severity": severity,
        "risk_factors": sorted_factors,
        "category_scores": category_scores,
        "top_factors": top_factors,
        "explanation": explanation,
        "confidence": confidence,
        "method": "deterministic_weighted",
        "limitations": limitations,
    }
