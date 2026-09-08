"""
services/forensics.py — MAILTRACE Deep Email Forensic & Authentication Analysis.

Primary Entry Point:
    run_forensic_analysis(parsed_email: dict, raw_bytes: bytes | None = None) -> dict

Responsibilities:
    1. Authentication Forensics (SPF, DKIM, DMARC, ARC alignment & status).
    2. Identity Consistency Analysis (From vs Reply-To, Return-Path, Sender, DKIM, Message-ID, Display Name Spoofing).
    3. Received Header Relay Forensics (Hops, chronological validation, public vs internal IPs, earliest infrastructure).
    4. Header Anomaly Detection (Missing mandatory headers, duplicate headers, syntax anomalies).
    5. Message-ID Forensics (Domain consistency, syntax validation, missing tracking).
    6. Date & Timestamp Forensics (Future dates, chronological anomalies, timezone sanity).
    7. Strict FACT vs. INFERENCE Separation.

Design Rules:
    - Zero outbound network requests (offline / sandbox-safe).
    - Missing evidence produces 'unknown' / 'info' status — never fabricated failures.
    - Attribution language strictly uses 'earliest observed sending infrastructure', never 'attacker identity'.
    - Output is a deterministic, JSON-serializable dictionary.
"""

from __future__ import annotations

import email.utils
import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from backend.utils.ip_utils import classify_ip
from backend.utils.url_utils import normalize_domain

logger = logging.getLogger("mailtrace.forensics")


# ================================================================== #
#  Domain Alignment Helpers                                           #
# ================================================================== #

def _get_base_domain(domain: str) -> str:
    """Extract organizational/base domain (e.g. sub.example.com -> example.com)."""
    d = normalize_domain(domain)
    parts = d.split(".")
    if len(parts) >= 2:
        # Common two-level TLD checks
        two_level_tlds = {
            "co.uk", "gov.uk", "ac.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
            "com.au", "net.au", "org.au", "edu.au", "gov.au",
            "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "gov.in", "ac.in", "edu.in", "res.in",
            "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp",
            "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
            "com.br", "org.br", "net.br", "gov.br", "edu.br",
            "com.sg", "org.sg", "net.sg", "gov.sg", "edu.sg",
            "co.za", "org.za", "net.za", "gov.za", "ac.za",
        }
        if len(parts) >= 3 and ".".join(parts[-2:]) in two_level_tlds:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return d


def is_domain_aligned(domain_a: Optional[str], domain_b: Optional[str], strict: bool = False) -> bool:
    """
    Check if two domains are aligned according to DMARC alignment rules.
    - Strict: Exact match (example.com == example.com).
    - Relaxed (default): Base organizational domains match (mail.example.com == example.com).
    """
    if not domain_a or not domain_b:
        return False
    da = normalize_domain(domain_a)
    db = normalize_domain(domain_b)
    if da == db:
        return True
    if not strict:
        return _get_base_domain(da) == _get_base_domain(db)
    return False


# ================================================================== #
#  Finding Helper                                                     #
# ================================================================== #

def _create_finding(
    category: str,
    finding_type: str,
    severity: str,
    status: str,
    title: str,
    description: str,
    evidence: dict[str, Any],
    confidence: float,
    fact: bool,
    inference_note: Optional[str] = None,
) -> dict[str, Any]:
    """
    Construct a standardized forensic finding record.

    Categories: 'authentication' | 'identity' | 'headers' | 'relay' | 'message_id' | 'timestamp' | 'content' | 'integrity'
    Severity:   'info' | 'low' | 'medium' | 'high' | 'critical'
    Status:     'passed' | 'failed' | 'warning' | 'info' | 'unknown'
    """
    fid = f"find_{category}_{finding_type}_{uuid.uuid4().hex[:8]}"
    return {
        "finding_id": fid,
        "category": category,
        "type": finding_type,
        "severity": severity,
        "status": status,
        "title": title,
        "description": description,
        "evidence": evidence,
        "confidence": round(float(confidence), 2),
        "fact": bool(fact),
        "inference_note": inference_note if not fact else None,
    }


# ================================================================== #
#  1. Authentication Forensics                                        #
# ================================================================== #

def analyze_authentication(parsed_email: dict) -> tuple[list[dict], dict]:
    """
    Analyze SPF, DKIM, DMARC results and domain alignment.
    Never assumes failure when headers are merely absent.
    """
    findings: list[dict] = []
    auth = parsed_email.get("authentication") or {}
    sender = parsed_email.get("sender") or {}
    from_domain = sender.get("domain")
    return_path = parsed_email.get("return_path") or {}
    return_path_domain = return_path.get("domain") if return_path else None

    # --- 1.1 SPF Analysis ---
    spf_data = auth.get("spf") or {}
    spf_status = (spf_data.get("status") or "").lower()
    spf_raw = spf_data.get("raw")

    if not spf_status:
        findings.append(_create_finding(
            category="authentication",
            finding_type="spf_status",
            severity="info",
            status="unknown",
            title="SPF authentication result unobserved",
            description="No SPF result found in Authentication-Results or Received-SPF headers.",
            evidence={"observed_spf": None, "from_domain": from_domain},
            confidence=0.85,
            fact=True,
        ))
        spf_aligned = False
    elif spf_status == "pass":
        # Check alignment with From domain
        spf_domain = return_path_domain or from_domain
        spf_aligned = is_domain_aligned(from_domain, spf_domain, strict=False)
        
        findings.append(_create_finding(
            category="authentication",
            finding_type="spf_status",
            severity="info",
            status="passed",
            title="SPF authentication passed",
            description=f"Receiving mail server recorded SPF pass for envelope domain: {spf_domain}.",
            evidence={"spf_status": "pass", "envelope_domain": spf_domain, "raw": spf_raw},
            confidence=0.98,
            fact=True,
        ))
        
        if not spf_aligned and from_domain and spf_domain:
            findings.append(_create_finding(
                category="authentication",
                finding_type="spf_alignment",
                severity="medium",
                status="warning",
                title="SPF passed but domain is unaligned with From header",
                description=(
                    f"SPF passed for envelope domain '{spf_domain}', but does not align with visible "
                    f"From domain '{from_domain}'."
                ),
                evidence={"from_domain": from_domain, "spf_domain": spf_domain},
                confidence=0.90,
                fact=True,
            ))
    elif spf_status in ("fail", "hardfail"):
        findings.append(_create_finding(
            category="authentication",
            finding_type="spf_status",
            severity="high",
            status="failed",
            title="SPF authentication failed",
            description="Sending host is not authorized by the sender domain's SPF record.",
            evidence={"spf_status": spf_status, "from_domain": from_domain, "raw": spf_raw},
            confidence=0.95,
            fact=True,
        ))
        findings.append(_create_finding(
            category="authentication",
            finding_type="spf_fail_inference",
            severity="high",
            status="warning",
            title="Suspected unauthorized sending infrastructure (SPF)",
            description="The mail server transmitting this message failed SPF verification for the claimed domain.",
            evidence={"spf_status": spf_status, "from_domain": from_domain},
            confidence=0.88,
            fact=False,
            inference_note="SPF failure indicates unauthorized sender IP according to domain DNS policy.",
        ))
        spf_aligned = False
    else:  # softfail, neutral, none, temperror, permerror
        findings.append(_create_finding(
            category="authentication",
            finding_type="spf_status",
            severity="low" if spf_status in ("neutral", "none") else "medium",
            status="warning" if spf_status == "softfail" else "info",
            title=f"SPF authentication result: {spf_status}",
            description=f"SPF evaluation returned '{spf_status}'.",
            evidence={"spf_status": spf_status, "from_domain": from_domain, "raw": spf_raw},
            confidence=0.90,
            fact=True,
        ))
        spf_aligned = False

    # --- 1.2 DKIM Analysis ---
    dkim_data = auth.get("dkim") or {}
    dkim_status = (dkim_data.get("status") or "").lower()
    dkim_domain = dkim_data.get("domain")
    dkim_selector = dkim_data.get("selector")
    dkim_raw = dkim_data.get("raw")

    if not dkim_status or dkim_status == "none":
        findings.append(_create_finding(
            category="authentication",
            finding_type="dkim_status",
            severity="info",
            status="unknown",
            title="DKIM signature not observed or evaluated",
            description="No DKIM signature or evaluation result found in email headers.",
            evidence={"dkim_status": dkim_status or "none", "from_domain": from_domain},
            confidence=0.85,
            fact=True,
        ))
        dkim_aligned = False
    elif dkim_status == "pass":
        dkim_aligned = is_domain_aligned(from_domain, dkim_domain, strict=False) if (from_domain and dkim_domain) else True
        findings.append(_create_finding(
            category="authentication",
            finding_type="dkim_status",
            severity="info",
            status="passed",
            title="DKIM signature verified (pass)",
            description=f"Receiving mail server verified DKIM signature for domain '{dkim_domain}' (selector: '{dkim_selector}').",
            evidence={"dkim_status": "pass", "dkim_domain": dkim_domain, "selector": dkim_selector},
            confidence=0.98,
            fact=True,
        ))
        if not dkim_aligned and from_domain and dkim_domain:
            findings.append(_create_finding(
                category="authentication",
                finding_type="dkim_alignment",
                severity="medium",
                status="warning",
                title="DKIM signature domain is unaligned with From header",
                description=f"DKIM signature is valid for '{dkim_domain}', but From header claims '{from_domain}'.",
                evidence={"from_domain": from_domain, "dkim_domain": dkim_domain},
                confidence=0.92,
                fact=True,
            ))
    elif dkim_status == "signature_present_unverified":
        dkim_aligned = is_domain_aligned(from_domain, dkim_domain, strict=False) if (from_domain and dkim_domain) else False
        findings.append(_create_finding(
            category="authentication",
            finding_type="dkim_status",
            severity="info",
            status="info",
            title="DKIM signature header present (upstream verification unrecorded)",
            description=f"DKIM-Signature header observed for domain '{dkim_domain}' (selector: '{dkim_selector}'). Receiving MTA verification was not recorded in Authentication-Results.",
            evidence={"dkim_domain": dkim_domain, "selector": dkim_selector, "raw_present": bool(dkim_raw)},
            confidence=0.90,
            fact=True,
        ))
    else:  # fail, permerror, temperror
        findings.append(_create_finding(
            category="authentication",
            finding_type="dkim_status",
            severity="high",
            status="failed",
            title=f"DKIM signature verification failed ({dkim_status})",
            description=f"Receiving MTA recorded DKIM failure ({dkim_status}) for domain '{dkim_domain}'.",
            evidence={"dkim_status": dkim_status, "dkim_domain": dkim_domain, "selector": dkim_selector},
            confidence=0.95,
            fact=True,
        ))
        findings.append(_create_finding(
            category="authentication",
            finding_type="dkim_fail_inference",
            severity="high",
            status="warning",
            title="Suspected message tampering or invalid cryptographic signature",
            description="DKIM signature verification failed, which may indicate message modification in transit or an invalid signature.",
            evidence={"dkim_status": dkim_status, "dkim_domain": dkim_domain},
            confidence=0.85,
            fact=False,
            inference_note="DKIM failure indicates the cryptographic signature did not validate the message content or headers.",
        ))
        dkim_aligned = False

    # --- 1.3 DMARC Analysis ---
    dmarc_data = auth.get("dmarc") or {}
    dmarc_status = (dmarc_data.get("status") or "").lower()
    dmarc_policy = dmarc_data.get("policy")

    if not dmarc_status or dmarc_status == "none":
        findings.append(_create_finding(
            category="authentication",
            finding_type="dmarc_status",
            severity="info",
            status="unknown",
            title="DMARC evaluation unrecorded",
            description="No DMARC result recorded by receiving mail server in Authentication-Results.",
            evidence={"dmarc_status": dmarc_status or "none", "from_domain": from_domain},
            confidence=0.80,
            fact=True,
        ))
        dmarc_aligned = False
    elif dmarc_status == "pass":
        dmarc_aligned = True
        findings.append(_create_finding(
            category="authentication",
            finding_type="dmarc_status",
            severity="info",
            status="passed",
            title="DMARC authentication passed",
            description=f"DMARC evaluation passed for domain '{from_domain}' (Policy: {dmarc_policy or 'default'}).",
            evidence={"dmarc_status": "pass", "policy": dmarc_policy, "from_domain": from_domain},
            confidence=0.98,
            fact=True,
        ))
    else:  # fail
        dmarc_aligned = False
        findings.append(_create_finding(
            category="authentication",
            finding_type="dmarc_status",
            severity="high",
            status="failed",
            title="DMARC authentication failed",
            description=f"DMARC evaluation failed for domain '{from_domain}' (Policy: {dmarc_policy or 'none'}).",
            evidence={"dmarc_status": "fail", "policy": dmarc_policy, "from_domain": from_domain},
            confidence=0.95,
            fact=True,
        ))
        findings.append(_create_finding(
            category="authentication",
            finding_type="dmarc_fail_inference",
            severity="high",
            status="warning",
            title="Sender domain spoofing risk indicated by DMARC failure",
            description=f"DMARC failed because neither SPF nor DKIM passed in alignment with the visible From domain '{from_domain}'.",
            evidence={"from_domain": from_domain, "spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned},
            confidence=0.92,
            fact=False,
            inference_note="DMARC failure is strong forensic indicator that sender identity is unverified or spoofed.",
        ))

    auth_summary = {
        "spf_status": spf_status or "unknown",
        "spf_aligned": spf_aligned,
        "dkim_status": dkim_status or "unknown",
        "dkim_aligned": dkim_aligned,
        "dmarc_status": dmarc_status or "unknown",
        "dmarc_aligned": dmarc_aligned,
        "overall_alignment": dmarc_aligned or (spf_aligned and dkim_aligned),
    }

    return findings, auth_summary


# ================================================================== #
#  2. Identity Consistency Analysis                                   #
# ================================================================== #

def analyze_identity_consistency(parsed_email: dict) -> tuple[list[dict], dict]:
    """
    Analyze From, Reply-To, Return-Path, Sender, and Display Name for anomalies.
    """
    findings: list[dict] = []
    sender = parsed_email.get("sender") or {}
    from_email = sender.get("email")
    from_display = sender.get("display_name")
    from_domain = sender.get("domain")

    reply_to = parsed_email.get("reply_to")
    return_path = parsed_email.get("return_path")
    env_sender = parsed_email.get("envelope_sender")
    headers = parsed_email.get("headers") or {}
    auth = parsed_email.get("authentication") or {}
    dkim_domain = (auth.get("dkim") or {}).get("domain")

    # --- 2.1 From header presence ---
    if not from_email:
        findings.append(_create_finding(
            category="identity",
            finding_type="missing_from",
            severity="high",
            status="failed",
            title="Missing or unparseable From address",
            description="The email has no valid RFC-5322 From address.",
            evidence={"from_raw": headers.get("from")},
            confidence=0.99,
            fact=True,
        ))

    # --- 2.2 Reply-To Mismatch ---
    if reply_to and reply_to.get("email") and from_email:
        reply_to_email = reply_to.get("email")
        reply_to_domain = reply_to.get("domain")
        if not is_domain_aligned(from_domain, reply_to_domain, strict=False):
            findings.append(_create_finding(
                category="identity",
                finding_type="reply_to_mismatch",
                severity="medium",
                status="warning",
                title="Reply-To domain differs from From domain",
                description=(
                    f"Replies will be directed to '{reply_to_email}' (domain: '{reply_to_domain}'), "
                    f"which differs from the visible sender domain '{from_domain}'."
                ),
                evidence={
                    "from_email": from_email,
                    "from_domain": from_domain,
                    "reply_to_email": reply_to_email,
                    "reply_to_domain": reply_to_domain,
                },
                confidence=0.95,
                fact=True,
            ))
            findings.append(_create_finding(
                category="identity",
                finding_type="reply_to_mismatch_inference",
                severity="medium",
                status="warning",
                title="Potential reply redirection or credential harvesting setup",
                description="A Reply-To address on a different domain may be configured to intercept victim responses.",
                evidence={"from_domain": from_domain, "reply_to_domain": reply_to_domain},
                confidence=0.78,
                fact=False,
                inference_note="Reply-To mismatches also occur legitimately in mailing lists and helpdesk software.",
            ))

    # --- 2.3 Return-Path Mismatch ---
    if return_path and return_path.get("email") and from_email:
        rp_email = return_path.get("email")
        rp_domain = return_path.get("domain")
        if not is_domain_aligned(from_domain, rp_domain, strict=False):
            findings.append(_create_finding(
                category="identity",
                finding_type="return_path_mismatch",
                severity="medium",
                status="warning",
                title="Return-Path (envelope) domain differs from From domain",
                description=(
                    f"Bounce notifications and envelope sender domain '{rp_domain}' differ "
                    f"from the visible From domain '{from_domain}'."
                ),
                evidence={
                    "from_domain": from_domain,
                    "return_path_domain": rp_domain,
                    "return_path_email": rp_email,
                },
                confidence=0.95,
                fact=True,
            ))

    # --- 2.4 Sender Header Mismatch ---
    if env_sender and env_sender.get("email") and from_email:
        sender_hdr_domain = env_sender.get("domain")
        if not is_domain_aligned(from_domain, sender_hdr_domain, strict=False):
            findings.append(_create_finding(
                category="identity",
                finding_type="sender_header_mismatch",
                severity="low",
                status="info",
                title="Sender header domain differs from From header",
                description=(
                    f"Technical Sender header '{env_sender.get('email')}' domain differs from From domain '{from_domain}'."
                ),
                evidence={"from_domain": from_domain, "sender_domain": sender_hdr_domain},
                confidence=0.95,
                fact=True,
            ))

    # --- 2.5 Display Name Spoofing Detection ---
    # Pattern: Display name contains an email address like "service@paypal.com" but actual From is "attacker@other.com"
    display_name_spoof = False
    if from_display and from_email:
        email_in_display = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", from_display)
        if email_in_display:
            embedded_addr = email_in_display[0].lower()
            if embedded_addr != from_email.lower():
                display_name_spoof = True
                findings.append(_create_finding(
                    category="identity",
                    finding_type="display_name_spoof",
                    severity="high",
                    status="failed",
                    title="Display name spoofing detected",
                    description=(
                        f"The sender display name contains an email address '{embedded_addr}' that differs "
                        f"from the actual transmitting address '{from_email}'."
                    ),
                    evidence={
                        "display_name": from_display,
                        "embedded_email": embedded_addr,
                        "actual_from": from_email,
                    },
                    confidence=0.96,
                    fact=True,
                ))
                findings.append(_create_finding(
                    category="identity",
                    finding_type="display_name_spoof_inference",
                    severity="high",
                    status="warning",
                    title="Deceptive identity impersonation suspected",
                    description="The sender is deliberately masking their true identity by presenting a trusted address in the display name.",
                    evidence={"embedded_email": embedded_addr, "actual_from": from_email},
                    confidence=0.92,
                    fact=False,
                    inference_note="Display name masking is a hallmark technique in VIP and brand impersonation phishing.",
                ))

    # --- 2.6 DKIM Signing Domain Mismatch ---
    if dkim_domain and from_domain:
        if not is_domain_aligned(from_domain, dkim_domain, strict=False):
            findings.append(_create_finding(
                category="identity",
                finding_type="dkim_domain_mismatch",
                severity="low",
                status="info",
                title="Third-party DKIM signing domain observed",
                description=f"Email was signed by domain '{dkim_domain}', which differs from From domain '{from_domain}'.",
                evidence={"from_domain": from_domain, "dkim_domain": dkim_domain},
                confidence=0.95,
                fact=True,
            ))

    identity_summary = {
        "from_email": from_email,
        "from_domain": from_domain,
        "from_display": from_display,
        "reply_to_mismatch": bool(reply_to and not is_domain_aligned(from_domain, reply_to.get("domain"))),
        "return_path_mismatch": bool(return_path and not is_domain_aligned(from_domain, return_path.get("domain"))),
        "display_name_spoof_suspected": display_name_spoof,
    }

    return findings, identity_summary


# ================================================================== #
#  3. Received Chain & Relay Forensics                                #
# ================================================================== #

def analyze_received_chain(parsed_email: dict) -> tuple[list[dict], dict]:
    """
    Analyze the full SMTP Received chain.
    - Preserves relay order (hop 0 = earliest observed infrastructure).
    - Identifies public and internal/private IP exposure.
    - Never identifies the earliest IP as the 'attacker IP'.
    """
    findings: list[dict] = []
    relay = parsed_email.get("received_chain") or {}
    chain = relay.get("chain") or []
    hop_count = relay.get("hop_count", len(chain))
    public_ips = relay.get("public_ips_observed") or []
    earliest_node = relay.get("earliest_observed_node") or (chain[0] if chain else None)
    latest_node = chain[-1] if chain else None

    internal_ips: list[str] = []
    malformed_hops: list[dict] = []

    # Check each hop
    for i, hop in enumerate(chain):
        raw = hop.get("raw", "")
        from_ip = hop.get("from_ip")
        if from_ip:
            cat = classify_ip(from_ip)
            if cat in ("private", "loopback", "link_local"):
                internal_ips.append(from_ip)
        if not hop.get("by_host") and not hop.get("from_host") and not from_ip:
            malformed_hops.append({"hop_index": i, "raw": raw})

    # Malformed hop finding
    if malformed_hops:
        findings.append(_create_finding(
            category="relay",
            finding_type="malformed_received_header",
            severity="low",
            status="warning",
            title="Malformed Received header syntax observed",
            description=f"Encountered {len(malformed_hops)} Received header(s) lacking standard 'from', 'by', or IP tokens.",
            evidence={"malformed_hops": malformed_hops},
            confidence=0.90,
            fact=True,
        ))

    # Internal IP exposure finding
    if internal_ips:
        findings.append(_create_finding(
            category="relay",
            finding_type="internal_ip_exposure",
            severity="low",
            status="info",
            title="Internal/Private IP address observed in relay headers",
            description=(
                f"Internal network IP addresses were exposed in Received headers: {', '.join(sorted(set(internal_ips)))}. "
                "This typically indicates the originating client sent through an internal corporate relay."
            ),
            evidence={"internal_ips": sorted(list(set(internal_ips)))},
            confidence=0.95,
            fact=True,
        ))

    # Relay path summary finding
    if hop_count == 0:
        findings.append(_create_finding(
            category="relay",
            finding_type="missing_received_headers",
            severity="medium",
            status="warning",
            title="No Received headers present",
            description="The message contains zero Received headers. Transport history is unavailable.",
            evidence={"hop_count": 0},
            confidence=0.99,
            fact=True,
        ))
    else:
        earliest_ip = earliest_node.get("from_ip") if earliest_node else None
        earliest_host = earliest_node.get("from_host") if earliest_node else None
        
        findings.append(_create_finding(
            category="relay",
            finding_type="relay_path_summary",
            severity="info",
            status="info",
            title=f"SMTP relay path: {hop_count} hop(s) observed",
            description=(
                f"Message traversed {hop_count} observed mail relay server(s). "
                f"Earliest observed sending infrastructure: host '{earliest_host or 'unknown'}', IP '{earliest_ip or 'unknown'}'. "
                "Note: Earliest visible infrastructure represents observed network telemetry and does not prove human operator identity."
            ),
            evidence={
                "hop_count": hop_count,
                "public_ips": public_ips,
                "internal_ips": sorted(list(set(internal_ips))),
                "earliest_node": earliest_node,
                "latest_node": latest_node,
            },
            confidence=0.95,
            fact=True,
        ))

    # Chronological Hop Ordering Check
    hop_timestamps: list[datetime] = []
    for hop in chain:
        ts_iso = hop.get("timestamp_iso")
        if ts_iso:
            try:
                dt = datetime.fromisoformat(ts_iso)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                hop_timestamps.append(dt)
            except Exception:
                pass

    if len(hop_timestamps) >= 2:
        # Check if timestamps move forward in time (with small 5min clock skew margin)
        is_chronological = all(
            hop_timestamps[i] <= hop_timestamps[i + 1] + timedelta(minutes=5)
            for i in range(len(hop_timestamps) - 1)
        )
        if not is_chronological:
            findings.append(_create_finding(
                category="relay",
                finding_type="hop_timestamp_inconsistency",
                severity="medium",
                status="warning",
                title="Non-chronological Received header timestamps observed",
                description="Relay hop timestamps do not follow a forward chronological sequence, which may indicate forged headers or severe clock desynchronization.",
                evidence={"hop_timestamps": [t.isoformat() for t in hop_timestamps]},
                confidence=0.88,
                fact=True,
            ))

    relay_summary = {
        "hop_count": hop_count,
        "public_ips": public_ips,
        "internal_ips": sorted(list(set(internal_ips))),
        "earliest_observed_infrastructure": {
            "host": earliest_node.get("from_host") if earliest_node else None,
            "ip": earliest_node.get("from_ip") if earliest_node else None,
            "timestamp": earliest_node.get("timestamp_iso") if earliest_node else None,
        } if earliest_node else None,
        "latest_relay": {
            "host": latest_node.get("by_host") or latest_node.get("from_host") if latest_node else None,
            "ip": latest_node.get("from_ip") if latest_node else None,
            "timestamp": latest_node.get("timestamp_iso") if latest_node else None,
        } if latest_node else None,
    }

    return findings, relay_summary


# ================================================================== #
#  4. Header Anomaly & Message-ID Forensics                           #
# ================================================================== #

def analyze_headers(parsed_email: dict) -> tuple[list[dict], dict]:
    """
    Check for missing mandatory RFC-5322 headers, duplicate headers,
    and Message-ID domain consistency.
    """
    findings: list[dict] = []
    headers = parsed_email.get("headers") or {}
    raw_headers = parsed_email.get("raw_headers") or {}
    sender = parsed_email.get("sender") or {}
    from_domain = sender.get("domain")

    # --- 4.1 Missing Core Headers ---
    for hname in ("From", "Date", "Subject"):
        val = headers.get(hname.lower()) or headers.get(f"{hname.lower()}_raw")
        if not val and hname.title() not in raw_headers:
            findings.append(_create_finding(
                category="headers",
                finding_type=f"missing_{hname.lower()}",
                severity="medium" if hname != "Subject" else "low",
                status="warning",
                title=f"Missing standard header: {hname}",
                description=f"The RFC-5322 '{hname}' header is absent from this message.",
                evidence={"header": hname},
                confidence=0.99,
                fact=True,
            ))

    # --- 4.2 Duplicate Single-Instance Headers ---
    single_instance_headers = ["From", "Subject", "Message-Id", "Date", "Reply-To", "Sender"]
    duplicate_headers = []
    for h in single_instance_headers:
        # Check title-cased or direct key in raw_headers
        vals = raw_headers.get(h.title()) or raw_headers.get(h) or []
        if len(vals) > 1:
            duplicate_headers.append(h)
            findings.append(_create_finding(
                category="headers",
                finding_type="duplicate_header",
                severity="high",
                status="failed",
                title=f"Duplicate single-instance header: {h}",
                description=(
                    f"The message contains {len(vals)} instances of the '{h}' header, which violates RFC-5322 "
                    "and is commonly exploited in email security filter evasion."
                ),
                evidence={"header": h, "count": len(vals), "values": vals},
                confidence=0.98,
                fact=True,
            ))

    # --- 4.3 Message-ID Analysis ---
    message_id = headers.get("message_id")
    msg_id_domain = None

    if not message_id:
        findings.append(_create_finding(
            category="message_id",
            finding_type="missing_message_id",
            severity="low",
            status="info",
            title="Message-ID header absent",
            description="The message lacks a Message-ID header. While permitted in some RFC contexts, legitimate MTAs usually inject one.",
            evidence={"message_id": None},
            confidence=0.95,
            fact=True,
        ))
    else:
        # Extract domain from <unique-id@domain.com>
        m = re.search(r"@([a-zA-Z0-9\.-]+)>?", message_id)
        if m:
            msg_id_domain = normalize_domain(m.group(1))
            if from_domain and not is_domain_aligned(from_domain, msg_id_domain, strict=False):
                findings.append(_create_finding(
                    category="message_id",
                    finding_type="message_id_domain_mismatch",
                    severity="low",
                    status="info",
                    title="Message-ID domain differs from From domain",
                    description=(
                        f"Message-ID domain '{msg_id_domain}' does not align with From domain '{from_domain}'. "
                        "This commonly occurs when sending via third-party mailers or bulk services."
                    ),
                    evidence={"from_domain": from_domain, "message_id_domain": msg_id_domain, "message_id": message_id},
                    confidence=0.92,
                    fact=True,
                ))
        else:
            findings.append(_create_finding(
                category="message_id",
                finding_type="malformed_message_id",
                severity="low",
                status="warning",
                title="Malformed Message-ID format",
                description=f"The Message-ID header '{message_id}' does not conform to the standard RFC-5322 `<id@domain>` format.",
                evidence={"message_id": message_id},
                confidence=0.90,
                fact=True,
            ))

    missing_hdrs = [
        h for h in ["From", "Date", "Subject", "Message-ID"]
        if not headers.get(h.lower().replace("-", "_")) and h.title() not in raw_headers
    ]

    header_summary = {
        "missing_headers": missing_hdrs,
        "duplicate_headers": duplicate_headers,
        "message_id": message_id,
        "message_id_domain": msg_id_domain,
    }

    return findings, header_summary


# ================================================================== #
#  5. Date & Timestamp Forensics                                      #
# ================================================================== #

def analyze_timestamps(parsed_email: dict) -> tuple[list[dict], dict]:
    """
    Analyze Date header and compare against Received timestamps.
    """
    findings: list[dict] = []
    headers = parsed_email.get("headers") or {}
    date_raw = headers.get("date_raw")
    date_iso = headers.get("date_iso")
    relay = parsed_email.get("received_chain") or {}
    chain = relay.get("chain") or []

    date_dt: Optional[datetime] = None
    is_future_dated = False
    parse_error = False

    if not date_raw:
        findings.append(_create_finding(
            category="timestamp",
            finding_type="missing_date_header",
            severity="medium",
            status="warning",
            title="Date header absent",
            description="The message contains no Date header.",
            evidence={"date_raw": None},
            confidence=0.99,
            fact=True,
        ))
    else:
        try:
            date_dt = email.utils.parsedate_to_datetime(date_raw)
            if date_dt.tzinfo is None:
                date_dt = date_dt.replace(tzinfo=timezone.utc)
            
            # Check for future date (> 24 hours into the future)
            now = datetime.now(timezone.utc)
            if date_dt > now + timedelta(hours=24):
                is_future_dated = True
                findings.append(_create_finding(
                    category="timestamp",
                    finding_type="future_dated_email",
                    severity="high",
                    status="failed",
                    title="Future-dated email detected",
                    description=(
                        f"The Date header is timestamped {date_dt.isoformat()}, which is in the future relative "
                        f"to current time {now.isoformat()}."
                    ),
                    evidence={"date_raw": date_raw, "date_iso": date_dt.isoformat(), "evaluated_at": now.isoformat()},
                    confidence=0.98,
                    fact=True,
                ))
                findings.append(_create_finding(
                    category="timestamp",
                    finding_type="future_date_inference",
                    severity="medium",
                    status="warning",
                    title="Potential timestamp manipulation or filter evasion attempt",
                    description="Future dating is sometimes used in spam and phishing campaigns to pin emails at the top of victim inboxes.",
                    evidence={"date_raw": date_raw},
                    confidence=0.75,
                    fact=False,
                    inference_note="Can also be caused by an incorrectly configured sending server clock.",
                ))
        except Exception as exc:
            parse_error = True
            findings.append(_create_finding(
                category="timestamp",
                finding_type="malformed_date_header",
                severity="medium",
                status="warning",
                title="Malformed Date header",
                description=f"Could not parse Date header '{date_raw}': {exc}",
                evidence={"date_raw": date_raw, "error": str(exc)},
                confidence=0.95,
                fact=True,
            ))

    # Compare Date header against earliest Received hop
    if date_dt and chain:
        earliest_hop = chain[0]
        hop_iso = earliest_hop.get("timestamp_iso")
        if hop_iso:
            try:
                hop_dt = datetime.fromisoformat(hop_iso)
                if hop_dt.tzinfo is None:
                    hop_dt = hop_dt.replace(tzinfo=timezone.utc)
                # If Date is hours after the earliest Received hop, that's an anomaly
                gap = (date_dt - hop_dt).total_seconds()
                if gap > 86400:  # Date header is > 1 day after first relay received it
                    findings.append(_create_finding(
                        category="timestamp",
                        finding_type="date_received_skew",
                        severity="medium",
                        status="warning",
                        title="Significant timestamp disparity between Date and Received header",
                        description=(
                            f"The claimed Date header ({date_dt.isoformat()}) is significantly ahead of the "
                            f"earliest Received relay timestamp ({hop_dt.isoformat()})."
                        ),
                        evidence={"date_header": date_dt.isoformat(), "earliest_relay": hop_dt.isoformat(), "gap_seconds": gap},
                        confidence=0.90,
                        fact=True,
                    ))
            except Exception:
                pass

    timestamp_summary = {
        "date_raw": date_raw,
        "date_iso": date_iso,
        "is_future_dated": is_future_dated,
        "has_parse_error": parse_error,
    }

    return findings, timestamp_summary


# ================================================================== #
#  Main Forensic Engine Entry Point                                   #
# ================================================================== #

def run_forensic_analysis(parsed_email: dict, raw_bytes: Optional[bytes] = None) -> dict[str, Any]:
    """
    Execute full deterministic forensic analysis over parsed email data.

    Returns structured forensic analysis containing:
      - summary (counts, authentication, identity, relay, header status)
      - findings (complete ordered list of findings)
      - facts (filtered list of observed empirical facts)
      - inferences (filtered list of investigative inferences)
      - limitations (forensic boundaries and disclaimers)
    """
    all_findings: list[dict] = []

    # 1. Authentication Forensics
    auth_findings, auth_summary = analyze_authentication(parsed_email)
    all_findings.extend(auth_findings)

    # 2. Identity Consistency Forensics
    identity_findings, identity_summary = analyze_identity_consistency(parsed_email)
    all_findings.extend(identity_findings)

    # 3. Received Chain & Relay Forensics
    relay_findings, relay_summary = analyze_received_chain(parsed_email)
    all_findings.extend(relay_findings)

    # 4. Header Anomaly & Message-ID Forensics
    header_findings, header_summary = analyze_headers(parsed_email)
    all_findings.extend(header_findings)

    # 5. Date & Timestamp Forensics
    timestamp_findings, timestamp_summary = analyze_timestamps(parsed_email)
    all_findings.extend(timestamp_findings)

    # Separate Facts from Inferences
    facts = [f for f in all_findings if f.get("fact") is True]
    inferences = [f for f in all_findings if f.get("fact") is False]

    # Metrics
    passed_count = sum(1 for f in all_findings if f.get("status") == "passed")
    failed_count = sum(1 for f in all_findings if f.get("status") == "failed")
    warning_count = sum(1 for f in all_findings if f.get("status") == "warning")
    info_count = sum(1 for f in all_findings if f.get("status") in ("info", "unknown"))

    high_critical_risks = [f for f in all_findings if f.get("severity") in ("high", "critical")]

    summary = {
        "status": "completed",
        "findings_count": len(all_findings),
        "fact_count": len(facts),
        "inference_count": len(inferences),
        "passed_count": passed_count,
        "failed_count": failed_count,
        "warning_count": warning_count,
        "info_count": info_count,
        "high_risk_findings_count": len(high_critical_risks),
        "authentication": auth_summary,
        "identity": identity_summary,
        "relay": relay_summary,
        "headers": header_summary,
        "timestamps": timestamp_summary,
    }

    limitations = [
        "Forensic analysis is deterministic and derived directly from email headers, MIME structures, and transport metadata.",
        "Observed IP addresses reflect transmitting mail server infrastructure and do NOT directly identify physical human operators.",
        "Authentication status is grounded in receiving server Authentication-Results headers and cryptographic signature headers.",
        "Missing authentication records are classified as 'unknown' rather than assumed failures.",
        "Relay analysis identifies the 'earliest observed sending infrastructure' present in headers, noting headers can be forged prior to the first trusted MTA.",
    ]

    return {
        "summary": summary,
        "findings": all_findings,
        "facts": facts,
        "inferences": inferences,
        "limitations": limitations,
    }
