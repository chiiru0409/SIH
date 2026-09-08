"""
services/email_parser.py — MAILTRACE forensic email parser.

Single public entry point:  parse_email(raw_bytes: bytes) -> dict

Pipeline
--------
raw bytes
  → stdlib MIME parse
  → header extraction + normalization
  → Received-chain reconstruction
  → authentication result extraction  (SPF / DKIM / DMARC / ARC)
  → body extraction  (plain + HTML → normalized text)
  → URL extraction   (text body + HTML href)
  → IP extraction    (Received headers + X-Originating-IP)
  → domain extraction
  → attachment metadata + SHA-256
  → indicators summary

Design rules
------------
- Never raises on any input — every exception is caught and logged in
  parse_errors[].
- Every field is Optional.  Missing data → None, not an empty string.
- No external HTTP calls in this module.
- Output dict is JSON-serializable for direct storage in the DB
  parsed_email column.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import email.utils
import logging
import re
from typing import Any, Optional

from backend.services.evidence import sha256_bytes
from backend.utils.ip_utils import annotate_ip, classify_ip, extract_ips_from_text
from backend.utils.url_utils import (
    collect_all_domains,
    extract_domain_from_email,
    extract_domains_from_urls,
    extract_urls_from_html,
    extract_urls_from_text,
    html_to_text,
    normalize_domain,
)

logger = logging.getLogger("mailtrace.parser")


# ================================================================== #
#  Header helpers                                                     #
# ================================================================== #

def _decode_header(raw: Optional[str]) -> str:
    """Decode an RFC-2047 encoded header value to a plain Unicode string."""
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return "".join(decoded).strip()
    except Exception:
        return str(raw).strip()


def _hdr(msg: email.message.Message, name: str) -> str:
    """Get a single decoded header value, empty string if absent."""
    val = msg.get(name)
    return _decode_header(val) if val else ""


def _all_hdrs(msg: email.message.Message, name: str) -> list[str]:
    """Get all decoded values for a repeating header (e.g. Received)."""
    return [_decode_header(v) for v in (msg.get_all(name) or []) if v]


def _parse_address(raw: str) -> dict:
    """Parse 'Display <user@domain>' into {display_name, email, domain}."""
    if not raw:
        return {"display_name": None, "email": None, "domain": None}
    decoded = _decode_header(raw)
    name, addr = email.utils.parseaddr(decoded)
    addr = addr.strip().lower() if addr else None
    return {
        "display_name": name.strip() or None,
        "email": addr or None,
        "domain": extract_domain_from_email(addr) if addr else None,
    }


def _parse_address_list(raw: str) -> list[dict]:
    """Parse a comma-separated address list."""
    if not raw:
        return []
    decoded = _decode_header(raw)
    pairs = email.utils.getaddresses([decoded])
    result = []
    for name, addr in pairs:
        if addr:
            addr = addr.strip().lower()
            result.append({
                "display_name": name.strip() or None,
                "email": addr,
                "domain": extract_domain_from_email(addr),
            })
    return result


def _raw_headers(msg: email.message.Message) -> dict[str, list[str]]:
    """Dump all headers as {Title-Case-Name: [raw_value, ...]}."""
    out: dict[str, list[str]] = {}
    for k, v in msg.items():
        key = k.strip().title()
        out.setdefault(key, []).append(str(v))
    return out


# ================================================================== #
#  Received header parsing                                            #
# ================================================================== #

_RCV_FROM_RE = re.compile(
    r"from\s+(\S+)(?:\s+\(([^)]+)\))?", re.IGNORECASE
)
_RCV_BY_RE   = re.compile(r"by\s+(\S+)", re.IGNORECASE)
_RCV_DATE_RE = re.compile(r";\s*(.+)$",  re.MULTILINE)
_BRACKET_IP  = re.compile(r"\[([0-9a-fA-F.:]+)\]")


def _parse_received(raw: str) -> dict:
    result: dict[str, Any] = {
        "raw": raw,
        "from_host": None,
        "from_ip":   None,
        "by_host":   None,
        "timestamp": None,
        "timestamp_iso": None,
        "ips_found": [],
    }

    m = _RCV_FROM_RE.search(raw)
    if m:
        result["from_host"] = m.group(1)
        paren = m.group(2) or ""
        bm = _BRACKET_IP.search(paren)
        if bm:
            result["from_ip"] = bm.group(1)

    if not result["from_ip"]:
        all_ips = _BRACKET_IP.findall(raw)
        if all_ips:
            result["from_ip"] = all_ips[0]

    bm = _RCV_BY_RE.search(raw)
    if bm:
        result["by_host"] = bm.group(1)

    dm = _RCV_DATE_RE.search(raw)
    if dm:
        raw_date = dm.group(1).strip()
        result["timestamp"] = raw_date
        try:
            dt = email.utils.parsedate_to_datetime(raw_date)
            result["timestamp_iso"] = dt.isoformat()
        except Exception:
            pass

    result["ips_found"] = extract_ips_from_text(raw)
    return result


def _relay_chain(received_parsed: list[dict]) -> dict:
    """
    Reconstruct SMTP relay path.

    Received headers are prepended (newest first).
    We reverse them so index 0 is the earliest observed hop.

    IMPORTANT: We never claim the earliest IP is the attacker's IP —
    headers can be forged.  We label it 'earliest_observed_node'.
    """
    if not received_parsed:
        return {
            "hop_count": 0,
            "chain": [],
            "public_ips_observed": [],
            "earliest_observed_node": None,
            "confidence_note": "No Received headers — relay path unknown.",
        }

    ordered = list(reversed(received_parsed))   # oldest hop first
    public_ips = [
        hop["from_ip"]
        for hop in ordered
        if hop["from_ip"] and classify_ip(hop["from_ip"]) == "public"
    ]

    return {
        "hop_count": len(received_parsed),
        "chain": ordered,
        "public_ips_observed": public_ips,
        "earliest_observed_node": ordered[0],
        "confidence_note": (
            "The earliest observed node is the first Received header present "
            "in this email. It represents the earliest visible infrastructure, "
            "NOT necessarily the true origin — headers can be forged."
        ),
    }


# ================================================================== #
#  Authentication extraction                                          #
# ================================================================== #

_AUTH_STATUS_RE  = re.compile(
    r"\b(pass|fail|softfail|neutral|none|permerror|temperror|hardfail)\b",
    re.IGNORECASE,
)
_DKIM_DOMAIN_RE  = re.compile(r"\bd=([^\s;]+)",  re.IGNORECASE)
_DKIM_SEL_RE     = re.compile(r"\bs=([^\s;]+)",  re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(r"\bp=(\w+)",      re.IGNORECASE)


def _extract_spf(auth_hdrs: list[str], spf_hdrs: list[str]) -> dict:
    status = None
    spf_raw = " ".join(spf_hdrs)

    if spf_raw:
        m = _AUTH_STATUS_RE.search(spf_raw)
        if m:
            status = m.group(1).lower()

    if not status:
        for h in auth_hdrs:
            m = re.search(r"spf=(\S+)", h, re.IGNORECASE)
            if m:
                status = m.group(1).rstrip(";").lower()
                break

    return {"status": status, "raw": spf_raw or None}


def _extract_dkim(auth_hdrs: list[str], dkim_sigs: list[str]) -> dict:
    status = None
    domain = None
    selector = None
    dkim_raw = " ".join(dkim_sigs) if dkim_sigs else None

    for h in auth_hdrs:
        m = re.search(r"dkim=(\S+)", h, re.IGNORECASE)
        if m:
            status = m.group(1).rstrip(";").lower()
            dm = _DKIM_DOMAIN_RE.search(h)
            if dm:
                domain = dm.group(1).rstrip(";").lower()
            sm = _DKIM_SEL_RE.search(h)
            if sm:
                selector = sm.group(1).rstrip(";").lower()
            break

    # DKIM-Signature header exists but no Auth-Results entry
    # → signature PRESENT but not verified by a receiving server header
    if not status and dkim_raw:
        status = "signature_present_unverified"
        dm = _DKIM_DOMAIN_RE.search(dkim_raw)
        if dm:
            domain = dm.group(1).rstrip(";").lower()
        sm = _DKIM_SEL_RE.search(dkim_raw)
        if sm:
            selector = sm.group(1).rstrip(";").lower()

    return {"status": status, "domain": domain, "selector": selector, "raw": dkim_raw}


def _extract_dmarc(auth_hdrs: list[str]) -> dict:
    status = None
    policy = None
    for h in auth_hdrs:
        m = re.search(r"dmarc=(\S+)", h, re.IGNORECASE)
        if m:
            status = m.group(1).rstrip(";").lower()
            pm = _DMARC_POLICY_RE.search(h)
            if pm:
                policy = pm.group(1).lower()
            break
    raw = " ".join(auth_hdrs) if auth_hdrs else None
    return {"status": status, "policy": policy, "raw": raw}


def _extract_arc(msg: email.message.Message) -> list[dict]:
    arc: dict[int, dict] = {}
    for hname in ("ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"):
        for val in _all_hdrs(msg, hname):
            im = re.search(r"i=(\d+)", val, re.IGNORECASE)
            if im:
                idx = int(im.group(1))
                arc.setdefault(idx, {"instance": idx})
                arc[idx][hname.lower().replace("-", "_")] = val
    return [arc[k] for k in sorted(arc)]


# ================================================================== #
#  Body extraction                                                    #
# ================================================================== #

def _decode_part(part: email.message.Message) -> Optional[str]:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return None
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug(f"Part decode error: {e}")
        return None


def _extract_body(msg: email.message.Message) -> tuple[Optional[str], Optional[str]]:
    plains, htmls = [], []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp  = (part.get_content_disposition() or "").lower()
            if disp == "attachment":
                continue
            if ctype == "text/plain":
                t = _decode_part(part)
                if t:
                    plains.append(t)
            elif ctype == "text/html":
                t = _decode_part(part)
                if t:
                    htmls.append(t)
    else:
        ctype = msg.get_content_type()
        if ctype == "text/plain":
            t = _decode_part(msg)
            if t:
                plains.append(t)
        elif ctype == "text/html":
            t = _decode_part(msg)
            if t:
                htmls.append(t)

    plain = "\n\n".join(plains) or None
    html  = "\n\n".join(htmls)  or None
    return plain, html


# ================================================================== #
#  Attachment extraction                                              #
# ================================================================== #

def _extract_attachments(msg: email.message.Message) -> list[dict]:
    attachments = []
    seen_hashes: set[str] = set()

    for part in msg.walk():
        ctype = part.get_content_type()
        disp  = (part.get_content_disposition() or "").lower()

        # Detect attachments by disposition or non-text content type
        is_att = (
            disp == "attachment"
            or (disp == "inline" and part.get_filename())
        )
        if not is_att and not part.is_multipart():
            if ctype not in (
                "text/plain", "text/html",
                "multipart/mixed", "multipart/alternative",
                "multipart/related", "multipart/signed", "multipart/report",
            ):
                is_att = True

        if not is_att:
            continue

        filename = _decode_header(part.get_filename() or "") or "unnamed_attachment"

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        h = sha256_bytes(payload) if payload else None
        if h and h in seen_hashes:
            continue
        if h:
            seen_hashes.add(h)

        attachments.append({
            "filename": filename,
            "content_type": ctype,
            "content_disposition": disp or None,
            "size_bytes": len(payload),
            "sha256": h,
            "reputation": None,   # Phase 5 enrichment
        })

    return attachments


# ================================================================== #
#  MIME info summary                                                  #
# ================================================================== #

def _mime_info(msg: email.message.Message) -> dict:
    parts = []
    if msg.is_multipart():
        for p in msg.walk():
            if p is msg:
                continue
            parts.append({
                "content_type": p.get_content_type(),
                "content_disposition": p.get_content_disposition(),
                "filename": _decode_header(p.get_filename() or ""),
            })
    return {
        "content_type": msg.get_content_type(),
        "is_multipart": msg.is_multipart(),
        "mime_version": _hdr(msg, "MIME-Version") or None,
        "content_transfer_encoding": _hdr(msg, "Content-Transfer-Encoding") or None,
        "parts": parts,
    }


# ================================================================== #
#  Mismatch helpers                                                   #
# ================================================================== #

def _reply_to_mismatch(sender: dict, reply_to: Optional[dict]) -> bool:
    if not reply_to:
        return False
    sd = sender.get("domain")
    rd = reply_to.get("domain")
    if not sd or not rd:
        return False
    return normalize_domain(sd) != normalize_domain(rd)


def _return_path_mismatch(sender: dict, return_path: Optional[dict]) -> bool:
    if not return_path:
        return False
    sd = sender.get("domain")
    rpd = return_path.get("domain")
    if not sd or not rpd:
        return False
    return normalize_domain(sd) != normalize_domain(rpd)


# ================================================================== #
#  Main entry point                                                   #
# ================================================================== #

def parse_email(raw_bytes: bytes) -> dict:
    """
    Parse raw .eml bytes into a structured forensic dict.

    Never raises — all exceptions are caught and surfaced in parse_errors[].
    Returns a JSON-serializable dict ready for DB storage.
    """
    errors: list[str] = []

    # ---- 1. MIME parse ----
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as exc:
        logger.error(f"Fatal MIME parse: {exc}")
        return {"parse_errors": [f"Fatal MIME parse: {exc}"], "fatal": True}

    # ---- 2. Core headers ----
    subject       = _decode_header(_hdr(msg, "Subject")) or None
    date_raw      = _hdr(msg, "Date") or None
    message_id    = _hdr(msg, "Message-ID") or None
    in_reply_to   = _hdr(msg, "In-Reply-To") or None
    references    = _hdr(msg, "References") or None
    mime_version  = _hdr(msg, "MIME-Version") or None
    user_agent    = _hdr(msg, "User-Agent") or _hdr(msg, "X-Mailer") or None
    x_orig_ip     = _hdr(msg, "X-Originating-IP") or None

    date_iso = None
    if date_raw:
        try:
            date_iso = email.utils.parsedate_to_datetime(date_raw).isoformat()
        except Exception:
            errors.append(f"Cannot parse Date: {date_raw!r}")

    # ---- 3. Sender / recipients ----
    from_raw        = _hdr(msg, "From") or None
    to_raw          = _hdr(msg, "To") or None
    cc_raw          = _hdr(msg, "Cc") or None
    bcc_raw         = _hdr(msg, "Bcc") or None
    reply_to_raw    = _hdr(msg, "Reply-To") or None
    return_path_raw = _hdr(msg, "Return-Path") or None
    sender_raw      = _hdr(msg, "Sender") or None

    sender       = _parse_address(from_raw) if from_raw else {"display_name": None, "email": None, "domain": None}
    reply_to     = _parse_address(reply_to_raw)    if reply_to_raw    else None
    return_path  = _parse_address(return_path_raw) if return_path_raw else None
    env_sender   = _parse_address(sender_raw)      if sender_raw      else None
    to_list      = _parse_address_list(to_raw)     if to_raw          else []
    cc_list      = _parse_address_list(cc_raw)     if cc_raw          else []
    bcc_list     = _parse_address_list(bcc_raw)    if bcc_raw         else []

    # ---- 4. Received chain ----
    received_raw    = _all_hdrs(msg, "Received")
    received_parsed = []
    for r in received_raw:
        try:
            received_parsed.append(_parse_received(r))
        except Exception as exc:
            errors.append(f"Received parse error: {exc}")
    relay = _relay_chain(received_parsed)

    # ---- 5. Authentication ----
    auth_hdrs  = _all_hdrs(msg, "Authentication-Results")
    spf_hdrs   = _all_hdrs(msg, "Received-SPF")
    dkim_sigs  = _all_hdrs(msg, "DKIM-Signature")

    auth = {
        "spf":              _extract_spf(auth_hdrs, spf_hdrs),
        "dkim":             _extract_dkim(auth_hdrs, dkim_sigs),
        "dmarc":            _extract_dmarc(auth_hdrs),
        "arc":              _extract_arc(msg),
        "auth_results_raw": auth_hdrs or None,
    }

    # ---- 6. Body ----
    plain_body, html_body = _extract_body(msg)
    normalized_body = plain_body
    if not plain_body and html_body:
        try:
            normalized_body = html_to_text(html_body)
        except Exception as exc:
            errors.append(f"HTML→text failed: {exc}")

    # ---- 7. URLs ----
    urls: list[dict] = []
    if plain_body:
        try:
            urls.extend(extract_urls_from_text(plain_body))
        except Exception as exc:
            errors.append(f"URL(text) extraction failed: {exc}")

    if html_body:
        try:
            seen_url_strs = {u["url"] for u in urls}
            for u in extract_urls_from_html(html_body):
                if u["url"] not in seen_url_strs:
                    urls.append(u)
                    seen_url_strs.add(u["url"])
        except Exception as exc:
            errors.append(f"URL(html) extraction failed: {exc}")

    # ---- 8. IPs ----
    raw_ips: list[str] = []
    for hop in received_parsed:
        raw_ips.extend(hop.get("ips_found", []))
    raw_ips.extend(relay.get("public_ips_observed", []))

    orig_ips: list[str] = []
    if x_orig_ip:
        orig_ips = extract_ips_from_text(x_orig_ip)
        raw_ips.extend(orig_ips)

    seen_ips: set[str] = set()
    ip_annotations: list[dict] = []
    for ip in raw_ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            ip_annotations.append(annotate_ip(ip))

    # ---- 9. Domains ----
    all_domains = collect_all_domains(
        [sender["domain"]]       if sender.get("domain")             else [],
        [reply_to["domain"]]     if reply_to  and reply_to.get("domain")  else [],
        [return_path["domain"]]  if return_path and return_path.get("domain") else [],
        extract_domains_from_urls(urls),
    )

    # ---- 10. Attachments ----
    attachments: list[dict] = []
    try:
        attachments = _extract_attachments(msg)
    except Exception as exc:
        errors.append(f"Attachment extraction failed: {exc}")

    # ---- 11. MIME info + raw headers ----
    mime  = _mime_info(msg)
    raw_h = _raw_headers(msg)

    # ---- 12. Indicators (fast forensic flags — no AI) ----
    indicators = {
        "reply_to_mismatch":    _reply_to_mismatch(sender, reply_to),
        "return_path_mismatch": _return_path_mismatch(sender, return_path),
        "sender_domain":        sender.get("domain"),
        "reply_to_domain":      reply_to["domain"]     if reply_to     else None,
        "return_path_domain":   return_path["domain"]  if return_path  else None,
        "has_attachments":      len(attachments) > 0,
        "attachment_count":     len(attachments),
        "url_count":            len(urls),
        "ip_count":             len(ip_annotations),
        "domain_count":         len(all_domains),
        "hop_count":            relay["hop_count"],
        "has_dkim_signature":   bool(dkim_sigs),
        "has_auth_results":     bool(auth_hdrs),
        "has_spf_header":       bool(spf_hdrs),
        "missing_message_id":   not bool(message_id),
        "has_x_originating_ip": bool(x_orig_ip),
    }

    # ---- 13. Assemble ----
    return {
        "headers": {
            "subject":       subject,
            "date_raw":      date_raw,
            "date_iso":      date_iso,
            "message_id":    message_id,
            "in_reply_to":   in_reply_to,
            "references":    references,
            "mime_version":  mime_version,
            "user_agent":    user_agent,
            "x_originating_ip": x_orig_ip,
        },
        "sender":        sender,
        "envelope_sender": env_sender,
        "recipients": {
            "to":  to_list,
            "cc":  cc_list,
            "bcc": bcc_list,
        },
        "reply_to":    reply_to,
        "return_path": return_path,
        "authentication": auth,
        "received_chain": relay,
        "originating_ips": orig_ips,
        "ip_addresses":    ip_annotations,
        "urls":            urls,
        "domains":         all_domains,
        "body": {
            "plain":      plain_body,
            "html":       html_body,
            "normalized": normalized_body,
        },
        "attachments":  attachments,
        "indicators":   indicators,
        "mime_info":    mime,
        "raw_headers":  raw_h,
        "parse_errors": errors,
        "fatal":        False,
    }
