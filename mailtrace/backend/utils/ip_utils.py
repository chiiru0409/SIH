"""
utils/ip_utils.py — IP address classification helpers.

Pure stdlib — no external API calls.
Phase 5 will add GeoIP / ASN / reputation enrichment on top of these.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

# ------------------------------------------------------------------ #
#  Regexes                                                            #
# ------------------------------------------------------------------ #

_IPV4_RE = re.compile(
    r"(?<!\d)"
    r"((?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3})"
    r"(?!\d)"
)

# Simplified IPv6 — catches addresses that appear in email Received headers
_IPV6_RE = re.compile(
    r"(?<![:\w])"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}"
    r"|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}::"
    r"|::"
    r")"
    r"(?![:\w])"
)

IpCategory = Literal["private", "loopback", "public", "reserved", "link_local", "multicast", "unknown"]


# ------------------------------------------------------------------ #
#  Classification                                                     #
# ------------------------------------------------------------------ #

def classify_ip(ip_str: str) -> IpCategory:
    """Classify an IP address without any external API call."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


def is_public_ip(ip_str: str) -> bool:
    return classify_ip(ip_str) == "public"


# ------------------------------------------------------------------ #
#  Extraction                                                         #
# ------------------------------------------------------------------ #

def extract_ips_from_text(text: str) -> list[str]:
    """Return deduplicated list of all IP addresses found in a text block."""
    found: list[str] = []
    seen: set[str] = set()

    for m in _IPV4_RE.finditer(text):
        ip = m.group(1)
        if ip not in seen:
            try:
                ipaddress.IPv4Address(ip)
                seen.add(ip)
                found.append(ip)
            except ValueError:
                pass

    for m in _IPV6_RE.finditer(text):
        raw = m.group(1)
        try:
            normalized = str(ipaddress.IPv6Address(raw))
            if normalized not in seen:
                seen.add(normalized)
                found.append(normalized)
        except ValueError:
            pass

    return found


# ------------------------------------------------------------------ #
#  Annotation                                                         #
# ------------------------------------------------------------------ #

def annotate_ip(ip_str: str) -> dict:
    """
    Return a base IP annotation dict.
    Phase 5 will fill in country/city/asn/isp/reputation from external APIs.
    """
    category = classify_ip(ip_str)
    try:
        version = ipaddress.ip_address(ip_str.strip()).version
    except ValueError:
        version = None

    return {
        "ip": ip_str,
        "version": version,
        "category": category,
        "is_public": category == "public",
        # Phase 5 enrichment placeholders
        "country": None,
        "city": None,
        "asn": None,
        "isp": None,
        "reputation": None,
    }
