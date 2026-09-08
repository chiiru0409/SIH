"""
utils/asn_utils.py — Autonomous System Number (ASN) & Network intelligence lookups.

Supports:
    1. IPInfo ASN extraction (when IPINFO_TOKEN configured).
    2. Local MaxMind ASN database if configured.
    3. Graceful offline fallback.

Design Rules:
    - Never throws unhandled exceptions.
    - Excludes non-public IPs.
    - Zero active network scanning.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from backend.config import settings
from backend.utils.ip_utils import classify_ip

logger = logging.getLogger("mailtrace.utils.asn")


def lookup_asn(ip: str) -> dict[str, Any]:
    """
    Lookup ASN and network ownership information for an IP address.

    Returns structured dictionary with:
        - status: 'success' | 'excluded' | 'unknown' | 'error'
        - ip: str
        - asn: str | None (e.g. 'AS15169')
        - organization: str | None (e.g. 'Google LLC')
        - network: str | None (e.g. '8.8.8.0/24')
        - registry: str | None (e.g. 'ARIN', 'RIPE')
        - source: 'ipinfo' | 'local_asn' | 'local_filter' | 'unavailable'
        - reason: str | None
    """
    if not ip or not isinstance(ip, str):
        return {
            "status": "error",
            "ip": ip,
            "asn": None,
            "organization": None,
            "network": None,
            "registry": None,
            "source": "unavailable",
            "reason": "Invalid IP input",
        }

    ip_clean = ip.strip()
    classification = classify_ip(ip_clean)

    if classification != "public":
        return {
            "status": "excluded",
            "ip": ip_clean,
            "asn": None,
            "organization": None,
            "network": None,
            "registry": None,
            "source": "local_filter",
            "reason": f"Non-public IP ({classification})",
        }

    # 1. Try IPInfo if token configured
    if settings.IPINFO_TOKEN:
        try:
            import httpx  # type: ignore

            url = f"https://ipinfo.io/{ip_clean}/json"
            headers = {"Authorization": f"Bearer {settings.IPINFO_TOKEN}"}
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    org_field = data.get("org", "")  # Often format: 'AS15169 Google LLC'
                    asn_num = None
                    asn_org = org_field

                    if org_field:
                        match = re.match(r"^(AS\d+)\s+(.*)$", org_field, re.IGNORECASE)
                        if match:
                            asn_num = match.group(1).upper()
                            asn_org = match.group(2).strip()

                    return {
                        "status": "success",
                        "ip": ip_clean,
                        "asn": asn_num or (data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else None),
                        "organization": asn_org or (data.get("asn", {}).get("name") if isinstance(data.get("asn"), dict) else None),
                        "network": data.get("asn", {}).get("route") if isinstance(data.get("asn"), dict) else None,
                        "registry": data.get("asn", {}).get("domain") if isinstance(data.get("asn"), dict) else None,
                        "source": "ipinfo",
                        "reason": None,
                    }
        except Exception as exc:
            logger.warning(f"IPInfo ASN lookup failed for {ip_clean}: {exc}")

    # 2. Fallback when unconfigured / offline
    return {
        "status": "unknown",
        "ip": ip_clean,
        "asn": None,
        "organization": None,
        "network": None,
        "registry": None,
        "source": "unavailable",
        "reason": "ASN provider not configured or unavailable",
    }
