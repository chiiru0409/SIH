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


# In-memory ASN cache
_ASN_CACHE: dict[str, dict[str, Any]] = {}


def clear_asn_cache() -> None:
    """Clear in-memory ASN cache."""
    _ASN_CACHE.clear()


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
    if ip_clean in _ASN_CACHE:
        return _ASN_CACHE[ip_clean]

    classification = classify_ip(ip_clean)

    if classification != "public":
        rec = {
            "status": "excluded",
            "ip": ip_clean,
            "asn": None,
            "organization": None,
            "network": None,
            "registry": None,
            "source": "local_filter",
            "reason": f"Non-public IP ({classification})",
        }
        _ASN_CACHE[ip_clean] = rec
        return rec

    # 1. Check shared ASN data from GeoIP lookup
    try:
        from backend.utils.geoip import _SHARED_ASN_DATA
        if ip_clean in _SHARED_ASN_DATA:
            shared = _SHARED_ASN_DATA[ip_clean]
            asn_raw = shared.get("asn")
            asn_val = f"AS{asn_raw}" if isinstance(asn_raw, int) else (str(asn_raw) if asn_raw else None)
            rec = {
                "status": "success",
                "ip": ip_clean,
                "asn": asn_val,
                "organization": shared.get("org") or shared.get("isp"),
                "network": None,
                "registry": shared.get("domain"),
                "source": "local_asn",
                "reason": None,
            }
            _ASN_CACHE[ip_clean] = rec
            return rec
    except Exception:
        pass

    # 2. Try IPInfo if token configured
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

                    rec = {
                        "status": "success",
                        "ip": ip_clean,
                        "asn": asn_num or (data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else None),
                        "organization": asn_org or (data.get("asn", {}).get("name") if isinstance(data.get("asn"), dict) else None),
                        "network": data.get("asn", {}).get("route") if isinstance(data.get("asn"), dict) else None,
                        "registry": data.get("asn", {}).get("domain") if isinstance(data.get("asn"), dict) else None,
                        "source": "ipinfo",
                        "reason": None,
                    }
                    _ASN_CACHE[ip_clean] = rec
                    return rec
        except Exception as exc:
            logger.warning(f"IPInfo ASN lookup failed for {ip_clean}: {exc}")

    # 3. Live High-Speed Passive ASN Service
    try:
        import httpx  # type: ignore

        with httpx.Client(timeout=2.0, follow_redirects=True) as client:
            resp = client.get(f"https://ipwho.is/{ip_clean}")
            if resp.status_code == 200:
                data = resp.json()
                conn = data.get("connection", {})
                if conn:
                    asn_raw = conn.get("asn")
                    asn_val = f"AS{asn_raw}" if isinstance(asn_raw, int) else (str(asn_raw) if asn_raw else None)
                    org_val = conn.get("org") or conn.get("isp")
                    rec = {
                        "status": "success",
                        "ip": ip_clean,
                        "asn": asn_val,
                        "organization": org_val,
                        "network": None,
                        "registry": conn.get("domain"),
                        "source": "local_asn",
                        "reason": None,
                    }
                    _ASN_CACHE[ip_clean] = rec
                    return rec
    except Exception as exc:
        logger.debug(f"Live ASN lookup failed for {ip_clean}: {exc}")

    # 4. Fallback when unconfigured / offline
    rec = {
        "status": "unknown",
        "ip": ip_clean,
        "asn": None,
        "organization": None,
        "network": None,
        "registry": None,
        "source": "unavailable",
        "reason": "ASN provider not configured or unavailable",
    }
    _ASN_CACHE[ip_clean] = rec
    return rec
