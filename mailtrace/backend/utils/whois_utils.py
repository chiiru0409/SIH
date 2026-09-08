"""
utils/whois_utils.py — Domain Registration & RDAP intelligence lookup abstraction.

Supports:
    1. RFC 7480 / RFC 9082 structured RDAP lookup.
    2. Registrable root domain extraction & normalization.
    3. Privacy redaction detection.
    4. Graceful offline fallback.

Design Rules:
    - Zero active website visits or web crawling.
    - Strictly passive registration metadata lookup.
    - Never throws unhandled exceptions.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from backend.utils.url_utils import normalize_domain

logger = logging.getLogger("mailtrace.utils.whois")


def _get_base_domain(domain: str) -> str:
    """Extract organizational/base domain (e.g. sub.example.com -> example.com)."""
    d = normalize_domain(domain)
    parts = d.split(".")
    if len(parts) >= 2:
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


# In-memory RDAP domain cache
_RDAP_CACHE: dict[str, dict[str, Any]] = {}


def clear_rdap_cache() -> None:
    """Clear in-memory RDAP cache."""
    _RDAP_CACHE.clear()


def lookup_rdap_domain(domain: str) -> dict[str, Any]:
    """
    Perform passive RDAP registration lookup for a domain.

    Returns structured dictionary with:
        - status: 'success' | 'unavailable' | 'error'
        - domain: str
        - registrable_domain: str
        - registrar: str | None
        - created / creation_date: str | None
        - expires / expiration_date: str | None
        - updated / updated_date: str | None
        - status_codes: list[str]
        - nameservers: list[str]
        - registrant_privacy: str
        - source: 'rdap' | 'unavailable'
        - reason: str | None
    """
    if not domain or not isinstance(domain, str):
        return {
            "status": "error",
            "domain": domain,
            "registrable_domain": None,
            "registrar": None,
            "created": None,
            "creation_date": None,
            "expires": None,
            "expiration_date": None,
            "updated": None,
            "updated_date": None,
            "status_codes": [],
            "nameservers": [],
            "registrant_privacy": "unknown",
            "source": "unavailable",
            "reason": "Invalid domain input",
        }

    norm_domain = normalize_domain(domain)
    base_domain = _get_base_domain(norm_domain)

    if not base_domain or "." not in base_domain:
        return {
            "status": "unavailable",
            "domain": norm_domain,
            "registrable_domain": base_domain,
            "registrar": None,
            "created": None,
            "creation_date": None,
            "expires": None,
            "expiration_date": None,
            "updated": None,
            "updated_date": None,
            "status_codes": [],
            "nameservers": [],
            "registrant_privacy": "unknown",
            "source": "unavailable",
            "reason": "Invalid registrable domain",
        }

    if base_domain in _RDAP_CACHE:
        return _RDAP_CACHE[base_domain]

    # Attempt RDAP lookup via standard HTTPS RDAP endpoints
    rdap_endpoints = [
        f"https://rdap.org/domain/{base_domain}",
        f"https://rdap.iana.org/domain/{base_domain}",
    ]

    try:
        import httpx  # type: ignore

        for url in rdap_endpoints:
            try:
                with httpx.Client(timeout=2.5, follow_redirects=True) as client:
                    resp = client.get(url, headers={"Accept": "application/rdap+json, application/json"})
                    if resp.status_code == 200:
                        data = resp.json()

                        # Extract events (created, expires, updated)
                        events = data.get("events", [])
                        created = None
                        expires = None
                        updated = None
                        for ev in events:
                            action = ev.get("eventAction", "").lower()
                            date_val = ev.get("eventDate")
                            if action == "registration":
                                created = date_val
                            elif action == "expiration":
                                expires = date_val
                            elif action in ("last changed", "last update"):
                                updated = date_val

                        # Extract registrar
                        registrar = None
                        entities = data.get("entities", [])
                        for ent in entities:
                            roles = ent.get("roles", [])
                            if "registrar" in roles:
                                vcard = ent.get("vcardArray", [])
                                if len(vcard) > 1 and isinstance(vcard[1], list):
                                    for prop in vcard[1]:
                                        if len(prop) > 3 and prop[0] == "fn":
                                            registrar = prop[3]
                                            break
                                if not registrar:
                                    registrar = ent.get("handle") or ent.get("name")

                        # Extract nameservers
                        nameservers = []
                        for ns in data.get("nameservers", []):
                            ns_name = ns.get("ldhName") or ns.get("handle") or (ns.get("name") if isinstance(ns, dict) else str(ns))
                            if ns_name:
                                nameservers.append(str(ns_name).lower())

                        # Status codes
                        status_codes = data.get("status", [])

                        # Privacy detection
                        privacy = "redacted"
                        raw_str = str(data).lower()
                        if "privacy" in raw_str or "proxy" in raw_str or "withheld" in raw_str or "redacted" in raw_str:
                            privacy = "protected"

                        rec = {
                            "status": "success",
                            "domain": norm_domain,
                            "registrable_domain": base_domain,
                            "registrar": registrar,
                            "created": created,
                            "creation_date": created,
                            "expires": expires,
                            "expiration_date": expires,
                            "updated": updated,
                            "updated_date": updated,
                            "status_codes": status_codes,
                            "nameservers": nameservers,
                            "registrant_privacy": privacy,
                            "source": "rdap",
                            "reason": None,
                        }
                        _RDAP_CACHE[base_domain] = rec
                        return rec
            except Exception:
                continue
    except Exception as exc:
        logger.debug(f"RDAP lookup exception for {base_domain}: {exc}")

    # Fallback when unavailable / offline
    rec = {
        "status": "unavailable",
        "domain": norm_domain,
        "registrable_domain": base_domain,
        "registrar": None,
        "created": None,
        "creation_date": None,
        "expires": None,
        "expiration_date": None,
        "updated": None,
        "updated_date": None,
        "status_codes": [],
        "nameservers": [],
        "registrant_privacy": "not available",
        "source": "unavailable",
        "reason": "RDAP lookup not configured or domain not found",
    }
    _RDAP_CACHE[base_domain] = rec
    return rec
