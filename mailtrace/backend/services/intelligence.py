"""
services/intelligence.py — MAILTRACE Infrastructure Intelligence Layer.

Primary Entry Point:
    enrich_infrastructure(
        parsed_email: dict[str, Any],
        forensic_analysis: dict[str, Any] | None = None,
        threat_analysis: dict[str, Any] | None = None,
    ) -> dict[str, Any]

Enrichment Responsibilities:
    1. IP Intelligence:
       - Classification (public, private, loopback, reserved).
       - Non-public IP exclusion from external lookups.
       - Approximate infrastructure GeoIP (Country, Region, City, Coordinates, Timezone).
       - Autonomous System (ASN number, ASN organization, Network CIDR).
    2. Domain Intelligence:
       - Normalization & Registrable Root Domain isolation.
       - RDAP / Registration metadata (Registrar, Created/Expires timestamps, Privacy).
    3. Safe Passive URL Intelligence:
       - Structural decomposition (Scheme, Host, Port, Path, Query).
       - Structural anomaly detection (IP hosts, Shorteners, Punycode, High-risk extensions).
       - Stable SHA-256 URL hashing for entity correlation.
    4. Lightweight in-memory caching to avoid redundant infrastructure queries.
    5. Preparation of correlation entities for downstream campaign graph modeling.

Forensic Limitation & Attribution Safeguard:
    - GeoIP represents approximate sending infrastructure transport nodes, NOT physical human attacker locations.
    - Zero active website visits, crawling, or attachment execution.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import concurrent.futures
import socket
from backend.utils.asn_utils import clear_asn_cache, lookup_asn
from backend.utils.geoip import clear_geoip_cache, lookup_geoip
from backend.utils.ip_utils import classify_ip
from backend.utils.url_intel import analyze_url_structure
from backend.utils.url_utils import normalize_domain
from backend.utils.whois_utils import _get_base_domain, clear_rdap_cache, lookup_rdap_domain

logger = logging.getLogger("mailtrace.intelligence")

# ------------------------------------------------------------------ #
#  In-Memory Caches                                                  #
# ------------------------------------------------------------------ #

_IP_INTEL_CACHE: dict[str, dict[str, Any]] = {}
_DOMAIN_INTEL_CACHE: dict[str, dict[str, Any]] = {}
_DOMAIN_DNS_CACHE: dict[str, list[str]] = {}


def clear_intel_cache() -> None:
    """Clear in-memory intelligence caches (primarily used for unit testing)."""
    global _IP_INTEL_CACHE, _DOMAIN_INTEL_CACHE, _DOMAIN_DNS_CACHE
    _IP_INTEL_CACHE.clear()
    _DOMAIN_INTEL_CACHE.clear()
    _DOMAIN_DNS_CACHE.clear()
    clear_geoip_cache()
    clear_asn_cache()
    clear_rdap_cache()


def _resolve_domain_ips(domain: str) -> list[str]:
    """Perform fast, non-blocking DNS A-record resolution for a domain name."""
    norm = normalize_domain(domain)
    if not norm or "." not in norm or classify_ip(norm) != "unknown":
        return []
    if norm in _DOMAIN_DNS_CACHE:
        return _DOMAIN_DNS_CACHE[norm]
    try:
        addr_info = socket.getaddrinfo(norm, 80, socket.AF_INET, socket.SOCK_STREAM)
        ips = []
        for item in addr_info:
            ip_val = item[4][0]
            if ip_val and classify_ip(ip_val) == "public" and ip_val not in ips:
                ips.append(ip_val)
        _DOMAIN_DNS_CACHE[norm] = ips
        return ips
    except Exception:
        _DOMAIN_DNS_CACHE[norm] = []
        return []


# ------------------------------------------------------------------ #
#  Enrichment Helper Functions                                       #
# ------------------------------------------------------------------ #

def _enrich_single_ip(ip: str) -> dict[str, Any]:
    """Enrich a single IP address with GeoIP, ASN, and classification."""
    ip_clean = ip.strip()
    if ip_clean in _IP_INTEL_CACHE:
        return _IP_INTEL_CACHE[ip_clean]

    classification = classify_ip(ip_clean)
    geo_data = lookup_geoip(ip_clean)
    asn_data = lookup_asn(ip_clean)

    is_public = classification == "public"
    status = "success" if is_public and (geo_data.get("status") == "success" or asn_data.get("status") == "success") else (
        "excluded" if not is_public else "unavailable"
    )

    primary_source = "unavailable"
    if geo_data.get("source") not in ("unavailable", "local_filter", None):
        primary_source = geo_data.get("source")
    elif asn_data.get("source") not in ("unavailable", "local_filter", None):
        primary_source = asn_data.get("source")
    elif not is_public:
        primary_source = "local_filter"

    record = {
        "ip": ip_clean,
        "version": 4 if ":" not in ip_clean else 6,
        "classification": classification,
        "geo": geo_data,
        "asn": asn_data,
        "source": primary_source,
        "status": status,
    }

    _IP_INTEL_CACHE[ip_clean] = record
    return record


def _enrich_single_domain(domain: str) -> dict[str, Any]:
    """Enrich a single domain with RDAP metadata and structural decomposition."""
    domain_clean = normalize_domain(domain)
    if domain_clean in _DOMAIN_INTEL_CACHE:
        return _DOMAIN_INTEL_CACHE[domain_clean]

    base_domain = _get_base_domain(domain_clean)
    rdap_data = lookup_rdap_domain(domain_clean)

    # Subdomain calculation
    subdomain = None
    if domain_clean != base_domain and domain_clean.endswith("." + base_domain):
        subdomain = domain_clean[: -(len(base_domain) + 1)]

    tld = base_domain.split(".")[-1] if "." in base_domain else ""

    record = {
        "domain": domain_clean,
        "registrable_domain": base_domain,
        "subdomain": subdomain,
        "tld": tld,
        "rdap": rdap_data,
        "source": rdap_data.get("source", "unavailable"),
        "status": rdap_data.get("status", "unavailable"),
    }

    _DOMAIN_INTEL_CACHE[domain_clean] = record
    return record


# ------------------------------------------------------------------ #
#  Main Orchestrator                                                 #
# ------------------------------------------------------------------ #

def enrich_infrastructure(
    parsed_email: dict[str, Any],
    forensic_analysis: dict[str, Any] | None = None,
    threat_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Perform passive infrastructure intelligence enrichment on parsed email IOCs.

    Returns structured dictionary with:
        - summary: counts and completion status
        - ips: list of enriched IP records
        - domains: list of enriched domain records
        - urls: list of passive URL structure analysis records
        - correlation_entities: structured entity maps for correlation modeling
        - limitations: explicit attribution safeguards and data limitations
    """
    if not isinstance(parsed_email, dict):
        parsed_email = {}

    # 1. Collect unique domains
    collected_domains: list[str] = []
    seen_domains: set[str] = set()

    for dom in parsed_email.get("domains", []):
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            collected_domains.append(dom)

    # Sender, Reply-To, Return-Path domains
    sender_domain = parsed_email.get("sender", {}).get("domain") if isinstance(parsed_email.get("sender"), dict) else None
    if sender_domain and sender_domain not in seen_domains:
        seen_domains.add(sender_domain)
        collected_domains.append(sender_domain)

    reply_to_dom = parsed_email.get("reply_to", {}).get("domain") if isinstance(parsed_email.get("reply_to"), dict) else None
    if reply_to_dom and reply_to_dom not in seen_domains:
        seen_domains.add(reply_to_dom)
        collected_domains.append(reply_to_dom)

    return_path_dom = parsed_email.get("return_path", {}).get("domain") if isinstance(parsed_email.get("return_path"), dict) else None
    if return_path_dom and return_path_dom not in seen_domains:
        seen_domains.add(return_path_dom)
        collected_domains.append(return_path_dom)

    # Domains from URLs
    for u_item in parsed_email.get("urls", []):
        u_str = u_item.get("url", "") if isinstance(u_item, dict) else str(u_item)
        u_dom = u_item.get("domain", "") if isinstance(u_item, dict) else ""
        if not u_dom and "://" in u_str:
            u_dom = u_str.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        if u_dom and classify_ip(u_dom) == "unknown" and u_dom not in seen_domains:
            seen_domains.add(u_dom)
            collected_domains.append(u_dom)

    # 2. Collect unique IP addresses (headers, transport hops, URL hosts)
    collected_ips: list[str] = []
    seen_ips: set[str] = set()

    for item in parsed_email.get("ip_addresses", []):
        ip_val = item.get("ip") if isinstance(item, dict) else str(item)
        if ip_val and ip_val not in seen_ips:
            seen_ips.add(ip_val)
            collected_ips.append(ip_val)

    for ip_val in parsed_email.get("originating_ips", []):
        if ip_val and ip_val not in seen_ips:
            seen_ips.add(ip_val)
            collected_ips.append(ip_val)

    relay = parsed_email.get("received_chain", {})
    if isinstance(relay, dict):
        for ip_val in relay.get("public_ips_observed", []):
            if ip_val and ip_val not in seen_ips:
                seen_ips.add(ip_val)
                collected_ips.append(ip_val)

        for hop in relay.get("chain", []):
            if isinstance(hop, dict):
                for ip_val in hop.get("ips_found", []):
                    if ip_val and ip_val not in seen_ips:
                        seen_ips.add(ip_val)
                        collected_ips.append(ip_val)

    # Collect IPs from URL hosts
    for u_item in parsed_email.get("urls", []):
        u_str = u_item.get("url", "") if isinstance(u_item, dict) else str(u_item)
        domain = u_item.get("domain", "") if isinstance(u_item, dict) else ""
        if not domain and "://" in u_str:
            domain = u_str.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        if domain and classify_ip(domain) != "unknown":
            if domain not in seen_ips:
                seen_ips.add(domain)
                collected_ips.append(domain)

    # 3. Live DNS A-Record Resolution for domains
    domain_resolved_map: dict[str, list[str]] = {}
    if collected_domains:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(collected_domains))) as ex:
                domain_ip_results = list(ex.map(_resolve_domain_ips, collected_domains))
            for dom, res_ips in zip(collected_domains, domain_ip_results):
                domain_resolved_map[dom] = res_ips
                # If no explicit header/hop IPs were present in the email, use resolved domain IPs for GeoMap plotting
                if not collected_ips:
                    for ip_res in res_ips:
                        if ip_res not in seen_ips:
                            seen_ips.add(ip_res)
                            collected_ips.append(ip_res)
        except Exception as dns_exc:
            logger.debug(f"DNS resolution batch error: {dns_exc}")

    # 4. Enrich IPs (concurrent / parallel)
    enriched_ips: list[dict[str, Any]] = []
    public_ip_count = 0
    private_ip_count = 0

    if collected_ips:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(collected_ips))) as ex:
                enriched_ips = list(ex.map(_enrich_single_ip, collected_ips))
        except Exception:
            enriched_ips = [_enrich_single_ip(ip) for ip in collected_ips]

        for rec in enriched_ips:
            if rec.get("classification") == "public":
                public_ip_count += 1
            else:
                private_ip_count += 1

    # 5. Enrich domains (concurrent / parallel)
    enriched_domains: list[dict[str, Any]] = []
    if collected_domains:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(collected_domains))) as ex:
                enriched_domains = list(ex.map(_enrich_single_domain, collected_domains))
        except Exception:
            enriched_domains = [_enrich_single_domain(d) for d in collected_domains]

    # 6. Analyze URLs passively
    analyzed_urls: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    suspicious_url_count = 0

    for u_item in parsed_email.get("urls", []):
        u_str = u_item.get("url", "") if isinstance(u_item, dict) else str(u_item)
        if u_str and u_str not in seen_urls:
            seen_urls.add(u_str)
            u_analysis = analyze_url_structure(u_str)
            analyzed_urls.append(u_analysis)
            if u_analysis.get("indicators"):
                suspicious_url_count += 1

    # 4. Correlation Entities Preparation
    correlation_entities = {
        "ips": [
            {
                "ip": r["ip"],
                "classification": r["classification"],
                "asn": r.get("asn", {}).get("asn"),
                "country": r.get("geo", {}).get("country"),
            }
            for r in enriched_ips
        ],
        "domains": [
            {
                "domain": d["domain"],
                "registrable_domain": d["registrable_domain"],
                "registrar": d.get("rdap", {}).get("registrar"),
            }
            for d in enriched_domains
        ],
        "urls": [
            {
                "url": u["url"],
                "registrable_domain": u["registrable_domain"],
                "url_hash": u["url_hash"],
            }
            for u in analyzed_urls
        ],
        "asns": list({
            r.get("asn", {}).get("asn")
            for r in enriched_ips
            if r.get("asn", {}).get("asn")
        }),
    }

    summary = {
        "status": "completed",
        "total_ips": len(enriched_ips),
        "public_ips": public_ip_count,
        "private_ips": private_ip_count,
        "total_domains": len(enriched_domains),
        "total_urls": len(analyzed_urls),
        "suspicious_urls_count": suspicious_url_count,
    }

    limitations = [
        "IP geolocation and ASN data reflect observed network transport infrastructure and do NOT identify physical human operators or confirm attacker attribution.",
        "Private, loopback, and reserved IP addresses are classified and excluded from external lookups.",
        "WHOIS/RDAP data may be redacted or withheld per registrar privacy proxy policies.",
        "URL intelligence is strictly structural and passive; URLs are never fetched, rendered, or crawled.",
    ]

    return {
        "summary": summary,
        "ips": enriched_ips,
        "domains": enriched_domains,
        "urls": analyzed_urls,
        "correlation_entities": correlation_entities,
        "limitations": limitations,
    }
