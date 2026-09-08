"""
utils/url_intel.py — Safe, passive URL structural intelligence and indicator analysis.

Features:
    1. 100% Passive decomposition (ZERO outbound network requests / NO fetching).
    2. Structural anomaly detection:
       - IP host URLs
       - Punycode / IDN deception
       - Known URL shorteners
       - Excessive subdomain nesting
       - Unusual non-standard network ports
       - Credential / authentication phishing paths
       - Executable or archive file extensions in URL paths
       - Userinfo '@' symbol misdirection
    3. Stable SHA-256 URL hashing for entity correlation.

Design Rules:
    - Never fetches, opens, or follows redirects.
    - Never throws unhandled exceptions.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from backend.utils.ip_utils import classify_ip
from backend.utils.url_utils import normalize_domain
from backend.utils.whois_utils import _get_base_domain

logger = logging.getLogger("mailtrace.utils.url_intel")

# Known URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "goo.gl", "rb.gy", "shorturl.at", "bl.ink", "rebrandly.com", "snip.ly"
}

# Credential / Authentication path keywords
CREDENTIAL_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "password",
    "credential", "account-update", "secure-login", "auth", "webscr",
    "cmd=_login-run", "owa", "logon", "re-authenticate"
]

# High risk extensions in URL paths
DANGEROUS_PATH_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".hta", ".cpl",
    ".jar", ".ps1", ".iso", ".img", ".pif", ".docm", ".xlsm"
}


def analyze_url_structure(url: str) -> dict[str, Any]:
    """
    Perform safe, passive structural intelligence on a URL string.

    Returns structured dictionary with:
        - url: str
        - scheme: str
        - hostname: str
        - port: int | None
        - registrable_domain: str
        - path: str
        - query_params_count: int
        - url_hash: str (SHA-256)
        - flags: dict of boolean flags
        - indicators: list of structural risk indicator strings
    """
    if not url or not isinstance(url, str):
        return {
            "url": str(url),
            "scheme": "",
            "hostname": "",
            "port": None,
            "registrable_domain": "",
            "path": "",
            "query_params_count": 0,
            "url_hash": hashlib.sha256(b"").hexdigest(),
            "flags": {},
            "indicators": [],
        }

    clean_url = url.strip().rstrip(".,;:!?)>\"'")
    url_hash = hashlib.sha256(clean_url.encode("utf-8")).hexdigest()

    try:
        p = urlparse(clean_url)
    except Exception:
        return {
            "url": clean_url,
            "scheme": "",
            "hostname": "",
            "port": None,
            "registrable_domain": "",
            "path": "",
            "query_params_count": 0,
            "url_hash": url_hash,
            "flags": {"malformed": True},
            "indicators": ["Malformed URL syntax"],
        }

    scheme = p.scheme.lower() if p.scheme else ""
    hostname = p.hostname.lower() if p.hostname else ""
    port = p.port
    path = p.path or ""
    query = p.query or ""

    # Parse query parameter count
    query_params_count = 0
    if query:
        try:
            params = parse_qs(query)
            query_params_count = len(params)
        except Exception:
            pass

    # Base domain
    registrable_domain = _get_base_domain(hostname) if hostname else ""

    # Flags
    is_ip = classify_ip(hostname) != "unknown" if hostname else False
    is_punycode = "xn--" in hostname
    is_shortener = registrable_domain in URL_SHORTENERS or hostname in URL_SHORTENERS
    
    # Subdomain count
    subdomains = hostname.split(".")
    excessive_subdomains = len(subdomains) > 4 if not is_ip else False

    # Port check
    unusual_port = False
    if port and port not in (80, 443):
        unusual_port = True

    # Credential keywords in path or query
    combined_path_query = f"{path.lower()}?{query.lower()}"
    has_credential_keywords = any(kw in combined_path_query for kw in CREDENTIAL_PATH_KEYWORDS)

    # Dangerous extensions in path
    has_suspicious_ext = any(path.lower().endswith(ext) for ext in DANGEROUS_PATH_EXTENSIONS)

    # '@' symbol in netloc
    at_symbol_present = "@" in p.netloc

    # Collect indicators
    indicators: list[str] = []
    if is_ip:
        indicators.append(f"URL uses direct IP address host ({hostname}) instead of registered domain name")
    if is_punycode:
        indicators.append(f"URL uses internationalized/punycode domain ({hostname}) which may indicate visual spoofing")
    if is_shortener:
        indicators.append(f"URL uses shortening service ({registrable_domain}) which obscures destination target")
    if excessive_subdomains:
        indicators.append(f"URL contains excessive subdomain nesting ({len(subdomains)} levels)")
    if unusual_port:
        indicators.append(f"URL specifies non-standard web port ({port})")
    if has_credential_keywords:
        indicators.append("URL path contains credential solicitation / authentication keywords")
    if has_suspicious_ext:
        indicators.append("URL path targets an executable or high-risk file extension")
    if at_symbol_present:
        indicators.append("URL authority contains '@' character which can be used to deceive visual inspection")

    flags = {
        "is_ip_host": is_ip,
        "is_punycode": is_punycode,
        "is_shortened": is_shortener,
        "excessive_subdomains": excessive_subdomains,
        "unusual_port": unusual_port,
        "has_credential_keywords": has_credential_keywords,
        "has_suspicious_extension": has_suspicious_ext,
        "at_symbol_misdirection": at_symbol_present,
    }

    return {
        "url": clean_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "registrable_domain": registrable_domain,
        "path": path,
        "query_params_count": query_params_count,
        "url_hash": url_hash,
        "flags": flags,
        "indicators": indicators,
    }
