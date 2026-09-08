"""
utils/url_utils.py — URL/domain extraction and HTML-to-text helpers.

Pure stdlib — no outbound HTTP calls.
Phase 5 adds reputation lookups on top of the data extracted here.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlparse, urlunparse

# ------------------------------------------------------------------ #
#  URL regex — matches http/https/ftp URLs in plain text             #
# ------------------------------------------------------------------ #

_URL_RE = re.compile(
    r"(?:https?|ftp)://"                    # scheme
    r"[^\s<>\"'(){}\[\]|\\^`]+",           # rest of URL
    re.IGNORECASE,
)

# ------------------------------------------------------------------ #
#  HTML parsers                                                       #
# ------------------------------------------------------------------ #

class _HrefExtractor(HTMLParser):
    """Collect href/src/action attribute values from HTML."""

    def __init__(self):
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]):
        for attr_name, attr_val in attrs:
            if attr_name in ("href", "src", "action") and attr_val:
                v = attr_val.strip()
                if v and not v.startswith(("#", "mailto:", "tel:", "javascript:")):
                    self.urls.append(v)


class _TextExtractor(HTMLParser):
    """Strip HTML tags and return visible text."""

    _SKIP = {"script", "style", "head", "meta", "link", "noscript"}

    def __init__(self):
        super().__init__()
        self._chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag: str):
        if tag.lower() in self._SKIP and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str):
        if self._skip_depth == 0:
            s = data.strip()
            if s:
                self._chunks.append(s)

    def get_text(self) -> str:
        return "\n".join(self._chunks)


# ------------------------------------------------------------------ #
#  URL extraction                                                     #
# ------------------------------------------------------------------ #

def _normalize_url(raw: str) -> Optional[str]:
    try:
        raw = raw.rstrip(".,;:!?)>\"'")
        p = urlparse(raw)
        if not p.scheme or not p.netloc:
            return None
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, p.params, p.query, ""))
    except Exception:
        return None


def _make_url_dict(url: str, source: str) -> dict:
    p = urlparse(url)
    return {
        "url": url,
        "scheme": p.scheme,
        "domain": p.hostname or "",
        "path": p.path or "",
        "query": p.query or "",
        "source": source,
    }


def extract_urls_from_text(text: str) -> list[dict]:
    """Extract URLs from plain-text body."""
    results: list[dict] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(text):
        norm = _normalize_url(m.group(0))
        if norm and norm not in seen:
            seen.add(norm)
            results.append(_make_url_dict(norm, "text_body"))
    return results


def extract_urls_from_html(html: str) -> list[dict]:
    """Extract URLs from HTML — href attributes + inline text URLs."""
    results: list[dict] = []
    seen: set[str] = set()

    # --- href / src attributes ---
    parser = _HrefExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    for raw in parser.urls:
        if raw.startswith("//"):
            raw = "https:" + raw
        norm = _normalize_url(raw)
        if norm and norm not in seen:
            seen.add(norm)
            results.append(_make_url_dict(norm, "html_href"))

    # --- inline text URLs inside HTML ---
    for m in _URL_RE.finditer(html):
        norm = _normalize_url(m.group(0))
        if norm and norm not in seen:
            seen.add(norm)
            results.append(_make_url_dict(norm, "html_text"))

    return results


# ------------------------------------------------------------------ #
#  Domain helpers                                                     #
# ------------------------------------------------------------------ #

def extract_domain_from_email(addr: str) -> Optional[str]:
    """Return the domain part of an email address, or None."""
    if not addr:
        return None
    # Strip display name: 'Name <user@domain>'
    if "<" in addr and ">" in addr:
        addr = addr[addr.index("<") + 1 : addr.index(">")]
    addr = addr.strip().lower()
    if "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[1].strip()
    return domain or None


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def extract_domains_from_urls(urls: list[dict]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for u in urls:
        d = normalize_domain(u.get("domain", ""))
        if d and d not in seen:
            seen.add(d)
            result.append(d)
    return result


def collect_all_domains(*domain_lists: list[str]) -> list[str]:
    """Merge, deduplicate, normalize, and sort domain lists."""
    seen: set[str] = set()
    result: list[str] = []
    for lst in domain_lists:
        for d in lst:
            d = normalize_domain(d)
            if d and "." in d and d not in seen:
                seen.add(d)
                result.append(d)
    return sorted(result)


# ------------------------------------------------------------------ #
#  HTML → plain text                                                  #
# ------------------------------------------------------------------ #

def html_to_text(html: str) -> str:
    """Convert HTML to plain text for NLP consumption."""
    if not html:
        return ""
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
        text = extractor.get_text()
    except Exception:
        text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
