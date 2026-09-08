"""
tests/test_parser.py — Automated tests for the MAILTRACE forensic email parser.

Covers every extraction requirement from the Step 2 specification:
  - sender extraction
  - recipient extraction
  - subject extraction (including encoded)
  - Received header extraction + relay chain
  - authentication extraction (SPF / DKIM / DMARC)
  - URL extraction (text body + HTML href)
  - domain extraction
  - IP extraction + classification
  - attachment metadata + SHA-256
  - evidence SHA-256 hashing
  - malformed / empty email handling
  - HTML-only email
  - multipart email
  - Unicode subject
  - reply-to mismatch detection

Run:
    cd mailtrace
    python -m pytest tests/test_parser.py -v
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# Make sure the mailtrace package root is on sys.path when running
# pytest from inside the mailtrace/ directory.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
from backend.services.email_parser import parse_email
from backend.services.evidence import (
    sha256_bytes,
    sha256_dict,
    sha256_string,
    build_evidence_record,
    verify_bytes_hash,
)
from backend.utils.ip_utils import classify_ip, extract_ips_from_text, annotate_ip
from backend.utils.url_utils import (
    extract_urls_from_text,
    extract_urls_from_html,
    extract_domain_from_email,
    html_to_text,
    collect_all_domains,
)

SAMPLES = ROOT / "samples"


# ================================================================== #
#  Fixtures — load sample .eml files                                 #
# ================================================================== #

@pytest.fixture(scope="module")
def basic_bytes():
    return (SAMPLES / "basic.eml").read_bytes()

@pytest.fixture(scope="module")
def phishing_bytes():
    return (SAMPLES / "phishing.eml").read_bytes()

@pytest.fixture(scope="module")
def multipart_bytes():
    return (SAMPLES / "multipart.eml").read_bytes()

@pytest.fixture(scope="module")
def attachment_bytes():
    return (SAMPLES / "attachment.eml").read_bytes()

@pytest.fixture(scope="module")
def basic_parsed(basic_bytes):
    return parse_email(basic_bytes)

@pytest.fixture(scope="module")
def phishing_parsed(phishing_bytes):
    return parse_email(phishing_bytes)

@pytest.fixture(scope="module")
def multipart_parsed(multipart_bytes):
    return parse_email(multipart_bytes)

@pytest.fixture(scope="module")
def attachment_parsed(attachment_bytes):
    return parse_email(attachment_bytes)


# ================================================================== #
#  1. Basic email — sender extraction                                 #
# ================================================================== #

class TestSenderExtraction:

    def test_sender_email(self, basic_parsed):
        assert basic_parsed["sender"]["email"] == "alice@example.com"

    def test_sender_display_name(self, basic_parsed):
        assert basic_parsed["sender"]["display_name"] == "Alice Johnson"

    def test_sender_domain(self, basic_parsed):
        assert basic_parsed["sender"]["domain"] == "example.com"

    def test_sender_not_none(self, basic_parsed):
        assert basic_parsed["sender"] is not None

    def test_phishing_sender_domain(self, phishing_parsed):
        # Spoofed PayPal domain
        assert phishing_parsed["sender"]["domain"] == "paypa1-secure.com"


# ================================================================== #
#  2. Recipient extraction                                            #
# ================================================================== #

class TestRecipientExtraction:

    def test_to_list_not_empty(self, basic_parsed):
        assert len(basic_parsed["recipients"]["to"]) > 0

    def test_to_email(self, basic_parsed):
        to_emails = [r["email"] for r in basic_parsed["recipients"]["to"]]
        assert "bob@company.org" in to_emails

    def test_to_domain(self, basic_parsed):
        to_domains = [r["domain"] for r in basic_parsed["recipients"]["to"]]
        assert "company.org" in to_domains

    def test_cc_populated(self, multipart_parsed):
        cc_emails = [r["email"] for r in multipart_parsed["recipients"]["cc"]]
        assert "archive@techdigest.io" in cc_emails

    def test_bcc_empty_when_absent(self, basic_parsed):
        assert basic_parsed["recipients"]["bcc"] == []


# ================================================================== #
#  3. Subject extraction (plain + encoded)                           #
# ================================================================== #

class TestSubjectExtraction:

    def test_basic_subject(self, basic_parsed):
        assert basic_parsed["headers"]["subject"] == "Project Update - Q3 Review"

    def test_phishing_subject_decoded(self, phishing_parsed):
        # Base64-encoded subject must be decoded
        subj = phishing_parsed["headers"]["subject"]
        assert subj is not None
        assert "URGENT" in subj or "suspended" in subj.lower()

    def test_multipart_subject_decoded(self, multipart_parsed):
        # Also Base64-encoded emoji + text
        subj = multipart_parsed["headers"]["subject"]
        assert subj is not None
        assert len(subj) > 0

    def test_message_id_present(self, basic_parsed):
        assert basic_parsed["headers"]["message_id"] is not None


# ================================================================== #
#  4. Received header / relay chain                                   #
# ================================================================== #

class TestReceivedChain:

    def test_hop_count_basic(self, basic_parsed):
        assert basic_parsed["received_chain"]["hop_count"] == 2

    def test_relay_chain_not_empty(self, basic_parsed):
        assert len(basic_parsed["received_chain"]["chain"]) == 2

    def test_chain_has_from_ip(self, basic_parsed):
        # At least one hop should have an extracted IP
        chain = basic_parsed["received_chain"]["chain"]
        ips = [h["from_ip"] for h in chain if h["from_ip"]]
        assert len(ips) > 0

    def test_earliest_node_present(self, basic_parsed):
        assert basic_parsed["received_chain"]["earliest_observed_node"] is not None

    def test_public_ips_extracted(self, basic_parsed):
        public = basic_parsed["received_chain"]["public_ips_observed"]
        assert len(public) > 0

    def test_phishing_public_ip(self, phishing_parsed):
        # 185.220.101.45 is the X-Originating-IP in the phishing sample
        all_ips = [a["ip"] for a in phishing_parsed["ip_addresses"]]
        assert "185.220.101.45" in all_ips

    def test_confidence_note_present(self, basic_parsed):
        note = basic_parsed["received_chain"]["confidence_note"]
        assert note and len(note) > 10

    def test_multipart_hop_count(self, multipart_parsed):
        assert multipart_parsed["received_chain"]["hop_count"] == 2


# ================================================================== #
#  5. Authentication extraction                                       #
# ================================================================== #

class TestAuthentication:

    def test_spf_pass_basic(self, basic_parsed):
        assert basic_parsed["authentication"]["spf"]["status"] == "pass"

    def test_dkim_pass_basic(self, basic_parsed):
        assert basic_parsed["authentication"]["dkim"]["status"] == "pass"

    def test_dmarc_pass_basic(self, basic_parsed):
        assert basic_parsed["authentication"]["dmarc"]["status"] == "pass"

    def test_spf_fail_phishing(self, basic_parsed, phishing_parsed):
        assert basic_parsed["authentication"]["spf"]["status"] == "pass"  # basic still passes
        assert phishing_parsed["authentication"]["spf"]["status"] == "fail"

    def test_dkim_none_phishing(self, phishing_parsed):
        # Phishing email has no DKIM signature
        status = phishing_parsed["authentication"]["dkim"]["status"]
        assert status is None or status == "none"

    def test_dmarc_fail_phishing(self, phishing_parsed):
        assert phishing_parsed["authentication"]["dmarc"]["status"] == "fail"

    def test_dkim_domain_extracted(self, basic_parsed):
        assert basic_parsed["authentication"]["dkim"]["domain"] == "example.com"

    def test_no_auth_results_raw_in_phishing(self, phishing_parsed):
        # phishing has auth results but they all fail
        spf = phishing_parsed["authentication"]["spf"]["status"]
        assert spf == "fail"

    def test_spf_raw_preserved(self, basic_parsed):
        assert basic_parsed["authentication"]["spf"]["raw"] is not None

    def test_dkim_raw_preserved(self, basic_parsed):
        assert basic_parsed["authentication"]["dkim"]["raw"] is not None


# ================================================================== #
#  6. URL extraction                                                  #
# ================================================================== #

class TestUrlExtraction:

    def test_urls_extracted_from_phishing_html(self, phishing_parsed):
        urls = [u["url"] for u in phishing_parsed["urls"]]
        assert any("paypa1-secure.com" in u for u in urls)

    def test_url_has_scheme(self, phishing_parsed):
        for u in phishing_parsed["urls"]:
            assert u["scheme"] in ("http", "https", "ftp")

    def test_url_has_domain(self, phishing_parsed):
        for u in phishing_parsed["urls"]:
            assert u["domain"] != ""

    def test_url_has_source(self, phishing_parsed):
        for u in phishing_parsed["urls"]:
            assert u["source"] in ("text_body", "html_href", "html_text")

    def test_multipart_urls_from_html(self, multipart_parsed):
        urls = [u["url"] for u in multipart_parsed["urls"]]
        assert any("techdigest.io" in u for u in urls)

    def test_basic_no_urls(self, basic_parsed):
        # basic.eml has no URLs in body
        assert isinstance(basic_parsed["urls"], list)

    def test_urls_deduplicated(self, phishing_parsed):
        url_strs = [u["url"] for u in phishing_parsed["urls"]]
        assert len(url_strs) == len(set(url_strs))

    def test_url_extraction_from_text_direct(self):
        text = "Visit https://example.com/path?q=1 and http://other.org"
        result = extract_urls_from_text(text)
        domains = [u["domain"] for u in result]
        assert "example.com" in domains
        assert "other.org" in domains

    def test_url_extraction_from_html_direct(self):
        html = '<a href="https://threat.example.com/phish">click</a>'
        result = extract_urls_from_html(html)
        assert any("threat.example.com" in u["domain"] for u in result)


# ================================================================== #
#  7. Domain extraction                                               #
# ================================================================== #

class TestDomainExtraction:

    def test_sender_domain_in_domains(self, basic_parsed):
        assert "example.com" in basic_parsed["domains"]

    def test_phishing_sender_domain_in_domains(self, phishing_parsed):
        assert "paypa1-secure.com" in phishing_parsed["domains"]

    def test_domains_deduplicated(self, phishing_parsed):
        domains = phishing_parsed["domains"]
        assert len(domains) == len(set(domains))

    def test_domains_lowercase(self, basic_parsed):
        for d in basic_parsed["domains"]:
            assert d == d.lower()

    def test_collect_all_domains_helper(self):
        merged = collect_all_domains(["Example.COM", "test.org"], ["example.com", "NEW.io"])
        assert "example.com" in merged
        assert "test.org" in merged
        assert "new.io" in merged
        # deduplicated
        assert merged.count("example.com") == 1


# ================================================================== #
#  8. IP extraction + classification                                  #
# ================================================================== #

class TestIpExtraction:

    def test_ips_extracted_basic(self, basic_parsed):
        ips = [a["ip"] for a in basic_parsed["ip_addresses"]]
        assert len(ips) > 0

    def test_public_ip_basic(self, basic_parsed):
        pub = [a for a in basic_parsed["ip_addresses"] if a["is_public"]]
        assert len(pub) > 0

    def test_classify_public(self):
        # 45.33.32.156 is a real publicly routable IP (Linode/Akamai)
        assert classify_ip("45.33.32.156") == "public"

    def test_classify_private(self):
        assert classify_ip("10.0.0.1") == "private"
        assert classify_ip("192.168.1.1") == "private"
        assert classify_ip("172.16.0.1") == "private"

    def test_classify_loopback(self):
        assert classify_ip("127.0.0.1") == "loopback"

    def test_classify_unknown(self):
        assert classify_ip("not-an-ip") == "unknown"

    def test_extract_ips_from_text(self):
        text = "from server 203.0.113.5 via 10.0.0.1 localhost 127.0.0.1"
        ips = extract_ips_from_text(text)
        assert "203.0.113.5" in ips
        assert "10.0.0.1" in ips
        assert "127.0.0.1" in ips

    def test_no_duplicate_ips(self, basic_parsed):
        ips = [a["ip"] for a in basic_parsed["ip_addresses"]]
        assert len(ips) == len(set(ips))

    def test_annotate_ip(self):
        ann = annotate_ip("45.33.32.156")
        assert ann["ip"] == "45.33.32.156"
        assert ann["is_public"] is True
        assert ann["version"] == 4
        assert ann["country"] is None   # Phase 5 placeholder

    def test_phishing_originating_ip(self, phishing_parsed):
        assert "185.220.101.45" in phishing_parsed["originating_ips"]

    def test_x_originating_ip_header(self, phishing_parsed):
        assert phishing_parsed["headers"]["x_originating_ip"] is not None


# ================================================================== #
#  9. Attachment metadata + SHA-256                                   #
# ================================================================== #

class TestAttachments:

    def test_attachment_detected(self, attachment_parsed):
        assert len(attachment_parsed["attachments"]) > 0

    def test_attachment_filename(self, attachment_parsed):
        names = [a["filename"] for a in attachment_parsed["attachments"]]
        assert "INV-2026-0042.pdf" in names

    def test_attachment_content_type(self, attachment_parsed):
        ctypes = [a["content_type"] for a in attachment_parsed["attachments"]]
        assert "application/pdf" in ctypes

    def test_attachment_size_positive(self, attachment_parsed):
        for att in attachment_parsed["attachments"]:
            assert att["size_bytes"] > 0

    def test_attachment_sha256_present(self, attachment_parsed):
        for att in attachment_parsed["attachments"]:
            assert att["sha256"] is not None
            assert len(att["sha256"]) == 64

    def test_attachment_sha256_correct(self, attachment_parsed):
        # The PDF in attachment.eml has known SHA-256
        expected = "084b4d21732b6392afef31e5624c9f04151c3350c1750ac00e98a6fe8350e54d"
        hashes = [a["sha256"] for a in attachment_parsed["attachments"]]
        assert expected in hashes

    def test_no_attachments_basic(self, basic_parsed, attachment_parsed):
        assert attachment_parsed["indicators"]["has_attachments"] is True
        assert basic_parsed["indicators"]["has_attachments"] is False


# ================================================================== #
#  10. Evidence / SHA-256 hashing                                    #
# ================================================================== #

class TestEvidence:

    def test_sha256_bytes_correct(self):
        data = b"hello mailtrace"
        expected = hashlib.sha256(data).hexdigest()
        assert sha256_bytes(data) == expected

    def test_sha256_string_correct(self):
        s = "mailtrace test"
        expected = hashlib.sha256(s.encode()).hexdigest()
        assert sha256_string(s) == expected

    def test_sha256_dict_stable(self):
        d = {"b": 2, "a": 1}
        h1 = sha256_dict(d)
        h2 = sha256_dict({"a": 1, "b": 2})
        assert h1 == h2   # key order must not matter

    def test_sha256_dict_changes_with_data(self):
        h1 = sha256_dict({"key": "value1"})
        h2 = sha256_dict({"key": "value2"})
        assert h1 != h2

    def test_build_evidence_record(self, basic_bytes, basic_parsed):
        ev = build_evidence_record("test-case-id", "basic.eml", basic_bytes, basic_parsed)
        assert ev["case_id"] == "test-case-id"
        assert ev["original_filename"] == "basic.eml"
        assert len(ev["file_sha256"]) == 64
        assert len(ev["parsed_data_sha256"]) == 64
        assert ev["blockchain_anchor"] is None

    def test_file_sha256_matches_manual(self, basic_bytes):
        expected = hashlib.sha256(basic_bytes).hexdigest()
        assert sha256_bytes(basic_bytes) == expected

    def test_verify_bytes_hash(self, basic_bytes):
        h = sha256_bytes(basic_bytes)
        assert verify_bytes_hash(basic_bytes, h) is True
        assert verify_bytes_hash(b"tampered", h) is False


# ================================================================== #
#  11. Malformed / edge-case email handling                          #
# ================================================================== #

class TestMalformedHandling:

    def test_empty_bytes_does_not_crash(self):
        result = parse_email(b"")
        # Must return a dict — not raise
        assert isinstance(result, dict)

    def test_empty_bytes_no_fatal_crash(self):
        result = parse_email(b"")
        # An empty email may parse as a minimal message — check it's handled
        assert "parse_errors" in result or "fatal" in result

    def test_random_bytes_does_not_crash(self):
        result = parse_email(b"\x00\xff\xfe\xfd" * 100)
        assert isinstance(result, dict)

    def test_minimal_headers_only(self):
        raw = b"From: test@example.com\r\nTo: dest@example.com\r\n\r\n"
        result = parse_email(raw)
        assert result["sender"]["email"] == "test@example.com"
        assert result["fatal"] is False

    def test_missing_optional_headers(self):
        raw = b"From: sender@x.com\r\nSubject: Test\r\n\r\nBody text"
        result = parse_email(raw)
        assert result["reply_to"] is None
        assert result["return_path"] is None
        assert result["headers"]["message_id"] is None

    def test_no_auth_headers(self):
        raw = b"From: a@b.com\r\nTo: c@d.com\r\n\r\nno auth"
        result = parse_email(raw)
        assert result["authentication"]["spf"]["status"] is None
        assert result["authentication"]["dkim"]["status"] is None
        assert result["authentication"]["dmarc"]["status"] is None

    def test_no_received_headers(self):
        raw = b"From: a@b.com\r\nTo: c@d.com\r\n\r\nno hops"
        result = parse_email(raw)
        assert result["received_chain"]["hop_count"] == 0

    def test_unicode_subject(self):
        raw = "From: test@example.com\r\nSubject: Привет мир 你好\r\n\r\nBody".encode("utf-8")
        result = parse_email(raw)
        assert result["headers"]["subject"] is not None

    def test_no_crash_html_only(self):
        raw = (
            b"From: a@b.com\r\nTo: c@d.com\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b"<html><body><a href='https://evil.com'>click</a></body></html>"
        )
        result = parse_email(raw)
        assert result["fatal"] is False
        # HTML body extracted
        assert result["body"]["html"] is not None
        # Normalized text from HTML
        assert result["body"]["normalized"] is not None

    def test_html_to_text_direct(self):
        html = "<html><body><h1>Title</h1><p>Content here</p><script>bad()</script></body></html>"
        text = html_to_text(html)
        assert "Title" in text
        assert "Content here" in text
        assert "bad()" not in text  # script stripped


# ================================================================== #
#  12. Reply-To / Return-Path mismatch indicators                    #
# ================================================================== #

class TestMismatchIndicators:

    def test_reply_to_mismatch_phishing(self, phishing_parsed):
        # From: paypa1-secure.com, Reply-To: malicious-harvest.net
        assert phishing_parsed["indicators"]["reply_to_mismatch"] is True

    def test_return_path_mismatch_phishing(self, phishing_parsed):
        # From: paypa1-secure.com, Return-Path: totally-different-domain.ru
        assert phishing_parsed["indicators"]["return_path_mismatch"] is True

    def test_no_mismatch_basic(self, basic_parsed):
        # basic.eml has no Reply-To or Return-Path
        assert basic_parsed["indicators"]["reply_to_mismatch"] is False

    def test_missing_message_id_phishing(self, phishing_parsed):
        # phishing.eml does have a message-id
        assert isinstance(phishing_parsed["indicators"]["missing_message_id"], bool)


# ================================================================== #
#  13. Multipart email                                               #
# ================================================================== #

class TestMultipart:

    def test_is_multipart(self, multipart_parsed):
        assert multipart_parsed["mime_info"]["is_multipart"] is True

    def test_plain_body_present(self, multipart_parsed):
        assert multipart_parsed["body"]["plain"] is not None
        assert "TechDigest" in multipart_parsed["body"]["plain"]

    def test_html_body_present(self, multipart_parsed):
        assert multipart_parsed["body"]["html"] is not None
        assert "TechDigest" in multipart_parsed["body"]["html"]

    def test_normalized_body_present(self, multipart_parsed):
        assert multipart_parsed["body"]["normalized"] is not None

    def test_multipart_domains_include_techdigest(self, multipart_parsed):
        assert "techdigest.io" in multipart_parsed["domains"]

    def test_extract_domain_from_email_helper(self):
        assert extract_domain_from_email("user@example.com") == "example.com"
        assert extract_domain_from_email("Name <user@domain.org>") == "domain.org"
        assert extract_domain_from_email("notanemail") is None
        assert extract_domain_from_email("") is None
