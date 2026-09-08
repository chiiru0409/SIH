"""
tests/test_correlation.py — Step 7 Unit and Integration Tests for Campaign Correlation & Graph Engine.

Tests:
    1. Indicator extraction & canonical normalization.
    2. Shared exact URL correlation (score >= 40).
    3. Shared public IP correlation (score >= 35).
    4. Shared registrable domain correlation (score >= 25).
    5. Shared sender email correlation (score >= 25).
    6. Shared ASN only (score < 50, not classified as campaign).
    7. Unrelated emails produce zero correlation.
    8. Three-case campaign cluster generation (NetworkX connected components).
    9. Transitive chain clustering (A-domain-B, B-ip-C -> A, B, C in single campaign).
    10. Duplicate indicators deduplication.
    11. Private / loopback / reserved IP exclusion (no cross-case correlation).
    12. Single-case graph generation without errors.
    13. Empty cases list resilience.
    14. Graph integrity: all edge sources and targets exist in nodes list, no orphaned edges.
    15. Case-specific sub-graph extraction (`get_case_correlation_subgraph`).
    16. Attribution safety disclaimers in correlation output.
"""

from __future__ import annotations

import pytest
from backend.services.correlation import (
    build_campaign_correlation,
    compute_pairwise_correlations,
    extract_case_entities,
    get_case_correlation_subgraph,
    CORRELATION_THRESHOLD,
    CORRELATION_WEIGHTS,
)


# ------------------------------------------------------------------ #
#  Fixtures / Helpers                                                #
# ------------------------------------------------------------------ #

def _make_case(
    case_id: str,
    sender: str | None = None,
    domains: list[str] | None = None,
    public_ips: list[str] | None = None,
    urls: list[str] | None = None,
    asns: list[str] | None = None,
    risk_score: float = 75.0,
) -> dict:
    url_intel_list = [{"url": u, "url_hash": f"hash_{u}", "registrable_domain": u.split("/")[2] if "://" in u else None} for u in (urls or [])]
    ip_intel_list = [{"ip": ip, "classification": "public", "asn": {"asn": asns[0] if asns else "AS13335"}} for ip in (public_ips or [])]
    domain_intel_list = [{"domain": d, "registrable_domain": d} for d in (domains or [])]

    return {
        "id": case_id,
        "case_id": case_id,
        "original_filename": f"{case_id}.eml",
        "parsed_email": {
            "from_address": sender,
            "sender": {"email": sender},
            "domains": domains or [],
            "urls": [{"url": u} for u in (urls or [])],
            "ip_addresses": [{"ip": ip} for ip in (public_ips or [])],
        },
        "ip_intel": {"ips": ip_intel_list},
        "domain_intel": {"domains": domain_intel_list},
        "url_intel": {"urls": url_intel_list},
        "risk_score": risk_score,
        "risk_label": "HIGH",
    }


# ------------------------------------------------------------------ #
#  Test Cases                                                        #
# ------------------------------------------------------------------ #

def test_1_indicator_extraction_normalization():
    """Extract and normalize senders, domains, public IPs, URLs, and ASNs."""
    case = _make_case(
        case_id="case-1",
        sender="Admin <Alerts@Corp-Example.Com>",
        domains=["sub.malicious-site.org"],
        public_ips=["104.244.42.1"],
        urls=["http://malicious-site.org/login.php?id=1"],
        asns=["AS13335"],
    )
    ent = extract_case_entities(case)
    assert ent["case_id"] == "case-1"
    assert ent["sender"] == "alerts@corp-example.com"
    assert "malicious-site.org" in ent["domains"]
    assert "104.244.42.1" in ent["public_ips"]
    assert len(ent["urls"]) == 1
    assert "AS13335" in ent["asns"]


def test_2_shared_exact_url_correlation():
    """Two cases sharing an exact URL score high correlation."""
    shared_url = "http://phish-portal.net/auth/login.aspx"
    case_a = _make_case("case-a", urls=[shared_url], public_ips=["93.184.216.34"])
    case_b = _make_case("case-b", urls=[shared_url], public_ips=["104.244.42.1"])

    corrs, _ = compute_pairwise_correlations([extract_case_entities(case_a), extract_case_entities(case_b)], threshold=40.0)
    assert len(corrs) == 1
    assert corrs[0]["case_a"] == "case-a"
    assert corrs[0]["case_b"] == "case-b"
    assert corrs[0]["correlation_score"] >= CORRELATION_WEIGHTS["url"]
    assert any(i["type"] == "url" for i in corrs[0]["shared_indicators"])


def test_3_shared_public_ip_correlation():
    """Two cases sharing a public IP infrastructure score high correlation."""
    shared_ip = "198.51.100.77"
    case_a = _make_case("case-a", public_ips=[shared_ip], domains=["site-a.com"])
    case_b = _make_case("case-b", public_ips=[shared_ip], domains=["site-b.org"])

    corrs, _ = compute_pairwise_correlations([extract_case_entities(case_a), extract_case_entities(case_b)], threshold=30.0)
    assert len(corrs) == 1
    assert corrs[0]["correlation_score"] >= CORRELATION_WEIGHTS["ip"]
    assert any(i["type"] == "ip" and i["value"] == shared_ip for i in corrs[0]["shared_indicators"])


def test_4_shared_domain_and_sender_correlation():
    """Two cases sharing sender and domain exceed standard threshold (>= 50)."""
    case_a = _make_case("case-a", sender="attacker@evil-domain.com", domains=["evil-domain.com"])
    case_b = _make_case("case-b", sender="attacker@evil-domain.com", domains=["evil-domain.com"])

    corrs, _ = compute_pairwise_correlations([extract_case_entities(case_a), extract_case_entities(case_b)])
    assert len(corrs) == 1
    # 25 (sender) + 25 (domain) = 50.0
    assert corrs[0]["correlation_score"] >= CORRELATION_THRESHOLD
    assert any(i["type"] == "sender" for i in corrs[0]["shared_indicators"])
    assert any(i["type"] == "domain" for i in corrs[0]["shared_indicators"])


def test_5_shared_asn_only_sub_threshold():
    """Sharing only an ASN produces low score (< 50) and does not trigger correlation."""
    case_a = _make_case("case-a", asns=["AS15169"], domains=["unrelated-a.com"])
    case_b = _make_case("case-b", asns=["AS15169"], domains=["unrelated-b.com"])

    corrs, _ = compute_pairwise_correlations([extract_case_entities(case_a), extract_case_entities(case_b)], threshold=CORRELATION_THRESHOLD)
    assert len(corrs) == 0


def test_6_unrelated_emails_zero_correlation():
    """Two completely unrelated cases produce 0 correlation score."""
    case_a = _make_case("case-a", sender="alice@company.com", domains=["company.com"], public_ips=["1.1.1.1"])
    case_b = _make_case("case-b", sender="bob@service.org", domains=["service.org"], public_ips=["2.2.2.2"])

    overview = build_campaign_correlation([case_a, case_b])
    assert overview["total_campaigns"] == 0
    assert len(overview["correlations"]) == 0


def test_7_three_case_campaign_cluster():
    """Three cases sharing domain and IP form a single campaign cluster."""
    shared_dom = "credential-stealer.net"
    shared_ip = "185.220.101.5"

    case_1 = _make_case("case-1", domains=[shared_dom], public_ips=[shared_ip])
    case_2 = _make_case("case-2", domains=[shared_dom], public_ips=[shared_ip])
    case_3 = _make_case("case-3", domains=[shared_dom], public_ips=[shared_ip])

    overview = build_campaign_correlation([case_1, case_2, case_3])
    assert overview["total_campaigns"] == 1
    camp = overview["campaigns"][0]
    assert camp["case_count"] == 3
    assert sorted(camp["case_ids"]) == ["case-1", "case-2", "case-3"]
    assert any(ind["value"] == shared_dom for ind in camp["shared_indicators"])
    assert any(ind["value"] == shared_ip for ind in camp["shared_indicators"])


def test_8_transitive_chain_clustering():
    """Transitive relationship: Case A links to Case B, Case B links to Case C -> All in single campaign."""
    # Case A and Case B share URL + domain (score = 65)
    # Case B and Case C share public IP + domain (score = 60)
    # Case A and Case C share only domain (score = 25)
    case_a = _make_case("case-a", domains=["shared-hub.org"], urls=["http://shared-hub.org/auth"])
    case_b = _make_case("case-b", domains=["shared-hub.org"], urls=["http://shared-hub.org/auth"], public_ips=["194.26.29.10"])
    case_c = _make_case("case-c", domains=["shared-hub.org"], public_ips=["194.26.29.10"])

    overview = build_campaign_correlation([case_a, case_b, case_c])
    assert overview["total_campaigns"] == 1
    camp = overview["campaigns"][0]
    assert len(camp["case_ids"]) == 3
    assert set(camp["case_ids"]) == {"case-a", "case-b", "case-c"}


def test_9_duplicate_indicators_deduplication():
    """Duplicate indicators in a single case do not multiply scores incorrectly."""
    case_a = _make_case("case-a", domains=["phish.com", "phish.com", "sub.phish.com"], public_ips=["104.244.42.1", "104.244.42.1"])
    case_b = _make_case("case-b", domains=["phish.com"], public_ips=["104.244.42.1"])

    corrs, _ = compute_pairwise_correlations([extract_case_entities(case_a), extract_case_entities(case_b)])
    assert len(corrs) == 1
    # 25 (domain) + 35 (ip) + 5 (asn) = 65.0
    assert corrs[0]["correlation_score"] == 65.0


def test_10_private_ip_exclusion():
    """Private and loopback IPs must NEVER correlate cases."""
    case_a = {
        "case_id": "case-a",
        "parsed_email": {"ip_addresses": [{"ip": "10.0.0.1"}, {"ip": "192.168.1.100"}, {"ip": "127.0.0.1"}]},
        "ip_intel": {"ips": [{"ip": "10.0.0.1", "classification": "private"}]},
    }
    case_b = {
        "case_id": "case-b",
        "parsed_email": {"ip_addresses": [{"ip": "10.0.0.1"}, {"ip": "192.168.1.100"}]},
        "ip_intel": {"ips": [{"ip": "10.0.0.1", "classification": "private"}]},
    }

    ent_a = extract_case_entities(case_a)
    ent_b = extract_case_entities(case_b)

    assert len(ent_a["public_ips"]) == 0
    assert len(ent_b["public_ips"]) == 0

    corrs, _ = compute_pairwise_correlations([ent_a, ent_b])
    assert len(corrs) == 0


def test_11_single_case_graph():
    """Single case produces a valid investigation graph with nodes and internal edges."""
    case = _make_case("case-single", sender="sender@test.com", domains=["test.com"], public_ips=["8.8.8.8"])
    overview = build_campaign_correlation([case])

    assert overview["total_cases"] == 1
    assert overview["total_campaigns"] == 0
    graph = overview["graph"]
    assert len(graph["nodes"]) >= 3  # Case, Sender, Domain, IP
    assert len(graph["edges"]) >= 2


def test_12_empty_cases_resilience():
    """Empty cases list returns zeroed response without errors."""
    overview = build_campaign_correlation([])
    assert overview["total_cases"] == 0
    assert overview["total_campaigns"] == 0
    assert len(overview["graph"]["nodes"]) == 0
    assert len(overview["graph"]["edges"]) == 0


def test_13_graph_integrity_validation():
    """Verify that every edge in the graph connects to valid existing nodes (no orphan edges)."""
    case_1 = _make_case("case-1", sender="bad@evil.com", domains=["evil.com"], urls=["http://evil.com/login"])
    case_2 = _make_case("case-2", sender="bad@evil.com", domains=["evil.com"], urls=["http://evil.com/login"])

    overview = build_campaign_correlation([case_1, case_2])
    graph = overview["graph"]

    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["source"] in node_ids, f"Edge source {edge['source']} not found in nodes"
        assert edge["target"] in node_ids, f"Edge target {edge['target']} not found in nodes"
        assert edge["relationship"] in (
            "CONTAINS", "SENT_BY", "REFERENCES", "HOSTED_ON", "RESOLVES_TO",
            "ANNOUNCED_BY", "BELONGS_TO", "CORRELATED_WITH", "OBSERVED_IP"
        )


def test_14_case_specific_subgraph_extraction():
    """Extracting sub-graph for a specific case returns focused nodes and related cases."""
    shared_dom = "campaign-target.org"
    shared_url = "http://campaign-target.org/auth"

    case_1 = _make_case("case-1", domains=[shared_dom], urls=[shared_url])
    case_2 = _make_case("case-2", domains=[shared_dom], urls=[shared_url])
    case_unrelated = _make_case("case-unrelated", domains=["other.com"])

    overview = build_campaign_correlation([case_1, case_2, case_unrelated])
    sub_1 = get_case_correlation_subgraph("case-1", overview)

    assert sub_1["case_id"] == "case-1"
    assert sub_1["campaign_id"] is not None
    assert len(sub_1["related_cases"]) == 1
    assert sub_1["related_cases"][0]["case_id"] == "case-2"
    assert len(sub_1["graph"]["nodes"]) >= 2
    assert any(n["id"] == "case:case-1" for n in sub_1["graph"]["nodes"])


def test_15_attribution_safety_limitations():
    """Correlation results always contain attribution safety limitations."""
    overview = build_campaign_correlation([])
    assert len(overview["limitations"]) >= 2
    assert any("not physical human attacker identification" in lim.lower() for lim in overview["limitations"])
