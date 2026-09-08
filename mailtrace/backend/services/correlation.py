"""
services/correlation.py — MAILTRACE Campaign Correlation & Investigation Graph Engine.

Primary Entry Points:
    build_campaign_correlation(cases: list[dict[str, Any]]) -> dict[str, Any]
    get_case_correlation_subgraph(case_id: str, correlation_overview: dict[str, Any]) -> dict[str, Any]

Architecture:
    1. Entity Extraction & Canonical Normalization (Senders, Domains, URLs, Public IPs, ASNs).
    2. Private/Loopback IP Filter (Ensures internal networks NEVER create external correlations).
    3. Inverted Index Candidate Discovery (O(1) lookup avoiding unnecessary O(N^2) pairwise comparisons).
    4. Deterministic Pairwise Correlation Scoring (Weights: URL=40, Public IP=35, Domain=25, Sender=25, ASN=5).
    5. NetworkX Graph Representation (Nodes: CASE, EMAIL, SENDER, DOMAIN, URL, IP, ASN, CAMPAIGN).
    6. Connected Components Clustering (Identifies campaign clusters of correlated cases).
    7. Subgraph Extraction for Case-Specific Investigation Views.
    8. Strict Attribution Guardrails (Correlation != Human Attacker Attribution).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional
import networkx as nx

from backend.utils.ip_utils import classify_ip
from backend.utils.url_utils import normalize_domain
from backend.utils.whois_utils import _get_base_domain

logger = logging.getLogger("mailtrace.correlation")

# ================================================================== #
#  Correlation Weights & Threshold Constants                         #
# ================================================================== #

CORRELATION_WEIGHTS = {
    "url": 40.0,         # Exact URL match / URL hash
    "ip": 35.0,          # Shared public IP address
    "domain": 25.0,      # Shared registrable domain
    "sender": 25.0,      # Shared sender email address
    "asn": 5.0,          # Shared ASN routing context
}

# Minimum score to establish a cross-case correlation link
CORRELATION_THRESHOLD = 50.0

CORRELATION_LIMITATIONS = [
    "Correlation represents shared technical infrastructure and communication indicators, NOT physical human attacker identification.",
    "Shared infrastructure (e.g. shared public IPs or cloud domains) may indicate shared service providers rather than a single coordinated adversary.",
    "Private, loopback, and reserved IP addresses are excluded from correlation indexes.",
    "Campaign clusters reflect empirical indicator overlap and warrant further forensic verification.",
]


# ================================================================== #
#  Normalization Helpers                                              #
# ================================================================== #

def _normalize_email(addr: str | None) -> str | None:
    if not addr or not isinstance(addr, str):
        return None
    clean = addr.strip().lower()
    if "<" in clean and ">" in clean:
        clean = clean[clean.find("<") + 1 : clean.find(">")].strip()
    return clean if "@" in clean else None


def _normalize_url_hash(url_str: str) -> str:
    clean = url_str.strip().lower()
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def _canonical_asn(asn_str: str | None) -> str | None:
    if not asn_str or not isinstance(asn_str, str):
        return None
    clean = asn_str.strip().upper()
    if not clean or clean in ("UNKNOWN", "UNAVAILABLE", "NONE"):
        return None
    if not clean.startswith("AS") and clean.isdigit():
        return f"AS{clean}"
    return clean if clean.startswith("AS") else None


# ================================================================== #
#  Case Indicator Extraction                                          #
# ================================================================== #

def extract_case_entities(case: dict[str, Any]) -> dict[str, Any]:
    """
    Extract and normalize all correlateable entities from an analyzed case dict.
    Returns normalized sender, domains, public IPs, URLs, and ASNs.
    """
    case_id = str(case.get("id") or case.get("case_id") or "")
    filename = str(case.get("original_filename") or case.get("filename") or "case.eml")
    parsed = case.get("parsed_email") or case.get("email") or {}
    ip_intel = case.get("ip_intel") or {}
    domain_intel = case.get("domain_intel") or {}
    url_intel = case.get("url_intel") or {}
    forensic = case.get("forensic_analysis") or {}

    # 1. Sender
    sender_email = None
    if isinstance(parsed, dict):
        sender_obj = parsed.get("sender")
        if isinstance(sender_obj, dict):
            sender_email = _normalize_email(sender_obj.get("email"))
        if not sender_email:
            sender_email = _normalize_email(parsed.get("from_address") or parsed.get("from"))

    # 2. Domains (Registrable domains)
    domains: set[str] = set()
    if isinstance(parsed, dict):
        raw_domains = parsed.get("domains") or []
        for d in raw_domains:
            if isinstance(d, str):
                base = _get_base_domain(d)
                if base and "." in base:
                    domains.add(base.lower())

    if isinstance(domain_intel, dict):
        for dom_rec in domain_intel.get("domains", []):
            if isinstance(dom_rec, dict):
                reg_dom = dom_rec.get("registrable_domain") or dom_rec.get("domain")
                if reg_dom and "." in reg_dom:
                    domains.add(reg_dom.lower())

    # 3. Public IPs (Strictly filter private/loopback/reserved)
    public_ips: set[str] = set()
    asns: set[str] = set()

    # From ip_intel
    if isinstance(ip_intel, dict):
        for ip_rec in ip_intel.get("ips", []):
            if isinstance(ip_rec, dict):
                ip_addr = str(ip_rec.get("ip", "")).strip()
                clf = ip_rec.get("classification") or classify_ip(ip_addr)
                if clf == "public" and ip_addr:
                    public_ips.add(ip_addr)
                    asn_obj = ip_rec.get("asn") or {}
                    if isinstance(asn_obj, dict):
                        asn_num = _canonical_asn(asn_obj.get("asn"))
                        if asn_num:
                            asns.add(asn_num)

    # From parsed ip_addresses
    if isinstance(parsed, dict):
        for ip_entry in parsed.get("ip_addresses", []):
            ip_str = ip_entry.get("ip") if isinstance(ip_entry, dict) else str(ip_entry)
            if ip_str and classify_ip(ip_str) == "public":
                public_ips.add(ip_str.strip())

    # 4. URLs
    urls: dict[str, str] = {}  # url_hash -> normalized_url
    if isinstance(url_intel, dict):
        for u_rec in url_intel.get("urls", []):
            if isinstance(u_rec, dict):
                u_str = u_rec.get("url", "").strip()
                if u_str:
                    u_hash = _normalize_url_hash(u_str)
                    urls[u_hash] = u_str
                    # Extract domain from URL if available
                    reg_dom = u_rec.get("registrable_domain")
                    if reg_dom and "." in reg_dom:
                        domains.add(reg_dom.lower())

    if isinstance(parsed, dict):
        for u in parsed.get("urls", []):
            u_str = u.get("url") if isinstance(u, dict) else str(u)
            if u_str and isinstance(u_str, str):
                u_hash = _normalize_url_hash(u_str)
                urls[u_hash] = u_str.strip()

    risk_score = case.get("risk_score")
    risk_label = case.get("risk_label") or case.get("severity") or "UNKNOWN"

    return {
        "case_id": case_id,
        "filename": filename,
        "sender": sender_email,
        "domains": sorted(list(domains)),
        "public_ips": sorted(list(public_ips)),
        "urls": urls,
        "asns": sorted(list(asns)),
        "risk_score": risk_score,
        "risk_label": risk_label,
    }


# ================================================================== #
#  Inverted Index & Pairwise Correlation Scoring                     #
# ================================================================== #

def compute_pairwise_correlations(
    extracted_cases: list[dict[str, Any]],
    threshold: float = CORRELATION_THRESHOLD,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """
    Build inverted indexes over indicators and compute pairwise correlation scores.
    Returns:
      - all_correlations: list of pairwise correlation records (score >= threshold)
      - case_correlations_map: case_id -> list of correlations
    """
    cases_by_id: dict[str, dict[str, Any]] = {c["case_id"]: c for c in extracted_cases}
    case_ids = list(cases_by_id.keys())

    # Build Inverted Indexes
    sender_to_cases: dict[str, set[str]] = {}
    domain_to_cases: dict[str, set[str]] = {}
    ip_to_cases: dict[str, set[str]] = {}
    url_to_cases: dict[str, set[str]] = {}
    asn_to_cases: dict[str, set[str]] = {}

    for c in extracted_cases:
        cid = c["case_id"]
        if c["sender"]:
            sender_to_cases.setdefault(c["sender"], set()).add(cid)
        for dom in c["domains"]:
            domain_to_cases.setdefault(dom, set()).add(cid)
        for ip in c["public_ips"]:
            ip_to_cases.setdefault(ip, set()).add(cid)
        for u_hash in c["urls"]:
            url_to_cases.setdefault(u_hash, set()).add(cid)
        for asn in c["asns"]:
            asn_to_cases.setdefault(asn, set()).add(cid)

    # Candidate Pairs Generation (Only evaluate pairs sharing at least one indicator)
    candidate_pairs: set[tuple[str, str]] = set()

    for index_map in (sender_to_cases, domain_to_cases, ip_to_cases, url_to_cases, asn_to_cases):
        for indicator_val, cids in index_map.items():
            if len(cids) >= 2:
                sorted_cids = sorted(list(cids))
                for i in range(len(sorted_cids)):
                    for j in range(i + 1, len(sorted_cids)):
                        candidate_pairs.add((sorted_cids[i], sorted_cids[j]))

    all_correlations: list[dict[str, Any]] = []
    case_correlations_map: dict[str, list[dict[str, Any]]] = {cid: [] for cid in case_ids}

    for cid_a, cid_b in sorted(list(candidate_pairs)):
        case_a = cases_by_id[cid_a]
        case_b = cases_by_id[cid_b]

        shared_indicators: list[dict[str, Any]] = []
        raw_score = 0.0

        # 1. Exact URL match (High confidence)
        common_urls = set(case_a["urls"].keys()) & set(case_b["urls"].keys())
        for u_hash in sorted(list(common_urls)):
            u_sample = case_a["urls"][u_hash]
            w = CORRELATION_WEIGHTS["url"]
            raw_score += w
            shared_indicators.append({
                "type": "url",
                "value": u_sample,
                "weight": w,
                "description": f"Exact shared URL: {u_sample[:60]}",
            })

        # 2. Shared Public IP
        common_ips = set(case_a["public_ips"]) & set(case_b["public_ips"])
        for ip in sorted(list(common_ips)):
            w = CORRELATION_WEIGHTS["ip"]
            raw_score += w
            shared_indicators.append({
                "type": "ip",
                "value": ip,
                "weight": w,
                "description": f"Shared public transmitting IP infrastructure: {ip}",
            })

        # 3. Shared Registrable Domain
        common_domains = set(case_a["domains"]) & set(case_b["domains"])
        for dom in sorted(list(common_domains)):
            w = CORRELATION_WEIGHTS["domain"]
            raw_score += w
            shared_indicators.append({
                "type": "domain",
                "value": dom,
                "weight": w,
                "description": f"Shared registrable domain: {dom}",
            })

        # 4. Shared Sender
        if case_a["sender"] and case_a["sender"] == case_b["sender"]:
            w = CORRELATION_WEIGHTS["sender"]
            raw_score += w
            shared_indicators.append({
                "type": "sender",
                "value": case_a["sender"],
                "weight": w,
                "description": f"Identical sender address: {case_a['sender']}",
            })

        # 5. Shared ASN
        common_asns = set(case_a["asns"]) & set(case_b["asns"])
        for asn in sorted(list(common_asns)):
            w = CORRELATION_WEIGHTS["asn"]
            raw_score += w
            shared_indicators.append({
                "type": "asn",
                "value": asn,
                "weight": w,
                "description": f"Shared autonomous system routing network: {asn}",
            })

        final_score = round(min(100.0, raw_score), 1)

        # Build Reason Summary
        shared_types = [ind["type"] for ind in shared_indicators]
        reason_parts = []
        if "url" in shared_types:
            reason_parts.append("identical destination URLs")
        if "ip" in shared_types:
            reason_parts.append("shared public sending IP infrastructure")
        if "domain" in shared_types:
            reason_parts.append("common root domain")
        if "sender" in shared_types:
            reason_parts.append("matching sender address")
        if "asn" in shared_types and len(shared_types) > 1:
            reason_parts.append("shared network routing ASN")

        reason_text = "Cases share " + ", ".join(reason_parts) if reason_parts else "No significant indicators shared"

        corr_record = {
            "case_a": cid_a,
            "case_b": cid_b,
            "correlation_score": final_score,
            "shared_indicators": shared_indicators,
            "reason": reason_text,
        }

        if final_score >= threshold:
            all_correlations.append(corr_record)
            case_correlations_map[cid_a].append(corr_record)
            case_correlations_map[cid_b].append(corr_record)

    return all_correlations, case_correlations_map


# ================================================================== #
#  NetworkX Investigation Graph & Campaign Clustering                #
# ================================================================== #

def build_investigation_graph_and_clusters(
    extracted_cases: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Construct NetworkX graph of all entities and identify connected campaign clusters.
    Returns:
      - graph_dict: {"nodes": [...], "edges": [...]}
      - campaigns: list of CampaignCluster dicts
    """
    G = nx.Graph()
    case_cluster_graph = nx.Graph()

    # Track unique nodes and edges to avoid duplicates
    nodes_map: dict[str, dict[str, Any]] = {}
    edges_set: set[tuple[str, str, str]] = set()
    edges_list: list[dict[str, Any]] = []

    def _add_node(node_id: str, node_type: str, label: str, metadata: dict[str, Any] | None = None):
        if node_id not in nodes_map:
            nodes_map[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "metadata": metadata or {},
            }
            G.add_node(node_id, type=node_type, label=label, **(metadata or {}))

    def _add_edge(source: str, target: str, rel: str, strength: float = 1.0, source_evidence: str = "step7_correlation"):
        if source not in nodes_map or target not in nodes_map:
            return
        edge_key = tuple(sorted([source, target])) + (rel,)
        if edge_key not in edges_set:
            edges_set.add(edge_key)
            edges_list.append({
                "source": source,
                "target": target,
                "relationship": rel,
                "strength": strength,
                "evidence_source": source_evidence,
                "metadata": {},
            })
            G.add_edge(source, target, relationship=rel, strength=strength)

    # 1. Add All Case Nodes and Internal Indicator Nodes
    for c in extracted_cases:
        cid = c["case_id"]
        c_node_id = f"case:{cid}"
        case_cluster_graph.add_node(cid)

        _add_node(
            c_node_id,
            "CASE",
            f"Case {cid[:8]}",
            {"case_id": cid, "filename": c["filename"], "risk_score": c["risk_score"], "risk_label": c["risk_label"]}
        )

        # Sender Node
        if c["sender"]:
            s_node_id = f"sender:{c['sender']}"
            _add_node(s_node_id, "SENDER", c["sender"], {"email": c["sender"]})
            _add_edge(c_node_id, s_node_id, "SENT_BY", 1.0, "step2_extraction")

        # Domain Nodes
        for dom in c["domains"]:
            d_node_id = f"domain:{dom}"
            _add_node(d_node_id, "DOMAIN", dom, {"domain": dom})
            _add_edge(c_node_id, d_node_id, "REFERENCES", 1.0, "step2_extraction")

        # URL Nodes
        for u_hash, u_str in c["urls"].items():
            u_node_id = f"url:{u_hash}"
            _add_node(u_node_id, "URL", u_str[:40], {"url": u_str, "url_hash": u_hash})
            _add_edge(c_node_id, u_node_id, "CONTAINS", 1.0, "step2_extraction")

            # Connect URL to domain if present
            dom = normalize_domain(u_str.split("/")[2]) if "://" in u_str and len(u_str.split("/")) > 2 else None
            if dom:
                base_dom = _get_base_domain(dom)
                if base_dom:
                    _add_node(f"domain:{base_dom}", "DOMAIN", base_dom, {"domain": base_dom})
                    _add_edge(u_node_id, f"domain:{base_dom}", "HOSTED_ON", 1.0, "step5_intelligence")

        # Public IP Nodes
        for ip in c["public_ips"]:
            ip_node_id = f"ip:{ip}"
            _add_node(ip_node_id, "IP", ip, {"ip": ip, "classification": "public"})
            _add_edge(c_node_id, ip_node_id, "OBSERVED_IP", 1.0, "step3_forensics")

        # ASN Nodes
        for asn in c["asns"]:
            asn_node_id = f"asn:{asn}"
            _add_node(asn_node_id, "ASN", asn, {"asn": asn})
            # Connect IPs to ASN
            for ip in c["public_ips"]:
                _add_edge(f"ip:{ip}", asn_node_id, "ANNOUNCED_BY", 1.0, "step5_intelligence")

    # 2. Add Cross-Case Correlation Edges
    for corr in correlations:
        cid_a = corr["case_a"]
        cid_b = corr["case_b"]
        score = corr["correlation_score"]
        case_cluster_graph.add_edge(cid_a, cid_b, weight=score)

        _add_edge(
            f"case:{cid_a}",
            f"case:{cid_b}",
            "CORRELATED_WITH",
            strength=score / 100.0,
            source_evidence="step7_correlation",
        )

    # 3. Detect Connected Campaign Components (Clusters >= 2 cases)
    campaigns: list[dict[str, Any]] = []
    cluster_idx = 1

    for component in nx.connected_components(case_cluster_graph):
        cluster_case_ids = sorted(list(component))
        if len(cluster_case_ids) >= 2:
            # Generate deterministic campaign ID
            camp_hash = hashlib.md5("".join(cluster_case_ids).encode("utf-8")).hexdigest()[:6].upper()
            campaign_id = f"CAMP-{camp_hash}"

            # Aggregate shared indicators across all cases in cluster
            shared_doms: set[str] = set()
            shared_ips: set[str] = set()
            shared_urls: set[str] = set()
            shared_senders: set[str] = set()

            cluster_cases = [c for c in extracted_cases if c["case_id"] in cluster_case_ids]

            # Find indicators present in at least 2 cases of this cluster
            all_doms: dict[str, int] = {}
            all_ips: dict[str, int] = {}
            all_urls: dict[str, int] = {}
            all_senders: dict[str, int] = {}

            for cc in cluster_cases:
                for d in cc["domains"]:
                    all_doms[d] = all_doms.get(d, 0) + 1
                for ip in cc["public_ips"]:
                    all_ips[ip] = all_ips.get(ip, 0) + 1
                for uh, us in cc["urls"].items():
                    all_urls[us] = all_urls.get(us, 0) + 1
                if cc["sender"]:
                    all_senders[cc["sender"]] = all_senders.get(cc["sender"], 0) + 1

            for d, count in all_doms.items():
                if count >= 2:
                    shared_doms.add(d)
            for ip, count in all_ips.items():
                if count >= 2:
                    shared_ips.add(ip)
            for u, count in all_urls.items():
                if count >= 2:
                    shared_urls.add(u)
            for s, count in all_senders.items():
                if count >= 2:
                    shared_senders.add(s)

            # Calculate average correlation strength
            cluster_corrs = [
                c["correlation_score"]
                for c in correlations
                if c["case_a"] in cluster_case_ids and c["case_b"] in cluster_case_ids
            ]
            avg_strength = round(sum(cluster_corrs) / max(1, len(cluster_corrs)), 1) if cluster_corrs else 75.0
            confidence = round(min(0.95, 0.60 + 0.10 * len(cluster_case_ids) + 0.05 * (len(shared_doms) + len(shared_ips) + len(shared_urls))), 2)

            # Summarize explanation
            reasons = []
            if shared_urls:
                reasons.append(f"{len(shared_urls)} common URL(s)")
            if shared_ips:
                reasons.append(f"{len(shared_ips)} shared sending IP(s)")
            if shared_doms:
                reasons.append(f"{len(shared_doms)} common domain(s)")
            if shared_senders:
                reasons.append("common sender identity")

            summary_reason = f"Cluster of {len(cluster_case_ids)} cases sharing " + ", ".join(reasons) if reasons else f"Cluster of {len(cluster_case_ids)} correlated cases"

            # Add Campaign Node and Edges to Graph
            camp_node_id = f"campaign:{campaign_id}"
            _add_node(
                camp_node_id,
                "CAMPAIGN",
                f"Campaign {campaign_id}",
                {"campaign_id": campaign_id, "case_count": len(cluster_case_ids), "confidence": confidence}
            )

            for cid in cluster_case_ids:
                _add_edge(f"case:{cid}", camp_node_id, "BELONGS_TO", 1.0, "step7_correlation")

            shared_ind_list = []
            for u in sorted(list(shared_urls)):
                shared_ind_list.append({"type": "url", "value": u})
            for ip in sorted(list(shared_ips)):
                shared_ind_list.append({"type": "ip", "value": ip})
            for d in sorted(list(shared_doms)):
                shared_ind_list.append({"type": "domain", "value": d})
            for s in sorted(list(shared_senders)):
                shared_ind_list.append({"type": "sender", "value": s})

            campaign_record = {
                "campaign_id": campaign_id,
                "case_count": len(cluster_case_ids),
                "case_ids": cluster_case_ids,
                "shared_indicators": shared_ind_list,
                "correlation_strength": avg_strength,
                "confidence": confidence,
                "explanation": summary_reason,
            }
            campaigns.append(campaign_record)
            cluster_idx += 1

    graph_dict = {
        "nodes": list(nodes_map.values()),
        "edges": edges_list,
    }

    return graph_dict, campaigns


# ================================================================== #
#  Master Entry Point: Build Global Correlation                      #
# ================================================================== #

def build_campaign_correlation(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Execute full multi-case indicator extraction, pairwise correlation,
    and investigation graph synthesis.
    """
    if not isinstance(cases, list):
        cases = []

    extracted_cases = [extract_case_entities(c) for c in cases if isinstance(c, dict)]
    correlations, case_corrs_map = compute_pairwise_correlations(extracted_cases)
    graph_dict, campaigns = build_investigation_graph_and_clusters(extracted_cases, correlations)

    return {
        "total_cases": len(extracted_cases),
        "total_campaigns": len(campaigns),
        "campaigns": campaigns,
        "correlations": correlations,
        "graph": graph_dict,
        "limitations": CORRELATION_LIMITATIONS,
    }


# ================================================================== #
#  Case-Specific Subgraph Extraction                                  #
# ================================================================== #

def get_case_correlation_subgraph(
    case_id: str,
    correlation_overview: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract a focused sub-graph and correlation detail for a specific case ID.
    """
    target_node_id = f"case:{case_id}"
    all_nodes = {n["id"]: n for n in correlation_overview.get("graph", {}).get("nodes", [])}
    all_edges = correlation_overview.get("graph", {}).get("edges", [])

    # Find campaign membership
    campaigns = correlation_overview.get("campaigns", [])
    matching_campaign = next((c for c in campaigns if case_id in c["case_ids"]), None)

    # Find related cases
    related_cases: list[dict[str, Any]] = []
    shared_indicators_seen: list[dict[str, Any]] = []

    for corr in correlation_overview.get("correlations", []):
        other_id = None
        if corr["case_a"] == case_id:
            other_id = corr["case_b"]
        elif corr["case_b"] == case_id:
            other_id = corr["case_a"]

        if other_id:
            related_cases.append({
                "case_id": other_id,
                "correlation_score": corr["correlation_score"],
                "reason": corr["reason"],
            })
            for ind in corr.get("shared_indicators", []):
                if ind not in shared_indicators_seen:
                    shared_indicators_seen.append(ind)

    # Extract sub-graph nodes: target case node + all 1-hop and 2-hop connected nodes
    relevant_node_ids: set[str] = {target_node_id}
    sub_edges: list[dict[str, Any]] = []

    # 1. First hop edges and neighbors
    first_hop_neighbors: set[str] = set()
    for e in all_edges:
        if e["source"] == target_node_id:
            first_hop_neighbors.add(e["target"])
            sub_edges.append(e)
        elif e["target"] == target_node_id:
            first_hop_neighbors.add(e["source"])
            sub_edges.append(e)

    relevant_node_ids.update(first_hop_neighbors)

    # 2. Second hop edges between neighbors (e.g. URL -> Domain, IP -> ASN, or Case -> Campaign)
    for e in all_edges:
        if e["source"] in relevant_node_ids and e["target"] in relevant_node_ids and e not in sub_edges:
            sub_edges.append(e)

    sub_nodes = [all_nodes[nid] for nid in sorted(list(relevant_node_ids)) if nid in all_nodes]

    subgraph = {
        "nodes": sub_nodes,
        "edges": sub_edges,
    }

    return {
        "case_id": case_id,
        "campaign_id": matching_campaign["campaign_id"] if matching_campaign else None,
        "related_cases": related_cases,
        "shared_indicators": shared_indicators_seen,
        "campaign": matching_campaign,
        "graph": subgraph,
        "limitations": CORRELATION_LIMITATIONS,
    }
