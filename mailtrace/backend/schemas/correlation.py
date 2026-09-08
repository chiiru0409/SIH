"""
schemas/correlation.py — Pydantic schemas for Campaign Correlation & Investigation Graph.

Models:
    - GraphNode: Entity node in the investigation graph (CASE, EMAIL, SENDER, DOMAIN, URL, IP, ASN, CAMPAIGN).
    - GraphEdge: Relationship edge with source, target, relationship type, strength, and evidence source.
    - InvestigationGraph: Collection of nodes and edges ready for frontend graph visualization.
    - SharedIndicator: A common indicator between cases with its type, value, and weight.
    - CaseCorrelation: Pairwise correlation summary between two cases.
    - CampaignCluster: A detected group of interconnected cases sharing infrastructure indicators.
    - CorrelationOverviewResponse: Global correlation view across all cases.
    - CaseCorrelationDetailResponse: Case-specific correlation and sub-graph response.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    type: str  # CASE | EMAIL | SENDER | DOMAIN | URL | IP | ASN | CAMPAIGN
    label: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # CONTAINS | SENT_BY | REFERENCES | HOSTED_ON | RESOLVES_TO | ANNOUNCED_BY | BELONGS_TO | CORRELATED_WITH
    strength: float = 1.0
    evidence_source: str = "step7_correlation"
    metadata: dict[str, Any] = Field(default_factory=dict)


class InvestigationGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class SharedIndicator(BaseModel):
    type: str  # url | ip | domain | sender | asn
    value: str
    weight: float
    description: str | None = None


class CaseCorrelation(BaseModel):
    case_a: str
    case_b: str
    correlation_score: float
    shared_indicators: list[SharedIndicator] = Field(default_factory=list)
    reason: str


class CampaignCluster(BaseModel):
    campaign_id: str
    case_count: int
    case_ids: list[str] = Field(default_factory=list)
    shared_indicators: list[dict[str, Any]] = Field(default_factory=list)
    correlation_strength: float
    confidence: float
    explanation: str


class CorrelationOverviewResponse(BaseModel):
    total_cases: int
    total_campaigns: int
    campaigns: list[CampaignCluster] = Field(default_factory=list)
    correlations: list[CaseCorrelation] = Field(default_factory=list)
    graph: InvestigationGraph = Field(default_factory=InvestigationGraph)
    limitations: list[str] = Field(default_factory=list)


class CaseCorrelationDetailResponse(BaseModel):
    case_id: str
    campaign_id: str | None = None
    related_cases: list[dict[str, Any]] = Field(default_factory=list)
    shared_indicators: list[SharedIndicator] = Field(default_factory=list)
    campaign: CampaignCluster | None = None
    graph: InvestigationGraph = Field(default_factory=InvestigationGraph)
    limitations: list[str] = Field(default_factory=list)
