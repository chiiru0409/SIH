"""
routes/correlation.py — Campaign Correlation, Investigation Graph & Threat Hunting API Endpoints.

Endpoints:
    GET  /api/correlation                     — Global correlation overview, campaign clusters, and graph.
    GET  /api/correlation/cases               — Alias for /api/correlation.
    POST /api/correlation/hunt                — Execute hypothesis-driven threat hunt across all cases.
    GET  /api/correlation/hunt                — Execute threat hunt via query parameters.
    GET  /api/correlation/export-iocs/{id}     — Export standardized IoC manifest for a specific case.
    GET  /api/correlation/{id}                — Case-specific correlation details, related cases, and sub-graph.
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.analysis import AnalysisCase
from backend.schemas.correlation import (
    CorrelationOverviewResponse,
    CaseCorrelationDetailResponse,
    ThreatHuntRequest,
    ThreatHuntResponse,
    IoCExportResponse,
)
from backend.services.correlation import (
    build_campaign_correlation,
    get_case_correlation_subgraph,
    execute_threat_hunt,
    export_case_iocs,
)

logger = logging.getLogger("mailtrace.routes.correlation")

router = APIRouter(prefix="/api/correlation", tags=["correlation"])


def _case_to_dict(c: AnalysisCase) -> dict:
    """Helper to convert an ORM AnalysisCase to dictionary representation for correlation."""
    return {
        "id": c.id,
        "case_id": c.id,
        "original_filename": c.original_filename,
        "parsed_email": c.parsed_email,
        "forensic_analysis": c.forensic_analysis,
        "ai_analysis": c.ai_analysis,
        "ip_intel": c.ip_intel,
        "domain_intel": c.domain_intel,
        "url_intel": c.url_intel,
        "risk_score": c.risk_score,
        "risk_label": c.risk_label,
        "risk_reasons": c.risk_reasons,
        "campaign_id": c.campaign_id,
        "correlation_data": c.correlation_data,
    }


# ------------------------------------------------------------------ #
#  GET /api/correlation & GET /api/correlation/cases                 #
# ------------------------------------------------------------------ #

@router.get(
    "",
    response_model=CorrelationOverviewResponse,
    summary="Get global campaign correlation overview and investigation graph",
    description="Analyzes shared infrastructure across all stored email cases and clusters them into campaigns.",
)
@router.get(
    "/cases",
    response_model=CorrelationOverviewResponse,
    include_in_schema=False,
)
async def get_global_correlation(
    db: AsyncSession = Depends(get_db),
) -> CorrelationOverviewResponse:
    try:
        # 1. Fetch all cases from database
        result = await db.execute(select(AnalysisCase))
        cases = result.scalars().all()
    except Exception as exc:
        logger.error(f"Failed to query cases for correlation: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "code": "DB_QUERY_ERROR", "message": "Failed to retrieve correlation data."},
        )

    cases_dicts = [_case_to_dict(c) for c in cases]

    # 2. Build multi-case correlation and graph
    overview = build_campaign_correlation(cases_dicts)

    # 3. Synchronize campaign IDs back to database if updated and cases exist
    if cases:
        campaigns = overview.get("campaigns", [])
        campaign_map: dict[str, str] = {}
        for camp in campaigns:
            cid = camp["campaign_id"]
            for case_id in camp.get("case_ids", []):
                campaign_map[case_id] = cid

        for c in cases:
            assigned_camp = campaign_map.get(c.id)
            if assigned_camp and c.campaign_id != assigned_camp:
                c.campaign_id = assigned_camp
                c.correlation_data = {
                    "campaign_id": assigned_camp,
                    "correlated": True,
                }

        try:
            await db.flush()
        except Exception as exc:
            logger.warning(f"Failed to persist campaign assignments: {exc}")

    return CorrelationOverviewResponse(
        total_cases=overview["total_cases"],
        total_campaigns=overview["total_campaigns"],
        campaigns=overview["campaigns"],
        correlations=overview["correlations"],
        graph=overview["graph"],
        limitations=overview["limitations"],
    )


# ------------------------------------------------------------------ #
#  POST & GET /api/correlation/hunt (Hypothesis-Driven Hunting)      #
# ------------------------------------------------------------------ #

@router.post(
    "/hunt",
    response_model=ThreatHuntResponse,
    summary="Execute hypothesis-driven threat hunt across cases",
    description="Evaluates threat hunting hypotheses (Shared Infrastructure, Executive Spoofing, SaaS Abuse, Credential Campaigns) across all ingested emails.",
)
async def post_threat_hunt(
    req: ThreatHuntRequest,
    db: AsyncSession = Depends(get_db),
) -> ThreatHuntResponse:
    try:
        result = await db.execute(select(AnalysisCase))
        cases = result.scalars().all()
    except Exception as exc:
        logger.error(f"Failed to query cases for threat hunt: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "code": "DB_QUERY_ERROR", "message": "Failed to query cases for threat hunting."},
        )

    cases_dicts = [_case_to_dict(c) for c in cases]
    hunt_results = execute_threat_hunt(cases_dicts, hypothesis_type=req.hypothesis_type, query=req.query)

    return ThreatHuntResponse(
        status=hunt_results["status"],
        hunt_query=hunt_results["hunt_query"],
        total_cases_analyzed=hunt_results["total_cases_analyzed"],
        hypotheses_evaluated=hunt_results["hypotheses_evaluated"],
        results=hunt_results["results"],
    )


@router.get(
    "/hunt",
    response_model=ThreatHuntResponse,
    summary="Execute threat hunt via query parameters",
    include_in_schema=False,
)
async def get_threat_hunt(
    hypothesis: str = Query(default="ALL", description="Hypothesis type to evaluate"),
    q: str = Query(default="", description="Search query string or indicator pivot"),
    db: AsyncSession = Depends(get_db),
) -> ThreatHuntResponse:
    return await post_threat_hunt(ThreatHuntRequest(hypothesis_type=hypothesis, query=q), db=db)


# ------------------------------------------------------------------ #
#  GET /api/correlation/export-iocs/{case_id}                        #
# ------------------------------------------------------------------ #

@router.get(
    "/export-iocs/{case_id}",
    response_model=IoCExportResponse,
    summary="Export technical IoCs for a specific case in standard formats",
    description="Generates normalized JSON, CSV, and STIX-pattern IoCs for integration with SIEM/EDR platforms.",
)
async def export_iocs(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> IoCExportResponse:
    try:
        target_res = await db.execute(select(AnalysisCase).where(AnalysisCase.id == case_id))
        target_case = target_res.scalar_one_or_none()
    except Exception as exc:
        logger.error(f"Failed to query target case {case_id} for IoC export: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "code": "DB_QUERY_ERROR", "message": "Failed to retrieve case for IoC export."},
        )

    if not target_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": "error",
                "code": "CASE_NOT_FOUND",
                "message": f"No analysis case found with ID: {case_id}",
            },
        )

    case_dict = _case_to_dict(target_case)
    ioc_data = export_case_iocs(case_dict)

    return IoCExportResponse(
        case_id=ioc_data["case_id"],
        filename=ioc_data["filename"],
        risk_label=ioc_data["risk_label"],
        total_iocs=ioc_data["total_iocs"],
        iocs=ioc_data["iocs"],
        csv_export=ioc_data["csv_export"],
        stix_patterns=ioc_data["stix_patterns"],
    )


# ------------------------------------------------------------------ #
#  GET /api/correlation/{case_id}                                    #
# ------------------------------------------------------------------ #

@router.get(
    "/{case_id}",
    response_model=CaseCorrelationDetailResponse,
    summary="Get correlation details and sub-graph for a specific case",
    description="Returns related cases, shared indicators, campaign membership, and focused graph for the given case ID.",
)
async def get_case_correlation(
    case_id: str,
    db: AsyncSession = Depends(get_db),
) -> CaseCorrelationDetailResponse:
    try:
        # 1. Verify case exists
        target_res = await db.execute(select(AnalysisCase).where(AnalysisCase.id == case_id))
        target_case = target_res.scalar_one_or_none()
    except Exception as exc:
        logger.error(f"Failed to query target case {case_id} for correlation: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "code": "DB_QUERY_ERROR", "message": "Failed to retrieve case correlation."},
        )

    if not target_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": "error",
                "code": "CASE_NOT_FOUND",
                "message": f"No analysis case found with ID: {case_id}",
            },
        )

    try:
        # 2. Fetch all cases to compute correlation context
        all_res = await db.execute(select(AnalysisCase))
        all_cases = all_res.scalars().all()
    except Exception as exc:
        logger.error(f"Failed to query all cases for correlation subgraph: {exc}", exc_info=True)
        all_cases = [target_case]

    cases_dicts = [_case_to_dict(c) for c in all_cases]

    # 3. Build correlation overview and extract case subgraph
    overview = build_campaign_correlation(cases_dicts)
    subgraph_detail = get_case_correlation_subgraph(case_id, overview)

    return CaseCorrelationDetailResponse(
        case_id=case_id,
        campaign_id=subgraph_detail.get("campaign_id"),
        related_cases=subgraph_detail.get("related_cases", []),
        shared_indicators=subgraph_detail.get("shared_indicators", []),
        campaign=subgraph_detail.get("campaign"),
        graph=subgraph_detail.get("graph", {"nodes": [], "edges": []}),
        limitations=subgraph_detail.get("limitations", []),
    )
