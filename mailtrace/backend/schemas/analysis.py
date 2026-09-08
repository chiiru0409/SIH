"""
schemas/analysis.py — Pydantic schemas for request/response validation.

ORM models own persistence; Pydantic schemas own API contracts.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


# ------------------------------------------------------------------ #
#  Phase 2 — Upload response                                         #
# ------------------------------------------------------------------ #

class UploadResponse(BaseModel):
    """Returned immediately after a successful .eml upload + parse."""
    case_id: str
    status: str
    filename: str
    sha256: str
    message: str
    email: dict[str, Any]
    authentication: dict[str, Any]
    smtp_trace: dict[str, Any]
    indicators: dict[str, Any]
    evidence: dict[str, Any]


# ------------------------------------------------------------------ #
#  Parsed email internals (used in CaseDetail)                       #
# ------------------------------------------------------------------ #

class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str | None = None


class AuthenticationResults(BaseModel):
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw: list[str] = Field(default_factory=list)


class ParsedEmail(BaseModel):
    from_address: str | None = None
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    reply_to: str | None = None
    return_path: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    received: list[str] = Field(default_factory=list)
    authentication: AuthenticationResults = Field(default_factory=AuthenticationResults)
    originating_ips: list[str] = Field(default_factory=list)
    body: str | None = None
    html_body: str | None = None
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    mime_info: dict[str, Any] = Field(default_factory=dict)
    raw_headers: dict[str, list[str]] = Field(default_factory=dict)


# ------------------------------------------------------------------ #
#  Case response schemas                                             #
# ------------------------------------------------------------------ #

class CaseCreateResponse(BaseModel):
    """Returned immediately after a successful upload/enqueue."""
    case_id: str
    status: str
    original_filename: str
    message: str


class CaseSummary(BaseModel):
    """Lightweight row for list endpoints."""
    case_id: str
    original_filename: str
    status: str
    risk_score: float | None
    risk_label: str | None
    created_at: datetime


class CaseDetail(BaseModel):
    """Full case record returned to the frontend dashboard."""
    case_id: str
    original_filename: str
    status: str
    created_at: datetime
    updated_at: datetime
    parsed_email: dict[str, Any] | None = None
    forensic_analysis: dict[str, Any] | None = None
    ai_analysis: dict[str, Any] | None = None
    ip_intel: dict[str, Any] | None = None
    domain_intel: dict[str, Any] | None = None
    url_intel: dict[str, Any] | None = None
    risk_score: float | None = None
    risk_label: str | None = None
    risk_reasons: dict[str, Any] | None = None
    campaign_id: str | None = None
    correlation_data: dict[str, Any] | None = None
    report_path: str | None = None
    evidence_hash: str | None = None
    error_detail: str | None = None


# ------------------------------------------------------------------ #
#  Health check                                                      #
# ------------------------------------------------------------------ #

class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    database: str


# ------------------------------------------------------------------ #
#  Generic error                                                     #
# ------------------------------------------------------------------ #

class ErrorResponse(BaseModel):
    detail: str
    code: str | None = None
