"""
schemas/evidence.py — Pydantic models for Evidence Integrity, Manifest & Blockchain Anchoring.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class ChainOfCustodyEventResponse(BaseModel):
    id: str
    event_type: str
    event_hash: str
    evidence_hash: str
    previous_event_hash: str | None = None
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BlockchainAnchorInfo(BaseModel):
    enabled: bool
    provider: str
    network: str
    transaction_id: str | None = None
    anchor_data: dict[str, Any] | None = None
    status: str


class EvidenceManifestResponse(BaseModel):
    case_id: str
    evidence_type: str
    original_filename: str
    file_size_bytes: int
    file_sha256: str
    parsed_evidence_sha256: str
    analysis_sha256: str
    hash_algorithm: str
    integrity_status: str
    created_at: str
    updated_at: str
    chain_of_custody: dict[str, Any]
    blockchain_anchoring: BlockchainAnchorInfo
    legal_attribution_notice: str


class EvidenceVerifyResponse(BaseModel):
    valid: bool
    case_id: str
    file_sha256: str
    stored_file_sha256: str
    parsed_evidence_sha256: str
    stored_parsed_sha256: str
    analysis_sha256: str
    stored_analysis_sha256: str
    verification_method: str
    chain_of_custody_valid: bool
    chain_of_custody_events_count: int
    blockchain_verified: bool | None = None
    blockchain_details: dict[str, Any] = Field(default_factory=dict)
    details: list[str] = Field(default_factory=list)
    verified_at: str


class BlockchainAnchorResponse(BaseModel):
    status: str
    anchored: bool
    case_id: str
    evidence_hash: str
    transaction_id: str | None = None
    block_number: int | None = None
    block_timestamp: str | None = None
    network: str | None = None
    message: str


class ChainOfCustodyResponse(BaseModel):
    case_id: str
    evidence_hash: str
    total_events: int
    chain_valid: bool
    events: list[ChainOfCustodyEventResponse] = Field(default_factory=list)
