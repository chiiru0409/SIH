"""
services/storage.py — Durable Evidence Storage Abstraction.

Provides a unified interface for persisting, loading, and verifying email evidence bytes.
Primary backend: PostgreSQL BYTEA (Neon) / SQLite BLOB (Local Dev).
Fallback: Local filesystem for legacy cases where evidence was stored prior to DB storage.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.models.analysis import AnalysisCase
from backend.services.evidence import sha256_bytes, sha256_file

logger = logging.getLogger("mailtrace.services.storage")


class EvidenceStorage:
    """
    Durable storage interface for forensic raw evidence.
    Decouples analysis and verification workflows from physical filesystem paths.
    """

    @staticmethod
    def save_evidence_to_case(
        case: AnalysisCase,
        raw_bytes: bytes,
        filename: str,
        content_type: str = "message/rfc822",
    ) -> None:
        """
        Attach raw evidence bytes and metadata directly to an AnalysisCase entity.
        The entity is persisted within the active DB transaction.
        """
        case.evidence_bytes = raw_bytes
        case.original_filename = filename
        case.file_size_bytes = len(raw_bytes)
        case.evidence_content_type = content_type
        case.evidence_storage_type = "db_bytea"
        case.evidence_hash = sha256_bytes(raw_bytes)

    @staticmethod
    async def load_evidence(
        db: AsyncSession,
        case: AnalysisCase,
    ) -> bytes | None:
        """
        Load raw evidence bytes for a case.
        1. Returns in-database evidence_bytes if populated.
        2. Fallback: inspects local filesystem samples directory for legacy cases.
        """
        if case.evidence_bytes is not None:
            return case.evidence_bytes

        # Legacy fallback for local dev / pre-migration cases
        if case.stored_filename:
            local_path = Path(settings.UPLOAD_DIR) / case.stored_filename
            try:
                if local_path.is_file():
                    logger.info(f"Loaded evidence from legacy disk path: {local_path.name}")
                    return local_path.read_bytes()
            except Exception as exc:
                logger.warning(f"Could not read legacy evidence file {local_path}: {exc}")

        return None

    @staticmethod
    async def evidence_exists(
        db: AsyncSession,
        case: AnalysisCase,
    ) -> bool:
        """Check whether evidence bytes are recoverable for the given case."""
        if case.evidence_bytes is not None:
            return True
        if case.stored_filename:
            local_path = Path(settings.UPLOAD_DIR) / case.stored_filename
            return local_path.is_file()
        return False

    @staticmethod
    def get_metadata(case: AnalysisCase) -> dict[str, Any]:
        """Return non-sensitive metadata describing the stored evidence."""
        return {
            "case_id": case.id,
            "filename": case.original_filename,
            "size_bytes": case.file_size_bytes,
            "content_type": case.evidence_content_type or "message/rfc822",
            "sha256": case.evidence_hash or "",
            "storage_type": case.evidence_storage_type or ("db_bytea" if case.evidence_bytes else "filesystem"),
            "has_raw_bytes": case.evidence_bytes is not None,
        }


# Global convenience helper instances
storage = EvidenceStorage()
