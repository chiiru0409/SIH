"""
models/evidence.py — ORM model for Tamper-Evident Chain-of-Custody Events.

Each investigation case generates an audited, hash-chained sequence of evidence events:
  - EVIDENCE_INGESTED
  - EVIDENCE_HASHED
  - EVIDENCE_ANALYZED
  - EVIDENCE_VERIFIED
  - BLOCKCHAIN_ANCHORED

Hash Chaining:
  event_n_hash = SHA256(event_type + case_id + evidence_hash + timestamp + metadata_json + previous_event_hash)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, Index, JSON
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class EvidenceEvent(Base):
    """
    Immutable, hash-chained event record establishing chain of custody for a case.
    """

    __tablename__ = "evidence_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid, index=True
    )
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # EVIDENCE_INGESTED | EVIDENCE_HASHED | EVIDENCE_ANALYZED | EVIDENCE_VERIFIED | BLOCKCHAIN_ANCHORED

    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Primary SHA-256 of the raw .eml file or commitment

    previous_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Hash of previous event in chain (None for genesis event)

    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Cryptographic hash of this event committing to all prior events

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    event_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_evidence_case_time", "case_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceEvent id={self.id!r} "
            f"case_id={self.case_id!r} "
            f"type={self.event_type!r} "
            f"hash={self.event_hash[:12]}…>"
        )
