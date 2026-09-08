"""
models/analysis.py — ORM model for a MailTrace analysis case.

One row per uploaded .eml file.  All extracted intelligence and scores
are stored as JSON columns so the schema stays flexible as new phases
are added, while still being queryable via SQLite JSON functions or
PostgreSQL JSONB.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Float, Integer, DateTime, Text, JSON, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class AnalysisCase(Base):
    """
    Central record for one analyzed email.

    Phases populate columns progressively:
      Phase 2  → parsed_email (JSON)
      Phase 3  → forensic_analysis (JSON)
      Phase 4  → ai_analysis (JSON)
      Phase 5  → ip_intel, domain_intel, url_intel (JSON)
      Phase 6  → risk_score, risk_reasons (JSON)
      Phase 7  → campaign_id, correlation_data (JSON)
      Phase 8  → report_path
      Phase 9  → evidence_hash, parsed_evidence_hash, analysis_hash, blockchain_tx_id, blockchain_anchor_data
      Evidence → evidence_bytes (BYTEA/LargeBinary), evidence_content_type, evidence_storage_type
    """

    __tablename__ = "analysis_cases"

    # ---------------------------------------------------------------- #
    #  Identity                                                          #
    # ---------------------------------------------------------------- #
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    # ---------------------------------------------------------------- #
    #  Input & Persistent Evidence Storage                             #
    # ---------------------------------------------------------------- #
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Raw persistent evidence bytes (stored in PostgreSQL BYTEA / SQLite BLOB)
    evidence_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    evidence_content_type: Mapped[str | None] = mapped_column(String(128), nullable=True, default="message/rfc822")
    evidence_storage_type: Mapped[str | None] = mapped_column(String(32), nullable=True, default="db_bytea")

    # ---------------------------------------------------------------- #
    #  Phase 2 — Parsed email                                            #
    # ---------------------------------------------------------------- #
    parsed_email: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 3 — Forensic analysis                                       #
    # ---------------------------------------------------------------- #
    forensic_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 4 — AI analysis                                             #
    # ---------------------------------------------------------------- #
    ai_analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 5 — Intelligence enrichment                                 #
    # ---------------------------------------------------------------- #
    ip_intel: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    domain_intel: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    url_intel: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 6 — Risk engine                                             #
    # ---------------------------------------------------------------- #
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_label: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # LOW | MEDIUM | HIGH | CRITICAL
    risk_reasons: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 7 — Campaign correlation                                    #
    # ---------------------------------------------------------------- #
    campaign_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    correlation_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 8 — Report                                                  #
    # ---------------------------------------------------------------- #
    report_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # ---------------------------------------------------------------- #
    #  Phase 9 — Evidence integrity & Blockchain commitments             #
    # ---------------------------------------------------------------- #
    evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parsed_evidence_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analysis_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    blockchain_tx_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    blockchain_anchor_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # ---------------------------------------------------------------- #
    #  Status                                                            #
    # ---------------------------------------------------------------- #
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )
    # pending | parsing | analyzing | complete | error
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AnalysisCase id={self.id!r} "
            f"file={self.original_filename!r} "
            f"status={self.status!r} "
            f"risk={self.risk_score}>"
        )
