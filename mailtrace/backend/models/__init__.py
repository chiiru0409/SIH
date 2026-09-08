"""
models/__init__.py — Export all SQLAlchemy models for metadata registration.
"""

from backend.models.analysis import AnalysisCase
from backend.models.evidence import EvidenceEvent

__all__ = ["AnalysisCase", "EvidenceEvent"]
