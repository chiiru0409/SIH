"""
services/evidence.py — Evidence integrity via SHA-256.

All hashing is pure stdlib.
Phase 9 adds blockchain anchoring as an extension point (see build_evidence_record).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Union


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Union[str, Path]) -> str:
    """Stream a file from disk and return its SHA-256 hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def sha256_string(text: str, encoding: str = "utf-8") -> str:
    return hashlib.sha256(text.encode(encoding)).hexdigest()


def sha256_dict(data: dict) -> str:
    """Deterministic SHA-256 of a dict — keys sorted for stability."""
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return sha256_string(serialized)


def build_evidence_record(
    case_id: str,
    original_filename: str,
    file_bytes: bytes,
    parsed_email_dict: dict,
) -> dict:
    """
    Build the evidence integrity record stored with every case.

    Phase 9 extension point: evidence_record → SHA-256 → blockchain anchor TX.
    """
    return {
        "case_id": case_id,
        "original_filename": original_filename,
        "file_sha256": sha256_bytes(file_bytes),
        "parsed_data_sha256": sha256_dict(parsed_email_dict),
        "report_sha256": None,        # populated in Phase 8
        "blockchain_anchor": None,    # Phase 9
        "integrity_note": (
            "SHA-256 computed at ingestion. "
            "file_sha256 fingerprints the raw .eml bytes. "
            "parsed_data_sha256 fingerprints the normalized parsed output."
        ),
    }


def verify_file_hash(path: Union[str, Path], expected: str) -> bool:
    return sha256_file(path).lower() == expected.lower()


def verify_bytes_hash(data: bytes, expected: str) -> bool:
    return sha256_bytes(data).lower() == expected.lower()
