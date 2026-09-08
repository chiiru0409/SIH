"""
run_tests.py — standalone test runner that prints results to a file.
Run: python run_tests.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

# ── run pytest programmatically and capture output ──────────────────
import pytest

result = pytest.main([
    "tests/test_parser.py",
    "-v",
    "--tb=short",
    "--no-header",
    "-p", "no:warnings",
])

print(f"\nEXIT_CODE={result}")
