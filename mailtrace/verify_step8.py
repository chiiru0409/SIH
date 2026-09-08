#!/usr/bin/env python3
"""
verify_step8.py — Comprehensive verification for MailTrace Step 8:
Premium Frontend Investigation Dashboard & Full-Stack Integration.
"""

import os
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure mailtrace root is on python path
sys.path.insert(0, str(Path(__file__).parent))

from backend.main import app

def run_verification():
    print("=" * 70)
    print("MAILTRACE STEP 8: FRONTEND DASHBOARD & FULL-STACK LIVE VERIFICATION")
    print("=" * 70)

    checks_passed = 0
    total_checks = 0

    def check(desc: str, condition: bool):
        nonlocal checks_passed, total_checks
        total_checks += 1
        status = "PASS" if condition else "FAIL"
        print(f"[{status}] Check {total_checks:02d}: {desc}")
        if condition:
            checks_passed += 1
        else:
            print(f"    -> FAILED: Condition not met for {desc}")

    # 1. Frontend build files check
    frontend_dist = Path(__file__).parent / "frontend" / "dist"
    index_html = frontend_dist / "index.html"
    check("Frontend build dist directory exists", frontend_dist.exists() and frontend_dist.is_dir())
    check("Frontend dist/index.html exists", index_html.exists() and index_html.is_file())

    if index_html.exists():
        content = index_html.read_text(encoding="utf-8")
        check("index.html contains root element", '<div id="root">' in content)
        check("index.html references bundled JS assets", ".js" in content)
        check("index.html references bundled CSS assets", ".css" in content)

    # 2. Frontend source files check
    src_dir = Path(__file__).parent / "frontend" / "src"
    check("Frontend types/api.ts exists", (src_dir / "types" / "api.ts").exists())
    check("Frontend lib/api.ts exists", (src_dir / "lib" / "api.ts").exists())
    check("Frontend lib/sanitize.ts exists", (src_dir / "lib" / "sanitize.ts").exists())
    check("Frontend components/risk/RiskScoreHero.tsx exists", (src_dir / "components" / "risk" / "RiskScoreHero.tsx").exists())
    check("Frontend components/threat/ThreatClassificationPanel.tsx exists", (src_dir / "components" / "threat" / "ThreatClassificationPanel.tsx").exists())
    check("Frontend components/forensic/AuthenticationMatrix.tsx exists", (src_dir / "components" / "forensic" / "AuthenticationMatrix.tsx").exists())
    check("Frontend components/forensic/IdentityInspector.tsx exists", (src_dir / "components" / "forensic" / "IdentityInspector.tsx").exists())
    check("Frontend components/forensic/RelayTimeline.tsx exists", (src_dir / "components" / "forensic" / "RelayTimeline.tsx").exists())
    check("Frontend components/forensic/ForensicEvidencePanel.tsx exists", (src_dir / "components" / "forensic" / "ForensicEvidencePanel.tsx").exists())
    check("Frontend components/infrastructure/GeoMap.tsx exists", (src_dir / "components" / "infrastructure" / "GeoMap.tsx").exists())
    check("Frontend components/infrastructure/InfrastructurePanel.tsx exists", (src_dir / "components" / "infrastructure" / "InfrastructurePanel.tsx").exists())
    check("Frontend components/graph/InvestigationGraphView.tsx exists", (src_dir / "components" / "graph" / "InvestigationGraphView.tsx").exists())
    check("Frontend components/campaign/CampaignClusterView.tsx exists", (src_dir / "components" / "campaign" / "CampaignClusterView.tsx").exists())
    check("Frontend components/cases/CaseListView.tsx exists", (src_dir / "components" / "cases" / "CaseListView.tsx").exists())
    check("Frontend components/cases/CaseDetailWorkspace.tsx exists", (src_dir / "components" / "cases" / "CaseDetailWorkspace.tsx").exists())

    # 3. Live API integration checks
    with TestClient(app) as client:
        # Health endpoint
        res = client.get("/api/health")
        check("API GET /api/health returns 200 OK", res.status_code == 200)
        health_data = res.json()
        check("API Health status is ok", health_data.get("status") in ["ok", "healthy"])

        # Cases list endpoint
        res = client.get("/api/analyze/cases")
        check("API GET /api/analyze/cases returns 200 OK", res.status_code == 200)
        check("API Cases returns a list", isinstance(res.json(), list))

        # Global correlation endpoint
        res = client.get("/api/correlation")
        check("API GET /api/correlation returns 200 OK", res.status_code == 200)
        corr_data = res.json()
        check("API Correlation returns investigation graph", "graph" in corr_data)
        check("API Correlation returns campaigns list", "campaigns" in corr_data)

        # Live upload of sample .eml
        sample_path = Path(__file__).parent / "samples" / "phishing.eml"
        if not sample_path.exists():
            sample_path = Path(__file__).parent / "samples" / "basic.eml"

        if sample_path.exists():
            with open(sample_path, "rb") as f:
                upload_res = client.post(
                    "/api/analyze/upload",
                    files={"file": (sample_path.name, f, "message/rfc822")},
                )
            check("API POST /api/analyze/upload returns 200 OK", upload_res.status_code == 200)
            data = upload_res.json()
            case_id = data.get("case_id")
            check("Upload response contains valid case_id", bool(case_id))
            check("Upload response contains SHA-256 evidence anchor", bool(data.get("sha256")))
            check("Upload response contains risk_assessment with score", "risk_assessment" in data and "risk_score" in data["risk_assessment"])
            check("Upload response contains threat_analysis with primary threat", "threat_analysis" in data and "primary_threat" in data["threat_analysis"])
            check("Upload response contains forensic_analysis with facts & inferences", "forensic_analysis" in data and "findings" in data["forensic_analysis"])
            check("Upload response contains authentication results", "authentication" in data and "spf" in data["authentication"])
            check("Upload response contains smtp_trace received_chain", "smtp_trace" in data and "received_chain" in data["smtp_trace"])
            check("Upload response contains infrastructure_intelligence", "infrastructure_intelligence" in data)

            # Get full case detail
            if case_id:
                case_res = client.get(f"/api/analyze/{case_id}")
                check(f"API GET /api/analyze/{case_id[:8]} returns 200 OK", case_res.status_code == 200)
                case_detail = case_res.json()
                check("Case detail contains parsed_email headers", "parsed_email" in case_detail)
                check("Case detail contains risk_score", case_detail.get("risk_score") is not None)

                # Get case correlation
                case_corr_res = client.get(f"/api/correlation/{case_id}")
                check(f"API GET /api/correlation/{case_id[:8]} returns 200 OK", case_corr_res.status_code == 200)
                case_corr = case_corr_res.json()
                check("Case correlation detail contains graph", "graph" in case_corr)

    # 4. Safe copy and attribution verification
    code_text = ""
    for p in src_dir.rglob("*.tsx"):
        code_text += p.read_text(encoding="utf-8")
    for p in src_dir.rglob("*.ts"):
        code_text += p.read_text(encoding="utf-8")

    check("Safe copy: No unauthorized claims 'Track every hacker'", "Track every hacker" not in code_text)
    check("Safe copy: No unauthorized claims 'Find the attacker'", "Find the attacker" not in code_text)
    check("Safe copy: No unauthorized claims 'Locate criminals'", "Locate criminals" not in code_text)
    check("Attribution safeguard: Uses approximate IP infrastructure location", "Approximate IP infrastructure location" in code_text or "approximate" in code_text.lower())
    check("Attribution safeguard: Differentiates FACTS from INFERENCES", "FACT" in code_text and "INFERENCE" in code_text)

    print("-" * 70)
    print(f"STEP 8 VERIFICATION SUMMARY: {checks_passed}/{total_checks} CHECKS PASSED")
    print("=" * 70)

    if checks_passed == total_checks:
        print(">>> ALL STEP 8 VERIFICATION CHECKS PASSED SUCCESSFULLY! <<<")
        return 0
    else:
        print(">>> SOME VERIFICATION CHECKS FAILED! <<<")
        return 1

if __name__ == "__main__":
    sys.exit(run_verification())
