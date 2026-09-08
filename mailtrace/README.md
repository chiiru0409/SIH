# MAILTRACE

**AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform**

> Built for SIH 2026.

---

## What it does

MAILTRACE analyzes `.eml` files to produce a full forensic + AI threat intelligence report:

| Phase | Capability |
|-------|-----------|
| 2 | `.eml` ingestion and structured parsing |
| 3 | Forensic analysis — sender, headers, SPF/DKIM/DMARC, SMTP trace |
| 4 | AI threat classification — phishing, BEC, impersonation, urgency |
| 5 | IP / domain / URL intelligence enrichment |
| 6 | Unified risk scoring (0–100) with per-signal breakdown |
| 7 | Campaign correlation across multiple emails (NetworkX) |
| 8 | Structured forensic report generation |
| 9 | SHA-256 evidence integrity hashing |
| 10 | React SOC-style dashboard |

---

## Quick start

### Prerequisites

- Python 3.11+
- Node.js 20+ (frontend — Phase 10)

### Backend setup

```bash
cd mailtrace/backend

# Create and activate a virtual environment
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the development server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open http://localhost:8000/docs to see the interactive API documentation.

### Environment variables

Copy `.env` (already in the repo root) and fill in API keys as needed.
All external API keys are optional — the system degrades gracefully without them.

---

## Project structure

```
mailtrace/
├── backend/
│   ├── main.py               # FastAPI app entry point
│   ├── config.py             # Settings (pydantic-settings + .env)
│   ├── database.py           # Async SQLAlchemy engine
│   ├── requirements.txt
│   ├── routes/
│   │   ├── health.py         # GET /api/health, /api/health/ready
│   │   └── analyze.py        # POST /api/analyze/upload (+ GET stubs)
│   ├── services/             # Business logic (phases 2–9)
│   ├── models/
│   │   └── analysis.py       # AnalysisCase ORM model
│   ├── schemas/
│   │   └── analysis.py       # Pydantic request/response schemas
│   └── utils/                # Shared helpers
├── frontend/                 # React dashboard (Phase 10)
├── samples/                  # Uploaded .eml files (runtime)
├── reports/                  # Generated reports (runtime)
└── .env                      # Local secrets (never commit)
```

---

## API endpoints

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/health` | Live | Liveness check |
| GET | `/api/health/ready` | Live | Readiness + DB check |
| POST | `/api/analyze/upload` | Phase 2 | Upload `.eml` for analysis |
| GET | `/api/analyze/cases` | Phase 2 | List all cases |
| GET | `/api/analyze/{id}` | Phase 2 | Get full case report |

---

## Important limitations and accuracy notes

- **GeoIP** provides approximate infrastructure location, not attacker physical location.
- **IP ownership** does not prove human identity.
- **Campaign correlation** indicates suspected relationships, not confirmed common ownership.
- **VPN/TOR detection** is an anonymization infrastructure indicator, not deanonymization.
- AI outputs are probabilistic. All risk assessments should be treated as investigative indicators.

---

## Future extensions (not yet implemented)

- Gmail / Outlook OAuth integration
- Mobile-number intelligence
- Authorized WhatsApp fraud report ingestion
- Cross-channel campaign correlation
- Neo4j graph backend
- Threat-intelligence feed integration
- Blockchain evidence anchoring
