# MAILTRACE

**AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**

> Production-ready, deterministic email forensics, NLP threat classification, infrastructure correlation, cryptographic evidence preservation, and interactive SOC investigation workspace.

---

## System Overview & Architecture

MAILTRACE is a passive email forensic and threat intelligence system designed for security operations center (SOC) analysts, incident responders, and digital forensics investigators. It ingests standard `.eml` (RFC-822 / MIME) files and executes a 9-stage analysis pipeline:

```
┌─────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│  .EML Ingestion │ ──> │ MIME & Header Parsing  │ ──> │ Forensic Auth Analysis │
└─────────────────┘     └────────────────────────┘     └────────────────────────┘
                                                                   │
┌─────────────────┐     ┌────────────────────────┐                 ▼
│ Unified Risk    │ <── │ Infrastructure Intel   │ <── ┌────────────────────────┐
│ Scoring (0-100) │     │ (GeoIP, WHOIS, ASN)    │     │ AI / NLP Threat Engine │
└─────────────────┘     └────────────────────────┘     └────────────────────────┘
        │
        ▼
┌─────────────────┐     ┌────────────────────────┐     ┌────────────────────────┐
│ Campaign Graph  │ ──> │ Evidence Integrity &   │ ──> │ SOC Investigation      │
│ Correlation     │     │ Blockchain Anchoring   │     │ Frontend Workspace     │
└─────────────────┘     └────────────────────────┘     └────────────────────────┘
```

---

## Key Capabilities Across Stages

| Stage | Capability | Description |
|---|---|---|
| **1. Foundation** | Async FastAPI & SQLite | Asynchronous API foundation, SQLAlchemy persistence, schema validation, and health telemetry. |
| **2. Ingestion & Parsing** | RFC-822 / MIME Engine | High-throughput parsing of headers, MIME trees, text/HTML bodies, attachment metadata, and hashes (SHA-256). |
| **3. Forensics & Auth** | Deep Email Forensics | Strict verification of SPF, DKIM, DMARC, reverse-hop Received header traversal, and display-name spoofing detection. |
| **4. AI Threat Analysis** | NLP Threat Classification | Hybrid AI/NLP classification detecting Phishing, BEC, Credential Harvesting, Malware, and Urgency tactics with offline fallback. |
| **5. Infrastructure Intel** | Passive Enrichment | GeoIP mapping, WHOIS/RDAP queries, ASN lookup, domain age calculation, and punycode/homograph detection. |
| **6. Unified Risk Scoring** | Deterministic Risk Engine | Transparent, bounded 0–100 risk score based on weighted forensic, authentication, AI, and infrastructure findings. |
| **7. Campaign Correlation** | Multi-Case Graph Engine | Inverted-index correlation clustering related cases via shared sender domains, auth IPs, reply-to targets, and threat signatures. |
| **8. Investigation UI** | React + Tailwind Dashboard | SOC-grade dark workspace featuring risk meters, auth matrices, relay timelines, GeoIP maps, and interactive NetworkX graphs. |
| **9. Evidence Integrity** | Cryptographic Anchoring | Deterministic SHA-256 evidence hashing, chained custody logs, tamper verification, and blockchain anchoring (Ethereum/Polygon/Mock). |
| **10. Hardening & Readiness** | Full-System Hardening | End-to-end defensive security, XSS defanging, strict attribution disclaimers, and 100% test coverage. |

---

## Defensive Security & Passive Analysis Model

MAILTRACE adheres strictly to passive forensic analysis principles:

- **No Active URL Fetching**: Suspicious URLs extracted from emails are decomposed and analyzed purely offline (domain, path, TLD, Punycode). MailTrace **NEVER** makes outbound HTTP/TCP requests to links contained in analyzed messages.
- **No Attachment Execution**: File attachments are hashed (SHA-256), inspected for MIME/extension anomalies, and extracted passively. Attachments are **NEVER** executed or dynamically invoked.
- **Defense-in-Depth HTML Sanitization**: Email HTML previews are strictly sanitized—stripping `<script>`, `<style>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<input>`, `<button>`, `<svg>`, inline event handlers (`onclick`, `onerror`), defanging links with `onclick="return false;"`, and forcing `rel="noopener noreferrer nofollow"`.
- **Secret Isolation**: Private blockchain keys and external API keys are strictly maintained within backend environment variables and **NEVER** exposed to frontend clients or persisted in public artifacts.
- **Cryptographic Privacy**: Blockchain anchoring commits only deterministic SHA-256 root hashes and case UUIDs. **NO raw email bodies, attachment bytes, credentials, or PII are ever stored on-chain**.

---

## Forensic Correctness & Attribution Disclaimers

MAILTRACE enforces clear separation between **deterministic forensic facts** and **probabilistic intelligence inferences**:

1. **GeoIP Disclaimer**: GeoIP coordinates represent the *approximate geographical location of the routing IP infrastructure* (e.g., mail relay, data center, hosting provider), **NOT** the verified physical location or identity of the human sender.
2. **Attribution Disclaimer**: IP addresses, server hostnames, and domain registrations indicate technical infrastructure ownership, not proof of individual criminal identity or state attribution.
3. **Campaign Correlation**: Graph linkages represent *statistically correlated technical indicators* (e.g., shared ASN, common sender domain, identical phishing kit markers), not confirmed legal attribution.
4. **Anonymization Technologies**: Indicators such as VPN, Tor, or public proxy relays represent *infrastructure obfuscation signals*, not deanonymization of operators.
5. **AI Outputs**: NLP threat classifications provide explainable probability indicators and forensic evidence snippets; all decisions remain under investigator oversight.

---

## API Reference

### Health & Telemetry
- `GET /api/health` — Returns basic API health and liveness status.
- `GET /api/health/ready` — Returns comprehensive readiness status including database connection state.

### Analysis & Case Management
- `POST /api/analyze/upload` — Ingests a raw `.eml` file, executes the full forensic pipeline, persists the case, and returns the complete analysis record.
- `GET /api/analyze/cases` — Lists all analyzed investigation cases with high-level summaries and risk scores.
- `GET /api/analyze/{id}` — Retrieves the complete forensic analysis record, risk assessment, and infrastructure intelligence for a specific case ID.

### Campaign Correlation & Investigation Graph
- `GET /api/correlation` — Returns the global investigation graph containing all cases, shared indicator nodes, and campaign cluster metadata.
- `GET /api/correlation/{case_id}` — Returns the focused subgraph and correlated campaign peers for a single investigation case.

### Evidence Integrity & Blockchain Anchoring
- `GET /api/evidence/{case_id}` — Retrieves the evidence manifest, SHA-256 raw bytes hash, deterministic parsed evidence hash, analysis hash, and custody chain.
- `POST /api/evidence/{case_id}/verify` — Recomputes cryptographic hashes server-side against current storage and verifies chain-of-custody integrity.
- `POST /api/evidence/{case_id}/anchor` — Anchors the case's cryptographic root hash to the configured blockchain provider (Ethereum, Polygon, Sepolia, or Mock).
- `GET /api/evidence/{case_id}/chain` — Retrieves the immutable chain-of-custody audit log for the case.

---

## Installation & Setup

### Prerequisites
- **Python 3.11+** (Python 3.13 recommended)
- **Node.js 20+** and **npm**

### 1. Backend Setup

```bash
# Navigate to backend directory
cd mailtrace/backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend development server
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The interactive OpenAPI / Swagger documentation will be available at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup

```bash
# Navigate to frontend directory
cd mailtrace/frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```

The investigation dashboard will be available at `http://localhost:5173`.

---

## Environment Configuration

Create a `.env` file in `mailtrace/` (or use the provided template):

```ini
# Application Environment
ENVIRONMENT=development
DATABASE_URL=sqlite+aiosqlite:///./mailtrace.db
CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]

# AI Threat Detection (Optional - falls back to deterministic heuristic rules)
OPENAI_API_KEY=

# Infrastructure Intelligence (Optional - falls back to passive resolution)
IPINFO_TOKEN=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# Blockchain Evidence Anchoring (Optional - defaults to 'mock' for testing)
BLOCKCHAIN_ENABLED=true
BLOCKCHAIN_PROVIDER=mock
BLOCKCHAIN_RPC_URL=
BLOCKCHAIN_CONTRACT_ADDRESS=
BLOCKCHAIN_PRIVATE_KEY=
```

---

## Running Verification & Tests

### Backend Unit & Integration Tests (215+ Tests)
```bash
cd mailtrace
pytest -v
```

### Frontend Unit & Component Tests (13+ Tests)
```bash
cd mailtrace/frontend
npm run test
```

### Frontend Production Build Verification
```bash
cd mailtrace/frontend
npm run build
```

### End-to-End Live Verification
```bash
cd mailtrace
python verify_step9.py
```

---

## Sample Dataset & Demo Workflow

Sample `.eml` files are available in `mailtrace/samples/`:
- `samples/phishing.eml` — High-urgency credential harvesting attack with spoofed display name and failed SPF/DMARC.
- `samples/basic.eml` — Clean transactional email with valid authentication.
- `samples/multipart.eml` — Multi-part HTML/text message with inline assets.
- `samples/attachment.eml` — Message containing suspicious payload attachment.

### Recommended Demo Flow
1. **Upload**: Drag-and-drop `samples/phishing.eml` on the workspace upload zone.
2. **Threat Assessment**: Observe immediate risk scoring (Critical / 80+), threat category breakdown (Phishing / BEC), and NLP explainability markers.
3. **Forensic Inspection**: Inspect the Authentication Matrix (SPF Fail, DKIM None, DMARC Fail) and reverse Received relay timeline.
4. **Infrastructure & GeoIP**: Explore the interactive world map pinpointing relay server hops and WHOIS registrar details.
5. **Investigation Graph**: View campaign correlation clusters revealing shared attacker infrastructure across multiple past cases.
6. **Evidence Integrity**: Verify the SHA-256 evidence manifest, inspect chain of custody, and trigger an idempotent blockchain anchor with transaction receipt.
