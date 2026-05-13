# ICS ThreatWeaver

ICS ThreatWeaver is a FastAPI-based web application that automates the **ISA/IEC 62443-3-2 Detailed Risk Assessment** process using the **MITRE ATT&CK for ICS** matrix. It ingests an existing ISA 62443-3-2 DRA workbook, enriches every row with canonical MITRE technique data, generates an adversary model, resolves applicable mitigations, and produces a fully structured output workbook — preserving all original column headers exactly as written.

## Features

### MITRE ATT&CK for ICS Integration
- **Live STIX bundle import** — fetches the latest MITRE ATT&CK for ICS dataset directly from MITRE, with per-import version tagging and full history
- **New / modified technique detection** — each import reports newly added and changed techniques against the previously stored version
- **STIX-derived technique↔asset links** — asset associations embedded in the STIX bundle are extracted and stored automatically alongside rule-based mappings

### Technique Mapping Engine
- **Rule-based auto-generation** — applies deterministic rules across all techniques in the latest dataset version to produce asset mappings in one click
- **Mapping suggestion with reasoning** — query the engine for a specific technique and receive ranked asset candidates with human-readable justification for each
- **Analyst approval workflow** — individual technique-to-asset mappings can be approved, overridden, or have their confidence and justification updated independently

### Custom Assets & Security Zones
- **Custom asset registry** — define site-specific assets (name, vendor, model, description) beyond the canonical MITRE asset catalogue
- **Custom-to-MITRE asset mapping** — link each custom asset to one or more MITRE ATT&CK ICS assets with an analyst-supplied justification and mapping version stamp
- **Security zone management** — create, name, and delete ISA 62443-3-2 security zones; assign any combination of MITRE or custom assets per zone
- **Zone threat matrix** — per-zone view of all applicable techniques and assets, with row-level deduplication across direct and legacy custom-asset assignments

### ISA 62443-3-2 DRA Workbook Pipeline
- **Source workbook ingestion** — parses an existing DRA `Worksheet` sheet from row 4 onward; resolves assets from zone cells automatically
- **Exact column header preservation** — all original source headers are replicated verbatim in the output workbook
- **Sequential Risk ID generation** — output rows are numbered 1, 2, 3 … regardless of blank or merged rows in the source
- **MITRE enrichment columns** — each risk scenario row is extended with canonical technique ID, name, tactic, mitigation, and adversary model fields
- **Adversary modelling** — free-text threat-source labels (nation-state, insider, criminal, hacktivist, etc.) are classified into a structured adversary model
- **Five output sheets** — Enhanced Risk Assessment, Mapping Reference, MITRE Reference Index, Change Log, and Original DRA Snapshot

### Excel Export
- **Direct browser download** — export any zone's threat matrix as a populated `.xlsx` file streamed directly to the browser
- **User-supplied templates** — upload any `.xlsx` or `.xlsm` file from your local machine via the Browse button; the server uses it as the workbook template
- **Macro preservation** — `.xlsm` templates retain VBA modules and named ranges throughout the transform pipeline

### Security & Operations
- **SSRF guard** — all outbound URLs are validated and restricted to HTTPS before any network call
- **Path-traversal validation** — every file path accepted by the API is resolved and checked against an allowlist of server-side roots
- **Rate limiting** — per-IP request throttling configurable via `.env`
- **Optional API-key authentication** — all state-mutating endpoints (`POST`, `DELETE`) require `X-API-Key` when `API_KEY` is set; read endpoints remain public
- **Browser-based UI** — single-page interface served at `/`; no build step or frontend framework required

---

## Quick Start

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy and review the environment template
cp .env.example .env

# 4. Start the API server
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload

# 5. Open the UI at http://127.0.0.1:8000  or the API docs at http://127.0.0.1:8000/docs
```

---

## Example Workflow

The primary workflow is the **workbook transform pipeline**:

1. Prepare two files:
   - **Source workbook** — your ISA 62443-3-2 DRA Excel file containing a sheet named `"Worksheet"` with risk scenarios from row 4 onward.
   - **Output template** — the `exports/template.xlsm` file (or your own `.xlsm` template with macros and branding).

2. Submit via the UI at `http://127.0.0.1:8000` or call the API directly:

   ```http
   POST /api/export/transform-risk-assessment
   Content-Type: application/json

   {
     "source_workbook_path":  "docs/your_dra_input.xlsx",
     "template_workbook_path": "exports/template.xlsm",
     "output_path": "exports/ICS_ThreatWeaver_Enhanced_Risk_Assessment.xlsm"
   }
   ```

3. The output workbook is saved to `exports/` and contains five sheets:

   | Sheet | Contents |
   |---|---|
   | `Enhanced Risk Assessment` | All original columns with exact source headers + MITRE-enrichment columns |
   | `Mapping Reference` | Per-row asset/technique deduplication log |
   | `MITRE Reference Index` | Unique technique/adversary/mitigation index |
   | `Change Log` | Row-level transformation audit trail |
   | `Original DRA Snapshot` | Verbatim copy of the source worksheet |

---

## Dependencies

| Package | Purpose |
|---|---|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `sqlalchemy` | ORM and database access |
| `pydantic-settings` | Environment-variable configuration |
| `openpyxl` | Excel workbook read/write (preserves VBA/macros) |
| `requests` | MITRE STIX bundle download |

```powershell
pip install -r requirements.txt
```

---

## Configuration

Copy `.env.example` to `.env` and adjust as needed.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./ics_threatweaver.db` | SQLAlchemy database URL |
| `MITRE_ICS_URL` | MITRE GitHub URL | Source for the ICS STIX bundle |
| `API_KEY` | *(empty — auth disabled)* | Shared secret for write endpoints |
| `CORS_ORIGINS` | `http://localhost:8000 http://127.0.0.1:8000` | Allowed CORS origins |
| `RATE_LIMIT_REQUESTS` | `100` | Max API requests per IP per window |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Security

Set `API_KEY` to a strong random value before exposing this service on any network:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

All state-mutating endpoints (`POST`, `DELETE`) require the `X-API-Key` header when `API_KEY` is set. `GET` endpoints remain public.

**Never set `CORS_ORIGINS=*` on a network-accessible deployment.**