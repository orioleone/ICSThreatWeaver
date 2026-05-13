# ICS ThreatWeaver Architecture

## 1. System Architecture Diagram

```text
+----------------------------- UI / Analyst Console -----------------------------+
| Import MITRE | Define Assets | Map Assets | Review Suggestions | Export Excel |
+------------------------------------+------------------------------------------+
                                     |
                                     v
+------------------------------- FastAPI Service Layer --------------------------+
| /api/mitre | /api/assets | /api/zones | /api/mappings | /api/export/excel     |
+--------------------+-------------------+---------------------+------------------+
                     |                   |                     |
                     v                   v                     v
            +----------------+   +----------------+   +----------------------+
            | MITRE Parser   |   | Mapping Engine |   | Matrix/Excel Engine  |
            | STIX normalize |   | Rules + audit  |   | Dedup + XLSM write   |
            +----------------+   +----------------+   +----------------------+
                     \                   |                     /
                      \                  |                    /
                       +-----------------v-------------------+
                       |      SQLite / PostgreSQL-ready      |
                       | versions, assets, zones, mappings   |
                       +-------------------------------------+
```

## 2. Database Schema

| Table | Purpose |
|---|---|
| dataset_versions | Tracks imported MITRE dataset versions |
| mitre_techniques | Normalized ICS techniques per version |
| mitre_tactics | Tactics linked to techniques |
| mitre_mitigations | Mitigations linked to techniques |
| technique_tactics | Many-to-many tactic linkage |
| technique_mitigations | Many-to-many mitigation linkage |
| mitre_assets | Standard MITRE ICS asset taxonomy |
| custom_assets | User-defined project assets |
| custom_asset_mappings | Custom asset → MITRE asset mappings |
| technique_mappings | MITRE asset → technique mappings with source/justification |
| zones | ISA/IEC 62443 zone definitions |
| zone_assets | Asset assignments per zone |

## 3. Backend API Design

### MITRE Data
- POST /api/mitre/import
- GET /api/mitre/versions

### Assets
- GET /api/assets/mitre
- GET /api/assets/custom
- POST /api/assets/custom
- POST /api/assets/{custom_asset_id}/map

### Zones
- GET /api/zones
- POST /api/zones
- POST /api/zones/{zone_id}/assets/{custom_asset_id}

### Mappings
- POST /api/mappings/suggest
- POST /api/mappings/auto-generate
- POST /api/mappings/approve

### Outputs
- GET /api/zones/{zone_id}/matrix
- POST /api/export/excel

## 4. MITRE Parsing Script

The parser:
- downloads MITRE ICS STIX JSON
- extracts tactics, techniques, mitigations, and mitigates relationships
- persists version snapshots
- flags new and modified techniques against the previous import

Implementation location: backend/app/mitre_parser.py

## 5. Mapping Engine

Rule examples:
- network, server, opc → Control Server
- user interaction, operator, screen → HMI
- plc, rtu, controller, firmware → Field Controller

All mappings can be stored with:
- source: manual, rule, ai
- confidence
- justification
- mapping version
- analyst approval state

## 6. Excel Integration Approach

To preserve existing VBA and formatting:
- load template with openpyxl and keep_vba=True for xlsm
- write only cell values into the target worksheet
- save as xlsm output without altering macros

This keeps analyst-owned workbook logic intact while automating data insertion.

## 7. Step-by-Step Implementation Plan

### MVP
1. Import MITRE ICS bundle
2. Normalize and store core ATT&CK entities
3. Capture custom assets and zones
4. Map assets manually or via rules
5. Generate deduplicated zone matrix
6. Export matrix into analyst template

### Production-Ready Hardening
1. Replace SQLite with PostgreSQL
2. Add authentication and RBAC
3. Add background jobs for MITRE sync
4. Add approval workflow and audit logs
5. Add AI suggestion provider abstraction
6. Add deployment packaging and monitoring
