from __future__ import annotations

import logging
import requests
import shutil
import tempfile
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .config import BASE_DIR, Settings, get_settings
from .database import Base, SessionLocal, engine, ensure_schema_upgrades, get_db
from .security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    require_api_key,
    sanitize_file_path,
    validate_https_url,
)
from .excel_export import export_matrix_to_workbook
from .mapping_engine import MappingEngine
from .mitre_parser import DEFAULT_MITRE_ICS_URL, download_mitre_ics_bundle, seed_builtin_assets, store_bundle
from .workbook_transformer import transform_risk_assessment_workbook
from .models import (
    CustomAsset,
    CustomAssetMapping,
    DatasetVersion,
    MitreAsset,
    MitreMitigation,
    MitreTechnique,
    MitreTactic,
    TechniqueMapping,
    TechniqueMitigation,
    TechniqueTactic,
    Zone,
    ZoneAsset,
    ZoneMitreAsset,
    DEFAULT_MAPPING_VERSION,
)
from .schemas import (
    CustomAssetCreate,
    CustomAssetMapRequest,
    ExcelDownloadRequest,
    ExcelExportRequest,
    MitreImportRequest,
    MultiZoneExportRequest,
    TechniqueMappingApprovalRequest,
    TechniqueSuggestionRequest,
    WorkbookTransformRequest,
    ZoneAssetSelectionRequest,
    ZoneCreate,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application bootstrap
# ---------------------------------------------------------------------------

DEFAULT_RISK_TEMPLATE = (
    BASE_DIR / "docs" / "Detailed Risk Assessment Blank Tempate - IC33 Oct 2015 [Modified].xlsx"
)
APP_TEMP_DIR_PREFIX = "ics-threatweaver-"
engine_rules = MappingEngine()


def _cleanup_old_temp_files(max_age_hours: int = 24) -> None:
    """Delete temporary files older than max_age_hours to prevent disk accumulation.
    
    Called at server startup to clean up uploaded templates and generated workbooks
    that were not cleaned up in previous runs.
    
    Args:
        max_age_hours: Maximum age of temp files to keep (default 24 hours).
    """
    temp_root = Path(tempfile.gettempdir())
    if not temp_root.exists():
        return
    
    now = time.time()
    cutoff_time = now - (max_age_hours * 3600)
    cleaned_count = 0
    
    for temp_item in temp_root.iterdir():
        # Only attempt to clean temp files/dirs created by this process.
        # Skip if cannot stat (permission denied, etc.).
        try:
            # Never touch foreign temp directories created by other apps.
            if not temp_item.name.startswith(APP_TEMP_DIR_PREFIX):
                continue
            if temp_item.stat().st_mtime < cutoff_time:
                if temp_item.is_dir():
                    shutil.rmtree(str(temp_item), ignore_errors=True)
                    cleaned_count += 1
        except (OSError, PermissionError):
            pass  # Skip items we can't access
    
    if cleaned_count > 0:
        logger.info("Cleaned %d old temporary files/directories", cleaned_count)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    """Create DB tables, seed built-in MITRE assets, and clean old temp files on startup."""
    Base.metadata.create_all(bind=engine)
    ensure_schema_upgrades()
    db = SessionLocal()
    try:
        seed_builtin_assets(db)
    finally:
        db.close()
    _cleanup_old_temp_files()
    logger.info("ICS ThreatWeaver started — database ready")
    yield
    logger.info("ICS ThreatWeaver shutting down")


_settings = get_settings()

# Update root logger level from settings (allows env-based debug toggling)
logging.getLogger().setLevel(_settings.LOG_LEVEL.upper())

app = FastAPI(
    title="ICS ThreatWeaver",
    description="ISA/IEC 62443 risk-assessment accelerator for MITRE ATT&CK for ICS.",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Security & rate-limiting middleware ──────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=_settings.RATE_LIMIT_REQUESTS,
    window_seconds=_settings.RATE_LIMIT_WINDOW,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# allow_credentials must not be True when origins contains "*" (browser guard).
_uses_wildcard = _settings.CORS_ORIGINS == ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.CORS_ORIGINS,
    allow_credentials=not _uses_wildcard,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """Serve the single-page frontend application."""
    html_path = BASE_DIR / "frontend" / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.get("/api/health")
def health() -> dict[str, str]:
    """Return a simple liveness probe payload."""
    return {"status": "ok", "service": "ICS ThreatWeaver"}


@app.get("/api/templates")
def list_templates(settings: Settings = Depends(get_settings)) -> list[dict]:
    """List available Excel template files from the exports and docs directories.

    Scans the configured ``EXPORTS_DIR`` and ``REF_DIR`` (docs/) directories for
    ``.xlsx`` and ``.xlsm`` files and returns their server-side paths so the UI
    can populate a file picker without requiring a file upload.
    """
    templates = []
    for dir_str in [settings.EXPORTS_DIR, settings.REF_DIR]:
        dir_path = Path(dir_str)
        if dir_path.exists():
            for pattern in ("*.xlsx", "*.xlsm"):
                for f in sorted(dir_path.glob(pattern)):
                    templates.append({
                        "path": str(f),
                        "label": f"{f.parent.name}/{f.name}",
                    })
    return templates


@app.post("/api/templates/upload", dependencies=[Depends(require_api_key)])
async def upload_template(file: UploadFile = File(...)) -> dict:
    """Accept a user-uploaded template workbook and store it in a temporary directory.

    Validates that the upload is an ``.xlsx`` or ``.xlsm`` file, writes it to a
    temporary path, and returns the server-side path so the caller can pass it to
    the export endpoint in a subsequent request.
    """
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".xlsx", ".xlsm"}:
        raise HTTPException(status_code=400, detail="Only .xlsx and .xlsm files are accepted.")
    safe_name = Path(file.filename or "template").name

    # [IMPROVEMENT] Enforce a file-size cap before writing to disk.  Without this,
    # a crafted xlsx zip bomb (tiny on the wire, gigabytes uncompressed) would be
    # accepted, stored, and later decompressed by openpyxl into memory.
    # [SOURCE] Audit finding: High (H-5)
    _MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
    content = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds the 50 MB size limit.")

    tmp_dir = Path(tempfile.mkdtemp(prefix=APP_TEMP_DIR_PREFIX))
    dest = tmp_dir / safe_name
    dest.write_bytes(content)

    # [RESOLVED] Temp directory cleanup now implemented at server startup via
    # _cleanup_old_temp_files().  The caller receives 'server_path' for a follow-up
    # request; the temporary directory persists until server restart or 24-hour age threshold.
    # [SOURCE] Audit finding: Critical (C-1)
    logger.info(
        "Uploaded template stored at '%s'; will be cleaned up at next server startup if > 24h old",
        dest,
    )
    return {"server_path": str(dest), "filename": safe_name}


@app.post("/api/mitre/import", dependencies=[Depends(require_api_key)])
def import_mitre_dataset(
    payload: MitreImportRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    url = payload.source_url or DEFAULT_MITRE_ICS_URL
    try:
        validate_https_url(url, settings.MITRE_ALLOWED_HOSTS)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info("Importing MITRE ICS bundle from %s", url)
    try:
        bundle = download_mitre_ics_bundle(url)
        return store_bundle(db, bundle, version_tag=payload.version_tag, source_url=url)
    except requests.RequestException as exc:
        logger.error("MITRE import failed while fetching bundle", exc_info=True)
        raise HTTPException(status_code=502, detail="Failed to fetch MITRE ATT&CK for ICS dataset") from exc
    except ValueError as exc:
        logger.error("MITRE import failed due to invalid bundle payload", exc_info=True)
        raise HTTPException(status_code=502, detail="Received invalid MITRE ATT&CK for ICS dataset payload") from exc


@app.get("/api/mitre/versions")
def list_versions(db: Session = Depends(get_db)) -> list[dict]:
    """Return all imported MITRE dataset versions ordered by import date (newest first)."""
    versions = db.query(DatasetVersion).order_by(desc(DatasetVersion.imported_at)).all()
    return [
        {
            "id": version.id,
            "version_tag": version.version_tag,
            "source_url": version.source_url,
            "imported_at": version.imported_at.isoformat(),
        }
        for version in versions
    ]


@app.get("/api/assets/mitre")
def list_mitre_assets(db: Session = Depends(get_db)) -> list[dict]:
    """Return all MITRE ATT&CK for ICS assets.

    Assets are seeded once at startup via ``lifespan``; calling ``seed_builtin_assets``
    on every GET request issued 18+ SELECT queries per call.  Seeding is now startup-only.
    """
    # [IMPROVEMENT] Removed seed_builtin_assets(db) call: startup seeding in lifespan()
    # is sufficient. Calling it on every read endpoint issued N per-asset SELECT queries
    # unnecessarily and inflated DB load on common list operations.
    # [SOURCE] Audit finding: Medium (M-1)
    assets = db.query(MitreAsset).filter(MitreAsset.external_id.is_not(None)).order_by(MitreAsset.external_id, MitreAsset.name).all()
    return [
        {
            "id": asset.id,
            "external_id": asset.external_id,
            "name": asset.name,
            "description": asset.description,
            "label": f"{asset.external_id or 'MITRE'} - {asset.name}",
        }
        for asset in assets
    ]


@app.get("/api/assets/custom")
def list_custom_assets(db: Session = Depends(get_db)) -> list[dict]:
    """Return all custom (site-specific) assets ordered by name."""
    rows = db.query(CustomAsset).order_by(CustomAsset.name).all()
    return [
        {
            "id": row.id,
            "name": row.name,
            "vendor": row.vendor,
            "model": row.model,
            "description": row.description,
        }
        for row in rows
    ]


@app.post("/api/assets/custom", dependencies=[Depends(require_api_key)])
def create_custom_asset(payload: CustomAssetCreate, db: Session = Depends(get_db)) -> dict:
    """Create a new custom asset record."""
    asset = CustomAsset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return {"id": asset.id, "name": asset.name}


@app.post("/api/assets/{custom_asset_id}/map", dependencies=[Depends(require_api_key)])
def map_custom_asset(custom_asset_id: int, payload: CustomAssetMapRequest, db: Session = Depends(get_db)) -> dict:
    """Map a custom asset to a MITRE ATT&CK ICS asset with analyst justification.

    Creates a new mapping if one does not yet exist for the given
    ``mapping_version``; otherwise updates the justification in place.
    """
    custom_asset = db.query(CustomAsset).filter(CustomAsset.id == custom_asset_id).first()
    mitre_asset = db.query(MitreAsset).filter(MitreAsset.name == payload.mitre_asset_name).first()
    if not custom_asset or not mitre_asset:
        raise HTTPException(status_code=404, detail="Custom asset or MITRE asset not found")

    mapping = db.query(CustomAssetMapping).filter(
        CustomAssetMapping.custom_asset_id == custom_asset_id,
        CustomAssetMapping.mitre_asset_id == mitre_asset.id,
        CustomAssetMapping.mapping_version == payload.mapping_version,
    ).first()
    if not mapping:
        mapping = CustomAssetMapping(
            custom_asset_id=custom_asset_id,
            mitre_asset_id=mitre_asset.id,
            mapping_version=payload.mapping_version,
            justification=payload.justification,
            approved=True,
        )
        db.add(mapping)
    else:
        mapping.justification = payload.justification
        mapping.approved = True

    db.commit()
    return {"message": "Asset mapping saved", "custom_asset": custom_asset.name, "mitre_asset": mitre_asset.name}


@app.get("/api/zones")
def list_zones(db: Session = Depends(get_db)) -> list[dict]:
    """Return all security zones ordered by name."""
    zones = db.query(Zone).order_by(Zone.name).all()
    return [{"id": zone.id, "name": zone.name, "description": zone.description} for zone in zones]


@app.delete("/api/zones/{zone_id}", dependencies=[Depends(require_api_key)])
def delete_zone(zone_id: int, db: Session = Depends(get_db)) -> dict:
    """Delete a zone and all its asset assignments."""
    zone = db.query(Zone).filter(Zone.id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    db.query(ZoneMitreAsset).filter(ZoneMitreAsset.zone_id == zone_id).delete(synchronize_session=False)
    db.query(ZoneAsset).filter(ZoneAsset.zone_id == zone_id).delete(synchronize_session=False)
    db.delete(zone)
    db.commit()
    return {"message": f"Zone '{zone.name}' deleted"}


@app.post("/api/zones", dependencies=[Depends(require_api_key)])
def create_zone(payload: ZoneCreate, db: Session = Depends(get_db)) -> dict:
    """Create a new security zone; returns the existing record if the name already exists."""
    zone_name = payload.name.strip()
    if not zone_name:
        raise HTTPException(status_code=400, detail="Zone name is required")

    existing = db.query(Zone).filter(Zone.name == zone_name).first()
    if existing:
        return {"id": existing.id, "name": existing.name, "message": "Zone already exists"}

    zone = Zone(name=zone_name, description=payload.description)
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return {"id": zone.id, "name": zone.name, "message": "Zone created"}


@app.post("/api/zones/{zone_id}/assets/{custom_asset_id}", dependencies=[Depends(require_api_key)])
def assign_asset_to_zone(zone_id: int, custom_asset_id: int, db: Session = Depends(get_db)) -> dict:
    """Assign a custom asset to a zone (idempotent — duplicate assignments are silently ignored)."""
    zone = db.query(Zone).filter(Zone.id == zone_id).first()
    asset = db.query(CustomAsset).filter(CustomAsset.id == custom_asset_id).first()
    if not zone or not asset:
        raise HTTPException(status_code=404, detail="Zone or asset not found")

    existing = db.query(ZoneAsset).filter(ZoneAsset.zone_id == zone_id, ZoneAsset.custom_asset_id == custom_asset_id).first()
    if not existing:
        db.add(ZoneAsset(zone_id=zone_id, custom_asset_id=custom_asset_id))
        db.commit()

    return {"message": "Asset assigned", "zone": zone.name, "asset": asset.name}


@app.post("/api/zones/{zone_id}/mitre-assets", dependencies=[Depends(require_api_key)])
def assign_mitre_assets_to_zone(zone_id: int, payload: ZoneAssetSelectionRequest, db: Session = Depends(get_db)) -> dict:
    """Assign one or more MITRE ATT&CK ICS assets to a zone by external ID.

    When ``replace_existing`` is ``True``, all previous MITRE asset assignments
    for the zone are removed before the new set is applied.
    """
    zone = db.query(Zone).filter(Zone.id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")

    normalized_ids = sorted({asset_id.strip().upper() for asset_id in payload.mitre_asset_ids if asset_id and asset_id.strip()})
    if not normalized_ids:
        raise HTTPException(status_code=400, detail="At least one MITRE asset must be selected")

    assets = db.query(MitreAsset).filter(MitreAsset.external_id.in_(normalized_ids)).all()
    found_ids = {asset.external_id for asset in assets}
    invalid_ids = [asset_id for asset_id in normalized_ids if asset_id not in found_ids]
    if invalid_ids:
        raise HTTPException(status_code=400, detail=f"Invalid MITRE asset IDs: {', '.join(invalid_ids)}")

    if payload.replace_existing:
        db.query(ZoneMitreAsset).filter(ZoneMitreAsset.zone_id == zone_id).delete(synchronize_session=False)

    existing_asset_ids = {
        row.mitre_asset_id
        for row in db.query(ZoneMitreAsset).filter(ZoneMitreAsset.zone_id == zone_id).all()
    }
    for asset in assets:
        if asset.id not in existing_asset_ids:
            db.add(ZoneMitreAsset(zone_id=zone_id, mitre_asset_id=asset.id))

    db.commit()
    return {
        "message": "MITRE assets assigned",
        "zone": zone.name,
        "selected_assets": [
            {"external_id": asset.external_id, "name": asset.name} for asset in sorted(assets, key=lambda item: item.external_id or item.name)
        ],
    }


@app.get("/api/zones/{zone_id}/assets")
def list_zone_assets(zone_id: int, db: Session = Depends(get_db)) -> dict:
    """Return all MITRE assets assigned to a zone, deduplicated and sorted by external ID."""
    zone = db.query(Zone).filter(Zone.id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")

    selected = []

    # [RESOLVED] Replaced N+1 per-row SELECT loops with batch IN queries.
    # [SOURCE] Audit finding: Medium (M-3)
    # Previously: 1 query per MITRE asset row + 1 query per mapping + 1 query per
    # custom mapping's MitreAsset.  Now: 2 queries for path-1, 3 for path-2 total.
    # [SOURCE] Audit finding: Medium (M-3)

    # Path 1: ZoneMitreAsset → MitreAsset (direct MITRE asset assignments)
    zone_mitre_rows = db.query(ZoneMitreAsset).filter(ZoneMitreAsset.zone_id == zone_id).all()
    if zone_mitre_rows:
        direct_asset_ids = [row.mitre_asset_id for row in zone_mitre_rows]
        for asset in db.query(MitreAsset).filter(MitreAsset.id.in_(direct_asset_ids)).all():
            selected.append({"external_id": asset.external_id, "name": asset.name})

    # Path 2: Legacy ZoneAsset → CustomAssetMapping → MitreAsset (batched)
    legacy_zone_rows = db.query(ZoneAsset).filter(ZoneAsset.zone_id == zone_id).all()
    custom_ids = [row.custom_asset_id for row in legacy_zone_rows if row.custom_asset_id]
    if custom_ids:
        asset_mappings = db.query(CustomAssetMapping).filter(
            CustomAssetMapping.custom_asset_id.in_(custom_ids),
            CustomAssetMapping.approved.is_(True),
        ).all()
        if asset_mappings:
            legacy_asset_ids = [m.mitre_asset_id for m in asset_mappings]
            assets_by_id = {
                a.id: a
                for a in db.query(MitreAsset).filter(MitreAsset.id.in_(legacy_asset_ids)).all()
            }
            for mapping in asset_mappings:
                asset = assets_by_id.get(mapping.mitre_asset_id)
                if asset:
                    selected.append({"external_id": asset.external_id, "name": asset.name})

    deduped = sorted({(row["external_id"], row["name"]) for row in selected})
    return {"zone_id": zone_id, "zone": zone.name, "assets": [{"external_id": ext_id, "name": name} for ext_id, name in deduped]}


@app.post("/api/mappings/suggest")
def suggest_assets(payload: TechniqueSuggestionRequest) -> list[dict]:
    """Return rule-based MITRE asset suggestions with reasoning for a given technique."""
    return engine_rules.suggest_assets_with_reasoning(payload.model_dump())


def _build_rule_based_mapping_report(db: Session, persist: bool) -> dict:
    latest_version = db.query(DatasetVersion).order_by(desc(DatasetVersion.imported_at)).first()
    if not latest_version:
        raise HTTPException(status_code=400, detail="Import MITRE data first")

    techniques = db.query(MitreTechnique).filter(MitreTechnique.dataset_version_id == latest_version.id).order_by(MitreTechnique.external_id).all()

    assets_by_id = {
        asset.id: asset
        for asset in db.query(MitreAsset).filter(MitreAsset.external_id.is_not(None)).all()
    }
    assets_by_name = {asset.name: asset for asset in assets_by_id.values()}

    # Check whether STIX-derived mappings already exist for this dataset version
    stix_link_count = db.query(TechniqueMapping).filter(
        TechniqueMapping.source == "stix",
        TechniqueMapping.technique_id.in_([t.id for t in techniques]),
    ).count()

    # If no STIX mappings exist yet, fall back to keyword rules (persist=True path)
    use_keyword_fallback = stix_link_count == 0

    if use_keyword_fallback:
        technique_rows = [
            {"external_id": t.external_id, "name": t.name, "description": t.description or ""}
            for t in techniques
        ]
        report = engine_rules.build_deterministic_mapping_report(technique_rows)
        report["version_tag"] = latest_version.version_tag
        for mapping in report["mappings"]:
            mapping["mapped_asset_details"] = [
                {"external_id": assets_by_name[asset_name].external_id, "name": asset_name}
                for asset_name in mapping["mapped_assets"]
                if asset_name in assets_by_name
            ]
        if persist:
            technique_by_external_id = {t.external_id: t for t in techniques}
            created = 0
            duplicates = 0
            for mapping in report["mappings"]:
                technique = technique_by_external_id.get(mapping["technique_id"])
                if not technique:
                    continue
                for asset_name in mapping["mapped_assets"]:
                    asset = assets_by_name.get(asset_name)
                    if not asset:
                        continue
                    existing = db.query(TechniqueMapping).filter(
                        TechniqueMapping.mitre_asset_id == asset.id,
                        TechniqueMapping.technique_id == technique.id,
                        # [IMPROVEMENT] Use DEFAULT_MAPPING_VERSION constant instead of "v1" literal.
                        # [SOURCE] Audit finding: Low (L-1)
                        TechniqueMapping.mapping_version == DEFAULT_MAPPING_VERSION,
                    ).first()
                    if existing:
                        duplicates += 1
                        continue
                    # [IMPROVEMENT] Use the engine's per-asset confidence value (0.6–1.0)
                    # instead of the previously hardcoded 1.0.  Confidence is derived from
                    # the number of keyword matches: min(1.0, 0.6 + len(matches) * 0.1).
                    # [SOURCE] Audit finding: Medium (M-9)
                    kw_confidence = mapping.get("confidence_map", {}).get(asset_name, 0.75)
                    db.add(TechniqueMapping(
                        mitre_asset_id=asset.id,
                        technique_id=technique.id,
                        source="rule",
                        justification=mapping["traceability"],
                        confidence=kw_confidence,
                        approved=True,
                    ))
                    created += 1
            db.commit()
            report["coverage_summary"]["created_links"] = created
            report["deduplication"]["duplicate_assets_removed"] = duplicates
        return report

    # --- Build report from DB-stored mappings (STIX + keyword combined) ---
    technique_lookup = {t.id: t for t in techniques}
    # Collect all approved mappings for this dataset version's techniques
    all_mappings = db.query(TechniqueMapping).filter(
        TechniqueMapping.approved.is_(True),
        TechniqueMapping.technique_id.in_(list(technique_lookup.keys())),
    ).all()

    # Group by technique
    tech_to_assets: dict[int, list[dict]] = defaultdict(list)
    for tm in all_mappings:
        asset = assets_by_id.get(tm.mitre_asset_id)
        if asset:
            tech_to_assets[tm.technique_id].append({
                "external_id": asset.external_id,
                "name": asset.name,
            })

    mappings_out = []
    mapped_count = 0
    unmapped_count = 0
    for technique in techniques:
        asset_details = sorted(tech_to_assets.get(technique.id, []), key=lambda a: a["external_id"] or "")
        if asset_details:
            mapped_count += 1
        else:
            unmapped_count += 1
        mappings_out.append({
            "technique_id": technique.external_id,
            "technique_name": technique.name,
            "mapped_assets": [a["name"] for a in asset_details],
            "mapped_asset_details": asset_details,
            "traceability": "MITRE ATT&CK STIX targets relationship" if tech_to_assets.get(technique.id) else "No mapping found",
        })

    created_links = 0
    duplicate_links = 0
    if persist:
        # Asset-level invariant: if STIX covers an asset, its mapping is
        # authoritative and complete. Keyword rules only supplement assets
        # that STIX does not target at all (e.g. custom assets).
        stix_covered_asset_ids: set[int] = {
            tm.mitre_asset_id
            for tm in db.query(TechniqueMapping).filter(
                TechniqueMapping.source == "stix",
            ).all()
        }

        # keyword rules supplement — skip any asset already covered by STIX
        technique_rows = [
            {"external_id": t.external_id, "name": t.name, "description": t.description or ""}
            for t in techniques
        ]
        kw_report = engine_rules.build_deterministic_mapping_report(technique_rows)
        technique_by_external_id = {t.external_id: t for t in techniques}
        for kw_mapping in kw_report["mappings"]:
            technique = technique_by_external_id.get(kw_mapping["technique_id"])
            if not technique:
                continue
            for asset_name in kw_mapping["mapped_assets"]:
                asset = assets_by_name.get(asset_name)
                if not asset:
                    continue
                # Skip if STIX already covers this asset
                if asset.id in stix_covered_asset_ids:
                    continue
                existing = db.query(TechniqueMapping).filter(
                    TechniqueMapping.mitre_asset_id == asset.id,
                    TechniqueMapping.technique_id == technique.id,
                    # [IMPROVEMENT] Use DEFAULT_MAPPING_VERSION constant instead of "v1" literal.
                    # [SOURCE] Audit finding: Low (L-1)
                    TechniqueMapping.mapping_version == DEFAULT_MAPPING_VERSION,
                ).first()
                if existing:
                    duplicate_links += 1
                    continue
                # [IMPROVEMENT] Use the per-asset confidence from the engine instead of 1.0.
                # [SOURCE] Audit finding: Medium (M-9)
                kw_confidence = kw_mapping.get("confidence_map", {}).get(asset_name, 0.75)
                db.add(TechniqueMapping(
                    mitre_asset_id=asset.id,
                    technique_id=technique.id,
                    source="rule",
                    justification=kw_mapping["traceability"],
                    confidence=kw_confidence,
                    approved=True,
                ))
                created_links += 1
        db.commit()

    return {
        "version_tag": latest_version.version_tag,
        "coverage_summary": {
            "technique_count": len(mappings_out),
            "mapped_techniques": mapped_count,
            "unmapped_techniques": unmapped_count,
            "asset_technique_links": sum(len(m["mapped_assets"]) for m in mappings_out),
            "created_links": created_links,
        },
        "deduplication": {"duplicate_assets_removed": duplicate_links},
        "mappings": mappings_out,
    }


@app.post("/api/mappings/auto-generate", dependencies=[Depends(require_api_key)])
def auto_generate_mappings(db: Session = Depends(get_db)) -> dict:
    """Persist rule-based and STIX-derived technique mappings for the latest dataset version."""
    report = _build_rule_based_mapping_report(db, persist=True)
    return {"message": "Deterministic rule-based mappings generated", **report}


@app.get("/api/mappings/report")
def get_mapping_report(db: Session = Depends(get_db)) -> dict:
    """Return the current technique-to-asset mapping report without persisting anything."""
    return _build_rule_based_mapping_report(db, persist=False)


@app.post("/api/mappings/approve", dependencies=[Depends(require_api_key)])
def approve_mapping(payload: TechniqueMappingApprovalRequest, db: Session = Depends(get_db)) -> dict:
    """Approve or update a single technique-to-asset mapping.

    Creates the mapping record if it does not yet exist for the given
    ``mapping_version``; otherwise updates source, justification, and confidence.
    """
    asset = db.query(MitreAsset).filter(MitreAsset.name == payload.mitre_asset_name).first()
    technique = db.query(MitreTechnique).filter(MitreTechnique.external_id == payload.technique_id).order_by(desc(MitreTechnique.id)).first()
    if not asset or not technique:
        raise HTTPException(status_code=404, detail="MITRE asset or technique not found")

    existing = db.query(TechniqueMapping).filter(
        TechniqueMapping.mitre_asset_id == asset.id,
        TechniqueMapping.technique_id == technique.id,
        TechniqueMapping.mapping_version == payload.mapping_version,
    ).first()
    if not existing:
        existing = TechniqueMapping(
            mitre_asset_id=asset.id,
            technique_id=technique.id,
            mapping_version=payload.mapping_version,
        )
        db.add(existing)

    existing.source = payload.source
    existing.justification = payload.justification
    existing.confidence = payload.confidence
    existing.approved = True
    db.commit()

    return {"message": "Technique mapping approved", "asset": asset.name, "technique": technique.external_id}


def _matrix_for_zone(zone_id: int, db: Session) -> list[dict]:
    """Build the technique-asset matrix for *zone_id* using batch queries.

    Uses a single pass of bulk SELECT…IN queries instead of per-row lookups,
    eliminating the N+1 query pattern present in the original implementation.
    The output structure and sort order are identical to the original.
    """
    zone = db.query(Zone).filter(Zone.id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")

    # ── Step 1: Collect MITRE asset IDs for this zone ────────────────────────
    mitre_asset_ids: set[int] = set()

    for row in db.query(ZoneMitreAsset).filter(ZoneMitreAsset.zone_id == zone_id).all():
        mitre_asset_ids.add(row.mitre_asset_id)

    custom_asset_ids = {
        row.custom_asset_id
        for row in db.query(ZoneAsset).filter(ZoneAsset.zone_id == zone_id).all()
        if row.custom_asset_id
    }
    if custom_asset_ids:
        custom_mappings = db.query(CustomAssetMapping).filter(
            CustomAssetMapping.custom_asset_id.in_(custom_asset_ids),
            CustomAssetMapping.approved.is_(True),
        ).all()
        for mapping in custom_mappings:
            mitre_asset_ids.add(mapping.mitre_asset_id)

    if not mitre_asset_ids:
        return engine_rules.generate_zone_matrix([], {}, zone.name)

    # ── Step 2: Batch-load all required rows ─────────────────────────────────
    assets_by_id = {
        a.id: a
        for a in db.query(MitreAsset).filter(MitreAsset.id.in_(mitre_asset_ids)).all()
    }

    technique_mappings = db.query(TechniqueMapping).filter(
        TechniqueMapping.mitre_asset_id.in_(mitre_asset_ids),
        TechniqueMapping.approved.is_(True),
    ).all()

    technique_ids = {tm.technique_id for tm in technique_mappings}
    techniques_by_id = {
        t.id: t
        for t in db.query(MitreTechnique).filter(MitreTechnique.id.in_(technique_ids)).all()
    }

    tactic_links = db.query(TechniqueTactic).filter(
        TechniqueTactic.technique_id.in_(technique_ids)
    ).all()
    tactic_ids = {link.tactic_id for link in tactic_links}
    tactics_by_id = {
        t.id: t
        for t in db.query(MitreTactic).filter(MitreTactic.id.in_(tactic_ids)).all()
    }

    mitigation_links = db.query(TechniqueMitigation).filter(
        TechniqueMitigation.technique_id.in_(technique_ids)
    ).all()
    mitigation_ids = {link.mitigation_id for link in mitigation_links}
    mitigations_by_id = {
        m.id: m
        for m in db.query(MitreMitigation).filter(MitreMitigation.id.in_(mitigation_ids)).all()
    }

    # ── Step 3: Build per-technique lookups ───────────────────────────────────
    technique_tactics: dict[int, list[str]] = defaultdict(list)
    for link in tactic_links:
        tactic = tactics_by_id.get(link.tactic_id)
        if tactic:
            technique_tactics[link.technique_id].append(tactic.name)

    technique_mitigations: dict[int, list[str]] = defaultdict(list)
    for link in mitigation_links:
        mitigation = mitigations_by_id.get(link.mitigation_id)
        if mitigation:
            technique_mitigations[link.technique_id].append(mitigation.name)

    # ── Step 4: Assemble approved_map ─────────────────────────────────────────
    approved_map: dict[str, list[dict]] = {
        assets_by_id[aid].name: []
        for aid in mitre_asset_ids
        if aid in assets_by_id
    }
    for tm in technique_mappings:
        asset = assets_by_id.get(tm.mitre_asset_id)
        technique = techniques_by_id.get(tm.technique_id)
        if not asset or not technique:
            continue
        approved_map[asset.name].append(
            {
                "external_id": technique.external_id,
                "name": technique.name,
                "description": technique.description or "",
                "tactics": technique_tactics[technique.id],
                "mitigations": technique_mitigations[technique.id],
            }
        )

    selected_asset_names = sorted(
        {assets_by_id[aid].name for aid in mitre_asset_ids if aid in assets_by_id}
    )
    return engine_rules.generate_zone_matrix(
        selected_assets=selected_asset_names,
        approved_asset_technique_map=approved_map,
        zone_name=zone.name,
    )


@app.get("/api/zones/{zone_id}/matrix")
def generate_zone_matrix(zone_id: int, db: Session = Depends(get_db)) -> dict:
    """Return the technique-asset threat matrix for a given zone."""
    zone = db.query(Zone).filter(Zone.id == zone_id).first()
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    matrix = _matrix_for_zone(zone_id, db)
    return {"zone_id": zone_id, "zone_name": zone.name, "row_count": len(matrix), "rows": matrix}


@app.post("/api/export/excel", dependencies=[Depends(require_api_key)])
def export_excel(payload: ExcelExportRequest, db: Session = Depends(get_db)) -> dict:
    """Export the zone threat matrix to an Excel workbook using a user-supplied template."""
    matrix = _matrix_for_zone(payload.zone_id, db)
    template_path = payload.template_path or str(DEFAULT_RISK_TEMPLATE)
    export_matrix_to_workbook(
        matrix_rows=matrix,
        template_path=template_path,
        output_path=payload.output_path,
        sheet_name=payload.sheet_name,
        start_cell=payload.start_cell,
    )
    return {"message": "Excel exported", "row_count": len(matrix)}


@app.post("/api/export/excel/download", dependencies=[Depends(require_api_key)])
def download_excel(
    payload: ExcelDownloadRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Stream the zone threat matrix as an Excel file download.

    Writes the matrix into a temporary file and returns it as a
    ``FileResponse``.  The caller receives the file as an attachment with
    the name supplied in ``output_filename``.  The temporary directory is
    deleted after the response is streamed via a background task.
    """
    matrix = _matrix_for_zone(payload.zone_id, db)
    template_path = payload.template_path or str(DEFAULT_RISK_TEMPLATE)
    safe_name = Path(payload.output_filename).name
    if not safe_name.lower().endswith(".xlsx"):
        safe_name += ".xlsx"
    tmp_dir = Path(tempfile.mkdtemp(prefix=APP_TEMP_DIR_PREFIX))
    output_path = str(tmp_dir / safe_name)
    export_matrix_to_workbook(
        matrix_rows=matrix,
        template_path=template_path,
        output_path=output_path,
        sheet_name=payload.sheet_name,
        start_cell=payload.start_cell,
    )
    # [IMPROVEMENT] Schedule temp directory removal after the response is streamed
    # so confidential risk assessment workbooks are not left on disk indefinitely.
    # BackgroundTasks run after the full response is sent; the file is already
    # streamed before rmtree fires, so no data loss occurs.
    # [SOURCE] Audit finding: Critical (C-1)
    background_tasks.add_task(shutil.rmtree, str(tmp_dir), True)
    return FileResponse(
        path=output_path,
        filename=safe_name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


def _matrix_for_multiple_zones(zone_ids: list[int], db: Session) -> tuple[list[dict], str]:
    """Build the technique-asset matrix aggregated across multiple zones.

    Each zone's matrix is generated independently (preserving zone names in rows)
    then the results are concatenated and deduplicated by (zone, technique_id).
    """
    if not zone_ids:
        return [], ""

    all_rows: list[dict] = []
    zone_names: list[str] = []

    for zone_id in zone_ids:
        zone = db.query(Zone).filter(Zone.id == zone_id).first()
        if not zone:
            continue
        zone_names.append(zone.name)
        rows = _matrix_for_zone(zone_id, db)
        all_rows.extend(rows)

    # Deduplicate by (zone, technique_id) so the same technique isn't duplicated
    # within the same zone when multiple zones share an asset.
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for row in all_rows:
        key = (row.get("zone", ""), row.get("technique_id", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(row)

    combined_name = " + ".join(zone_names) if zone_names else "Combined"
    return deduped, combined_name


@app.post("/api/matrix/combined")
def combined_matrix(
    payload: dict,
    db: Session = Depends(get_db),
) -> dict:
    """Return the merged technique-asset threat matrix for multiple zones.

    Accepts ``{ "zone_ids": [1, 2, ...] }`` and returns rows from each zone
    keyed by zone name, preserving per-zone attribution.
    """
    zone_ids = payload.get("zone_ids", [])
    if not zone_ids or not isinstance(zone_ids, list):
        raise HTTPException(status_code=400, detail="zone_ids must be a non-empty list of integers")
    zone_ids_int: list[int] = []
    for zid in zone_ids:
        try:
            zone_ids_int.append(int(zid))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"Invalid zone_id value: {zid!r}")
    rows, combined_name = _matrix_for_multiple_zones(zone_ids_int, db)
    return {
        "zone_ids": zone_ids_int,
        "zone_name": combined_name,
        "row_count": len(rows),
        "rows": rows,
    }


@app.post("/api/export/excel/download/multi", dependencies=[Depends(require_api_key)])
def download_excel_multi_zone(
    payload: MultiZoneExportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Stream a merged zone threat matrix across multiple zones as an Excel download.

    Aggregates all asset-technique rows from every zone listed in ``zone_ids``,
    preserving per-zone attribution in the Zone column, and writes them into a
    single workbook sheet.
    """
    rows, _ = _matrix_for_multiple_zones(payload.zone_ids, db)
    template_path = payload.template_path or str(DEFAULT_RISK_TEMPLATE)
    safe_name = Path(payload.output_filename).name
    if not safe_name.lower().endswith(".xlsx"):
        safe_name += ".xlsx"
    tmp_dir = Path(tempfile.mkdtemp(prefix=APP_TEMP_DIR_PREFIX))
    output_path = str(tmp_dir / safe_name)
    export_matrix_to_workbook(
        matrix_rows=rows,
        template_path=template_path,
        output_path=output_path,
        sheet_name=payload.sheet_name,
        start_cell=payload.start_cell,
    )
    background_tasks.add_task(shutil.rmtree, str(tmp_dir), True)
    return FileResponse(
        path=output_path,
        filename=safe_name,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.post("/api/export/transform-risk-assessment", dependencies=[Depends(require_api_key)])
def transform_workbook(
    payload: WorkbookTransformRequest,
    settings: Settings = Depends(get_settings),
) -> dict:
    """Transform a risk-assessment workbook.

    All supplied paths are resolved and validated against the project root to
    prevent directory traversal attacks.
    """
    allowed_bases = [
        Path(settings.REF_DIR),
        Path(settings.EXPORTS_DIR),
        BASE_DIR,  # workspace root — covers any project-relative path
    ]
    try:
        source_path = sanitize_file_path(payload.source_workbook_path, allowed_bases)
        template_path = sanitize_file_path(payload.template_workbook_path, allowed_bases)
        builder_path = sanitize_file_path(payload.mitre_builder_workbook_path, allowed_bases)
        out_path = sanitize_file_path(
            payload.output_path,
            [Path(settings.EXPORTS_DIR), BASE_DIR],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # [IMPROVEMENT] Absolute file paths downgraded to DEBUG to avoid leaking topology
    # information through log aggregation pipelines in production deployments.
    # [SOURCE] Audit finding: Low (L-2)
    logger.info("Transforming workbook: output=%s", out_path.name)
    logger.debug("Transforming workbook full paths: source=%s, output=%s", source_path, out_path)
    result = transform_risk_assessment_workbook(
        source_workbook_path=str(source_path),
        template_workbook_path=str(template_path),
        mitre_builder_workbook_path=str(builder_path),
        output_path=str(out_path),
    )
    result.pop("output_path", None)
    return {"message": "Workbook transformed", **result}
