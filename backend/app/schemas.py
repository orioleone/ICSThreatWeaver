from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from .models import DEFAULT_MAPPING_VERSION
from .security import UNSAFE_CHARS_RE

# [RESOLVED] Excel sheet-name validation constants (M-4).
# [SOURCE] Audit finding: Medium (M-4)
# Excel limits sheet names to 31 chars and forbids these characters.
_SHEET_NAME_FORBIDDEN_RE = re.compile(r"[:\\/*?\[\]]")
_MAX_SHEET_NAME_LEN = 31

# [RESOLVED] Valid Excel cell reference pattern: 1–3 uppercase letters + row ≥ 1.
# [SOURCE] Audit finding: Medium (M-4)
_CELL_REF_RE = re.compile(r"^[A-Z]{1,3}[1-9]\d{0,6}$", re.IGNORECASE)


def _check_path_chars(v: str) -> str:
    """Shared validator: reject strings with unsafe control characters."""
    if v and UNSAFE_CHARS_RE.search(v):
        raise ValueError("Path contains unsafe control characters.")
    return v


class MitreImportRequest(BaseModel):
    version_tag: str | None = None
    # [IMPROVEMENT] URL aligned with DEFAULT_MITRE_ICS_URL in mitre_parser.py.
    # Previously schemas.py defaulted to the "mitre/cti" repo while the parser
    # used "mitre-attack/attack-stix-data", causing divergent data sources.
    # [SOURCE] Audit finding: High (H-1)
    source_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    )

    @field_validator("source_url")
    @classmethod
    def source_url_must_be_https(cls, v: str) -> str:
        """Reject non-HTTPS URLs to reduce the SSRF attack surface."""
        try:
            parsed = urlparse(v)
        except Exception as exc:
            raise ValueError("Malformed URL.") from exc
        if parsed.scheme not in ("https",):
            raise ValueError("source_url must use HTTPS.")
        if not parsed.hostname:
            raise ValueError("source_url must contain a valid hostname.")
        return v


class CustomAssetCreate(BaseModel):
    name: str
    vendor: str | None = None
    model: str | None = None
    description: str | None = None


class CustomAssetMapRequest(BaseModel):
    mitre_asset_name: str
    justification: str = Field(default="Mapped by analyst review.")
    # [RESOLVED] Using DEFAULT_MAPPING_VERSION constant imported from models.py.
    # [SOURCE] Audit finding: Low (L-1)
    mapping_version: str = DEFAULT_MAPPING_VERSION


class ZoneCreate(BaseModel):
    name: str
    description: str | None = None


class ZoneAssetSelectionRequest(BaseModel):
    mitre_asset_ids: list[str] = Field(default_factory=list)
    replace_existing: bool = True


class TechniqueSuggestionRequest(BaseModel):
    name: str
    description: str = ""


class TechniqueMappingApprovalRequest(BaseModel):
    mitre_asset_name: str
    technique_id: str
    source: str = "manual"
    justification: str = "Approved by analyst."
    confidence: float = 0.9
    # [RESOLVED] Using DEFAULT_MAPPING_VERSION constant imported from models.py.
    # [SOURCE] Audit finding: Low (L-1)
    mapping_version: str = DEFAULT_MAPPING_VERSION


class ExcelExportRequest(BaseModel):
    zone_id: int
    template_path: str = ""
    output_path: str
    sheet_name: str = "Assessment Matrix"
    start_cell: str = "A2"

    @field_validator("template_path", "output_path")
    @classmethod
    def validate_path_chars(cls, v: str) -> str:
        return _check_path_chars(v)

    # [IMPROVEMENT] Validate sheet_name length and forbidden characters so openpyxl
    # never raises an obscure InvalidSheetNameException at export time.
    # [SOURCE] Audit finding: Medium (M-4)
    @field_validator("sheet_name")
    @classmethod
    def validate_sheet_name(cls, v: str) -> str:
        # [RESOLVED] Validate sheet_name length and forbidden characters to prevent
        # openpyxl errors. Excel limits sheet names to 31 chars and forbids \ / : * ? [ ]
        # [SOURCE] Audit finding: Medium (M-4)
        if not v or not v.strip():
            raise ValueError("sheet_name must not be empty.")
        if len(v) > _MAX_SHEET_NAME_LEN:
            raise ValueError(f"sheet_name must be ≤ {_MAX_SHEET_NAME_LEN} characters (Excel limit).")
        if _SHEET_NAME_FORBIDDEN_RE.search(v):
            raise ValueError(r"sheet_name contains a character forbidden by Excel: \ / : * ? [ ]")
        return v

    # [RESOLVED] Validate start_cell is a well-formed Excel cell reference (e.g. "A2").
    # Invalid values would silently produce garbage column/row indices.
    # [SOURCE] Audit finding: Medium (M-4)
    @field_validator("start_cell")
    @classmethod
    def validate_start_cell(cls, v: str) -> str:
        if not _CELL_REF_RE.match(v):
            raise ValueError("start_cell must be a valid Excel cell reference, e.g. 'A2'.")
        return v.upper()


class ExcelDownloadRequest(BaseModel):
    zone_id: int
    template_path: str = ""
    output_filename: str = "ICS_Risk_Assessment.xlsx"
    sheet_name: str = "Assessment Matrix"
    start_cell: str = "A2"

    @field_validator("output_filename")
    @classmethod
    def sanitize_filename(cls, v: str) -> str:
        """Strip any directory component — accept filenames only."""
        name = Path(v).name
        if not name:
            raise ValueError("output_filename must not be empty.")
        _check_path_chars(name)
        return name

    @field_validator("template_path")
    @classmethod
    def validate_template_path_chars(cls, v: str) -> str:
        return _check_path_chars(v)

    @field_validator("sheet_name")
    @classmethod
    def validate_sheet_name(cls, v: str) -> str:
        # [RESOLVED] Validate sheet_name length and forbidden characters to prevent
        # openpyxl errors. Excel limits sheet names to 31 chars and forbids \ / : * ? [ ]
        # [SOURCE] Audit finding: Medium (M-4)
        if not v or not v.strip():
            raise ValueError("sheet_name must not be empty.")
        if len(v) > _MAX_SHEET_NAME_LEN:
            raise ValueError(f"sheet_name must be ≤ {_MAX_SHEET_NAME_LEN} characters (Excel limit).")
        if _SHEET_NAME_FORBIDDEN_RE.search(v):
            raise ValueError(r"sheet_name contains a character forbidden by Excel: \ / : * ? [ ]")
        return v

    # [RESOLVED] Validate start_cell is a well-formed Excel cell reference (e.g. "A2").
    # Invalid values would silently produce garbage column/row indices.
    # [SOURCE] Audit finding: Medium (M-4)
    @field_validator("start_cell")
    @classmethod
    def validate_start_cell(cls, v: str) -> str:
        if not _CELL_REF_RE.match(v):
            raise ValueError("start_cell must be a valid Excel cell reference, e.g. 'A2'.")
        return v.upper()


class MultiZoneExportRequest(BaseModel):
    zone_ids: list[int] = Field(default_factory=list, min_length=1)
    template_path: str = ""
    output_filename: str = "ICS_Risk_Assessment_MultiZone.xlsx"
    sheet_name: str = "Assessment Matrix"
    start_cell: str = "A2"

    @field_validator("output_filename")
    @classmethod
    def sanitize_filename(cls, v: str) -> str:
        name = Path(v).name
        if not name:
            raise ValueError("output_filename must not be empty.")
        _check_path_chars(name)
        return name

    @field_validator("template_path")
    @classmethod
    def validate_template_path_chars(cls, v: str) -> str:
        return _check_path_chars(v)

    @field_validator("sheet_name")
    @classmethod
    def validate_sheet_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("sheet_name must not be empty.")
        if len(v) > _MAX_SHEET_NAME_LEN:
            raise ValueError(f"sheet_name must be ≤ {_MAX_SHEET_NAME_LEN} characters (Excel limit).")
        if _SHEET_NAME_FORBIDDEN_RE.search(v):
            raise ValueError(r"sheet_name contains a character forbidden by Excel: \ / : * ? [ ]")
        return v

    @field_validator("start_cell")
    @classmethod
    def validate_start_cell(cls, v: str) -> str:
        if not _CELL_REF_RE.match(v):
            raise ValueError("start_cell must be a valid Excel cell reference, e.g. 'A2'.")
        return v.upper()


class WorkbookTransformRequest(BaseModel):
    source_workbook_path: str
    template_workbook_path: str
    mitre_builder_workbook_path: str
    output_path: str

    @field_validator(
        "source_workbook_path",
        "template_workbook_path",
        "mitre_builder_workbook_path",
        "output_path",
    )
    @classmethod
    def validate_workbook_path_chars(cls, v: str) -> str:
        return _check_path_chars(v)
