from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base

# [IMPROVEMENT] Single source of truth for the default mapping version string.
# Import this constant in main.py and mitre_parser.py instead of using "v1" literals.
# [SOURCE] Audit finding: Low (L-1)
DEFAULT_MAPPING_VERSION: str = "v1"


class DatasetVersion(Base):
    __tablename__ = "dataset_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    version_tag: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    source_url: Mapped[str] = mapped_column(String(500))
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # [RESOLVED] Use timezone-aware datetime.now() instead of deprecated utcnow().
    # [SOURCE] Audit finding: High (H-4)
    imported_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class MitreTactic(Base):
    __tablename__ = "mitre_tactics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), index=True)
    external_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    shortname: Mapped[str] = mapped_column(String(100), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_version_id: Mapped[int] = mapped_column(ForeignKey("dataset_versions.id"))


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"
    __table_args__ = (UniqueConstraint("external_id", "dataset_version_id", name="uq_technique_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), index=True)
    external_id: Mapped[str] = mapped_column(String(50), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    modified: Mapped[str | None] = mapped_column(String(100), nullable=True)
    platforms: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)
    is_modified: Mapped[bool] = mapped_column(Boolean, default=False)
    dataset_version_id: Mapped[int] = mapped_column(ForeignKey("dataset_versions.id"))


class MitreMitigation(Base):
    __tablename__ = "mitre_mitigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stix_id: Mapped[str] = mapped_column(String(100), index=True)
    external_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_version_id: Mapped[int] = mapped_column(ForeignKey("dataset_versions.id"))


class TechniqueTactic(Base):
    __tablename__ = "technique_tactics"
    __table_args__ = (UniqueConstraint("technique_id", "tactic_id", name="uq_technique_tactic"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique_id: Mapped[int] = mapped_column(ForeignKey("mitre_techniques.id"))
    tactic_id: Mapped[int] = mapped_column(ForeignKey("mitre_tactics.id"))


class TechniqueMitigation(Base):
    __tablename__ = "technique_mitigations"
    __table_args__ = (UniqueConstraint("technique_id", "mitigation_id", name="uq_technique_mitigation"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique_id: Mapped[int] = mapped_column(ForeignKey("mitre_techniques.id"))
    mitigation_id: Mapped[int] = mapped_column(ForeignKey("mitre_mitigations.id"))


class MitreAsset(Base):
    __tablename__ = "mitre_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    external_id: Mapped[str | None] = mapped_column(String(50), unique=True, index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="MITRE")


class CustomAsset(Base):
    __tablename__ = "custom_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class CustomAssetMapping(Base):
    __tablename__ = "custom_asset_mappings"
    __table_args__ = (
        UniqueConstraint("custom_asset_id", "mitre_asset_id", "mapping_version", name="uq_custom_mitre_mapping"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    custom_asset_id: Mapped[int] = mapped_column(ForeignKey("custom_assets.id"))
    mitre_asset_id: Mapped[int] = mapped_column(ForeignKey("mitre_assets.id"))
    mapping_version: Mapped[str] = mapped_column(String(50), default="v1")
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=True)


class TechniqueMapping(Base):
    __tablename__ = "technique_mappings"
    __table_args__ = (
        UniqueConstraint("mitre_asset_id", "technique_id", "mapping_version", name="uq_asset_technique_mapping"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mitre_asset_id: Mapped[int] = mapped_column(ForeignKey("mitre_assets.id"))
    technique_id: Mapped[int] = mapped_column(ForeignKey("mitre_techniques.id"))
    mapping_version: Mapped[str] = mapped_column(String(50), default="v1")
    source: Mapped[str] = mapped_column(String(50), default="rule")
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.75)
    approved: Mapped[bool] = mapped_column(Boolean, default=True)


class Zone(Base):
    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class ZoneAsset(Base):
    __tablename__ = "zone_assets"
    __table_args__ = (UniqueConstraint("zone_id", "custom_asset_id", name="uq_zone_custom_asset"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id"))
    custom_asset_id: Mapped[int | None] = mapped_column(ForeignKey("custom_assets.id"), nullable=True)


class ZoneMitreAsset(Base):
    __tablename__ = "zone_mitre_assets"
    __table_args__ = (UniqueConstraint("zone_id", "mitre_asset_id", name="uq_zone_mitre_asset_selection"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    zone_id: Mapped[int] = mapped_column(ForeignKey("zones.id"))
    mitre_asset_id: Mapped[int] = mapped_column(ForeignKey("mitre_assets.id"))
