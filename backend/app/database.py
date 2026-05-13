from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import get_settings

_settings = get_settings()
_db_url = _settings.DATABASE_URL
# SQLite requires check_same_thread=False; other drivers do not support it.
_connect_args = {"check_same_thread": False} if _db_url.startswith("sqlite") else {}

engine = create_engine(_db_url, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def ensure_schema_upgrades() -> None:
    """Apply incremental schema migrations to an existing database.

    Checks for missing columns that were added in later versions and adds them
    inline using ``ALTER TABLE``.  Also enforces the STIX-vs-keyword-rule
    invariant: any rule-sourced technique mapping that overlaps with a
    STIX-sourced mapping for the same asset is purged so the ATT&CK ICS matrix
    remains authoritative.

    Safe to call on every startup — no-ops when the schema is already current.
    """
    inspector = inspect(engine)
    table_names = inspector.get_table_names()

    with engine.begin() as connection:
        if "mitre_assets" in table_names:
            mitre_columns = {column["name"] for column in inspector.get_columns("mitre_assets")}
            if "external_id" not in mitre_columns:
                connection.execute(text("ALTER TABLE mitre_assets ADD COLUMN external_id VARCHAR(50)"))

        if "zone_assets" in table_names:
            zone_columns = {column["name"] for column in inspector.get_columns("zone_assets")}
            if "mitre_asset_id" not in zone_columns:
                connection.execute(text("ALTER TABLE zone_assets ADD COLUMN mitre_asset_id INTEGER"))

        # Invariant: if STIX defines any techniques for an asset, that asset's
        # mapping is authoritative and complete. Keyword rule rows must never
        # exist for any asset that STIX covers, regardless of which technique.
        # Purge all violations so every asset count matches the ATT&CK ICS matrix.
        if "technique_mappings" in table_names:
            connection.execute(text(
                "DELETE FROM technique_mappings "
                "WHERE source = 'rule' "
                "AND mitre_asset_id IN ("
                "  SELECT DISTINCT mitre_asset_id FROM technique_mappings WHERE source = 'stix'"
                ")"
            ))


def get_db():
    """Yield a SQLAlchemy database session and ensure it is closed afterwards.

    Intended for use as a FastAPI dependency via ``Depends(get_db)``.
    The session is always closed in the ``finally`` block regardless of whether
    the request succeeds or raises an exception.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
