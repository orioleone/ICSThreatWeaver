"""Centralised application settings loaded from environment variables and .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root — two levels above this file (backend/app/config.py → project root)
BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """All tuneable knobs for ICS ThreatWeaver.

    Values are read from environment variables (case-insensitive) and, as a
    fallback, from a ``.env`` file located in the project root.  Defaults are
    safe for local development; production deployments must override at least
    ``API_KEY`` and ``CORS_ORIGINS``.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'ics_threatweaver.db'}"

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    # [RESOLVED] Unified to the same URL as DEFAULT_MITRE_ICS_URL in mitre_parser.py.
    # [SOURCE] Audit finding: High (H-1)
    # Previously config.py pointed to "mitre/cti" while mitre_parser.py used
    # "mitre-attack/attack-stix-data" — two different GitHub repositories that
    # can diverge, causing technique mismatches between the DB and enrichment pipeline.
    # [SOURCE] Audit finding: High (H-1)
    MITRE_ICS_URL: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    )
    # Hosts that are allowed as a target for the MITRE import URL (SSRF guard).
    # Extend this list when mirroring the STIX bundle on an internal server.
    MITRE_ALLOWED_HOSTS: list[str] = [
        "raw.githubusercontent.com",
        "github.com",
    ]

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Space-separated origins OR a JSON list, e.g.
    #   CORS_ORIGINS=http://localhost:8000 http://127.0.0.1:8000
    # Set to ["*"] only in local-only, non-networked deployments.
    CORS_ORIGINS: list[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # ── Authentication ────────────────────────────────────────────────────────
    # When set to a non-empty string all /api/* endpoints require the
    # ``X-API-Key`` request header with this value.
    # Leave empty ("") to disable authentication (development default).
    API_KEY: str = ""

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = 100   # max requests per window
    RATE_LIMIT_WINDOW: int = 60      # window size in seconds

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    # ── File-system base directories ──────────────────────────────────────────
    # These are used by the path-traversal guard in the security module.
    # Only files under these directories (or their sub-trees) can be read or
    # written by the API.
    REF_DIR: str = str(BASE_DIR / "docs")
    EXPORTS_DIR: str = str(BASE_DIR / "exports")


@lru_cache
def get_settings() -> Settings:
    """Return a cached ``Settings`` singleton.

    Call ``get_settings.cache_clear()`` in tests to force re-reading .env.
    """
    return Settings()
