from __future__ import annotations

import os
import time
from pathlib import Path

import requests

from backend.app.config import get_settings
from backend.app.main import APP_TEMP_DIR_PREFIX, _cleanup_old_temp_files, import_mitre_dataset
from backend.app.schemas import MitreImportRequest
from backend.app.mitre_parser import download_mitre_ics_bundle


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {"type": "bundle", "objects": []}

    def raise_for_status(self):
        if self.status_code >= 400:
            err = requests.HTTPError(f"HTTP {self.status_code}")
            err.response = self
            raise err
        return None

    def json(self):
        return self._payload


def test_download_mitre_bundle_retries_transient_failures(monkeypatch):
    calls = {"count": 0}

    def fake_get(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] < 3:
            raise requests.Timeout("transient timeout")
        return _FakeResponse()

    monkeypatch.setattr("backend.app.mitre_parser.requests.get", fake_get)
    monkeypatch.setattr("backend.app.mitre_parser.time.sleep", lambda *_: None)

    bundle = download_mitre_ics_bundle("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json")

    assert calls["count"] == 3
    assert bundle["type"] == "bundle"


def test_download_mitre_bundle_retries_transient_http_status(monkeypatch):
    calls = {"count": 0}

    def fake_get(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] < 3:
            return _FakeResponse(status_code=503)
        return _FakeResponse(status_code=200, payload={"type": "bundle", "objects": [{"id": "ok"}]})

    monkeypatch.setattr("backend.app.mitre_parser.requests.get", fake_get)
    monkeypatch.setattr("backend.app.mitre_parser.time.sleep", lambda *_: None)

    bundle = download_mitre_ics_bundle("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json")

    assert calls["count"] == 3
    assert bundle["objects"] == [{"id": "ok"}]


def test_import_endpoint_returns_502_for_fetch_failures(monkeypatch):
    payload = MitreImportRequest(
        source_url="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    )

    def failing_download(*args, **kwargs):
        raise requests.Timeout("network unreachable")

    monkeypatch.setattr("backend.app.main.download_mitre_ics_bundle", failing_download)

    settings = get_settings()

    try:
        import_mitre_dataset(payload=payload, db=None, settings=settings)
        assert False, "Expected HTTPException"
    except Exception as exc:
        from fastapi import HTTPException

        assert isinstance(exc, HTTPException)
        assert exc.status_code == 502
        assert "MITRE ATT&CK for ICS dataset" in str(exc.detail)


def test_temp_cleanup_only_removes_app_owned_old_dirs(tmp_path: Path, monkeypatch):
    temp_root = tmp_path / "temp-root"
    temp_root.mkdir()

    old_app_dir = temp_root / f"{APP_TEMP_DIR_PREFIX}old"
    old_app_dir.mkdir()
    new_app_dir = temp_root / f"{APP_TEMP_DIR_PREFIX}new"
    new_app_dir.mkdir()
    old_foreign_dir = temp_root / "other-app-old"
    old_foreign_dir.mkdir()

    now = time.time()
    old_ts = now - (48 * 3600)
    new_ts = now - (1 * 3600)
    for p, ts in ((old_app_dir, old_ts), (new_app_dir, new_ts), (old_foreign_dir, old_ts)):
        os.utime(p, (ts, ts))

    monkeypatch.setattr("backend.app.main.tempfile.gettempdir", lambda: str(temp_root))

    _cleanup_old_temp_files(max_age_hours=24)

    assert not old_app_dir.exists()
    assert new_app_dir.exists()
    assert old_foreign_dir.exists()
