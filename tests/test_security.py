"""Security tests: middleware, validators, auth, and path/URL guards."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import get_settings
from backend.app.security import sanitize_file_path, validate_https_url


# ---------------------------------------------------------------------------
# Security utility unit tests
# ---------------------------------------------------------------------------


class TestValidateHttpsUrl:
    def test_accepts_valid_https_url(self):
        url = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
        assert validate_https_url(url, ["raw.githubusercontent.com"]) == url

    def test_rejects_http_url(self):
        with pytest.raises(ValueError, match="HTTPS"):
            validate_https_url("http://example.com/data.json", ["example.com"])

    def test_rejects_ftp_url(self):
        with pytest.raises(ValueError, match="HTTPS"):
            validate_https_url("ftp://example.com/data.json", ["example.com"])

    def test_rejects_disallowed_host(self):
        with pytest.raises(ValueError, match="allowed list"):
            validate_https_url(
                "https://evil.example.com/pwn.json",
                ["raw.githubusercontent.com"],
            )

    def test_accepts_subdomain_of_allowed_host(self):
        url = "https://sub.raw.githubusercontent.com/file.json"
        assert validate_https_url(url, ["raw.githubusercontent.com"]) == url

    def test_rejects_url_without_hostname(self):
        with pytest.raises(ValueError):
            validate_https_url("https:///path", ["raw.githubusercontent.com"])


class TestSanitizeFilePath:
    def test_accepts_path_inside_allowed_base(self, tmp_path: Path):
        target = tmp_path / "subdir" / "file.xlsx"
        resolved = sanitize_file_path(str(target), [tmp_path])
        assert resolved == target.resolve()

    def test_rejects_path_outside_allowed_base(self, tmp_path: Path):
        other_dir = tmp_path.parent  # one level up — not in allowed_bases
        with pytest.raises(ValueError, match="outside the allowed"):
            sanitize_file_path(str(other_dir / "secret.txt"), [tmp_path])

    def test_rejects_null_byte_in_path(self, tmp_path: Path):
        with pytest.raises(ValueError, match="unsafe"):
            sanitize_file_path(str(tmp_path) + "\x00evil", [tmp_path])

    def test_rejects_crlf_in_path(self, tmp_path: Path):
        with pytest.raises(ValueError, match="unsafe"):
            sanitize_file_path(str(tmp_path) + "\r\nevil", [tmp_path])

    def test_rejects_empty_path(self, tmp_path: Path):
        with pytest.raises(ValueError, match="empty"):
            sanitize_file_path("", [tmp_path])

    def test_path_traversal_attempt_is_rejected(self, tmp_path: Path):
        traversal = str(tmp_path / "subdir" / ".." / ".." / "etc" / "passwd")
        with pytest.raises(ValueError, match="outside the allowed"):
            sanitize_file_path(traversal, [tmp_path])


# ---------------------------------------------------------------------------
# Schema validators
# ---------------------------------------------------------------------------


class TestSchemaValidators:
    def test_mitre_import_request_rejects_http_url(self):
        from pydantic import ValidationError
        from backend.app.schemas import MitreImportRequest

        with pytest.raises(ValidationError, match="HTTPS"):
            MitreImportRequest(source_url="http://evil.example.com/data.json")

    def test_mitre_import_request_accepts_https_url(self):
        from backend.app.schemas import MitreImportRequest

        req = MitreImportRequest(source_url="https://example.com/data.json")
        assert req.source_url.startswith("https://")

    def test_excel_download_strips_path_from_filename(self):
        from backend.app.schemas import ExcelDownloadRequest

        req = ExcelDownloadRequest(zone_id=1, output_filename="../../etc/passwd")
        assert req.output_filename == "passwd"

    def test_excel_export_rejects_null_byte_in_path(self):
        from pydantic import ValidationError
        from backend.app.schemas import ExcelExportRequest

        with pytest.raises(ValidationError, match="unsafe"):
            ExcelExportRequest(zone_id=1, output_path="/tmp/out\x00.xlsx")

    def test_workbook_transform_rejects_crlf_in_path(self):
        from pydantic import ValidationError
        from backend.app.schemas import WorkbookTransformRequest

        with pytest.raises(ValidationError, match="unsafe"):
            WorkbookTransformRequest(
                source_workbook_path="/tmp/source\r\nevil.xlsx",
                template_workbook_path="/tmp/tmpl.xlsx",
                mitre_builder_workbook_path="/tmp/builder.xlsm",
                output_path="/tmp/out.xlsx",
            )


# ---------------------------------------------------------------------------
# API middleware: security headers and rate limiting
# ---------------------------------------------------------------------------


@pytest.fixture()
def client():
    """TestClient backed by an isolated in-memory database — never touches production DB."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from backend.app.database import Base, get_db
    from backend.app.main import app

    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app, raise_server_exceptions=True)
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


class TestSecurityHeaders:
    def test_health_endpoint_has_security_headers(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-xss-protection") == "1; mode=block"
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


class TestApiKeyAuth:
    def test_write_endpoint_allowed_without_key_when_auth_disabled(self, client: TestClient):
        """When API_KEY is empty, write endpoints must be reachable."""
        resp = client.post("/api/zones", json={"name": "Test Zone"})
        # May succeed (201/200) or fail with 400 for other reasons, but never 401.
        assert resp.status_code != 401

    def test_write_endpoint_blocked_without_key_when_auth_enabled(self, monkeypatch):
        """When API_KEY is set, endpoints must return 401 without the header."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from backend.app.database import Base, get_db

        monkeypatch.setenv("API_KEY", "super-secret-key-abc123")
        get_settings.cache_clear()
        from backend.app.main import app

        test_engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=test_engine)
        TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

        def override_get_db():
            db = TestSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        test_client = TestClient(app, raise_server_exceptions=False)
        resp = test_client.post("/api/zones", json={"name": "Blocked Zone"})
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()
        get_settings.cache_clear()
        assert resp.status_code == 401

    def test_write_endpoint_allowed_with_correct_key(self, tmp_path: Path, monkeypatch):
        """When API_KEY is set, the correct key must be accepted."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from backend.app.database import Base, get_db

        monkeypatch.setenv("API_KEY", "super-secret-key-abc123")
        get_settings.cache_clear()
        from backend.app.main import app

        test_engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=test_engine)
        TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

        def override_get_db():
            db = TestSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        test_client = TestClient(app, raise_server_exceptions=False)
        resp = test_client.post(
            "/api/zones",
            json={"name": "Auth Zone"},
            headers={"X-API-Key": "super-secret-key-abc123"},
        )
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()
        get_settings.cache_clear()
        assert resp.status_code in (200, 400)  # 400 = duplicate, but NOT 401
        assert resp.status_code != 401


class TestRateLimiting:
    def test_rate_limiter_blocks_after_limit_exceeded(self):
        """The RateLimitMiddleware must return 429 after the configured limit is hit."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from backend.app.security import RateLimitMiddleware

        mini_app = FastAPI()
        mini_app.add_middleware(RateLimitMiddleware, max_requests=3, window_seconds=60)

        @mini_app.get("/api/ping")
        def ping():
            return {"ok": True}

        client = TestClient(mini_app, raise_server_exceptions=False)

        # First 3 requests must succeed.
        for _ in range(3):
            resp = client.get("/api/ping")
            assert resp.status_code == 200

        # The 4th must be rate-limited.
        resp = client.get("/api/ping")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
