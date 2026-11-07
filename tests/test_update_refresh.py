import gzip
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import Settings, create_app
from app.updates import UpdateError, UpdateJob
from app.version import VERSION


@pytest.mark.parametrize(
    "path",
    ["/", "/index.html", "/app.js?v=old", "/security-ui.js?v=1", "/style.css", "/brand-options/"],
)
def test_ui_assets_revalidate_even_unchanged_nested_modules(tmp_path: Path, path: str) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-cache, must-revalidate"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "clear-site-data" not in response.headers
        assert "set-cookie" not in response.headers
        unchanged = client.get(path, headers={"If-None-Match": response.headers["etag"]})
        assert unchanged.status_code == 304
        assert unchanged.headers["cache-control"] == "no-cache, must-revalidate"


def test_images_keep_normal_caching_and_api_data_is_never_cached(tmp_path: Path) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        image = client.get("/logo.png")
        assert image.status_code == 200
        assert "etag" in image.headers
        assert "no-store" not in image.headers.get("cache-control", "")
        assert client.get("/api/state").headers["cache-control"] == "no-store"


def test_static_compression_preserves_revalidation_and_keeps_api_uncompressed(
    tmp_path: Path,
) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        plain = client.get("/app.js", headers={"Accept-Encoding": "identity"})
        compressed = client.get("/app.js", headers={"Accept-Encoding": "gzip"})
        assert compressed.content == plain.content
        assert compressed.headers["content-encoding"] == "gzip"
        assert "Accept-Encoding" in compressed.headers["vary"]
        assert compressed.headers["cache-control"] == "no-cache, must-revalidate"
        # Static files stream in production, so Content-Length may be absent.
        with client.stream("GET", "/app.js", headers={"Accept-Encoding": "gzip"}) as raw:
            encoded = b"".join(raw.iter_raw())
        assert gzip.decompress(encoded) == plain.content
        assert len(encoded) < len(plain.content) // 2
        unchanged = client.get(
            "/app.js",
            headers={"Accept-Encoding": "gzip", "If-None-Match": compressed.headers["etag"]},
        )
        assert unchanged.status_code == 304
        assert "content-encoding" not in client.get("/api/state").headers
        assert "content-encoding" not in client.get("/logo.png").headers


def test_health_reports_only_public_release_progress_after_session_expires(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, auth_enabled=True, password="test-only-strong-password")
    )
    job = UpdateJob(
        id="a" * 32,
        version=VERSION,
        manifest_sha256="b" * 64,
        requested_at=1,
        updated_at=2,
        phase="restarting",
        message="private service details",
        error="private error details",
    )
    with TestClient(app) as client, patch.object(app.state.updates, "job", return_value=job):
        assert client.get("/api/updates").status_code == 401
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "status": "ok",
            "mode": "demo",
            "version": VERSION,
            "update": {"version": VERSION, "phase": "restarting"},
        }
        job.phase = "succeeded"
        assert client.get("/api/health").json()["update"]["phase"] == "succeeded"


def test_broken_update_metadata_does_not_break_health_or_signal_completion(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))
    with (
        TestClient(app) as client,
        patch.object(app.state.updates, "job", side_effect=UpdateError("private path")),
    ):
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["update"] == {"version": "", "phase": "unavailable"}
        assert "private path" not in response.text
