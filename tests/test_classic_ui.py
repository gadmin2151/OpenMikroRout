"""The classic interface must not bootstrap or expose the retired workspace."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import Settings, create_app


def test_classic_entry_has_no_workspace_and_keeps_authenticated_api(tmp_path: Path) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, auth_enabled=True, password="classic-ui-fixture-password")
    )
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "workspace" not in response.text
        assert "<iframe" not in response.text
        assert response.headers["cache-control"] == "no-cache, must-revalidate"
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        source = client.get("/app.js").text
        assert "./workspace-" not in source
        assert "createDesktopWorkspace" not in source
        assert client.get("/api/state").status_code == 401


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST"])
def test_retired_workspace_frame_cannot_embed_a_panel(tmp_path: Path, method: str) -> None:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        response = client.request(
            method,
            "/workspace-frame?view=tools&window=old-layout",
            headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "iframe"},
        )
        assert response.status_code in (404, 405)
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "access-control-allow-origin" not in response.headers
