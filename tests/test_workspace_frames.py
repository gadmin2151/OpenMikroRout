from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import Settings, create_app

FRAME = "/workspace-frame?view=tools&window=diagnostic-1"
HEADERS = {"X-NAT-Request": "1"}
PASSWORD = "test-only-workspace-frame-password"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as connection:
        yield connection


def directives(value: str) -> dict[str, str]:
    return dict(part.strip().split(" ", 1) for part in value.split(";") if part.strip())


def test_only_the_exact_frame_entrypoint_allows_same_origin_ancestors(client: TestClient) -> None:
    root = client.get("/")
    frame = client.get(FRAME, headers={"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "iframe"})
    assert frame.status_code == 200 and frame.content == root.content
    assert frame.headers["content-type"].startswith("text/html")
    assert frame.headers["x-frame-options"] == "SAMEORIGIN"
    assert root.headers["x-frame-options"] == "DENY"
    frame_policy = directives(frame.headers["content-security-policy"])
    root_policy = directives(root.headers["content-security-policy"])
    assert frame_policy.pop("frame-ancestors") == "'self'"
    assert root_policy.pop("frame-ancestors") == "'none'"
    assert frame_policy == root_policy
    assert frame_policy["script-src"] == frame_policy["style-src"] == "'self'"
    assert frame_policy["object-src"] == frame_policy["base-uri"] == "'none'"
    assert "unsafe-inline" not in frame.headers["content-security-policy"]
    assert "access-control-allow-origin" not in frame.headers
    assert "set-cookie" not in frame.headers


@pytest.mark.parametrize(
    "path", ["/api/health", "/api/state", "/app.js", "/style.css", "/logo.png", "/index.html"]
)
def test_api_root_and_static_files_keep_the_original_frame_denial(
    client: TestClient, path: str
) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["x-frame-options"] == "DENY"
    assert directives(response.headers["content-security-policy"])["frame-ancestors"] == "'none'"


def test_frame_html_revalidates_and_does_not_reflect_query_parameters(client: TestClient) -> None:
    response = client.get(FRAME + "&title=FRAME_ATTACK_123%3Cscript%3E")
    assert response.status_code == 200
    assert "FRAME_ATTACK_123" not in response.text
    assert response.headers["cache-control"] == "no-cache, must-revalidate"
    unchanged = client.get(FRAME, headers={"If-None-Match": response.headers["etag"]})
    assert unchanged.status_code == 304
    assert unchanged.headers["cache-control"] == "no-cache, must-revalidate"
    assert unchanged.headers["x-frame-options"] == "SAMEORIGIN"
    assert directives(unchanged.headers["content-security-policy"])["frame-ancestors"] == "'self'"
    head = client.head(FRAME)
    assert head.status_code == 200 and not head.content
    assert head.headers["cache-control"] == "no-cache, must-revalidate"


@pytest.mark.parametrize(
    "headers",
    [
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "iframe"},
        {"Sec-Fetch-Site": "same-site", "Sec-Fetch-Dest": "iframe"},
        {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "script"},
        {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"},
    ],
)
def test_frame_fetch_metadata_cannot_turn_cross_origin_or_script_requests_into_frames(
    client: TestClient, headers: dict[str, str]
) -> None:
    denied = client.get(FRAME, headers=headers)
    assert denied.status_code == 403
    assert denied.headers["x-frame-options"] == "DENY"
    assert directives(denied.headers["content-security-policy"])["frame-ancestors"] == "'none'"


@pytest.mark.parametrize(
    "path", ["/workspace-frame/index.html", "/workspace-frame.html", "/unknown.html", "/tools/ping"]
)
def test_frame_route_does_not_create_an_html_fallback_for_unknown_paths(
    client: TestClient, path: str
) -> None:
    response = client.get(path)
    assert response.status_code == 404
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_frame_html_uses_static_compression_without_compressing_api_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    static = tmp_path / "static"
    static.mkdir()
    markup = "<!doctype html><html><body>" + "workspace frame " * 1000 + "</body></html>"
    (static / "index.html").write_text(markup)
    monkeypatch.setattr("app.main.STATIC", static)
    with TestClient(create_app(Settings(data_dir=tmp_path / "data"))) as client:
        frame = client.get(FRAME, headers={"Accept-Encoding": "gzip"})
        assert frame.status_code == 200 and frame.text == markup
        assert frame.headers["content-encoding"] == "gzip"
        assert "Accept-Encoding" in frame.headers["vary"]
        assert frame.headers["cache-control"] == "no-cache, must-revalidate"
        assert "content-encoding" not in client.get("/api/health").headers


def test_same_origin_frame_does_not_change_session_or_read_full_api_authorization(
    tmp_path: Path,
) -> None:
    app = create_app(
        Settings(data_dir=tmp_path, auth_enabled=True, password=PASSWORD, read_password=PASSWORD)
    )
    with TestClient(app) as client:
        assert client.get(FRAME).status_code == 200  # Static login UI contains no account data.
        assert client.get("/api/state").status_code == 401
        for username, role in (("viewer", "read"), ("admin", "full")):
            response = client.post(
                "/api/login", headers=HEADERS, json={"username": username, "password": PASSWORD}
            )
            assert response.status_code == 200
            token = client.cookies.get("nat_session")
            assert client.get(FRAME + "&role=full&view=users").status_code == 200
            assert client.cookies.get("nat_session") == token
            assert client.get("/api/state").json()["current_user"]["role"] == role
            if role == "read":
                assert client.get("/api/users").status_code == 403
                assert client.put("/api/config", headers=HEADERS, json={}).status_code == 403
                assert (
                    client.post(
                        "/api/tools/stream",
                        headers=HEADERS,
                        json={"tool": "ping", "target": "127.0.0.1"},
                    ).status_code
                    == 403
                )
            assert client.post("/api/logout", headers=HEADERS).status_code == 200
