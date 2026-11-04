import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.main import Settings, create_app
from app.network_models import DnsStaticRecord, NetworkConfiguration
from app.networking import dnsmasq_configs
from app.totp import code_at
from app.wireguard_keys import generate_key
from app.wireguard_profiles import parse_profile

HEADERS = {"X-NAT-Request": "1"}
PASSWORD = "wireguard-test-only-admin-password"
READ_PASSWORD = "wireguard-test-only-reader-password"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(Settings(data_dir=tmp_path))) as session:
        yield session


def post(client: TestClient, path: str, body: dict[str, Any]) -> Any:
    response = client.post("/api/wireguard/" + path, headers=HEADERS, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_server_peer_export_apply_and_rollback_are_a_single_draft_flow(client: TestClient) -> None:
    before = client.get("/api/network/status").json()
    server = post(
        client,
        "server",
        {"revision": 0, "endpoint": "vpn.example.com", "access_networks": ["192.168.10.0/24"]},
    )
    assert server["dirty"] and server["revision"] == 1
    interface = server["config"]["network"]["wireguard_interfaces"][0]
    assert interface["name"] == "wg-server"
    assert client.get("/api/network/status").json() == before
    saved = post(
        client,
        "peers",
        {
            "revision": 1,
            "interface": "wg-server",
            "name": "Phone",
            "client_allowed_ips": ["192.168.10.0/24"],
        },
    )
    peer = saved["config"]["network"]["wireguard_peers"][0]
    assert peer["client_address"] == "10.77.0.2/32"
    exported = post(client, "export", {"object_id": peer["id"]})
    private = parse_profile(SecretStr(exported["configuration"])).private_key.get_secret_value()
    assert exported["qr_data_url"].startswith("data:image/svg+xml;base64,")
    for path in ["state", "network/status", "audit", "wireguard/status"]:
        assert private not in client.get("/api/" + path).text
    preview = client.post("/api/preview", headers=HEADERS)
    assert preview.status_code == 200 and private not in preview.text
    applied = client.post("/api/apply", headers=HEADERS, json={"revision": 2})
    assert applied.status_code == 200 and private not in applied.text
    assert (
        client.get("/api/wireguard/status").json()["interfaces"][0]["peers"][0]["connected"]
        is False
    )
    assert client.post("/api/rollback", headers=HEADERS).status_code == 200
    assert not client.get("/api/wireguard/status").json()["interfaces"]


def test_client_import_is_strict_preserves_main_route_and_generates_selected_source_rules(
    client: TestClient,
) -> None:
    private, _ = generate_key("interface")
    _, remote = generate_key("peer-client")
    text = (
        f"[Interface]\nPrivateKey={private}\nAddress=10.88.0.2/32\nDNS=1.1.1.1\n"
        f"[Peer]\nPublicKey={remote}\nAllowedIPs=0.0.0.0/0\n"
        "Endpoint=vpn.example.com:51820\nPersistentKeepalive=25\n"
    )
    saved = post(
        client, "import", {"revision": 0, "profile": text, "route_sources": ["192.168.10.0/24"]}
    )
    interface = saved["config"]["network"]["wireguard_interfaces"][0]
    assert interface["role"] == "client" and interface["route_allowed_ips"]
    assert interface["client_dns"] == ["1.1.1.1"]
    assert not any(
        item.get("interface") == "wg-client" for item in saved["config"]["network"]["routes"]
    )
    assert private not in str(saved)
    assert (
        client.post(
            "/api/wireguard/import",
            headers=HEADERS,
            json={"revision": 1, "name": "wg-bad", "profile": text + "\nPostUp=touch /tmp/no"},
        ).status_code
        == 409
    )
    assert client.get("/api/state").json()["revision"] == 1
    assert (
        client.post(
            "/api/wireguard/import", headers=HEADERS, json={"revision": 0, "profile": text}
        ).status_code
        == 409
    )


def test_keys_are_public_metadata_only_and_unknown_references_cannot_be_saved(
    client: TestClient,
) -> None:
    private, public = generate_key("interface")
    key = post(client, "keys", {"value": private})
    assert key["public_key"] == public and private not in str(key)
    state = client.get("/api/state").json()
    state["config"]["network"]["wireguard_interfaces"] = [
        {"name": "wg-bad", "private_key_id": str(uuid4()), "public_key": public}
    ]
    response = client.put(
        "/api/config", headers=HEADERS, json={"revision": 0, "config": state["config"]}
    )
    assert response.status_code == 409 and private not in response.text


def test_setup_wizards_reject_overlapping_addresses_and_unbounded_interface_prefixes(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/wireguard/server", headers=HEADERS, json={"revision": 0, "address": "192.168.10.2/24"}
    )
    assert response.status_code == 409 and "overlap" in response.text
    assert (
        client.post(
            "/api/wireguard/server", headers=HEADERS, json={"revision": 0, "address": "10.77.0.1/0"}
        ).status_code
        == 422
    )
    private, _ = generate_key("interface")
    _, public = generate_key("peer-client")
    profile = (
        f"[Interface]\nPrivateKey={private}\nAddress=192.168.10.20/32\n"
        f"[Peer]\nPublicKey={public}\nAllowedIPs=0.0.0.0/0\nEndpoint=192.0.2.1:51820\n"
    )
    response = client.post(
        "/api/wireguard/import", headers=HEADERS, json={"revision": 0, "profile": profile}
    )
    assert response.status_code == 409 and private not in response.text
    profile = profile.replace("192.168.10.20/32", "10.88.0.2/0")
    response = client.post(
        "/api/wireguard/import", headers=HEADERS, json={"revision": 0, "profile": profile}
    )
    assert response.status_code == 409 and private not in response.text
    assert client.get("/api/state").json()["revision"] == 0


def test_generated_clients_get_unique_addresses(client: TestClient) -> None:
    post(
        client,
        "server",
        {"revision": 0, "endpoint": "vpn.example.com", "access_networks": ["192.168.10.0/24"]},
    )
    for revision in (1, 2):
        saved = post(
            client,
            "peers",
            {"revision": revision, "interface": "wg-server", "name": f"Device {revision}"},
        )
    assert [item["client_address"] for item in saved["config"]["network"]["wireguard_peers"]] == [
        "10.77.0.2/32",
        "10.77.0.3/32",
    ]
    assert saved["config"]["network"]["wireguard_peers"][0]["client_allowed_ips"] == [
        "10.77.0.0/24",
        "192.168.10.0/24",
    ]


def test_authenticated_export_requires_full_and_password_without_leaking_keys(
    tmp_path: Path,
) -> None:
    settings = Settings(
        data_dir=tmp_path, auth_enabled=True, password=PASSWORD, read_password=READ_PASSWORD
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/wireguard/status").status_code == 401
        assert (
            client.post(
                "/api/login", headers=HEADERS, json={"username": "admin", "password": PASSWORD}
            ).status_code
            == 200
        )
        post(client, "server", {"revision": 0, "endpoint": "vpn.example.com"})
        saved = post(client, "peers", {"revision": 1, "interface": "wg-server", "name": "Phone"})
        peer_id = saved["config"]["network"]["wireguard_peers"][0]["id"]
        assert (
            client.post(
                "/api/wireguard/export", headers=HEADERS, json={"object_id": peer_id}
            ).status_code
            == 409
        )
        wrong = client.post(
            "/api/wireguard/export",
            headers=HEADERS,
            json={"object_id": peer_id, "proof": {"password": "wrong"}},
        )
        assert wrong.status_code == 403
        profile = post(client, "export", {"object_id": peer_id, "proof": {"password": PASSWORD}})
        private = parse_profile(SecretStr(profile["configuration"])).private_key.get_secret_value()
        client.post("/api/logout", headers=HEADERS)
        assert (
            client.post(
                "/api/login",
                headers=HEADERS,
                json={"username": "viewer", "password": READ_PASSWORD},
            ).status_code
            == 200
        )
        assert client.get("/api/wireguard/status").status_code == 200
        assert private not in client.get("/api/state").text
        for path, body in [
            ("keys", {}),
            ("export", {"object_id": peer_id, "proof": {"password": READ_PASSWORD}}),
            ("peers", {"revision": 2, "interface": "wg-server", "name": "Blocked"}),
            ("server", {"revision": 2}),
        ]:
            assert (
                client.post("/api/wireguard/" + path, headers=HEADERS, json=body).status_code == 403
            )
        assert (
            client.post(
                "/api/tools/run", headers=HEADERS, json={"tool": "ping", "target": "1.1.1.1"}
            ).status_code
            == 403
        )


def test_diagnostics_demo_has_no_network_side_effects_and_validates_input(
    client: TestClient,
) -> None:
    with patch("app.diagnostics.subprocess.run") as run:
        response = client.post(
            "/api/tools/run", headers=HEADERS, json={"tool": "ping", "target": "example.com"}
        )
        assert response.status_code == 200 and response.json()["demo"]
        run.assert_not_called()
    for target in ["$(id)", "host;reboot", "https://example.com", "::1", "-c100"]:
        assert (
            client.post(
                "/api/tools/run", headers=HEADERS, json={"tool": "ping", "target": target}
            ).status_code
            == 422
        )


def test_static_dns_records_validate_and_render_only_when_enabled(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        DnsStaticRecord(name="bad\nserver=evil", address="10.0.0.1")
    with pytest.raises(ValueError):
        DnsStaticRecord(name="host.lan", address="::1")
    from app.demo import demo_config

    data = demo_config().network.model_dump(mode="json")
    data["dns_static"] = [
        {"name": "NAS.HOME.", "address": "192.168.10.20", "ttl": 60},
        {"name": "off.home", "address": "192.168.10.30", "enabled": False},
    ]
    network = NetworkConfiguration.model_validate(data)
    text = dnsmasq_configs(network, tmp_path)["dns"]
    assert text and "host-record=nas.home,192.168.10.20,60" in text and "off.home" not in text


def test_private_export_enforces_enabled_totp_and_recovery_replay_protection(
    tmp_path: Path,
) -> None:
    settings = Settings(data_dir=tmp_path, auth_enabled=True, password=PASSWORD)
    with TestClient(create_app(settings)) as client:
        assert (
            client.post(
                "/api/login", headers=HEADERS, json={"username": "admin", "password": PASSWORD}
            ).status_code
            == 200
        )
        post(client, "server", {"revision": 0, "endpoint": "vpn.example.com"})
        saved = post(client, "peers", {"revision": 1, "interface": "wg-server", "name": "Phone"})
        peer_id = saved["config"]["network"]["wireguard_peers"][0]["id"]
        setup = client.post("/api/me/totp/setup", headers=HEADERS, json={"password": PASSWORD})
        assert setup.status_code == 200
        code = code_at(setup.json()["secret"], int(time.time() // 30))
        confirmed = client.post(
            "/api/me/totp/confirm", headers=HEADERS, json={"password": PASSWORD, "code": code}
        )
        assert confirmed.status_code == 200
        body = {"object_id": peer_id, "proof": {"password": PASSWORD}}
        assert client.post("/api/wireguard/export", headers=HEADERS, json=body).status_code == 403
        body["proof"]["code"] = confirmed.json()["recovery_codes"][0]
        assert client.post("/api/wireguard/export", headers=HEADERS, json=body).status_code == 200
        assert client.post("/api/wireguard/export", headers=HEADERS, json=body).status_code == 403
