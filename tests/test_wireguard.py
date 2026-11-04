import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr, ValidationError

from app.link_models import Bridge, WireGuardInterface
from app.network_models import IpAddress, NetworkConfiguration
from app.wireguard_keys import KeyKind, derive_public, generate_key
from app.wireguard_models import WireGuardPeer
from app.wireguard_profiles import export_client, export_interface, parse_profile, qr_profile
from app.wireguard_vault import WireGuardVault


def configured(tmp_path: Path) -> tuple[WireGuardVault, NetworkConfiguration]:
    vault = WireGuardVault(tmp_path)
    own = vault.create("interface")
    client = vault.create("peer-client")
    psk = vault.create("preshared")
    interface = WireGuardInterface(
        name="wg-test",
        private_key_id=own.id,
        public_key=own.public_key,
        export_endpoint="vpn.example.com",
    )
    peer = WireGuardPeer(
        name="Phone",
        interface=interface.name,
        public_key=client.public_key,
        allowed_ips=["10.99.0.2/32"],
        client_address="10.99.0.2/32",
        client_allowed_ips=["192.168.10.0/24"],
        client_dns=["1.1.1.1"],
        preshared_key_id=psk.id,
        client_private_key_id=client.id,
    )
    return vault, NetworkConfiguration(
        wireguard_interfaces=[interface],
        wireguard_peers=[peer],
        addresses=[IpAddress(interface=interface.name, address="10.99.0.1/24")],
    )


def test_vault_keys_are_encrypted_and_bound_to_their_identity(tmp_path: Path) -> None:
    vault, config = configured(tmp_path)
    interface = config.wireguard_interfaces[0]
    vault.validate(config)
    secret = vault.secret(interface.private_key_id, "interface")
    assert derive_public(secret) == interface.public_key
    assert secret not in config.model_dump_json()
    assert secret not in vault.path.read_bytes().decode(errors="ignore")
    assert vault.path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "wireguard.key").stat().st_mode & 0o777 == 0o600
    reopened = WireGuardVault(tmp_path)
    assert reopened.secret(interface.private_key_id, "interface") == secret
    encrypted = vault.seal_runtime("wg-test", "PrivateKey = " + secret)
    assert secret not in encrypted
    assert vault.open_runtime("wg-test", encrypted) == "PrivateKey = " + secret
    with pytest.raises(RuntimeError, match="recovery"):
        vault.open_runtime("wg-other", encrypted)
    with pytest.raises(ValueError, match="missing"):
        vault.secret(interface.private_key_id, "preshared")


def test_missing_private_master_key_never_silently_rotates_keys(tmp_path: Path) -> None:
    vault, config = configured(tmp_path)
    (tmp_path / "wireguard.key").unlink()
    with pytest.raises(RuntimeError, match="private backup"):
        WireGuardVault(tmp_path)
    assert config.wireguard_interfaces
    assert vault.path.exists()


def test_configuration_references_require_the_correct_key_and_public_half(tmp_path: Path) -> None:
    vault, config = configured(tmp_path)
    data = config.model_dump(mode="json")
    data["wireguard_interfaces"][0]["public_key"] = generate_key("interface")[1]
    with pytest.raises(ValueError, match="does not match"):
        vault.validate(NetworkConfiguration.model_validate(data))
    data["wireguard_interfaces"][0]["private_key_id"] = str(uuid4())
    with pytest.raises(ValueError, match="missing"):
        vault.validate(NetworkConfiguration.model_validate(data))


def test_peer_ranges_and_link_types_have_predictable_constraints(tmp_path: Path) -> None:
    _, config = configured(tmp_path)
    data = config.model_dump(mode="json")
    duplicate = {
        **data["wireguard_peers"][0],
        "id": str(uuid4()),
        "public_key": generate_key("peer-client")[1],
        "client_private_key_id": None,
    }
    data["wireguard_peers"].append(duplicate)
    with pytest.raises(ValidationError, match="overlap"):
        NetworkConfiguration.model_validate(data)
    duplicate["enabled"] = False
    NetworkConfiguration.model_validate(data)
    data["bridges"] = [Bridge(name="br-test", members=["wg-test"]).model_dump(mode="json")]
    with pytest.raises(ValidationError, match="bridge port"):
        NetworkConfiguration.model_validate(data)


def test_client_profile_export_import_and_qr_are_standard_and_ipv4_only(tmp_path: Path) -> None:
    vault, config = configured(tmp_path)
    interface, peer = config.wireguard_interfaces[0], config.wireguard_peers[0]
    text = export_client(interface, peer, vault)
    assert "PostUp" not in text and "::" not in text
    parsed = parse_profile(SecretStr(text))
    assert derive_public(parsed.private_key.get_secret_value()) == peer.public_key
    assert parsed.addresses == ["10.99.0.2/32"]
    assert parsed.peers[0].public_key == interface.public_key
    assert parsed.peers[0].allowed_ips == ["192.168.10.0/24"]
    assert parsed.peers[0].endpoint_host == "vpn.example.com"
    assert parsed.peers[0].persistent_keepalive == 25
    assert qr_profile(text).startswith("data:image/svg+xml;base64,")
    assert parsed.private_key.get_secret_value() not in repr(parsed)


def test_router_profile_preserves_keys_without_implicitly_replacing_routes(tmp_path: Path) -> None:
    vault, config = configured(tmp_path)
    text = export_interface(
        config.wireguard_interfaces[0], config.wireguard_peers, config.addresses, vault
    )
    parsed = parse_profile(SecretStr(text))
    assert not parsed.automatic_routes
    assert parsed.addresses == ["10.99.0.1/24"]
    assert parsed.peers[0].preshared_key
    psk_id = config.wireguard_peers[0].preshared_key_id
    assert psk_id is not None
    assert parsed.peers[0].preshared_key.get_secret_value() == vault.secret(psk_id, "preshared")
    without_address = "\n".join(
        line for line in text.splitlines() if not line.startswith("Address")
    )
    assert parse_profile(SecretStr(without_address)).addresses == []


@pytest.mark.parametrize(
    "bad_line",
    [
        "PostUp = touch /tmp/not-allowed",
        "PreDown = arbitrary-command",
        "SaveConfig = true",
        "FwMark = 1234",
        "Address = ::1/128",
        "DNS = ::1",
        "MTU = 0",
        "ListenPort = 70000",
    ],
)
def test_import_rejects_hooks_ipv6_and_invalid_fields_without_echoing_secrets(
    tmp_path: Path,
    bad_line: str,
) -> None:
    vault, config = configured(tmp_path)
    text = export_interface(
        config.wireguard_interfaces[0], config.wireguard_peers, config.addresses, vault
    )
    text = text.replace("[Interface]", "[Interface]\n" + bad_line)
    with pytest.raises(ValueError) as failure:
        parse_profile(SecretStr(text))
    assert vault.secret(config.wireguard_interfaces[0].private_key_id, "interface") not in str(
        failure.value
    )


def test_read_config_contains_only_public_material_and_references(tmp_path: Path) -> None:
    vault, config = configured(tmp_path)
    raw = json.dumps(config.model_dump(mode="json"))
    references: list[tuple[UUID | None, KeyKind]] = [
        (config.wireguard_interfaces[0].private_key_id, "interface"),
        (config.wireguard_peers[0].client_private_key_id, "peer-client"),
        (config.wireguard_peers[0].preshared_key_id, "preshared"),
    ]
    for key, kind in references:
        assert key is not None
        assert vault.secret(key, kind) not in raw
