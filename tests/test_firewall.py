import subprocess
import time
from pathlib import Path
from unittest.mock import patch as mock_patch

import pytest

from app.compiler import FirewallError, compiled_rules, counters, patch, rollback_patch
from app.demo import demo_config
from app.firewall import EMPTY_NAT, Conflict, DemoDriver, FirewallService, LinuxDriver
from app.models import Configuration, NatRule
from app.storage import Store


def make_service(tmp_path: Path, seconds: int = 60) -> FirewallService:
    initial = Configuration()
    return FirewallService(Store(tmp_path / "test.sqlite3", initial), DemoDriver(initial), seconds)


def changed_config() -> Configuration:
    return Configuration(rules=[NatRule(name="Web", to_address="192.168.1.10", dst_ports="443")])


def test_compiles_lists_and_skips_disabled() -> None:
    config = demo_config()
    lines = compiled_rules(config)
    assert len(lines) == 9
    assert not any(str(config.rules[-1].id) in line for line in lines)
    assert any("--dports 80,443" in line for line in lines)
    assert any("-j REDIRECT --to-ports 53" in line for line in lines)


@pytest.mark.parametrize(
    "chain,action,target",
    [
        ("srcnat", "src-nat", "SNAT"),
        ("srcnat", "masquerade", "MASQUERADE"),
        ("dstnat", "dst-nat", "DNAT"),
        ("output", "redirect", "REDIRECT"),
        ("srcnat", "accept", "ACCEPT"),
        ("dstnat", "accept", "ACCEPT"),
    ],
)
def test_target_compilation(chain: str, action: str, target: str) -> None:
    config = Configuration.model_validate(
        {
            "rules": [
                {
                    "name": "Test",
                    "chain": chain,
                    "action": action,
                    "to_address": "10.0.0.1" if action.endswith("-nat") else "",
                }
            ]
        }
    )
    assert f"-j {target}" in compiled_rules(config)[0]


def test_patch_never_flushes_builtin_or_other_chains() -> None:
    snapshot = EMPTY_NAT.replace("COMMIT", ":DOCKER - [0:0]\n-A POSTROUTING -j DOCKER\nCOMMIT")
    payload = patch(snapshot, changed_config())
    assert ":POSTROUTING" not in payload
    assert "DOCKER" not in payload
    assert "-F" not in payload
    assert "-A POSTROUTING -m comment --comment nat-panel:anchor -j NATP_POST" in payload


def test_anchors_are_not_duplicated_and_rollback_preserves_other_rules() -> None:
    driver = DemoDriver(Configuration())
    driver.table = driver.table.replace("COMMIT", "-A POSTROUTING -s 10.0.0.0/8 -j ACCEPT\nCOMMIT")
    before = driver.snapshot()
    payload = patch(before, changed_config())
    assert "nat-panel:anchor" not in payload
    driver.restore(payload)
    driver.restore(rollback_patch(driver.snapshot(), before))
    assert driver.snapshot() == before


def test_first_apply_rollback_removes_only_new_hooks() -> None:
    driver = DemoDriver(Configuration())
    driver.table = EMPTY_NAT
    driver.restore(patch(EMPTY_NAT, changed_config()))
    payload = rollback_patch(driver.snapshot(), EMPTY_NAT)
    assert payload.count("-D ") == 3
    driver.restore(payload)
    assert "nat-panel:anchor" not in driver.snapshot()


def test_refuses_unmanaged_reserved_chain_or_hook() -> None:
    for line in ("-A NATP_PRE -j ACCEPT", "-A PREROUTING -j NATP_PRE"):
        with pytest.raises(FirewallError, match="[Uu]nmanaged"):
            patch(EMPTY_NAT.replace("COMMIT", f"{line}\nCOMMIT"), Configuration())


def test_apply_confirm_blocks_edits_and_preserves_configuration(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    saved = service.save(changed_config(), 0)
    assert saved["dirty"]
    pending = service.apply(1)["pending"]
    with pytest.raises(Conflict, match="pending"):
        service.save(Configuration(), 1)
    with pytest.raises(Conflict, match="token"):
        service.confirm("wrong-token")
    state = service.confirm(pending["token"])
    assert not state["dirty"]
    assert state["pending"] is None
    assert "-j DNAT" in service.driver.snapshot()


def test_stale_revision_cannot_overwrite(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    service.save(changed_config(), 0)
    with pytest.raises(Conflict, match="another session"):
        service.save(Configuration(), 0)
    assert len(service.config().rules) == 1


def test_timeout_rolls_back_but_keeps_draft(tmp_path: Path) -> None:
    service = make_service(tmp_path, seconds=-1)
    before = service.driver.snapshot()
    service.save(changed_config(), 0)
    service.apply(1)
    service.recover()
    assert service.driver.snapshot() == before
    assert service.state()["pending"] is None
    assert service.state()["dirty"]


def test_late_confirmation_rolls_back(tmp_path: Path) -> None:
    service = make_service(tmp_path, seconds=-1)
    service.save(changed_config(), 0)
    token = service.apply(1)["pending"]["token"]
    with pytest.raises(Conflict, match="expired"):
        service.confirm(token)
    assert "-j DNAT" not in service.driver.snapshot()


def test_restart_recovers_before_deadline(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    service.save(changed_config(), 0)
    service.apply(1)
    restarted = FirewallService(Store(tmp_path / "test.sqlite3", Configuration()), service.driver)
    restarted.recover(startup=True)
    assert restarted.state()["pending"] is None
    assert "-j DNAT" not in restarted.driver.snapshot()


def test_failed_rollback_remains_durable_and_retries(tmp_path: Path) -> None:
    service = make_service(tmp_path, seconds=-1)
    service.save(changed_config(), 0)
    service.apply(1)
    with (
        mock_patch.object(
            service.driver, "restore", side_effect=FirewallError("Kernel unavailable")
        ),
        pytest.raises(FirewallError),
    ):
        service.recover()
    assert "Kernel unavailable" in service.state()["pending"]["error"]
    service.recover()
    assert service.state()["pending"] is not None
    next_retry = service.store.read("pending")["next_retry"]
    with mock_patch("app.firewall.time.time", return_value=next_retry + 1):
        service.recover()
    assert service.state()["pending"] is None


def test_automatic_rollback_attempts_are_bounded(tmp_path: Path) -> None:
    service = make_service(tmp_path, seconds=-1)
    service.save(changed_config(), 0)
    service.apply(1)
    with mock_patch.object(service.driver, "restore", side_effect=FirewallError("Unavailable")):
        for _ in range(5):
            pending = service.store.read("pending")
            with (
                mock_patch("app.firewall.time.time", return_value=pending["next_retry"] + 100),
                pytest.raises(FirewallError),
            ):
                service.recover(startup=True)
        service.recover(startup=True)
    assert service.store.read("pending")["attempts"] == 5
    # An explicit manual retry remains available after the automatic retry limit.
    service.rollback()
    assert service.state()["pending"] is None


def test_failed_apply_restores_managed_snapshot(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    service.save(changed_config(), 0)
    restore = service.driver.restore
    calls = 0

    def fail_once(payload: str, test: bool = False) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FirewallError("Commit failed")
        restore(payload, test)

    with (
        mock_patch.object(service.driver, "restore", side_effect=fail_once),
        pytest.raises(FirewallError, match="Commit failed"),
    ):
        service.apply(1)
    assert service.state()["pending"] is None


def test_counter_aggregation() -> None:
    config = changed_config()
    line = compiled_rules(config)[0]
    values = counters(f"[2:120] {line}\n[3:180] {line}\n[5:50] -A DOCKER -j ACCEPT")
    assert values[str(config.rules[0].id)] == {"packets": 5, "bytes": 300}


def test_subprocess_timeout_and_nonzero_are_domain_errors() -> None:
    with (
        mock_patch("subprocess.run", side_effect=subprocess.TimeoutExpired("iptables", 15)),
        pytest.raises(FirewallError, match="timeout"),
    ):
        LinuxDriver.run(["iptables-save"])
    result = subprocess.CompletedProcess(["iptables"], 1, stdout="", stderr="denied")
    with mock_patch("subprocess.run", return_value=result) as run:
        with pytest.raises(FirewallError, match="denied"):
            LinuxDriver.run(["iptables-restore"], "*nat\nCOMMIT\n")
        assert run.call_args.kwargs.get("shell") is None
        assert run.call_args.kwargs["timeout"] == 15


def test_discard_returns_confirmed_configuration(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    service.save(changed_config(), 0)
    result = service.discard(1)
    assert result["config"]["rules"] == []
    assert result["revision"] == 2
    assert not result["dirty"]


def test_pending_record_is_written_before_kernel_commit(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    service.save(changed_config(), 0)
    restore = service.driver.restore

    def inspect_commit(payload: str, test: bool = False) -> None:
        if not test:
            pending = service.store.read("pending")
            assert pending["snapshot"]
            assert pending["deadline"] > time.time()
        restore(payload, test)

    with mock_patch.object(service.driver, "restore", side_effect=inspect_commit):
        service.apply(1)
