import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from app.bootstrap import BootstrapError, main, read_confirmed, restore_confirmed_filters
from app.compiler import FirewallError
from app.filtering import DemoFilterDriver
from app.models import Configuration, FilterRule, NatRule


def write_state(directory: Path, values: dict[str, object]) -> Path:
    path = directory / "linux.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO state VALUES (?, ?)",
            [(key, json.dumps(value)) for key, value in values.items()],
        )
    return path


def confirmed() -> Configuration:
    return Configuration(
        filter_rules=[
            FilterRule(name="Loopback", chain="input", protocol="any", in_interface="lo"),
            FilterRule(name="Deny input", chain="input", protocol="any", action="drop"),
        ],
        rules=[NatRule(name="Not applied at early boot", to_address="10.77.0.4")],
    )


class RecordingDriver(DemoFilterDriver):
    def __init__(self) -> None:
        self.operations: list[tuple[str, bool]] = []
        self.reject_test = False
        super().__init__(Configuration())
        self.operations.clear()

    def restore(self, payload: str, test: bool = False) -> None:
        self.operations.append((payload, test))
        if test and self.reject_test:
            raise FirewallError("Synthetic kernel rejection")
        super().restore(payload, test)


def test_only_confirmed_filters_are_restored_without_database_changes(tmp_path: Path) -> None:
    config = confirmed()
    values: dict[str, object] = {
        "applied": config.model_dump(mode="json"),
        "config": Configuration().model_dump(mode="json"),
        "pending": {"config": Configuration().model_dump(mode="json"), "deadline": 0},
        "revision": 12,
    }
    path = write_state(tmp_path, values)
    before = path.read_bytes()
    driver = RecordingDriver()
    driver._table.table = driver.snapshot().replace(
        "COMMIT", ":FOREIGN - [0:0]\n-A INPUT -s 10.0.0.0/8 -j FOREIGN\nCOMMIT"
    )
    restore_confirmed_filters(tmp_path, driver)
    assert path.read_bytes() == before
    assert driver.operations[0][1] is True
    assert driver.operations[1] == (driver.operations[0][0], False)
    after = driver.snapshot()
    assert "-j DROP" in after
    assert f"openmikrorout:{config.filter_rules[0].id}" in after
    assert "-A INPUT -s 10.0.0.0/8 -j FOREIGN" in after
    assert ":FOREIGN - [0:0]" in after
    assert "DNAT" not in after and "*nat" not in after
    assert after.count("openmikrorout:filter-anchor") == 3


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"applied": None},
        {"applied": {"filter_rules": [{"name": "Invalid", "action": "execute"}]}},
        {"applied": "not-a-configuration"},
    ],
)
def test_invalid_or_missing_confirmed_state_never_touches_kernel(
    tmp_path: Path, values: dict[str, object]
) -> None:
    path = write_state(tmp_path, values)
    before = path.read_bytes()
    with (
        patch("app.bootstrap.LinuxFilterDriver") as factory,
        pytest.raises(BootstrapError, match="missing|invalid"),
    ):
        restore_confirmed_filters(tmp_path)
    factory.assert_not_called()
    assert path.read_bytes() == before


def test_malformed_json_never_touches_kernel(tmp_path: Path) -> None:
    path = write_state(tmp_path, {"applied": {}})
    with sqlite3.connect(path) as db:
        db.execute("UPDATE state SET value = ?", ("{broken-json",))
    with (
        patch("app.bootstrap.LinuxFilterDriver") as factory,
        pytest.raises(BootstrapError, match="invalid"),
    ):
        restore_confirmed_filters(tmp_path)
    factory.assert_not_called()


def test_missing_database_is_not_created(tmp_path: Path) -> None:
    missing = tmp_path / "missing-directory"
    with pytest.raises(BootstrapError, match="Cannot read"):
        read_confirmed(missing)
    assert not missing.exists()


def test_corrupt_database_is_not_replaced(tmp_path: Path) -> None:
    path = tmp_path / "linux.sqlite3"
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(BootstrapError, match="Cannot read"):
        read_confirmed(tmp_path)
    assert path.read_bytes() == b"not a sqlite database"


def test_clean_wal_database_without_sidecars_restores_confirmed_filters(tmp_path: Path) -> None:
    config = confirmed()
    path = write_state(tmp_path, {"applied": config.model_dump(mode="json")})
    db = sqlite3.connect(path)
    try:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    finally:
        db.close()
    assert not path.with_name(path.name + "-wal").exists()
    assert not path.with_name(path.name + "-shm").exists()
    before = path.read_bytes()
    driver = RecordingDriver()
    restore_confirmed_filters(tmp_path, driver)
    assert "-j DROP" in driver.snapshot()
    assert path.read_bytes() == before


def test_kernel_validation_failure_prevents_apply(tmp_path: Path) -> None:
    write_state(tmp_path, {"applied": confirmed().model_dump(mode="json")})
    driver = RecordingDriver()
    before = driver.snapshot()
    driver.reject_test = True
    with pytest.raises(BootstrapError, match="Synthetic kernel rejection"):
        restore_confirmed_filters(tmp_path, driver)
    assert len(driver.operations) == 1 and driver.operations[0][1] is True
    assert driver.snapshot() == before


def test_unmanaged_reserved_chain_is_rejected_before_restore(tmp_path: Path) -> None:
    write_state(tmp_path, {"applied": confirmed().model_dump(mode="json")})
    driver = RecordingDriver()
    driver._table.table = driver.snapshot().replace("COMMIT", "-A OMR_INPUT -j ACCEPT\nCOMMIT")
    with pytest.raises(BootstrapError, match="unmanaged"):
        restore_confirmed_filters(tmp_path, driver)
    assert driver.operations == []


def test_kernel_apply_failure_is_reported(tmp_path: Path) -> None:
    write_state(tmp_path, {"applied": confirmed().model_dump(mode="json")})
    driver = RecordingDriver()
    with (
        patch.object(
            driver, "restore", side_effect=[None, FirewallError("Apply failed")]
        ) as restore,
        pytest.raises(BootstrapError, match="Apply failed"),
    ):
        restore_confirmed_filters(tmp_path, driver)
    assert restore.call_count == 2
    assert restore.call_args_list[0].kwargs == {"test": True}
    assert restore.call_args_list[1].kwargs == {}


def test_cli_returns_failure_instead_of_green_startup(tmp_path: Path) -> None:
    assert main(["--data-dir", str(tmp_path)]) == 1
