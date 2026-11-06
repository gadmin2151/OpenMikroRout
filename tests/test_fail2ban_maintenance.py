"""Native companion stop semantics are compatible with the existing pinned updater."""

import socket
import sqlite3
from pathlib import Path

import pytest

from app.fail2ban_maintenance import stop_private_engine, stopped_engine


def test_stop_checkpoints_nested_database_and_removes_only_private_runtime_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "fail2ban"
    directory.mkdir()
    path = directory / "engine.sqlite3"
    writer = sqlite3.connect(path)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE tickets (address TEXT PRIMARY KEY)")
    writer.execute("INSERT INTO tickets VALUES ('1.1.1.1')")
    writer.commit()
    socket_path = directory / "engine.sock"
    monkeypatch.chdir(directory)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind("engine.sock")
    (directory / "engine.pid").write_text("12345")
    (directory / "auth.log").write_text("retained authentication journal")
    stopped_engine(tmp_path)
    assert not socket_path.exists() and not (directory / "engine.pid").exists()
    assert (directory / "auth.log").read_text() == "retained authentication journal"
    copy = tmp_path / "copied.sqlite3"
    copy.write_bytes(path.read_bytes())
    with sqlite3.connect(copy) as db:
        assert db.execute("SELECT address FROM tickets").fetchone()[0] == "1.1.1.1"
    writer.close()
    stopped_engine(tmp_path)  # Idempotent normal stop after the engine cleaned its own socket.


def test_stop_rejects_symlinks_and_does_not_create_missing_databases(tmp_path: Path) -> None:
    stopped_engine(tmp_path)
    assert not (tmp_path / "fail2ban").exists()
    directory = tmp_path / "fail2ban"
    directory.mkdir()
    other = tmp_path / "unrelated"
    other.write_text("keep")
    (directory / "engine.sock").symlink_to(other)
    with pytest.raises(RuntimeError, match="runtime file type"):
        stopped_engine(tmp_path)
    assert other.read_text() == "keep"


def test_native_install_couples_optional_companion_to_main_maintenance() -> None:
    engine = Path("deploy/openmikrorout-fail2ban.service").read_text()
    optional = Path("deploy/openmikrorout-fail2ban.conf").read_text()
    installer = Path("deploy/install-fail2ban.sh").read_text()
    main = Path("deploy/openmikrorout.service").read_text()
    assert "PartOf=openmikrorout.service" in engine
    assert "ExecStopPost=" not in engine  # Main hook is the single maintenance barrier.
    assert "Wants=openmikrorout-fail2ban.service" in optional
    assert "After=openmikrorout-fail2ban.service" in optional
    assert "ExecStopPost=" in optional and "app.fail2ban_maintenance --stop" in optional
    assert "openmikrorout.service.d/20-fail2ban.conf" in installer
    assert "systemctl is-active --quiet openmikrorout-update.service" in installer
    assert "modprobe -a ip_set ip_set_hash_ip ip_set_hash_net xt_set" in installer
    assert "/etc/modules-load.d/openmikrorout-security.conf" in installer
    modules = Path("deploy/openmikrorout-security-modules.conf").read_text().splitlines()
    assert all(
        name in modules for name in ("ip_set", "ip_set_hash_ip", "ip_set_hash_net", "xt_set")
    )
    # An uninstalled/disabled optional feature does not make an existing main unit fail.
    assert "Requires=openmikrorout-fail2ban.service" not in main


def test_main_stop_waits_for_daemon_exit_before_finalizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess
    from unittest.mock import Mock

    directory = tmp_path / "fail2ban"
    directory.mkdir()
    (directory / "engine.pid").write_text("12345")
    monkeypatch.chdir(directory)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind("engine.sock")
    phases: list[str] = []
    alive = iter([True, True, False])
    monkeypatch.setattr("app.fail2ban_maintenance.shutil.which", lambda name: "/usr/bin/" + name)
    run = Mock(return_value=subprocess.CompletedProcess([], 0))
    monkeypatch.setattr("app.fail2ban_maintenance.subprocess.run", run)
    monkeypatch.setattr("app.fail2ban_maintenance._alive", lambda pid: next(alive))
    monkeypatch.setattr(
        "app.fail2ban_maintenance.time.sleep", lambda seconds: phases.append("wait")
    )
    finalize = Mock(side_effect=lambda directory: phases.append("finalize"))
    monkeypatch.setattr("app.fail2ban_maintenance.stopped_engine", finalize)
    stop_private_engine(tmp_path)
    assert phases == ["wait", "wait", "finalize"]
    assert run.call_args.args[0] == [
        "/usr/bin/fail2ban-client",
        "-s",
        str(directory / "engine.sock"),
        "stop",
    ]
    assert run.call_args.kwargs["timeout"] == 20


def test_failed_engine_stop_does_not_remove_live_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess
    from unittest.mock import Mock

    directory = tmp_path / "fail2ban"
    directory.mkdir()
    (directory / "engine.pid").write_text("12345")
    monkeypatch.chdir(directory)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind("engine.sock")
    monkeypatch.setattr("app.fail2ban_maintenance.shutil.which", lambda name: name)
    monkeypatch.setattr(
        "app.fail2ban_maintenance.subprocess.run",
        Mock(return_value=subprocess.CompletedProcess([], 1)),
    )
    monkeypatch.setattr("app.fail2ban_maintenance._alive", lambda pid: True)
    with pytest.raises(RuntimeError, match="refused to stop"):
        stop_private_engine(tmp_path)
    assert (directory / "engine.sock").exists()
    assert (directory / "engine.pid").exists()
