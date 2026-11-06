"""Finalize a stopped private engine before the existing signed updater copies its data."""

import argparse
import os
import shutil
import sqlite3
import stat
import subprocess
import time
from contextlib import closing
from pathlib import Path


def stopped_engine(data_dir: Path) -> None:
    """Systemd ExecStopPost only: the service's entire process group has already exited."""
    directory = data_dir / "fail2ban"
    database = directory / "engine.sqlite3"
    if database.exists():
        if database.is_symlink() or not database.is_file():
            raise RuntimeError("The private Fail2ban database must be a regular file")
        # Older pinned updater controllers copy nested DBs as files and omit WAL files.
        # A successful stop therefore requires all committed engine tickets in the main DB.
        with closing(
            sqlite3.connect(database.resolve().as_uri() + "?mode=rw", uri=True, timeout=10)
        ) as db:
            result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result is None or result[0] != 0:
                raise RuntimeError("The private Fail2ban database is still busy")
    for filename in ("engine.sock", "engine.pid"):
        path = directory / filename
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            continue
        if not (stat.S_ISSOCK(mode) or stat.S_ISREG(mode)):
            raise RuntimeError("Unexpected private Fail2ban runtime file type")
        path.unlink(missing_ok=True)


def stop_private_engine(data_dir: Path) -> None:
    """Main unit ExecStopPost: drain the engine before this stop job can complete.

    PartOf alone is insufficient: systemctl may finish the requested main stop job
    before a dependent companion's later stop job. Talk to our private socket directly
    instead of invoking systemctl recursively (which would deadlock the stop ordering).
    """
    directory = data_dir / "fail2ban"
    pid_file, socket_file = directory / "engine.pid", directory / "engine.sock"
    pid: int | None = None
    if pid_file.exists():
        if pid_file.is_symlink() or pid_file.stat().st_size > 32:
            raise RuntimeError("Invalid private Fail2ban PID file")
        raw = pid_file.read_text().strip()
        if not raw.isdecimal() or not 1 < int(raw) < 2**31:
            raise RuntimeError("Invalid private Fail2ban PID")
        pid = int(raw)
    if socket_file.exists():
        if not stat.S_ISSOCK(socket_file.lstat().st_mode):
            raise RuntimeError("Unexpected private Fail2ban socket type")
        binary = shutil.which("fail2ban-client")
        if binary is None:
            raise RuntimeError("Cannot stop the private engine without fail2ban-client")
        try:
            result = subprocess.run(
                [binary, "-s", str(socket_file), "stop"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("Private Fail2ban shutdown failed or timed out") from exc
        if result.returncode and (pid is None or _alive(pid)):
            raise RuntimeError("Private Fail2ban engine refused to stop")
    deadline = time.monotonic() + 20
    while pid is not None and _alive(pid):
        if time.monotonic() >= deadline:
            raise RuntimeError("Private Fail2ban engine did not exit before maintenance")
        time.sleep(0.05)
    stopped_engine(data_dir)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    if args.stop:
        stop_private_engine(args.data_dir)
    else:
        stopped_engine(args.data_dir)


if __name__ == "__main__":
    main()
