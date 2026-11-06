"""Restore confirmed IPv4 filters before host networking starts.

This entry point deliberately avoids Store initialization, authentication, NAT,
interface changes and DHCP/DNS startup. It reads only the last confirmed state.
"""

import argparse
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from app.compiler import FirewallError
from app.filtering import FilterDriver, LinuxFilterDriver, filter_patch
from app.models import Configuration


class BootstrapError(RuntimeError):
    """The early firewall could not be restored safely."""


def read_confirmed(data_dir: Path) -> Configuration:
    path = data_dir / "linux.sqlite3"
    try:
        # mode=ro must never create an empty database on a configuration failure.
        with closing(
            sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as db:
            row = db.execute("SELECT value FROM state WHERE key = ?", ("applied",)).fetchone()
    except (sqlite3.Error, OSError) as exc:
        raise BootstrapError("Cannot read the existing confirmed firewall database") from exc
    if row is None or not isinstance(row[0], str):
        raise BootstrapError("The confirmed firewall configuration is missing")
    try:
        return Configuration.model_validate_json(row[0])
    except ValidationError as exc:
        raise BootstrapError("The confirmed firewall configuration is invalid") from exc


def restore_confirmed_filters(data_dir: Path, driver: FilterDriver | None = None) -> None:
    config = read_confirmed(data_dir)
    try:
        # Restore sets and original ban deadlines before installing rules that reference them.
        if driver is None:
            from app.fail2ban_runtime import Fail2banService
            from app.geoip import GeoIPService
            from app.ipsets import LinuxIPSetDriver
            from app.system_list_runtime import SystemListRuntime

            geoip = GeoIPService(data_dir)
            sets = LinuxIPSetDriver(data_dir)
            SystemListRuntime(geoip, sets).recover(config)
            protection = Fail2banService(
                data_dir,
                False,
                sets,
                lambda address: str(geoip.lookup(address).get("country") or ""),
            )
            try:
                protection.restore(config.fail2ban)
            finally:
                protection.journal.close()
        filters = driver if driver is not None else LinuxFilterDriver()
        payload = filter_patch(filters.snapshot(), config)
        # Both calls use --noflush in the existing Linux adapter: foreign chains survive.
        filters.restore(payload, test=True)
        filters.restore(payload)
    except (FirewallError, OSError, RuntimeError) as exc:
        raise BootstrapError(f"Cannot restore the confirmed firewall: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(
            os.environ.get("OMR_DATA_DIR", os.environ.get("NAT_DATA_DIR", "/var/lib/openmikrorout"))
        ),
    )
    args = parser.parse_args(argv)
    try:
        restore_confirmed_filters(args.data_dir)
    except BootstrapError as exc:
        print(f"Early firewall restore failed: {exc}", file=sys.stderr)
        return 1
    print("Confirmed IPv4 firewall restored before host networking")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
