"""Install only application quarantine on service stop; disabled/Observe is inert."""

import argparse
import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from app.application_policy import APP_CHAIN, active, app_anchor, guard_rules
from app.compiler import FirewallError
from app.filtering import FilterDriver, LinuxFilterDriver, inspect
from app.models import Configuration


def quarantine_patch(snapshot: str, *configs: Configuration) -> str | None:
    targets = [config for config in configs if active(config)]
    if not targets:
        return None
    _, hooks = inspect(snapshot)
    rules = list(
        dict.fromkeys(
            rule
            for target in targets
            for rule in guard_rules(target, None)
            if not rule.endswith("-j RETURN")
        )
    )
    jump = app_anchor()
    lines = ["*filter", f":{APP_CHAIN} - [0:0]", *rules]
    lines.append(f"-A {APP_CHAIN} -m comment --comment openmikrorout:application-guard -j RETURN")
    if "applications" in hooks:
        lines.append(" ".join(["-D", *jump[1:]]))
    lines.append(" ".join(["-I", "FORWARD", "1", *jump[2:]]))
    return "\n".join([*lines, "COMMIT", ""])


def quarantine(driver: FilterDriver, *configs: Configuration) -> bool:
    if not any(active(config) for config in configs):
        return False
    payload = quarantine_patch(driver.snapshot(), *configs)
    if payload is not None:
        driver.restore(payload, test=True)
        driver.restore(payload)
    return payload is not None


def confirmed_and_pending(directory: Path) -> list[Configuration]:
    with closing(
        sqlite3.connect(
            (directory / "linux.sqlite3").resolve().as_uri() + "?mode=ro", uri=True, timeout=5
        )
    ) as db:
        values = dict(db.execute("SELECT key,value FROM state WHERE key IN ('applied','pending')"))
    if "applied" not in values:
        raise ValueError("The confirmed router configuration is missing")
    result = [Configuration.model_validate_json(values["applied"])]
    pending = json.loads(values.get("pending", "null"))
    if pending:
        result.append(Configuration.model_validate(pending["config"]))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("OMR_DATA_DIR", "/var/lib/openmikrorout")),
    )
    arguments = parser.parse_args(argv)
    try:
        targets = confirmed_and_pending(arguments.data_dir)
        if not any(active(config) for config in targets):
            return 0
        quarantine(LinuxFilterDriver(), *targets)
    except (ValueError, OSError, sqlite3.Error, FirewallError) as exc:
        print(f"Application quarantine failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
