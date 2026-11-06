"""Local Fail2ban action bridge. Only structured, bounded ban-ticket input is accepted."""

import argparse
import ipaddress
import json
import math
import sys
from pathlib import Path

# This file is executed with the application's virtualenv by a system Python daemon.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.fail2ban_events import BanStore  # noqa: E402
from app.fail2ban_models import F2BConfiguration, profile_id  # noqa: E402
from app.geoip import GeoIPService  # noqa: E402
from app.ipsets import LinuxIPSetDriver  # noqa: E402


def process_event(data_dir: Path, profile: str, payload: str) -> bool:
    profile_id(profile)
    if len(payload) > 4096:
        raise ValueError("Event exceeds the allowed size")
    event = json.loads(payload)
    if not isinstance(event, dict) or set(event) != {"operation", "address", "started", "duration"}:
        raise ValueError("Invalid event shape")
    address = str(ipaddress.IPv4Address(event["address"]))
    started = float(event["started"])
    if not math.isfinite(started):
        raise ValueError("Invalid ticket timestamp")
    settings = F2BConfiguration.model_validate_json(
        (data_dir / "fail2ban" / "settings.json").read_text(encoding="utf-8")
    )
    store = BanStore(data_dir, LinuxIPSetDriver(data_dir))
    if event["operation"] == "unban":
        return store.unban(profile, address, started)
    if event["operation"] != "ban":
        raise ValueError("Unknown Fail2ban event")
    item = next((item for item in settings.profiles if item.id == profile), None)
    if not settings.enabled or item is None or not item.enabled:
        return False
    duration = int(event["duration"])
    country = str(GeoIPService(data_dir).lookup(address).get("country", "") or "")
    return store.ban(item, address, started, duration, country)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    payload = sys.stdin.read(4097)
    process_event(args.data_dir.resolve(), args.profile, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
