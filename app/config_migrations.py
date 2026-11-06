"""Deterministic compatibility migrations before strict configuration validation."""

import re

MAX_STATIC_LIST_NAME = 40
MAX_STATIC_LISTS = 128


def migrate_legacy_address_lists(value: object) -> object:
    """Keep pre-system-list configs static without allowing ambiguous new names.

    The old schema allowed geo_*/f2b_* as arbitrary static names. New-shaped
    configurations stay strict; only legacy dictionaries get a deterministic,
    collision-free rename with their references. Never alter the caller's input.
    """
    if not isinstance(value, dict) or "system_lists" in value or "fail2ban" in value:
        return value
    rows = value.get("address_lists")
    if not isinstance(rows, list) or len(rows) > MAX_STATIC_LISTS:
        return value
    occupied = {
        item["name"].strip()
        for item in rows
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    renames: dict[str, str] = {}
    for row in rows:
        name = row.get("name") if isinstance(row, dict) else None
        name = name.strip() if isinstance(name, str) else name
        if (
            not isinstance(name, str)
            or not name.startswith(("geo_", "f2b_"))
            or name in renames
            or len(name) > MAX_STATIC_LIST_NAME
            or re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", name) is None
        ):
            continue
        base = "legacy_" + name
        candidate = base[:MAX_STATIC_LIST_NAME]
        suffix = 1
        while candidate in occupied:
            suffix += 1
            tail = f"_{suffix}"
            candidate = base[: MAX_STATIC_LIST_NAME - len(tail)] + tail
        renames[name] = candidate
        occupied.add(candidate)
    if not renames:
        return value
    migrated = value.copy()
    migrated["address_lists"] = [
        {**row, "name": renames.get(row["name"].strip(), row["name"])}
        if isinstance(row, dict) and isinstance(row.get("name"), str)
        else row
        for row in rows
    ]
    for key in ("rules", "filter_rules"):
        rules = value.get(key)
        if not isinstance(rules, list):
            continue
        migrated[key] = []
        for rule in rules:
            if not isinstance(rule, dict):
                migrated[key].append(rule)
                continue
            copied = rule.copy()
            for side in ("src_list", "dst_list"):
                reference = rule.get(side)
                if isinstance(reference, str) and reference.strip() in renames:
                    copied[side] = renames[reference.strip()]
            migrated[key].append(copied)
    return migrated
