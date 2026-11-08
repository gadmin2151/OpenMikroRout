"""Declarative OpenMikroRout scripts: typed data, never an executable shell or RouterOS VM."""

import json
import re
from typing import Any

from pydantic import ValidationError

from app.models import Configuration
from app.version import VERSION

HEADER = "# OpenMikroRout RSC 1"
MAX_SCRIPT = 1024 * 1024
SECTIONS = {
    "/interface bridge": "bridges",
    "/interface vlan": "vlans",
    "/interface virtual": "virtual_interfaces",
    "/interface wireguard": "wireguard_interfaces",
    "/interface list": "interface_lists",
    "/ip address": "addresses",
    "/ip route": "routes",
    "/ip pool": "pools",
    "/ip dhcp-server": "dhcp_servers",
    "/ip dhcp-server reservation": "dhcp_reservations",
    "/ip dns static": "dns_static",
    "/interface wireguard peers": "wireguard_peers",
    "/ip firewall address-list": "address_lists",
    "/ip firewall system-list": "system_lists",
    "/ip firewall nat": "rules",
    "/ip firewall filter": "filter_rules",
}
ROOT_LISTS = {"address_lists", "system_lists", "rules", "filter_rules"}
ROOT_SETTINGS = {
    "/applications settings": "applications",
    "/security fail2ban": "fail2ban",
    "/security geoip": "geoip",
    "/ip discovery": "discovery",
    "/tool scanning": "scanning",
}


class ScriptError(ValueError):
    pass


def encode_properties(properties: dict[str, Any]) -> str:
    return " ".join(
        key.replace("_", "-") + "=" + json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        for key, value in properties.items()
    )


def export_rsc(config: Configuration, *, max_bytes: int = MAX_SCRIPT) -> str:
    data = config.model_dump(mode="json")
    lines = [HEADER, f"# OpenMikroRout {VERSION}; secret values are omitted", ""]
    lines.append("/system web set " + encode_properties({"domain": data["web_domain"]}))
    lines.append(
        "/ip settings set " + encode_properties({"forwarding": data["network"]["forwarding"]})
    )
    lines.append("/ip dns set " + encode_properties(data["network"]["dns"]))
    for path, key in ROOT_SETTINGS.items():
        lines.append(path + " set " + encode_properties(data[key]))
    for path, key in SECTIONS.items():
        rows = data[key] if key in ROOT_LISTS else data["network"][key]
        lines.extend(["", "# " + path])
        lines.extend(path + " add " + encode_properties(row) for row in rows)
    result = "\n".join(lines) + "\n"
    if len(result.encode()) > max_bytes:
        raise ScriptError(f"Экспорт превышает допустимый размер {max_bytes // (1024 * 1024)} MiB")
    return result


def decode_properties(text: str, line: int) -> dict[str, Any]:
    result: dict[str, Any] = {}
    decoder = json.JSONDecoder()
    remaining = text.strip()
    while remaining and not remaining.startswith("#"):
        match = re.match(r"([a-z][a-z0-9-]{0,63})=", remaining)
        if not match:
            raise ScriptError(f"Строка {line}: ожидается параметр key=JSON-value")
        key = match[1].replace("-", "_")
        if key in result:
            raise ScriptError(f"Строка {line}: повторяющийся параметр {match[1]}")
        try:
            value, end = decoder.raw_decode(remaining[match.end() :])
        except (ValueError, RecursionError) as exc:
            raise ScriptError(
                f"Строка {line}: некорректное JSON-значение параметра {match[1]}"
            ) from exc
        tail = remaining[match.end() + end :]
        if tail and not tail[0].isspace():
            raise ScriptError(f"Строка {line}: после значения нужен пробел")
        result[key] = value
        remaining = tail.strip()
    return result


def import_rsc(text: str) -> Configuration:
    if len(text.encode()) > MAX_SCRIPT or "\x00" in text:
        raise ScriptError("Файл слишком большой или содержит недопустимые символы")
    lines = text.lstrip("\ufeff").splitlines()
    if not lines or lines[0].strip() != HEADER:
        raise ScriptError("Ожидается OpenMikroRout RSC 1. Скрипты RouterOS не исполняются")
    data = Configuration().model_dump(mode="json")
    scalars: set[str] = set()
    has_system_lists = False
    commands = {path + " add": key for path, key in SECTIONS.items()}
    commands.update(
        {"/system web set": "web", "/ip settings set": "settings", "/ip dns set": "dns"}
    )
    commands.update({path + " set": key for path, key in ROOT_SETTINGS.items()})
    for number, raw in enumerate(lines[1:], 2):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        command = next((prefix for prefix in commands if line.startswith(prefix + " ")), None)
        if command is None:
            raise ScriptError(f"Строка {number}: неподдерживаемая команда")
        key = commands[command]
        has_system_lists = has_system_lists or key == "system_lists"
        values = decode_properties(line[len(command) :], number)
        if key in ("web", "settings", "dns", *ROOT_SETTINGS.values()):
            if key in scalars:
                raise ScriptError(f"Строка {number}: раздел set уже задан")
            scalars.add(key)
            if key in ROOT_SETTINGS.values():
                data[key] = values
            elif key == "web":
                if set(values) != {"domain"}:
                    raise ScriptError(f"Строка {number}: ожидается только domain")
                data["web_domain"] = values["domain"]
            elif key == "settings":
                if set(values) != {"forwarding"}:
                    raise ScriptError(f"Строка {number}: ожидается только forwarding")
                data["network"]["forwarding"] = values["forwarding"]
            else:
                data["network"]["dns"] = values
        else:
            target = data if key in ROOT_LISTS else data["network"]
            target[key].append(values)
    if "fail2ban" not in scalars and not has_system_lists:
        # Pre-system-list RSC scripts must enter the same compatibility migration as
        # old JSON/backups; synthetic new defaults are not evidence of a new schema.
        data.pop("fail2ban", None)
        data.pop("system_lists", None)
    try:
        return Configuration.model_validate(data)
    except (ValueError, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            path = ".".join(str(p) for p in exc.errors(include_input=False)[0]["loc"])
            raise ScriptError(f"Неверная конфигурация в разделе {path}") from exc
        raise ScriptError("Конфигурация не прошла проверку") from exc
