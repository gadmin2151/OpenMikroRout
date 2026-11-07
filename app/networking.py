"""Owned IPv4 resources and dedicated dnsmasq services for OpenMikroRout."""

import ipaddress
import json
import logging
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any, Literal, ParamSpec, Protocol, TypeVar

from app.compiler import FirewallError
from app.link_models import planned_interface_names
from app.network_models import (
    ADDRESS_LABEL_SUFFIX,
    ROUTE_PROTOCOL,
    IpAddress,
    NetworkConfiguration,
    StaticRoute,
    interface_name,
)

log = logging.getLogger(__name__)
ServiceKind = Literal["dhcp", "dns"]
SERVICE_KINDS: tuple[ServiceKind, ...] = ("dhcp", "dns")
MAX_COMMAND_SECONDS = 10
P = ParamSpec("P")
T = TypeVar("T")


class NetworkError(FirewallError):
    """An operation could not safely change the application's network resources."""


def network_operation(operation: Callable[P, T]) -> Callable[P, T]:
    """Keep filesystem/host parsing failures inside the recoverable domain boundary."""

    @wraps(operation)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return operation(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            detail = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
            raise NetworkError(f"Cannot {operation.__name__} managed networking: {detail}") from exc

    return wrapped


class NetworkDriver(Protocol):
    def snapshot(self, previous: NetworkConfiguration) -> dict[str, Any]: ...
    def preview(
        self, previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> dict[str, Any]: ...
    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None: ...
    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None: ...
    def rollback(self, snapshot: dict[str, Any]) -> None: ...
    def status(self) -> dict[str, Any]: ...


def run_command(args: list[str]) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=MAX_COMMAND_SECONDS,
            check=False,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkError("Network command failed or exceeded its 10-second timeout") from exc
    if result.returncode:
        raise NetworkError(f"Network command rejected: {result.stderr.strip()[:500]}")
    return result.stdout


def _address_key(item: IpAddress) -> tuple[str, str]:
    return item.interface, item.address


def _route_key(item: StaticRoute) -> tuple[str, str, str, int]:
    return item.destination, item.gateway, item.interface, item.metric


def address_command(binary: str, operation: str, item: IpAddress) -> list[str]:
    args = [binary, "-4", "address", operation, item.address, "dev", item.interface]
    if operation == "add":
        args += ["label", item.interface + ADDRESS_LABEL_SUFFIX]
        if ipaddress.IPv4Interface(item.address).network.prefixlen < 31:
            args += ["broadcast", "+"]
    return args


def route_command(binary: str, operation: str, item: StaticRoute) -> list[str]:
    args = [binary, "-4", "route", operation, item.destination, "table", "main"]
    if item.gateway:
        args += ["via", item.gateway]
    if item.interface:
        args += ["dev", item.interface]
    return [*args, "metric", str(item.metric), "proto", ROUTE_PROTOCOL]


def bounded_service_logging(content: str | None, kind: str) -> str | None:
    """Prevent packet-triggered logs from filling the persistent data volume.

    Also normalize recovery snapshots from releases that wrote unbounded files.
    Lease persistence and startup errors are independent of this runtime log sink.
    """
    if content is None:
        return None
    lines = [
        line
        for line in content.splitlines()
        if line.strip().partition("=")[0].strip() not in {"log-facility", "log-async", "quiet-dhcp"}
    ]
    lines.append("log-facility=/dev/null")
    if kind == "dhcp":
        lines.append("quiet-dhcp")
    return "\n".join(lines) + "\n"


def dnsmasq_configs(config: NetworkConfiguration, directory: Path) -> dict[str, str | None]:
    """Keep DNS and DHCP listeners separate so enabling one cannot expose the other."""
    result: dict[str, str | None] = {"dhcp": None, "dns": None}
    servers = [item for item in config.dhcp_servers if item.enabled]
    common = [
        "# Managed by OpenMikroRout; do not edit",
        "bind-interfaces",
        "user=root",
        "group=root",
        "no-hosts",
        "no-resolv",
    ]
    if servers:
        lines = [
            *common,
            "port=0",
            f"pid-file={directory / 'dhcp.pid'}",
            f"dhcp-leasefile={directory / 'dhcp.leases'}",
            "dhcp-authoritative",
            "except-interface=lo",
        ]
        for name in sorted({server.interface for server in servers}):
            # bind-interfaces checks alias labels as well as primary interface names.
            lines += [f"interface={name}", f"interface={name}{ADDRESS_LABEL_SUFFIX}"]
        pools = {pool.name: pool for pool in config.pools}
        lease_limit = sum(
            int(ipaddress.IPv4Address(pools[server.pool].end))
            - int(ipaddress.IPv4Address(pools[server.pool].start))
            + 1
            for server in servers
        ) + len(config.dhcp_reservations)
        lines.append(f"dhcp-lease-max={max(lease_limit, 150)}")
        for server in servers:
            pool = pools[server.pool]
            netmask = ipaddress.IPv4Network(server.network).netmask
            tag = "s" + server.id.hex
            lines.append(
                f"dhcp-range=tag:{server.interface},set:{tag},{pool.start},{pool.end},{netmask},{server.lease_minutes}m"
            )
            lines.append(f"dhcp-option=tag:{tag},option:router,{server.gateway}")
            dns_servers = server.dns_servers or [server.gateway]
            lines.append(f"dhcp-option=tag:{tag},option:dns-server,{','.join(dns_servers)}")
            if config.dns.local_domain:
                lines.append(f"dhcp-option=tag:{tag},option:domain-name,{config.dns.local_domain}")
        enabled = {server.name: server for server in servers}
        for reservation in config.dhcp_reservations:
            if reservation.enabled and reservation.server in enabled:
                server = enabled[reservation.server]
                host = f",{reservation.hostname}" if reservation.hostname else ""
                lines.append(
                    f"dhcp-host=tag:{server.interface},{reservation.mac},{reservation.address}{host}"
                )
        result["dhcp"] = "\n".join(lines) + "\n"
    if config.dns.enabled:
        listeners = sorted(
            {
                str(ipaddress.IPv4Interface(item.address).ip)
                for item in config.addresses
                if item.enabled and item.interface in config.dns.listen_interfaces
            }
        )
        lines = [
            *common,
            "port=53",
            f"pid-file={directory / 'dns.pid'}",
            "domain-needed",
            "bogus-priv",
            "stop-dns-rebind",
            f"cache-size={config.dns.cache_size}",
        ]
        lines += [f"listen-address={address}" for address in listeners]
        lines += [f"server={server}" for server in config.dns.servers]
        if config.dns.local_domain:
            lines += [f"domain={config.dns.local_domain}", f"local=/{config.dns.local_domain}/"]
        for reservation in config.dhcp_reservations:
            if reservation.enabled and reservation.hostname:
                name = reservation.hostname
                if config.dns.local_domain:
                    name += "." + config.dns.local_domain
                lines.append(f"host-record={name},{reservation.address}")
        for record in config.dns_static:
            if record.enabled:
                lines.append(f"host-record={record.name},{record.address},{record.ttl}")
        result["dns"] = "\n".join(lines) + "\n"
    return {kind: bounded_service_logging(content, kind) for kind, content in result.items()}


def configuration_commands(
    previous: NetworkConfiguration, target: NetworkConfiguration, ip_binary: str = "ip"
) -> list[list[str]]:
    old_addresses = {_address_key(item): item for item in previous.addresses if item.enabled}
    addresses = {_address_key(item): item for item in target.addresses if item.enabled}
    old_routes = {_route_key(item): item for item in previous.routes if item.enabled}
    routes = {_route_key(item): item for item in target.routes if item.enabled}
    return [
        *(
            route_command(ip_binary, "del", item)
            for key, item in old_routes.items()
            if key not in routes
        ),
        *(
            address_command(ip_binary, "del", item)
            for key, item in old_addresses.items()
            if key not in addresses
        ),
        *(
            address_command(ip_binary, "add", item)
            for key, item in addresses.items()
            if key not in old_addresses
        ),
        *(
            route_command(ip_binary, "add", item)
            for key, item in routes.items()
            if key not in old_routes
        ),
    ]


def _preview(
    previous: NetworkConfiguration,
    target: NetworkConfiguration,
    directory: Path,
    ip_binary: str = "ip",
) -> dict[str, Any]:
    commands = configuration_commands(previous, target, ip_binary)
    configs = dnsmasq_configs(target, directory)
    lines = [shlex.join(command) for command in commands]
    if target.forwarding is not None:
        lines.append(f"# IPv4 forwarding → {int(target.forwarding)} (only if changed)")
    for kind, content in configs.items():
        lines += [f"\n# OpenMikroRout {kind} service", content or "# disabled"]
    return {
        "commands": commands,
        "dnsmasq": configs,
        "script": "\n".join(lines),
        "forwarding": target.forwarding,
    }


class LinuxNetworkDriver:
    def __init__(self, data_dir: Path) -> None:
        self.directory = data_dir.resolve() / "network"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.ip_binary = shutil.which("ip")
        self.dnsmasq_binary = shutil.which("dnsmasq")
        self.forwarding_file = Path("/proc/sys/net/ipv4/ip_forward")

    def _ip(self) -> str:
        if not self.ip_binary:
            raise NetworkError("Install iproute2 to manage IP addresses and routes")
        return self.ip_binary

    def _addresses(self) -> list[dict[str, Any]]:
        rows = json.loads(run_command([self._ip(), "-j", "-4", "address", "show"]))
        result = []
        for row in rows:
            for item in row.get("addr_info", []):
                if item.get("family") != "inet":
                    continue
                name = row["ifname"]
                managed = item.get("label") == name + ADDRESS_LABEL_SUFFIX
                address = f"{item['local']}/{item['prefixlen']}"
                ipaddress.IPv4Interface(address)
                if managed:
                    IpAddress(interface=name, address=address)
                result.append(
                    {
                        "interface": name,
                        "address": address,
                        "managed": managed,
                        "secondary": bool(item.get("secondary", False)),
                    }
                )
        return result

    def _routes(self) -> list[dict[str, Any]]:
        rows = json.loads(
            run_command([self._ip(), "-j", "-N", "-4", "route", "show", "table", "main"])
        )
        result = []
        for row in rows:
            managed = str(row.get("protocol", "")) == ROUTE_PROTOCOL
            if managed and (row.get("type", "unicast") != "unicast" or "multipath" in row):
                raise NetworkError("Reserved route protocol 196 contains an unsupported route")
            if managed:
                StaticRoute(
                    destination="0.0.0.0/0"
                    if row.get("dst") == "default"
                    else row.get("dst", "0.0.0.0/0"),
                    gateway=row.get("gateway", ""),
                    interface=row.get("dev", ""),
                    metric=row.get("metric", 0),
                )
            result.append(
                {
                    "destination": "0.0.0.0/0"
                    if row.get("dst") == "default"
                    else row.get("dst", "0.0.0.0/0"),
                    "gateway": row.get("gateway", ""),
                    "interface": row.get("dev", ""),
                    "metric": row.get("metric", 0),
                    "managed": managed,
                }
            )
        return result

    def _forwarding(self) -> bool:
        try:
            return self.forwarding_file.read_text().strip() == "1"
        except OSError as exc:
            raise NetworkError("Cannot read Linux IPv4 forwarding state") from exc

    def _link_states(self) -> dict[str, bool]:
        rows = json.loads(run_command([self._ip(), "-j", "link", "show"]))
        return {item["ifname"]: "UP" in item.get("flags", []) for item in rows}

    def _admin_registry(self) -> dict[str, bool]:
        path = self.directory / "admin-up.json"
        if not path.exists():
            return {}
        if path.is_symlink() or path.stat().st_size > 65536:
            raise NetworkError("Managed interface state registry is not a regular bounded file")
        try:
            values = json.loads(path.read_text())
            if not isinstance(values, dict) or any(
                not isinstance(name, str) or not isinstance(up, bool) for name, up in values.items()
            ):
                raise ValueError("Invalid administrative state registry")
            # Validation also keeps stored state from becoming arbitrary command arguments.
            for name in values:
                interface_name(name)
            return values
        except (OSError, ValueError) as exc:
            raise NetworkError("Cannot read managed interface administrative state") from exc

    def _bring_up(self, target: NetworkConfiguration) -> None:
        disabled = {
            item.name
            for item in (
                *target.bridges,
                *target.vlans,
                *target.virtual_interfaces,
                *target.wireguard_interfaces,
            )
            if not item.enabled
        }
        required = {item.interface for item in target.addresses if item.enabled}
        required.update(item.interface for item in target.routes if item.enabled and item.interface)
        required.update(item.interface for item in target.dhcp_servers if item.enabled)
        if target.dns.enabled:
            required.update(target.dns.listen_interfaces)
        states = self._link_states()
        changes = sorted(
            name for name in required - disabled if name in states and not states[name]
        )
        registry = self._admin_registry()
        if changes:
            for name in changes:
                registry.setdefault(name, False)
            self._atomic_write(self.directory / "admin-up.json", json.dumps(registry))
            for name in changes:
                run_command([self._ip(), "link", "set", "dev", name, "up"])

    def _restore_admin_states(self, snapshot: dict[str, Any]) -> None:
        current_registry = self._admin_registry()
        old_registry = snapshot.get("admin_registry", {})
        current_states = self._link_states()
        old_states = snapshot.get("link_states", {})
        if not isinstance(old_registry, dict) or not isinstance(old_states, dict):
            raise NetworkError("Invalid administrative interface recovery state")
        for name in current_registry.keys() | old_registry.keys():
            interface_name(name)
            if name not in current_states or name not in old_states:
                continue
            if not isinstance(old_states[name], bool):
                raise NetworkError("Invalid interface recovery flag")
            if current_states[name] != old_states[name]:
                run_command(
                    [self._ip(), "link", "set", "dev", name, "up" if old_states[name] else "down"]
                )
        self._atomic_write(self.directory / "admin-up.json", json.dumps(old_registry))

    def _config_file(self, kind: str) -> Path:
        if kind not in SERVICE_KINDS:
            raise NetworkError("Unknown managed service")
        return self.directory / f"{kind}.conf"

    def _read_config(self, kind: str) -> str | None:
        path = self._config_file(kind)
        try:
            if path.exists():
                if path.is_symlink() or path.stat().st_size > 1_048_576:
                    raise NetworkError(
                        "Managed service configuration is not a regular bounded file"
                    )
                return path.read_text()
        except OSError as exc:
            raise NetworkError("Cannot read the managed service configuration") from exc
        return None

    def _owned_pid(self, kind: str) -> int | None:
        pid_file = self.directory / f"{kind}.pid"
        try:
            pid = int(pid_file.read_text().strip())
            if pid < 2:
                return None
            proc = Path(f"/proc/{pid}")
            argv = proc.joinpath("cmdline").read_bytes().split(b"\0")
            expected = f"--conf-file={self._config_file(kind)}".encode()
            executable = proc.joinpath("exe").resolve(strict=True)
            if expected in argv and executable.name == "dnsmasq":
                return pid
        except (OSError, ValueError):
            # A vanished process or stale pid file is an expected stopped-service state.
            return None
        return None

    @network_operation
    def snapshot(self, previous: NetworkConfiguration) -> dict[str, Any]:
        return {
            "version": 1,
            "addresses": [item for item in self._addresses() if item["managed"]],
            "routes": [item for item in self._routes() if item["managed"]],
            "forwarding": self._forwarding(),
            "link_states": self._link_states(),
            "admin_registry": self._admin_registry(),
            "dnsmasq": {kind: self._read_config(kind) for kind in SERVICE_KINDS},
        }

    @network_operation
    def preview(
        self, previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> dict[str, Any]:
        return _preview(previous, target, self.directory, self._ip())

    def _test_service_configs(self, configs: dict[str, str | None]) -> None:
        if not any(configs.values()):
            return
        if not self.dnsmasq_binary:
            raise NetworkError("Install dnsmasq-base (dnsmasq binary) to enable DHCP or DNS")
        with tempfile.TemporaryDirectory(prefix="check-", dir=self.directory) as directory:
            for kind, content in configs.items():
                content = bounded_service_logging(content, kind)
                if content:
                    path = Path(directory) / f"{kind}.conf"
                    path.write_text(content)
                    path.chmod(0o600)
                    run_command([self.dnsmasq_binary, "--test", f"--conf-file={path}"])

    @network_operation
    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        links = json.loads(run_command([self._ip(), "-j", "link", "show"]))
        available = {item["ifname"] for item in links} | planned_interface_names(target)
        required = {item.interface for item in target.addresses if item.enabled}
        required |= {item.interface for item in target.routes if item.enabled and item.interface}
        required |= {item.interface for item in target.dhcp_servers if item.enabled}
        required |= set(target.dns.listen_interfaces) if target.dns.enabled else set()
        missing = sorted(required - available)
        if missing:
            raise NetworkError(f"Unknown network interface(s): {', '.join(missing)}")
        addresses = self._addresses()
        for item in target.addresses:
            if not item.enabled:
                continue
            for live in addresses:
                if (
                    live["interface"] == item.interface
                    and live["address"] == item.address
                    and not live["managed"]
                ):
                    raise NetworkError(
                        f"Address {item.address} on {item.interface} belongs to "
                        "another network manager; use a new address"
                    )
        routes = self._routes()
        for configured_route in target.routes:
            if configured_route.enabled and any(
                live["destination"] == configured_route.destination
                and live["metric"] == configured_route.metric
                and not live["managed"]
                for live in routes
            ):
                raise NetworkError(
                    f"A non-managed route already uses {configured_route.destination} metric "
                    f"{configured_route.metric}; choose another metric"
                )
        self._test_service_configs(dnsmasq_configs(target, self.directory))

    def _sync_resources(self, addresses: list[IpAddress], routes: list[StaticRoute]) -> None:
        observed_addresses = self._addresses()
        current_addresses = {
            _address_key(IpAddress(interface=item["interface"], address=item["address"])): item
            for item in observed_addresses
            if item["managed"]
        }
        wanted_addresses = {_address_key(item): item for item in addresses}
        current_routes = {
            _route_key(
                StaticRoute(**{key: value for key, value in item.items() if key != "managed"})
            ): item
            for item in self._routes()
            if item["managed"]
        }
        wanted_routes = {_route_key(item): item for item in routes}
        for route_key, live_route in current_routes.items():
            if route_key not in wanted_routes:
                route = StaticRoute(
                    **{name: value for name, value in live_route.items() if name != "managed"}
                )
                run_command(route_command(self._ip(), "del", route))
        for address_key, live_address in current_addresses.items():
            if address_key not in wanted_addresses:
                address_network = ipaddress.IPv4Interface(live_address["address"]).network
                if not live_address.get("secondary", False) and any(
                    other["interface"] == live_address["interface"]
                    and not other["managed"]
                    and ipaddress.IPv4Interface(other["address"]).network == address_network
                    for other in observed_addresses
                ):
                    # Linux may remove secondary addresses when their primary is deleted.
                    raise NetworkError(
                        f"Cannot remove primary {live_address['address']} while foreign "
                        "addresses share its subnet; move them before retrying"
                    )
                run_command(
                    address_command(
                        self._ip(),
                        "del",
                        IpAddress(
                            interface=live_address["interface"], address=live_address["address"]
                        ),
                    )
                )
        for address_key, wanted_address in wanted_addresses.items():
            if address_key not in current_addresses:
                run_command(address_command(self._ip(), "add", wanted_address))
        for route_key, wanted_route in wanted_routes.items():
            if route_key not in current_routes:
                run_command(route_command(self._ip(), "add", wanted_route))

    def _write_forwarding(self, enabled: bool | None) -> None:
        if enabled is not None and self._forwarding() != enabled:
            try:
                self.forwarding_file.write_text("1\n" if enabled else "0\n")
            except OSError as exc:
                raise NetworkError(
                    "Cannot change IPv4 forwarding; check service /proc permissions"
                ) from exc

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".config-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                # The UP-intent registry must survive a power loss before a link is changed.
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _stop_service(self, kind: str) -> None:
        pid = self._owned_pid(kind)
        if pid is None:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError as exc:
            raise NetworkError(f"Cannot stop the managed {kind} service") from exc
        for _ in range(30):
            if self._owned_pid(kind) != pid:
                return
            time.sleep(0.1)
        raise NetworkError(f"Managed {kind} service did not stop within three seconds")

    def _configure_services(self, configs: dict[str, str | None]) -> None:
        for kind in SERVICE_KINDS:
            content = bounded_service_logging(configs.get(kind), kind)
            current = self._read_config(kind)
            running = self._owned_pid(kind) is not None
            if current == content and (bool(content) == running):
                continue
            self._stop_service(kind)
            path = self._config_file(kind)
            if content is None:
                if path.exists():
                    path.unlink()
                continue
            if not self.dnsmasq_binary:
                raise NetworkError("dnsmasq is unavailable while restoring a managed service")
            self._atomic_write(path, content)
            run_command([self.dnsmasq_binary, f"--conf-file={path}"])
            if self._owned_pid(kind) is None:
                raise NetworkError(f"Managed {kind} service exited during startup")

    @network_operation
    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        self._bring_up(target)
        self._sync_resources(
            [item for item in target.addresses if item.enabled],
            [item for item in target.routes if item.enabled],
        )
        self._write_forwarding(target.forwarding)
        self._configure_services(dnsmasq_configs(target, self.directory))

    @network_operation
    def rollback(self, snapshot: dict[str, Any]) -> None:
        if snapshot.get("version") != 1:
            raise NetworkError("Unsupported network recovery snapshot")
        addresses = [
            IpAddress(interface=item["interface"], address=item["address"])
            for item in snapshot["addresses"]
        ]
        routes = [
            StaticRoute(**{name: value for name, value in item.items() if name != "managed"})
            for item in snapshot["routes"]
        ]
        self._test_service_configs(snapshot["dnsmasq"])
        self._sync_resources(addresses, routes)
        self._write_forwarding(snapshot["forwarding"])
        self._configure_services(snapshot["dnsmasq"])
        self._restore_admin_states(snapshot)

    def _leases(self) -> list[dict[str, Any]]:
        path = self.directory / "dhcp.leases"
        if not path.exists():
            return []
        if path.stat().st_size > 2_097_152:
            raise NetworkError("DHCP lease file exceeds the status read limit")
        result = []
        invalid = 0
        for line in path.read_text().splitlines()[:16384]:
            parts = line.split()
            if len(parts) != 5:
                invalid += 1
                continue
            try:
                expires = int(parts[0])
                ipaddress.IPv4Address(parts[2])
            except ValueError:
                invalid += 1
                continue
            result.append(
                {
                    "expires": expires,
                    "mac": parts[1],
                    "address": parts[2],
                    "hostname": "" if parts[3] == "*" else parts[3],
                    "client_id": "" if parts[4] == "*" else parts[4],
                }
            )
        if invalid:
            log.warning("Ignored %d malformed DHCP lease entries", invalid)
        return result

    @network_operation
    def status(self) -> dict[str, Any]:
        return {
            "addresses": self._addresses(),
            "routes": self._routes(),
            "leases": self._leases(),
            "forwarding": self._forwarding(),
            "demo": False,
            "dnsmasq": {
                kind: {
                    "configured": bool(self._read_config(kind)),
                    "running": self._owned_pid(kind) is not None,
                }
                for kind in SERVICE_KINDS
            },
        }


class DemoNetworkDriver:
    def __init__(self, initial: NetworkConfiguration | None = None) -> None:
        self.active = (initial or NetworkConfiguration()).model_copy(deep=True)

    def snapshot(self, previous: NetworkConfiguration) -> dict[str, Any]:
        return {"version": 1, "config": self.active.model_dump(mode="json")}

    def preview(
        self, previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> dict[str, Any]:
        return _preview(previous, target, Path("/var/lib/openmikrorout/network"))

    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        NetworkConfiguration.model_validate(target.model_dump(mode="json"))

    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None:
        self.active = target.model_copy(deep=True)

    def rollback(self, snapshot: dict[str, Any]) -> None:
        self.active = NetworkConfiguration.model_validate(snapshot["config"])

    def status(self) -> dict[str, Any]:
        return {
            "addresses": [
                {"interface": item.interface, "address": item.address, "managed": True}
                for item in self.active.addresses
                if item.enabled
            ],
            "routes": [
                {
                    "destination": item.destination,
                    "gateway": item.gateway,
                    "interface": item.interface,
                    "metric": item.metric,
                    "managed": True,
                }
                for item in self.active.routes
                if item.enabled
            ],
            "leases": [],
            "forwarding": self.active.forwarding,
            "demo": True,
            "dnsmasq": {
                "dhcp": {
                    "configured": any(item.enabled for item in self.active.dhcp_servers),
                    "running": any(item.enabled for item in self.active.dhcp_servers),
                },
                "dns": {"configured": self.active.dns.enabled, "running": self.active.dns.enabled},
            },
        }
