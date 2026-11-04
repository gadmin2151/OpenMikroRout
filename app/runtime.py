"""Compose router subsystems inside the existing durable configuration transaction."""

from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from app.compiler import FirewallError
from app.filtering import FilterDriver, filter_counters, filter_patch, filter_rollback
from app.models import Configuration
from app.network_models import NetworkConfiguration

if TYPE_CHECKING:
    from app.wireguard_vault import WireGuardVault


class NetworkComponent(Protocol):
    def snapshot(self, previous: NetworkConfiguration) -> dict[str, Any]: ...
    def preview(
        self, previous: NetworkConfiguration, target: NetworkConfiguration
    ) -> dict[str, Any]: ...
    def check(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None: ...
    def apply(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None: ...
    def rollback(self, snapshot: dict[str, Any]) -> None: ...
    def status(self) -> dict[str, Any]: ...


class LinkComponent(NetworkComponent, Protocol):
    def finalize(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None: ...
    def prepare_rollback(self, snapshot: dict[str, Any]) -> None: ...


class WireGuardComponent(NetworkComponent, Protocol):
    def maintain(self) -> None: ...


class RouterRuntime:
    def __init__(
        self,
        network: NetworkComponent,
        links: LinkComponent,
        filters: FilterDriver,
        wireguard: WireGuardComponent | None = None,
        vpn_routes: NetworkComponent | None = None,
    ) -> None:
        self.network = network
        self.links = links
        self.filters = filters
        self.wireguard = wireguard
        self.vpn_routes = vpn_routes

    def snapshot(self, previous: Configuration) -> dict[str, Any]:
        snapshot = {
            "network": self.network.snapshot(previous.network),
            "links": self.links.snapshot(previous.network),
            "filter": self.filters.snapshot(),
        }
        if self.wireguard:
            snapshot["wireguard"] = self.wireguard.snapshot(previous.network)
        if self.vpn_routes:
            snapshot["vpn_routes"] = self.vpn_routes.snapshot(previous.network)
        return snapshot

    def check(self, previous: Configuration, target: Configuration) -> None:
        self.links.check(previous.network, target.network)
        if self.wireguard:
            self.wireguard.check(previous.network, target.network)
        if self.vpn_routes:
            self.vpn_routes.check(previous.network, target.network)
        self.network.check(previous.network, target.network)
        self.filters.restore(filter_patch(self.filters.snapshot(), target), test=True)

    def preview(self, previous: Configuration, target: Configuration) -> dict[str, Any]:
        preview = {
            "links": self.links.preview(previous.network, target.network),
            "network": self.network.preview(previous.network, target.network),
            "filter_script": filter_patch(self.filters.snapshot(), target),
        }
        if self.wireguard:
            preview["wireguard"] = self.wireguard.preview(previous.network, target.network)
        if self.vpn_routes:
            preview["vpn_routes"] = self.vpn_routes.preview(previous.network, target.network)
        return preview

    def apply(self, previous: Configuration, target: Configuration) -> None:
        self.links.apply(previous.network, target.network)
        if self.wireguard:
            self.wireguard.apply(previous.network, target.network)
        if self.vpn_routes:
            self.vpn_routes.apply(previous.network, target.network)
        self.network.apply(previous.network, target.network)
        self.links.finalize(previous.network, target.network)
        self.filters.restore(filter_patch(self.filters.snapshot(), target))

    def rollback(self, snapshot: dict[str, Any]) -> None:
        errors: list[str] = []
        # Old link shells must exist before old addresses and services can be restored.
        if "links" in snapshot:
            try:
                self.links.prepare_rollback(snapshot["links"])
            except (FirewallError, OSError) as exc:
                errors.append(f"Link recovery preparation: {exc}")
        if "filter" in snapshot:
            try:
                payload = filter_rollback(self.filters.snapshot(), snapshot["filter"])
                self.filters.restore(payload, test=True)
                self.filters.restore(payload)
            except (FirewallError, OSError) as exc:
                errors.append(f"Filter recovery: {exc}")
        if "wireguard" in snapshot and self.wireguard:
            try:
                self.wireguard.rollback(snapshot["wireguard"])
            except (FirewallError, OSError) as exc:
                errors.append(f"WireGuard recovery: {exc}")
        if "network" in snapshot:
            try:
                self.network.rollback(snapshot["network"])
            except (FirewallError, OSError) as exc:
                errors.append(f"IP/DHCP/DNS recovery: {exc}")
        if "vpn_routes" in snapshot and self.vpn_routes:
            try:
                self.vpn_routes.rollback(snapshot["vpn_routes"])
            except (FirewallError, OSError) as exc:
                errors.append(f"VPN routing recovery: {exc}")
        if "links" in snapshot:
            try:
                self.links.rollback(snapshot["links"])
            except (FirewallError, OSError) as exc:
                errors.append(f"Link recovery: {exc}")
        if errors:
            raise FirewallError("; ".join(errors)[:1500])

    def status(self) -> dict[str, Any]:
        result = {**self.network.status(), **self.links.status()}
        if self.wireguard:
            result["wireguard"] = self.wireguard.status()
        if self.vpn_routes:
            result["vpn_routes"] = self.vpn_routes.status()
        return result

    def counters(self) -> dict[str, dict[str, int]]:
        return filter_counters(self.filters.snapshot(with_counters=True))

    def maintain(self) -> None:
        if self.wireguard:
            self.wireguard.maintain()


def create_runtime(
    data_dir: Path,
    applied: Configuration,
    simulated: bool,
    wireguard_vault: "WireGuardVault | None" = None,
) -> RouterRuntime:
    from app.filtering import DemoFilterDriver, LinuxFilterDriver
    from app.links import DemoLinkDriver, LinuxLinkDriver
    from app.networking import DemoNetworkDriver, LinuxNetworkDriver
    from app.wireguard import DemoWireGuardDriver, LinuxWireGuardDriver
    from app.wireguard_routing import DemoWireGuardRouting, LinuxWireGuardRouting
    from app.wireguard_vault import WireGuardVault

    vault = wireguard_vault or WireGuardVault(data_dir, demo=simulated)

    if simulated:
        return RouterRuntime(
            DemoNetworkDriver(applied.network),
            DemoLinkDriver(applied.network),
            DemoFilterDriver(applied),
            DemoWireGuardDriver(applied.network, vault),
            DemoWireGuardRouting(applied.network),
        )
    links = LinuxLinkDriver(data_dir)
    return RouterRuntime(
        LinuxNetworkDriver(data_dir),
        links,
        LinuxFilterDriver(),
        LinuxWireGuardDriver(data_dir, applied.network, links, vault),
        LinuxWireGuardRouting(data_dir),
    )
