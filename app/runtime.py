"""Compose router subsystems inside the existing durable configuration transaction."""

from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from app.compiler import FirewallError
from app.fail2ban_attempts import ConnectionAttemptCollector
from app.fail2ban_models import F2BConfiguration
from app.fail2ban_runtime import Fail2banService
from app.filtering import FilterDriver, filter_counters, filter_patch, filter_rollback
from app.models import Configuration
from app.network_models import NetworkConfiguration
from app.rule_protection import effective_fail2ban
from app.system_list_runtime import SystemListRuntime

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
        system_lists: SystemListRuntime | None = None,
        fail2ban: Fail2banService | None = None,
        attempts: ConnectionAttemptCollector | None = None,
    ) -> None:
        self.network = network
        self.links = links
        self.filters = filters
        self.wireguard = wireguard
        self.vpn_routes = vpn_routes
        self.system_lists = system_lists
        self.fail2ban = fail2ban
        self.attempts = attempts

    def prepare(self, target: Configuration, *, create: bool = True) -> None:
        if self.system_lists:
            self.system_lists.prepare(target, create=create)

    def recover_security(self, applied: Configuration) -> None:
        if self.system_lists:
            self.system_lists.recover(applied)
        if self.fail2ban:
            self.fail2ban.restore(effective_fail2ban(applied))
        if self.attempts:
            self.attempts.configure(effective_fail2ban(applied))

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
        if self.system_lists:
            snapshot["system_lists"] = self.system_lists.snapshot(previous)
        if self.fail2ban:
            snapshot["fail2ban"] = self.fail2ban.snapshot(effective_fail2ban(previous))
        if self.attempts:
            snapshot["connection_attempts"] = effective_fail2ban(previous).model_dump(mode="json")
        return snapshot

    def check(
        self, previous: Configuration, target: Configuration, *, allow_prepare: bool = True
    ) -> None:
        if self.attempts:
            self.attempts.check(effective_fail2ban(target))
        self.prepare(target, create=allow_prepare)
        if self.fail2ban:
            self.fail2ban.check(effective_fail2ban(previous), effective_fail2ban(target))
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
        if self.system_lists:
            preview["system_lists"] = self.system_lists.preview(target)
        if self.fail2ban:
            preview["fail2ban"] = self.fail2ban.preview(
                effective_fail2ban(previous), effective_fail2ban(target)
            )
        return preview

    def apply(self, previous: Configuration, target: Configuration) -> None:
        # Bind the private NFLOG group before installing rules that publish to it.
        # The durable router snapshot restores the previous subscription on failure.
        if self.attempts:
            self.attempts.configure(effective_fail2ban(target))
        if self.system_lists:
            self.system_lists.apply(target)
        self.links.apply(previous.network, target.network)
        if self.wireguard:
            self.wireguard.apply(previous.network, target.network)
        if self.vpn_routes:
            self.vpn_routes.apply(previous.network, target.network)
        self.network.apply(previous.network, target.network)
        self.links.finalize(previous.network, target.network)
        self.filters.restore(filter_patch(self.filters.snapshot(), target))
        if self.fail2ban:
            self.fail2ban.apply(effective_fail2ban(previous), effective_fail2ban(target))

    def rollback(self, snapshot: dict[str, Any]) -> None:
        errors: list[str] = []
        if self.system_lists and "system_lists" in snapshot:
            try:
                self.system_lists.rollback(snapshot["system_lists"])
            except (FirewallError, OSError) as exc:
                errors.append(f"System list recovery: {exc}")
        if self.attempts and "connection_attempts" in snapshot:
            try:
                self.attempts.configure(
                    F2BConfiguration.model_validate(snapshot["connection_attempts"])
                )
            except (FirewallError, OSError, ValueError) as exc:
                errors.append(f"Connection event recovery: {exc}")
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
        if self.fail2ban and "fail2ban" in snapshot:
            try:
                self.fail2ban.rollback(snapshot["fail2ban"])
            except (FirewallError, OSError) as exc:
                errors.append(f"Fail2ban recovery: {exc}")
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
