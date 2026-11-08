"""Compose router subsystems inside the existing durable configuration transaction."""

from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from app.application_guard import quarantine
from app.application_policy import active as applications_active
from app.compiler import FirewallError
from app.fail2ban_attempts import ConnectionAttemptCollector
from app.fail2ban_models import F2BConfiguration
from app.fail2ban_runtime import Fail2banService
from app.filtering import (
    FilterDriver,
    filter_counters,
    filter_patch,
    filter_rollback,
    wireguard_guard_patch,
    wireguard_guard_rollback,
)
from app.models import Configuration
from app.network_models import NetworkConfiguration
from app.rule_protection import effective_fail2ban
from app.system_list_runtime import SystemListRuntime

if TYPE_CHECKING:
    from app.application_runtime import ApplicationRuntime
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


class RoutingComponent(NetworkComponent, Protocol):
    def restore_guards(self, config: NetworkConfiguration) -> None: ...
    def protect(self, previous: NetworkConfiguration, target: NetworkConfiguration) -> None: ...
    def finalize(self) -> None: ...
    def protect_rollback(self, snapshot: dict[str, Any]) -> None: ...
    def finish_rollback(self, snapshot: dict[str, Any]) -> None: ...


class RouterRuntime:
    def __init__(
        self,
        network: NetworkComponent,
        links: LinkComponent,
        filters: FilterDriver,
        wireguard: WireGuardComponent | None = None,
        vpn_routes: RoutingComponent | None = None,
        system_lists: SystemListRuntime | None = None,
        fail2ban: Fail2banService | None = None,
        attempts: ConnectionAttemptCollector | None = None,
        applications: "ApplicationRuntime | None" = None,
    ) -> None:
        self.network = network
        self.links = links
        self.filters = filters
        self.wireguard = wireguard
        self.vpn_routes = vpn_routes
        self.system_lists = system_lists
        self.fail2ban = fail2ban
        self.attempts = attempts
        self.applications = applications
        self.applications_failed = False

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

    def restore_guards(self, applied: Configuration) -> None:
        """Protect the confirmed configuration before any fallible startup dependency."""
        quarantine(self.filters, applied)
        if self.vpn_routes:
            self.vpn_routes.restore_guards(applied.network)
        self.filters.restore(wireguard_guard_patch(self.filters.snapshot(), applied))

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
        if self.applications:
            snapshot["applications"] = self.applications.snapshot(previous)
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
        epoch = None
        if self.applications:
            self.applications.check(target)
            epoch = self.applications.epoch_for(target)
            if applications_active(previous) or applications_active(target):
                self.applications.mangle_apply(
                    self.applications.mangle_snapshot(), target, epoch, test=True
                )
        self.filters.restore(
            filter_patch(self.filters.snapshot(), target, application_epoch=epoch), test=True
        )

    def preview(self, previous: Configuration, target: Configuration) -> dict[str, Any]:
        preview = {
            "links": self.links.preview(previous.network, target.network),
            "network": self.network.preview(previous.network, target.network),
            "filter_script": filter_patch(
                self.filters.snapshot(),
                target,
                application_epoch=self.applications.epoch_for(target)
                if self.applications
                else None,
            ),
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
        if self.applications:
            preview["applications"] = {
                "enabled": target.applications.enabled,
                "mode": target.applications.mode,
                "rules": len(target.applications.rules),
                "kernel_verified": self.applications.capabilities()["kernel_verified"],
            }
        return preview

    def apply(self, previous: Configuration, target: Configuration) -> None:
        quarantine(self.filters, previous, target)
        if self.vpn_routes:
            self.vpn_routes.protect(previous.network, target.network)
        self.filters.restore(wireguard_guard_patch(self.filters.snapshot(), target, previous))
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
        epoch = None
        if self.applications:
            self.applications.apply(target)
            epoch = self.applications.epoch_for(target)
            if applications_active(previous) or applications_active(target):
                self.applications.mangle_apply(self.applications.mangle_snapshot(), target, epoch)
            self.applications_failed = False
        self.filters.restore(filter_patch(self.filters.snapshot(), target, application_epoch=epoch))
        if self.fail2ban:
            self.fail2ban.apply(effective_fail2ban(previous), effective_fail2ban(target))
        if self.vpn_routes:
            self.vpn_routes.finalize()

    def rollback(self, snapshot: dict[str, Any]) -> None:
        errors: list[str] = []
        previous_app = None
        if self.applications and "applications" in snapshot:
            previous_app = Configuration.model_validate(snapshot["applications"]["configuration"])
            quarantine(self.filters, self.applications.config, previous_app)
        # Establish confinement before restoring any dependency or relaxing filter state.
        if "vpn_routes" in snapshot and self.vpn_routes:
            self.vpn_routes.protect_rollback(snapshot["vpn_routes"])
        if "filter" in snapshot:
            self.filters.restore(
                wireguard_guard_rollback(self.filters.snapshot(), snapshot["filter"])
            )
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
                payload = filter_rollback(
                    self.filters.snapshot(),
                    snapshot["filter"],
                    keep_wireguard_guards=True,
                    keep_application_guards=previous_app is not None,
                )
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
        if self.applications and previous_app is not None:
            try:
                was_active = applications_active(self.applications.config)
                self.applications.rollback(snapshot["applications"])
                if was_active or applications_active(previous_app):
                    self.applications.mangle_apply(
                        self.applications.mangle_snapshot(),
                        previous_app,
                        self.applications.epoch_for(previous_app),
                    )
                self.applications_failed = False
            except (FirewallError, OSError, ValueError) as exc:
                errors.append(f"Application recovery: {exc}")
        if errors:
            raise FirewallError("; ".join(errors)[:1500])
        if "filter" in snapshot:
            if previous_app is not None and self.applications and applications_active(previous_app):
                self.filters.restore(
                    filter_patch(
                        self.filters.snapshot(),
                        previous_app,
                        application_epoch=self.applications.epoch_for(previous_app),
                    )
                )
            else:
                self.filters.restore(filter_rollback(self.filters.snapshot(), snapshot["filter"]))
        if "vpn_routes" in snapshot and self.vpn_routes:
            self.vpn_routes.finish_rollback(snapshot["vpn_routes"])

    def status(self) -> dict[str, Any]:
        result = {**self.network.status(), **self.links.status()}
        if self.wireguard:
            result["wireguard"] = self.wireguard.status()
        if self.vpn_routes:
            result["vpn_routes"] = self.vpn_routes.status()
        if self.applications:
            result["applications"] = self.applications.status()
        return result

    def counters(self) -> dict[str, dict[str, int]]:
        return filter_counters(self.filters.snapshot(with_counters=True))

    def shutdown_applications(self) -> None:
        if self.applications:
            quarantine(self.filters, self.applications.config)
            self.applications.close()

    def guard_application_health(self) -> None:
        applications = self.applications
        if (
            applications
            and applications.config.applications.enabled
            and not self.applications_failed
            and (applications_active(applications.config) or applications.process is not None)
            and not applications.status()["healthy"]
        ):
            enforcing = applications_active(applications.config)
            if enforcing:
                quarantine(self.filters, applications.config)
            self.applications_failed = True
            applications.stop()
            applications.error = (
                "Application engine failed or license changed; scope quarantined"
                if enforcing
                else "Application observer stopped: engine, profile, license or integrity changed"
            )

    def maintain(self) -> None:
        self.guard_application_health()
        if self.applications:
            self.applications.maintain()
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
