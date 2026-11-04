"""Compose router subsystems inside the existing durable configuration transaction."""

from pathlib import Path
from typing import Any, Protocol

from app.compiler import FirewallError
from app.filtering import FilterDriver, filter_counters, filter_patch, filter_rollback
from app.models import Configuration
from app.network_models import NetworkConfiguration


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


class RouterRuntime:
    def __init__(
        self, network: NetworkComponent, links: LinkComponent, filters: FilterDriver
    ) -> None:
        self.network = network
        self.links = links
        self.filters = filters

    def snapshot(self, previous: Configuration) -> dict[str, Any]:
        return {
            "network": self.network.snapshot(previous.network),
            "links": self.links.snapshot(previous.network),
            "filter": self.filters.snapshot(),
        }

    def check(self, previous: Configuration, target: Configuration) -> None:
        self.links.check(previous.network, target.network)
        self.network.check(previous.network, target.network)
        self.filters.restore(filter_patch(self.filters.snapshot(), target), test=True)

    def preview(self, previous: Configuration, target: Configuration) -> dict[str, Any]:
        return {
            "links": self.links.preview(previous.network, target.network),
            "network": self.network.preview(previous.network, target.network),
            "filter_script": filter_patch(self.filters.snapshot(), target),
        }

    def apply(self, previous: Configuration, target: Configuration) -> None:
        self.links.apply(previous.network, target.network)
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
        if "network" in snapshot:
            try:
                self.network.rollback(snapshot["network"])
            except (FirewallError, OSError) as exc:
                errors.append(f"IP/DHCP/DNS recovery: {exc}")
        if "links" in snapshot:
            try:
                self.links.rollback(snapshot["links"])
            except (FirewallError, OSError) as exc:
                errors.append(f"Link recovery: {exc}")
        if errors:
            raise FirewallError("; ".join(errors)[:1500])

    def status(self) -> dict[str, Any]:
        return {**self.network.status(), **self.links.status()}

    def counters(self) -> dict[str, dict[str, int]]:
        return filter_counters(self.filters.snapshot(with_counters=True))


def create_runtime(data_dir: Path, applied: Configuration, simulated: bool) -> RouterRuntime:
    from app.filtering import DemoFilterDriver, LinuxFilterDriver
    from app.links import DemoLinkDriver, LinuxLinkDriver
    from app.networking import DemoNetworkDriver, LinuxNetworkDriver

    if simulated:
        return RouterRuntime(
            DemoNetworkDriver(applied.network),
            DemoLinkDriver(applied.network),
            DemoFilterDriver(applied),
        )
    return RouterRuntime(
        LinuxNetworkDriver(data_dir), LinuxLinkDriver(data_dir), LinuxFilterDriver()
    )
