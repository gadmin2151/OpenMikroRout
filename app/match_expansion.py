"""Bounded IPv4 set arithmetic shared by validation and firewall compilation."""

import ipaddress
from collections.abc import Sequence

MAX_RULE_EXPANSION = 256


def address_list_matches(values: Sequence[str], *, negate: bool = False) -> list[str]:
    """Complement the union, never OR together individually negated members.

    Every emitted gap is final once the sorted, collapsed exclusions are known,
    so aborting at the bound cannot reject a later collapse to a smaller result.
    """
    if not negate:
        return list(values)
    excluded = ipaddress.collapse_addresses(ipaddress.IPv4Network(value) for value in values)
    cursor = 0
    result: list[str] = []

    def gap(start: int, stop: int) -> None:
        if start > stop:
            return
        for network in ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start), ipaddress.IPv4Address(stop)
        ):
            result.append(str(network))
            if len(result) > MAX_RULE_EXPANSION:
                raise ValueError("Negated address list expands beyond 256 IPv4 networks")

    for network in excluded:
        first, last = int(network.network_address), int(network.broadcast_address)
        gap(cursor, first - 1)
        cursor = last + 1
    gap(cursor, (1 << 32) - 1)
    return result
