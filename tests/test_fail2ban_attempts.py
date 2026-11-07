"""Bounds, identity validation, file privacy and lifecycle for the private collector."""

import errno
import os
import socket
import struct
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock
from uuid import UUID

import pytest

from app import fail2ban_attempts as module
from app.compiler import FirewallError
from app.fail2ban_attempts import (
    ConnectionAttemptCollector,
    MissingConntrack,
    UnverifiedConnection,
    parse_attempt,
)
from app.fail2ban_models import F2BConfiguration, F2BProfile, F2BServiceScope

PROFILE = "r_1234567890abcdef12"


def settings() -> F2BConfiguration:
    return F2BConfiguration(
        enabled=True,
        profiles=[
            F2BProfile(
                id=PROFILE,
                name="Service",
                enabled=True,
                service="connections",
                ports=[443],
                rule_id=UUID("12345678-90ab-cdef-1234-567890abcdef"),
                rule_table="filter",
                scope=F2BServiceScope(destinations=["2.2.2.2/32"]),
            )
        ],
    )


def payload(
    *,
    source: str = "1.1.1.1",
    connection: int = 42,
    sequence: int = 1,
    profile: str = PROFILE,
    ct: bool = True,
    info: int = 0,
    status: int = 14,
    state: int = 3,
    hook: int | None = 1,
    input_index: int = 2,
    output_index: int = 0,
) -> bytes:
    attr = module._attribute
    original = attr(
        1 | 0x8000, attr(1, socket.inet_aton(source)) + attr(2, socket.inet_aton("2.2.2.2"))
    )
    original += attr(
        2 | 0x8000,
        attr(1, b"\x06") + attr(2, struct.pack("!H", 50000)) + attr(3, struct.pack("!H", 443)),
    )
    data = struct.pack("!BBH", socket.AF_INET, 0, module.NFLOG_GROUP)
    data += attr(10, profile.encode() + b"\0") + attr(12, struct.pack("!I", sequence))
    if hook is not None:
        data += attr(1, struct.pack("!HBB", 0x0800, hook, 0))
        data += attr(4, struct.pack("!I", input_index)) + attr(5, struct.pack("!I", output_index))
    if ct:
        data += attr(
            18 | 0x8000,
            attr(1 | 0x8000, original)
            + attr(12, struct.pack("!I", connection))
            + attr(3, struct.pack("!I", status))
            + attr(4 | 0x8000, attr(1 | 0x8000, attr(1, bytes([state])))),
        )
        data += attr(19, struct.pack("!I", info))
    return data


def reply_observation(attempt: module.ConnectionAttempt) -> module.ConnectionAttempt:
    return replace(
        attempt,
        established=False,
        reply=True,
        hook=3 if attempt.hook == 1 else 2,
        input_index=0 if attempt.hook == 1 else attempt.output_index,
        output_index=attempt.input_index,
    )


def begin_handshake(
    collector: ConnectionAttemptCollector,
    attempt: module.ConnectionAttempt,
    now: float,
) -> None:
    collector._record(replace(attempt, established=False), now)
    collector._record(reply_observation(attempt), now + 0.0005)


def handshake(
    collector: ConnectionAttemptCollector,
    attempt: module.ConnectionAttempt,
    now: float,
) -> None:
    begin_handshake(collector, attempt, now)
    collector._record(attempt, now + 0.001)


def datagram(data: bytes) -> bytes:
    return module._NL_HEADER.pack(16 + len(data), module.LOG_PACKET, 0, 0, 0) + data


def test_parses_original_tcp_conntrack_identity_without_packet_payload() -> None:
    attempt = parse_attempt(payload())
    assert (attempt.source, attempt.destination, attempt.source_port, attempt.destination_port) == (
        "1.1.1.1",
        "2.2.2.2",
        50000,
        443,
    )
    assert attempt.connection_id == 42
    assert attempt.zone == 0


@pytest.mark.parametrize("source", ["127.0.0.1", "0.0.0.0", "224.0.0.1"])
def test_invalid_sources_cannot_create_events(source: str) -> None:
    with pytest.raises(ValueError):
        parse_attempt(payload(source=source))


@pytest.mark.parametrize("profile", ["web", PROFILE + "\n", "r_" + "0" * 19, "../../auth"])
def test_prefix_is_exact_generated_identifier(profile: str) -> None:
    with pytest.raises(ValueError):
        parse_attempt(payload(profile=profile))


def test_conntrack_metadata_mandatory_and_original_direction() -> None:
    with pytest.raises(MissingConntrack):
        parse_attempt(payload(ct=False))
    for info in (1, 3, 4, 5):
        with pytest.raises(UnverifiedConnection):
            parse_attempt(payload(info=info))
    with pytest.raises(MissingConntrack):
        parse_attempt(payload(hook=None))


def test_reply_requires_syn_ack_state_and_tracks_kernel_path() -> None:
    reply = parse_attempt(
        payload(info=3, state=2, status=10, hook=3, input_index=0, output_index=2)
    )
    assert reply.reply and not reply.established
    assert (reply.hook, reply.input_index, reply.output_index) == (3, 0, 2)


@pytest.mark.parametrize(
    "hook,incoming,outgoing", [(0, 2, 0), (1, 0, 0), (2, 2, 0), (2, 0, 3), (2, 2, 2)]
)
def test_missing_or_ambiguous_forward_path_is_not_bannable(
    tmp_path: Path, hook: int, incoming: int, outgoing: int
) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    handshake(
        collector, parse_attempt(payload(hook=hook, input_index=incoming, output_index=outgoing)), 1
    )
    assert collector.status()["events"] == 0
    assert collector.status()["unverified_path"]
    assert collector.status()["last_error"]
    collector.close()


@pytest.mark.parametrize("forward", [False, True])
def test_original_established_requires_matching_reply_hook_and_interfaces(
    tmp_path: Path, forward: bool
) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    attempt = parse_attempt(payload(hook=2 if forward else 1, output_index=3 if forward else 0))
    collector._record(replace(attempt, established=False), 1)
    collector._record(attempt, 2)  # Conntrack flags alone are insufficient.
    reply = reply_observation(attempt)
    collector._record(replace(reply, hook=1), 3)
    collector._record(replace(reply, input_index=99), 4)
    collector._record(replace(reply, output_index=99), 5)
    collector._record(replace(reply, connection_id=99), 6)
    collector._record(attempt, 7)
    assert collector.status()["events"] == 0
    collector._record(reply, 8)
    collector._record(attempt, 9)
    collector._record(attempt, 10)
    assert collector.status()["events"] == 1
    collector.close()


@pytest.mark.parametrize("status", [0, 2, 4, 8, 10, 12])
def test_confirmed_or_one_sided_status_does_not_prove_source_participation(status: int) -> None:
    with pytest.raises(UnverifiedConnection):
        parse_attempt(payload(status=status))


@pytest.mark.parametrize("state", [0, 1, 2, 4, 5, 6, 7, 8, 9])
def test_only_established_tcp_state_completes_a_handshake(state: int) -> None:
    with pytest.raises(UnverifiedConnection):
        parse_attempt(payload(state=state))


def test_spoofed_syns_never_create_bannable_events_even_when_confirmed(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    for index in range(20):
        for status in (0, 8):
            attempt = parse_attempt(payload(info=2, status=status, state=1, connection=index))
            collector._record(replace(attempt, source_port=50000 + index), index)
    assert collector.status()["events"] == 0
    assert collector.journal.path.read_bytes() == b""
    collector.close()


def test_loose_midstream_or_different_id_cannot_complete_pending_syn(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    attempt = parse_attempt(payload())
    collector._record(attempt, 1)
    collector._record(replace(attempt, established=False, connection_id=41), 2)
    collector._record(attempt, 3)
    assert collector.status()["events"] == 0
    assert collector.status()["unverified"] == 2
    collector.close()


def test_every_truncated_attribute_is_rejected_without_crashing() -> None:
    data = payload()
    for length in range(len(data)):
        with pytest.raises(ValueError):
            parse_attempt(data[:length])
    duplicate = data + module._attribute(10, PROFILE.encode() + b"\0")
    with pytest.raises(ValueError, match="duplicate"):
        parse_attempt(duplicate)


def test_retransmissions_are_deduplicated_but_new_handshake_counts(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    attempt = parse_attempt(payload())
    handshake(collector, attempt, 0)
    for tick in (1, 2, 400, 800):
        collector._record(attempt, tick)
    handshake(collector, replace(attempt, connection_id=43), 801)
    handshake(collector, replace(attempt, source_port=50001), 802)
    assert collector.status()["events"] == 3
    assert collector.status()["duplicates"] == 4
    assert len(collector.journal.path.read_text().splitlines()) == 3
    collector.close()


def test_late_established_packets_after_expiry_never_count_again(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    attempt = parse_attempt(payload())
    handshake(collector, attempt, 0)
    collector._record(attempt, 601)
    assert collector.status()["events"] == 1
    assert collector.status()["unverified"] == 1
    collector.close()


def test_capacity_never_evicts_identity_to_count_retransmissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "MAX_CONNECTIONS_PER_PROFILE", 1)
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    attempt = parse_attempt(payload())
    handshake(collector, attempt, 1)
    handshake(collector, replace(attempt, source_port=50001, connection_id=43), 2)
    collector._record(attempt, 3)
    assert collector.status()["events"] == 1
    assert collector.status()["overflows"] == 1
    assert collector.status()["duplicates"] == 1
    assert collector.status()["tracked_connections"] == 1
    # Once the whole detection window expires a new identity can be accepted.
    handshake(collector, replace(attempt, source_port=50001, connection_id=43), 604)
    assert collector.status()["events"] == 2
    collector.close()


def test_rate_limit_and_missing_metadata_are_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "MAX_EVENTS_PER_PROFILE_SECOND", 1)
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    handshake(collector, parse_attempt(payload()), 1)
    handshake(collector, parse_attempt(payload(connection=43)), 1.5)
    # Rate-limited proof is consumed: later ordinary data cannot be re-attributed.
    collector._record(parse_attempt(payload(connection=43)), 2)
    collector._consume(datagram(payload(ct=False)))
    assert collector.status()["events"] == 1
    assert collector.status()["rate_limited"] == 1
    assert collector.status()["missing_conntrack"] == 1
    assert collector.status()["last_error"]
    collector.close()


def test_profile_cache_and_rate_capacity_are_independent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "MAX_CONNECTIONS_PER_PROFILE", 2)
    monkeypatch.setattr(module, "MAX_EVENTS_PER_PROFILE_SECOND", 1)
    config = settings()
    other = config.profiles[0].model_copy(update={"id": "r_234567890abcdef123", "find_time": 1800})
    config.profiles.append(other)
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(config)
    attempt = parse_attempt(payload())
    handshake(collector, attempt, 1)
    handshake(collector, replace(attempt, source_port=50001), 1.2)
    handshake(collector, replace(attempt, source_port=50002), 1.4)
    handshake(collector, replace(attempt, profile=other.id), 1.6)
    assert collector.status()["events"] == 2
    assert collector.status()["overflows"] == collector.status()["rate_limited"] == 1
    assert collector.status()["tracked_connections"] == 3
    collector._record(attempt, 2)
    assert collector.status()["events"] == 2
    # The shorter profile expires independently of the longer profile's window.
    handshake(collector, replace(attempt, source_port=50003), 603)
    assert collector.status()["events"] == 3
    assert collector.status()["tracked_connections"] == 2
    collector.close()


def test_sequence_loss_and_wrap(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    begin_handshake(collector, parse_attempt(payload()), time.monotonic())
    for sequence in (0xFFFFFFFF, 0, 2):
        collector._consume(datagram(payload(sequence=sequence)))
    assert collector.status()["dropped"] == 1
    assert collector.status()["events"] == 1
    collector.close()


def test_ignored_loopback_is_not_reported_as_a_lost_event(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    begin_handshake(collector, parse_attempt(payload()), time.monotonic())
    collector._consume(datagram(payload(sequence=1)))
    collector._consume(datagram(payload(source="127.0.0.1", sequence=2)))
    collector._consume(datagram(payload(sequence=3)))
    assert collector.status()["events"] == 1
    assert collector.status()["dropped"] == 0
    collector.close()


def test_private_bounded_rotation_and_no_writes_after_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "LOG_MAX_BYTES", 125)
    collector = ConnectionAttemptCollector(tmp_path, demo=True)
    collector.configure(settings())
    for index in range(10):
        handshake(collector, parse_attempt(payload(connection=index)), index)
    files = list((tmp_path / "fail2ban").glob("attempts.log*"))
    assert len(files) == 4
    for file in files:
        assert file.stat().st_mode & 0o777 == 0o600
        assert file.stat().st_size <= 125
        assert "openmikrorout connection_attempt profile=" in file.read_text()
    collector.close()
    before = collector.journal.path.read_bytes()
    collector._record(parse_attempt(payload(connection=100)), 100)
    assert collector.journal.path.read_bytes() == before
    collector.close()


def test_disabled_and_demo_never_bind_network_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied() -> socket.socket:
        raise AssertionError("Unexpected socket")

    monkeypatch.setattr(module, "_open_socket", denied)
    for demo in (False, True):
        collector = ConnectionAttemptCollector(tmp_path, demo=demo)
        collector.start()
        collector.check(F2BConfiguration())
        collector.configure(F2BConfiguration())
        if demo:
            collector.configure(settings())
        collector.close()
        with pytest.raises(FirewallError, match="closed"):
            collector.configure(settings())


def test_journal_refuses_symlink(tmp_path: Path) -> None:
    directory = tmp_path / "fail2ban"
    directory.mkdir()
    target = tmp_path / "target"
    target.write_text("unchanged")
    os.symlink(target, directory / "attempts.log")
    with pytest.raises(OSError) as error:
        ConnectionAttemptCollector(tmp_path)
    assert error.value.errno == errno.ELOOP
    assert target.read_text() == "unchanged"


def test_netlink_overflow_and_fatal_socket_error_report_unhealthy(tmp_path: Path) -> None:
    collector = ConnectionAttemptCollector(tmp_path)
    collector._profiles = collector._selected(settings())
    fake = Mock(spec=socket.socket)
    fake.recvmsg.side_effect = [
        OSError(errno.ENOBUFS, "Netlink receive buffer full"),
        OSError(errno.EIO, "Socket unavailable"),
    ]
    collector._socket = fake
    collector._receive()
    status = collector.status()
    assert status["dropped"] == 1
    assert not status["healthy"]
    assert "Socket unavailable" in status["last_error"]
    assert status["events"] == 0
    collector.close()


def test_journal_write_failure_stops_capture_without_claiming_an_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = ConnectionAttemptCollector(tmp_path)
    collector._profiles = collector._selected(settings())
    begin_handshake(collector, parse_attempt(payload()), time.monotonic())
    fake = Mock(spec=socket.socket)
    fake.recvmsg.return_value = (datagram(payload()), [], 0, (0, 0))
    collector._socket = fake

    def failed_write(_attempt: module.ConnectionAttempt) -> None:
        raise OSError(errno.ENOSPC, "Connection journal is full")

    monkeypatch.setattr(collector.journal, "append", failed_write)
    collector._receive()
    status = collector.status()
    assert not status["healthy"]
    assert "Connection journal is full" in status["last_error"]
    assert status["events"] == 0
    assert status["tracked_connections"] == 1  # Pending proof is retained, never marked counted.
    collector.close()


def test_socket_configuration_never_claims_or_releases_protocol_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = Mock(spec=socket.socket)
    monkeypatch.setattr(socket, "AF_NETLINK", 16, raising=False)
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake))
    commands: list[bytes] = []

    def capture(_sock: socket.socket, _sequence: int, attributes: bytes) -> None:
        commands.append(attributes)

    monkeypatch.setattr(module, "_command", capture)
    module._open_socket()
    assert module._attributes(commands[0]) == {1: b"\x01"}  # Only group BIND.
    options = module._attributes(commands[1])
    assert 1 not in options
    assert options[2] == struct.pack("!IBB", 0, 1, 0)  # Metadata only, no copied payload.
    assert options[6] == struct.pack("!H", 5)  # Conntrack identity and loss sequence.
