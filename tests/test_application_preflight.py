import json
from unittest.mock import patch

import pytest

from app.application_preflight import competing_nft_datapath, read_nft_ruleset
from app.compiler import FirewallError


def nft(*expressions: object) -> bytes:
    return json.dumps(
        {
            "nftables": [
                {
                    "rule": {
                        "family": "ip",
                        "table": "filter",
                        "chain": "PVEFW-FORWARD",
                        "expr": list(expressions),
                    }
                }
            ]
        }
    ).encode()


@pytest.mark.parametrize(
    "expression",
    [
        {"mangle": {"key": {"ct": {"key": "mark"}}, "value": 1}},
        {"mangle": {"key": {"ct": {"key": "helper"}}, "value": "ftp"}},
        {"flowtable": {"name": "fast"}},
        {"flow": {"op": "add", "flowtable": "fast"}},
        {"notrack": None},
        {"ct helper": {"name": "ftp"}},
        {"xt": {"type": "target", "name": "CONNMARK"}},
    ],
)
def test_native_writers_and_offload_fail_closed(expression: object) -> None:
    with pytest.raises(FirewallError, match="conflict"):
        competing_nft_datapath(nft(expression))


def test_read_only_ct_metadata_and_wireguard_skb_mark_are_compatible() -> None:
    competing_nft_datapath(
        nft(
            {"match": {"op": "==", "left": {"ct": {"key": "mark"}}, "right": 64}},
            {"mangle": {"key": {"meta": {"key": "mark"}}, "value": 0x4F4D0001}},
            {"xt": {"type": "match", "name": "connmark"}},
            {"accept": None},
        )
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"[" * 3000,
        b" " * (1024 * 1024 + 1),
        json.dumps({"nftables": [[[[[[[]]]]]]]}).encode().replace(b"[]", b"[" * 40 + b"]" * 40),
    ],
)
def test_untrusted_ruleset_output_is_bounded(raw: bytes) -> None:
    with pytest.raises(FirewallError):
        competing_nft_datapath(raw)


def test_missing_nft_does_not_silently_assume_safe_legacy_datapath() -> None:
    with (
        patch("app.application_preflight.shutil.which", return_value=None),
        pytest.raises(FirewallError, match="tooling"),
    ):
        read_nft_ruleset()


@pytest.mark.parametrize("queue", [5089, {"range": [5000, 5100]}, {"hash": "dynamic"}])
def test_foreign_native_queue_cannot_capture_router_input_packets(queue: object) -> None:
    with pytest.raises(FirewallError, match="queue conflicts"):
        competing_nft_datapath(nft({"queue": {"num": queue, "flags": ["bypass"]}}))


def test_owned_queue_and_foreign_unrelated_queue_remain_compatible() -> None:
    from app.application_preflight import verify_iptables_queue

    competing_nft_datapath(nft({"queue": {"num": 100}}))
    own = {
        "nftables": [
            {
                "rule": {
                    "family": "ip",
                    "table": "mangle",
                    "chain": "OMR_APP_QUEUE",
                    "comment": "openmikrorout:application-inspect",
                    "expr": [{"queue": {"num": 5089}}],
                }
            }
        ]
    }
    competing_nft_datapath(json.dumps(own).encode())
    verify_iptables_queue(["-A", "INPUT", "-j", "NFQUEUE", "--queue-num", "100"])
    for tokens in (
        ["-A", "INPUT", "-j", "NFQUEUE", "--queue-num", "5089", "--queue-bypass"],
        ["-A", "INPUT", "-j", "NFQUEUE", "--queue-balance", "5000:5100"],
    ):
        with pytest.raises(FirewallError, match="foreign NFQUEUE"):
            verify_iptables_queue(tokens)


def test_queue_chain_name_alone_never_grants_ownership() -> None:
    from app.application_preflight import verify_iptables_queue

    tokens = [
        "-A",
        "OMR_APP_QUEUE",
        "-m",
        "comment",
        "--comment",
        "openmikrorout:application-inspect",
        "-j",
        "NFQUEUE",
        "--queue-num",
        "5089",
    ]
    with pytest.raises(FirewallError, match="foreign NFQUEUE"):
        verify_iptables_queue(tokens)  # A same-named filter chain is foreign.
    verify_iptables_queue(tokens, allow_owned_mangle=True)
    tokens[tokens.index("--comment") + 1] = "foreign"
    with pytest.raises(FirewallError, match="foreign NFQUEUE"):
        verify_iptables_queue(tokens, allow_owned_mangle=True)
    for changes in ({"table": "filter"}, {"family": "inet"}, {"comment": "foreign"}):
        rule = {
            "family": "ip",
            "table": "mangle",
            "chain": "OMR_APP_QUEUE",
            "comment": "openmikrorout:application-inspect",
            "expr": [{"queue": {"num": 5089}}],
            **changes,
        }
        with pytest.raises(FirewallError, match="queue conflicts"):
            competing_nft_datapath(json.dumps({"nftables": [{"rule": rule}]}).encode())
