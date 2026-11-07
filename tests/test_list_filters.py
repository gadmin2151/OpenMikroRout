"""Shared typed predicates preserve Boolean scope, exact values and request bounds."""

import json
from pathlib import Path

import pytest

from app import list_filters
from app.list_filters import (
    Condition,
    FieldSpec,
    compile_expression,
    matches_expression,
    parse_expression,
)

SCHEMA = {
    "name": FieldSpec("text"),
    "protocol": FieldSpec("enum", options=("tcp", "udp", "icmp")),
    "address": FieldSpec("ipv4"),
    "ports": FieldSpec("ports"),
    "bytes": FieldSpec("number"),
}


def condition(field: str, op: str = "eq", value: str = "") -> dict[str, object]:
    return {"kind": "condition", "field": field, "op": op, "value": value}


def test_nested_and_or_groups_preserve_precedence_and_whole_any_negation() -> None:
    raw = {
        "kind": "group",
        "join": "and",
        "children": [
            {
                "kind": "group",
                "join": "or",
                "children": [
                    condition("name", "contains", "ALPHA"),
                    condition("protocol", "eq", "UDP"),
                ],
            },
            condition("ports", "not_in", "53,1000-2000"),
        ],
    }
    predicate = compile_expression(parse_expression(raw, SCHEMA), SCHEMA)
    assert predicate({"name": "Alpha Router", "protocol": "tcp", "ports": [443, 8443]})
    assert predicate({"name": "Beta", "protocol": "udp", "ports": [443]})
    assert not predicate({"name": "Beta", "protocol": "tcp", "ports": [443]})
    assert not predicate({"name": "Alpha Router", "ports": [443, 1500]})
    assert predicate({"name": "Alpha Router"})  # Negative comparison complements missing.


@pytest.mark.parametrize("op", ["eq", "contains", "in", "gt", "empty"])
def test_only_type_appropriate_operators_are_allowed(op: str) -> None:
    allowed = {"eq", "gt", "empty"}
    raw = condition("bytes", op, "" if op == "empty" else "10")
    if op in allowed:
        assert parse_expression(raw, SCHEMA)
    else:
        with pytest.raises(ValueError):
            parse_expression(raw, SCHEMA)


def test_ipv4_host_membership_network_overlap_and_negation() -> None:
    row = {"address": ["192.0.2.0/24", "198.51.100.10-198.51.100.20"]}
    for op, value, expected in [
        ("eq", "192.0.2.17", True),
        ("in", "203.0.113.0/24,198.51.100.16/28", True),
        ("not_in", "203.0.113.0/24,198.51.100.16/28", False),
        ("neq", "198.51.100.15", False),
        ("in", "203.0.113.0/24", False),
        ("not_in", "203.0.113.0/24", True),
    ]:
        assert (
            matches_expression(
                row, parse_expression(condition("address", op, value), SCHEMA), SCHEMA
            )
            is expected
        )


def test_port_range_comparisons_use_any_endpoint_and_numbers_keep_precision() -> None:
    for op, value, expected in [
        ("eq", "1500", True),
        ("neq", "1500", False),
        ("gt", "1500", True),
        ("lt", "1500", True),
        ("gte", "2001", False),
        ("lte", "999", False),
    ]:
        ast = parse_expression(condition("ports", op, value), SCHEMA)
        assert matches_expression({"ports": "1000-2000"}, ast, SCHEMA) is expected
    ast = parse_expression(condition("bytes", "gt", "9007199254740992.0000000000000001"), SCHEMA)
    predicate = compile_expression(ast, SCHEMA)
    assert predicate({"bytes": "9007199254740992.0000000000000002"})
    assert not predicate({"bytes": "9007199254740992.0000000000000001"})
    assert not predicate({"bytes": None})


@pytest.mark.parametrize("value", [None, "", [], [None, ""]])
def test_missing_is_explicit_and_negative_comparison_is_complement(value: object) -> None:
    for op, expected in [("eq", False), ("neq", True), ("empty", True), ("not_empty", False)]:
        ast = parse_expression(
            condition("bytes", op, "" if op in ("empty", "not_empty") else "0"), SCHEMA
        )
        assert matches_expression({"bytes": value}, ast, SCHEMA) is expected
    assert matches_expression(
        {"bytes": 0}, parse_expression(condition("bytes", "not_empty"), SCHEMA), SCHEMA
    )


@pytest.mark.parametrize(
    "raw",
    [
        {**condition("name", "eq", "a"), "unknown": True},
        condition("unknown", "eq", "x"),
        condition("protocol", "eq", "shell"),
        condition("protocol", "contains", "tcp"),
        condition("bytes", "eq", "NaN"),
        condition("bytes", "eq", "1e999"),
        condition("bytes", "eq", "Infinity"),
        condition("address", "eq", "192.0.2.0/24"),
        condition("address", "in", "::/0"),
        condition("ports", "in", "443; id"),
        condition("ports", "gt", "80,443"),
        condition("name", "eq", ""),
        condition("name", "empty", "ignored"),
        {**condition("name", "eq", "a"), "value": 1},
        {**condition("name", "eq", "a"), "value": True},
        condition("name", "eq", "a" * 129),
        {"kind": "group", "join": "and", "children": []},
        {"kind": "group", "join": "xor", "children": [condition("name", "eq", "a")]},
        '{"kind":"condition","field":"name","op":"eq","value":"a","value":"b"}',
        "[" * 1500 + "0" + "]" * 1500,
        " " * 4097,
    ],
)
def test_invalid_values_unknown_keys_and_oversized_expressions_are_rejected(raw: object) -> None:
    with pytest.raises(ValueError):
        parse_expression(raw, SCHEMA)


def test_budget_is_checked_before_recursive_model_validation() -> None:
    leaf = condition("name", "eq", "a")
    assert parse_expression({"kind": "group", "join": "and", "children": [leaf] * 16}, SCHEMA)
    with pytest.raises(ValueError, match="16 conditions"):
        parse_expression({"kind": "group", "join": "and", "children": [leaf] * 17}, SCHEMA)
    node = leaf
    for _ in range(3):
        node = {"kind": "group", "join": "and", "children": [node]}
    assert parse_expression(node, SCHEMA)
    with pytest.raises(ValueError, match="depth"):
        parse_expression({"kind": "group", "join": "and", "children": [node]}, SCHEMA)
    # Encoded UTF-8, not only Python character count, bounds the request.
    with pytest.raises(ValueError, match="4096"):
        parse_expression(
            json.dumps(
                {
                    "kind": "group",
                    "join": "and",
                    "children": [condition("name", "eq", "я" * 128)] * 16,
                },
                ensure_ascii=False,
            ),
            SCHEMA,
        )


def test_condition_values_are_normalized_without_float_coercion() -> None:
    ast = parse_expression(condition("protocol", "in", " TCP, udp,TCP "), SCHEMA)
    assert isinstance(ast, Condition) and ast.value == "tcp,udp"
    ast = parse_expression(condition("address", "in", "192.0.2.17/24"), SCHEMA)
    assert isinstance(ast, Condition) and ast.value == "192.0.2.0/24"
    ast = parse_expression(condition("bytes", "eq", " 9007199254740993.001 "), SCHEMA)
    assert isinstance(ast, Condition) and ast.value == "9007199254740993.001"


def test_shared_browser_backend_query_fixtures() -> None:
    document = json.loads((Path(__file__).parent / "fixtures/query-expressions.json").read_text())
    schema = {
        name: FieldSpec(item["kind"], options=tuple(item.get("options", [])))
        for name, item in document["schema"].items()
    }
    for case in document["cases"]:
        ast = parse_expression(case["expression"], schema)
        if "canonical" in case:
            assert (ast.model_dump() if ast is not None else None) == case["canonical"], case[
                "name"
            ]
        predicate = compile_expression(ast, schema)
        for row in case["rows"]:
            assert predicate(row["row"]) is row["matches"], (case["name"], row)
    for case in document["invalid"]:
        with pytest.raises(ValueError):
            parse_expression(case["expression"], schema)


def test_compiled_predicate_reuses_typed_queries_and_caches_repeated_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ast = parse_expression(
        {
            "kind": "group",
            "join": "and",
            "children": [
                condition("address", "not_in", "192.0.2.0/24"),
                condition("address", "in", "198.51.100.0/24"),
            ],
        },
        SCHEMA,
    )
    original = list_filters.ipv4_intervals
    calls: list[str] = []

    def parse(value: str) -> list[tuple[int, int]]:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(list_filters, "ipv4_intervals", parse)
    predicate = compile_expression(ast, SCHEMA)
    for _ in range(5):
        assert predicate({"address": "198.51.100.17"})
    assert calls.count("192.0.2.0/24") == calls.count("198.51.100.0/24") == 1
    assert calls.count("198.51.100.17") == 5  # Two conditions share one parsed observation per row.
