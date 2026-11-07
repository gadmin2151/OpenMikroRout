"""Small, typed Boolean display filters shared by list and diagnostic views."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Annotated, Literal, TypeAlias, cast

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from app.models import port_spec

MAX_EXPRESSION_BYTES = 4096
MAX_CONDITIONS = 16
MAX_NODES = 31
MAX_DEPTH = 4
Operator = Literal[
    "eq",
    "neq",
    "contains",
    "not_contains",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "empty",
    "not_empty",
]
FieldKind = Literal["text", "enum", "ipv4", "ports", "number"]
_DECIMAL = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_DEFAULT_OPERATORS: dict[FieldKind, tuple[Operator, ...]] = {
    "text": ("eq", "neq", "contains", "not_contains", "empty", "not_empty"),
    "enum": ("eq", "neq", "in", "not_in", "empty", "not_empty"),
    "ipv4": ("eq", "neq", "in", "not_in", "empty", "not_empty"),
    "ports": ("eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte", "empty", "not_empty"),
    "number": ("eq", "neq", "gt", "gte", "lt", "lte", "empty", "not_empty"),
}


@dataclass(frozen=True)
class FieldSpec:
    kind: FieldKind
    operators: tuple[Operator, ...] | None = None
    options: tuple[str, ...] = ()


def operators_for(spec: FieldSpec) -> tuple[Operator, ...]:
    return spec.operators if spec.operators is not None else _DEFAULT_OPERATORS[spec.kind]


class Condition(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["condition"]
    field: str = Field(min_length=1, max_length=40, pattern=r"^[a-z][a-z0-9_]*$")
    op: Operator
    value: str = Field(default="", max_length=128)


class Group(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    kind: Literal["group"]
    join: Literal["and", "or"]
    children: list[Annotated[Condition | Group, Field(discriminator="kind")]] = Field(
        min_length=1, max_length=MAX_CONDITIONS
    )


Group.model_rebuild()
FilterNode: TypeAlias = Annotated[Condition | Group, Field(discriminator="kind")]
_ADAPTER: TypeAdapter[FilterNode] = TypeAdapter(FilterNode)
_NEGATIVE = {"neq": "eq", "not_contains": "contains", "not_in": "in"}
Interval: TypeAlias = tuple[int, int]
Scalar: TypeAlias = str | Decimal | Interval
Predicate: TypeAlias = Callable[[Mapping[str, object]], bool]


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate filter expression key")
        result[key] = value
    return result


def _budget(value: object) -> None:
    pending = [(value, 1)]
    nodes = conditions = 0
    while pending:
        item, depth = pending.pop()
        if depth > MAX_DEPTH or not isinstance(item, dict):
            raise ValueError("Filter expression exceeds depth four or has an invalid node")
        nodes += 1
        if item.get("kind") == "condition":
            conditions += 1
        elif item.get("kind") == "group" and isinstance(item.get("children"), list):
            pending.extend((child, depth + 1) for child in item["children"])
        else:
            raise ValueError("Invalid filter expression node")
        if nodes > MAX_NODES or conditions > MAX_CONDITIONS:
            raise ValueError("Filter expression exceeds 31 nodes or 16 conditions")


def number_value(value: str) -> Decimal:
    if not _DECIMAL.fullmatch(value):
        raise ValueError("Enter a decimal number without an exponent")
    return Decimal(value)


def port_intervals(value: str) -> list[Interval]:
    canonical = port_spec(value)
    if not canonical:
        raise ValueError("Enter a TCP/UDP port or range")
    result = []
    for part in canonical.split(","):
        limits = part.split("-")
        result.append((int(limits[0]), int(limits[-1])))
    return result


def ipv4_intervals(value: str) -> list[Interval]:
    parts = value.split(",")
    if len(parts) > MAX_CONDITIONS:
        raise ValueError("Choose at most 16 IPv4 networks")
    result = []
    for part in parts:
        network = ipaddress.IPv4Network(part.strip(), strict=False)
        result.append((int(network.network_address), int(network.broadcast_address)))
    return result


def _normalize(condition: Condition, spec: FieldSpec) -> Condition:
    if condition.op not in operators_for(spec):
        raise ValueError(f"Unsupported operator for {condition.field}")
    value = condition.value.strip()
    if condition.op in ("empty", "not_empty"):
        if value:
            raise ValueError("Empty/not-empty conditions do not accept a value")
    elif not value:
        raise ValueError(f"Enter a value for {condition.field}")
    elif spec.kind == "enum":
        parts = value.split(",") if condition.op in ("in", "not_in") else [value]
        options = {item.casefold(): item for item in spec.options}
        if len(parts) > MAX_CONDITIONS or any(
            part.strip().casefold() not in options for part in parts
        ):
            raise ValueError(f"Choose a valid option for {condition.field}")
        value = ",".join(dict.fromkeys(options[part.strip().casefold()] for part in parts))
    elif spec.kind == "ipv4":
        if condition.op in ("eq", "neq"):
            network = ipaddress.IPv4Network(value, strict=False)
            if network.prefixlen != 32:
                raise ValueError("Equality requires one IPv4 host; use in/not-in for subnets")
            value = str(network.network_address)
        else:
            ipv4_intervals(value)
            value = ",".join(
                dict.fromkeys(
                    str(ipaddress.IPv4Network(part.strip(), strict=False))
                    for part in value.split(",")
                )
            )
    elif spec.kind == "ports":
        intervals = port_intervals(value)
        if condition.op in ("gt", "gte", "lt", "lte") and (
            len(intervals) != 1 or intervals[0][0] != intervals[0][1]
        ):
            raise ValueError("Port comparisons require one port")
        value = port_spec(value)
    elif spec.kind == "number":
        number_value(value)
    return condition.model_copy(update={"value": value})


def parse_expression(raw: object, schema: Mapping[str, FieldSpec]) -> FilterNode | None:
    if raw is None or raw == "":
        return None
    try:
        if isinstance(raw, Condition | Group):
            raw = raw.model_dump(mode="json")
        if isinstance(raw, str):
            if len(raw.encode("utf-8")) > MAX_EXPRESSION_BYTES:
                raise ValueError("Filter expression exceeds 4096 bytes")
            value = json.loads(raw, object_pairs_hook=_json_object)
        else:
            encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            if len(encoded.encode("utf-8")) > MAX_EXPRESSION_BYTES:
                raise ValueError("Filter expression exceeds 4096 bytes")
            value = raw
        _budget(value)
        node = _ADAPTER.validate_python(value)
    except (ValidationError, json.JSONDecodeError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid filter expression") from exc

    def normalize(item: FilterNode) -> FilterNode:
        if isinstance(item, Condition):
            if item.field not in schema:
                raise ValueError("Unknown filter expression field")
            return _normalize(item, schema[item.field])
        return item.model_copy(update={"children": [normalize(child) for child in item.children]})

    return normalize(node)


def _raw_values(value: object) -> list[object]:
    values = value if isinstance(value, list | tuple | set) else [value]
    return [item for item in values if item is not None and item != ""]


def _actual(value: object, spec: FieldSpec) -> list[Scalar]:
    result: list[Scalar] = []
    for item in _raw_values(value):
        try:
            if spec.kind in ("text", "enum"):
                result.append(str(item).casefold())
            elif spec.kind == "ipv4" and isinstance(item, str):
                if "-" in item:
                    first, last = item.split("-", 1)
                    low, high = int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(last))
                    if low <= high:
                        result.append((low, high))
                else:
                    result.extend(ipv4_intervals(item))
            elif spec.kind == "ports" and not isinstance(item, bool):
                if isinstance(item, int) and 0 <= item <= 65535:
                    result.append((item, item))
                elif isinstance(item, str):
                    result.extend(port_intervals(item))
            elif spec.kind == "number" and not isinstance(item, bool):
                number = Decimal(str(item))
                if number.is_finite():
                    result.append(number)
        except (ValueError, InvalidOperation):
            continue  # Missing/malformed observations cannot satisfy a positive comparison.
    return result


def compile_expression(node: FilterNode | None, schema: Mapping[str, FieldSpec]) -> Predicate:
    """Compile validated query values once; cache observed fields once per row."""
    Cache: TypeAlias = dict[str, tuple[bool, list[Scalar]]]
    Evaluator: TypeAlias = Callable[[Mapping[str, object], Cache], bool]

    def compile_node(item: FilterNode) -> Evaluator:
        if isinstance(item, Group):
            children = [compile_node(child) for child in item.children]
            if item.join == "and":
                return lambda row, cache: all(child(row, cache) for child in children)
            return lambda row, cache: any(child(row, cache) for child in children)
        spec = schema[item.field]
        operator = _NEGATIVE.get(item.op, item.op)
        negative = item.op in _NEGATIVE
        wanted: list[Scalar]
        if item.op in ("empty", "not_empty"):
            wanted = []
        elif spec.kind == "ipv4":
            wanted = list(ipv4_intervals(item.value))
        elif spec.kind == "ports":
            wanted = list(port_intervals(item.value))
        elif spec.kind == "number":
            wanted = [number_value(item.value)]
        else:
            wanted = [
                value.casefold()
                for value in (item.value.split(",") if operator == "in" else [item.value])
            ]

        def evaluate(row: Mapping[str, object], cache: Cache) -> bool:
            if item.field not in cache:
                raw = row.get(item.field)
                cache[item.field] = (bool(_raw_values(raw)), _actual(raw, spec))
            present, values = cache[item.field]
            if item.op in ("empty", "not_empty"):
                return not present if item.op == "empty" else present
            found = False
            for actual in values:
                for expected in wanted:
                    if spec.kind in ("ipv4", "ports"):
                        low, high = cast(Interval, actual)
                        first, last = cast(Interval, expected)
                        matched = {
                            "gt": high > first,
                            "gte": high >= first,
                            "lt": low < first,
                            "lte": low <= first,
                        }.get(operator, low <= last and high >= first)
                    elif operator == "contains":
                        matched = cast(str, expected) in cast(str, actual)
                    elif operator in ("eq", "in"):
                        matched = actual == expected
                    else:
                        number, threshold = cast(Decimal, actual), cast(Decimal, expected)
                        matched = {
                            "gt": number > threshold,
                            "gte": number >= threshold,
                            "lt": number < threshold,
                            "lte": number <= threshold,
                        }[operator]
                    if matched:
                        found = True
                        break
                if found:
                    break
            return not found if negative else found

        return evaluate

    if node is None:
        return lambda _: True
    evaluate = compile_node(node)
    return lambda row: evaluate(row, {})


def matches_expression(
    row: Mapping[str, object], node: FilterNode | None, schema: Mapping[str, FieldSpec]
) -> bool:
    return compile_expression(node, schema)(row)
