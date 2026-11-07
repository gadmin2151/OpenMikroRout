"""Compile validated list criteria using developer-owned SQL and bound values."""

import ipaddress
import math
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from typing import Any

from app.list_filters import Condition, FieldSpec, FilterNode, Group, parse_expression

SQLValue = str | int | float | None


class ListFilterError(ValueError):
    """A bounded expression is invalid for this display schema."""


@dataclass(frozen=True)
class SQLField:
    """Only source-owned expressions belong here; request keys never become SQL."""

    spec: FieldSpec
    expression: str
    values_from: str | None = None
    ipv4_range: tuple[str, str] | None = None
    parameters: tuple[SQLValue, ...] = ()


def _casefold(value: Any) -> str | None:
    return str(value).casefold() if value is not None else None


@lru_cache(maxsize=4096)
def _ipv4_integer(value: str) -> int | None:
    try:
        return int(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        return None


def _ip_integer(value: Any) -> int | None:
    return _ipv4_integer(str(value)) if value is not None else None


@lru_cache(maxsize=256)
def _decimal(value: str) -> Decimal | None:
    try:
        result = Decimal(value)
        return result if result.is_finite() else None
    except InvalidOperation:
        return None


def _number_compare(actual: Any, expected: str, operation: str) -> int:
    if actual is None or actual == "":
        return 0
    left, right = _decimal(str(actual)), _decimal(expected)
    if left is None or right is None:
        return 0
    operations = {
        "eq": left == right,
        "gt": left > right,
        "gte": left >= right,
        "lt": left < right,
        "lte": left <= right,
    }
    return int(operations.get(operation, False))


def register_list_filter_functions(db: sqlite3.Connection) -> None:
    """Register fixed pure functions per connection, without schema changes."""
    db.create_function("omr_casefold", 1, _casefold, deterministic=True)
    db.create_function("omr_ipv4_int", 1, _ip_integer, deterministic=True)
    db.create_function("omr_number_compare", 3, _number_compare, deterministic=True)
    db.create_function(
        "omr_remaining_seconds",
        2,
        lambda expiry, now: max(0, math.ceil(expiry - now)),
        deterministic=True,
    )


def _presence(field: SQLField) -> tuple[str, list[SQLValue]]:
    if field.ipv4_range:
        assert not field.parameters, "Range endpoints cannot contain expression parameters"
        low, high = field.ipv4_range
        return f"({low} IS NOT NULL AND {high} IS NOT NULL)", []
    return f"NULLIF(CAST({field.expression} AS TEXT),'') IS NOT NULL", list(field.parameters)


def _positive(condition: Condition, field: SQLField, operation: str) -> tuple[str, list[SQLValue]]:
    expression = field.expression
    parameters = list(field.parameters)
    value = condition.value
    if operation == "present":
        return _presence(field)
    if field.spec.kind == "number":
        return f"omr_number_compare({expression},?,?)", [*parameters, value, operation]
    if field.spec.kind == "ipv4":
        networks = [ipaddress.IPv4Network(part, strict=False) for part in value.split(",")]
        low, high = field.ipv4_range or (
            f"omr_ipv4_int({expression})",
            f"omr_ipv4_int({expression})",
        )
        alternatives = []
        operands: list[SQLValue] = []
        for network in networks:
            alternatives.append(f"({high}>=? AND {low}<=?)")
            operands.extend(
                [
                    *parameters,
                    int(network.network_address),
                    *parameters,
                    int(network.broadcast_address),
                ]
            )
        return "(" + " OR ".join(alternatives) + ")", operands
    if field.spec.kind not in ("text", "enum"):
        raise ValueError("This field is unavailable for SQL list filtering")
    folded = f"omr_casefold(NULLIF(CAST({expression} AS TEXT),''))"
    if operation == "eq":
        return f"{folded}=?", [*parameters, value.casefold()]
    if operation == "contains":
        return f"instr({folded},?)>0", [*parameters, value.casefold()]
    if operation == "in":
        values = [part.strip().casefold() for part in value.split(",")]
        return f"{folded} IN ({','.join('?' for _ in values)})", [*parameters, *values]
    raise ValueError("Unsupported SQL list filter operator")


def _condition(condition: Condition, field: SQLField) -> tuple[str, list[SQLValue]]:
    operation = condition.op
    negative = operation in {"neq", "not_contains", "not_in", "empty"}
    positive = {
        "neq": "eq",
        "not_contains": "contains",
        "not_in": "in",
        "empty": "present",
        "not_empty": "present",
    }.get(operation, operation)
    predicate, parameters = _positive(condition, field, positive)
    if field.values_from:
        predicate = f"EXISTS (SELECT 1 FROM {field.values_from} WHERE COALESCE({predicate},0))"
    else:
        predicate = f"COALESCE({predicate},0)"
    return (f"NOT ({predicate})" if negative else predicate), parameters


def _compile(node: FilterNode, fields: Mapping[str, SQLField]) -> tuple[str, list[SQLValue]]:
    if isinstance(node, Group):
        parts = [_compile(child, fields) for child in node.children]
        join = " AND " if node.join == "and" else " OR "
        return "(" + join.join(sql for sql, _ in parts) + ")", [
            parameter for _, parameters in parts for parameter in parameters
        ]
    return _condition(node, fields[node.field])


def compile_list_expression(
    expression: str | dict[str, Any] | FilterNode | None, fields: Mapping[str, SQLField]
) -> tuple[str, list[SQLValue]]:
    try:
        node = parse_expression(expression, {name: field.spec for name, field in fields.items()})
        return _compile(node, fields) if node is not None else ("1", [])
    except ValueError as exc:
        raise ListFilterError(str(exc)) from exc
