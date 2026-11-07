"""Bounded, allowlisted negation of display criteria; never changes router rules."""

from collections.abc import Collection, Mapping


def parse_display_negation(
    value: object, *, allowed: Collection[str], maximum: int = 7
) -> list[str]:
    """Accept CSV or repeated query chunks, with limits before deduplication."""
    if value == "":
        return []
    chunks = [value] if isinstance(value, str) else value
    if not isinstance(chunks, list) or len(chunks) > maximum:
        raise ValueError("Too many negated display filters")
    result: list[str] = []
    for chunk in chunks:
        if not isinstance(chunk, str) or len(chunk) > 100:
            raise ValueError("Invalid negated display filter")
        result.extend(chunk.split(","))
        if len(result) > maximum:
            raise ValueError("Too many negated display filters")
    if any(field not in allowed for field in result):
        raise ValueError("Unknown display filter to negate")
    return list(dict.fromkeys(result))


def validate_display_negation(
    value: object, active: Mapping[str, object], *, maximum: int = 7
) -> list[str]:
    """An excluded criterion must have a value; other active criteria remain ANDed."""
    result = parse_display_negation(value, allowed=active.keys(), maximum=maximum)
    for field in result:
        current = active[field]
        if not (current.strip() if isinstance(current, str) else current):
            raise ValueError(f"Negation requires a non-empty {field} filter")
    return result
