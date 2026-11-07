"""The actual exported browser schemas must stay within server filter capabilities."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.connections import CONNECTION_FILTERS
from app.discovery import DISCOVERY_FILTER_FIELDS
from app.fail2ban_events import ban_filter_fields
from app.geoip import GEO_COUNTRY_FILTER_FIELDS, GEO_ENTRY_FILTER_FIELDS
from app.list_filters import FieldSpec, operators_for
from app.packet_capture import CAPTURE_FILTERS

ROOT = Path(__file__).resolve().parents[1]
# Fixed source imports the same schema exports and operator resolver used by the
# browser. No request data, source-text parsing, eval or generated JS is involved.
NODE_SCHEMA_SNAPSHOT = """
import { connectionQuerySchema } from './app/static/connections-ui.js';
import { hostQuerySchema } from './app/static/discovery-ui.js';
import {
  banQuerySchema, countryQuerySchema, systemListQuerySchema,
} from './app/static/protection-ui.js';
import { captureQuerySchema } from './app/static/config-filter-schemas.js';
import { operatorsForField } from './app/static/query-expression.js';

const snapshot = (schema) => schema.map((field) => ({
  field: field.field,
  kind: field.type,
  operators: operatorsForField(field),
  declaredOperators: field.operators ?? null,
  options: (field.options || []).map((option) =>
    String(Array.isArray(option) ? option[0] : option)),
}));
process.stdout.write(JSON.stringify({
  connections: snapshot(connectionQuerySchema),
  hosts: snapshot(hostQuerySchema),
  bans: snapshot(banQuerySchema),
  countries: snapshot(countryQuerySchema),
  country_entries: snapshot(systemListQuerySchema('geo_MD')),
  temporary_entries: snapshot(systemListQuerySchema('f2b_web')),
  capture: snapshot(captureQuerySchema()),
}));
"""

BACKEND_SCHEMAS: dict[str, dict[str, FieldSpec]] = {
    "connections": CONNECTION_FILTERS,
    "hosts": {name: field.spec for name, field in DISCOVERY_FILTER_FIELDS.items()},
    "bans": {name: field.spec for name, field in ban_filter_fields(1.0).items()},
    "countries": {name: field.spec for name, field in GEO_COUNTRY_FILTER_FIELDS.items()},
    "country_entries": {name: field.spec for name, field in GEO_ENTRY_FILTER_FIELDS.items()},
    "temporary_entries": {name: field.spec for name, field in ban_filter_fields(1.0).items()},
    "capture": CAPTURE_FILTERS,
}


@pytest.fixture(scope="module")
def browser_schemas() -> dict[str, list[dict[str, Any]]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to import the actual browser query schemas")
    result = subprocess.run(
        [node, "--input-type=module", "-"],
        input=NODE_SCHEMA_SNAPSHOT,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    schemas: dict[str, list[dict[str, Any]]] = json.loads(result.stdout)
    assert set(schemas) == set(BACKEND_SCHEMAS)
    return schemas


@pytest.mark.parametrize("scope", BACKEND_SCHEMAS)
def test_browser_fields_types_operators_and_enum_choices_are_server_supported(
    scope: str, browser_schemas: dict[str, list[dict[str, Any]]]
) -> None:
    fields = browser_schemas[scope]
    assert fields, f"{scope}: no browser filter fields were exported"
    names = [field["field"] for field in fields]
    assert len(names) == len(set(names)), f"{scope}: duplicate browser filter fields"
    backend = BACKEND_SCHEMAS[scope]
    assert set(names) <= backend.keys(), f"{scope}: unsupported browser fields"
    for field in fields:
        name = field["field"]
        spec = backend[name]
        assert field["kind"] == spec.kind, f"{scope}.{name}: browser/server kind drift"
        allowed = set(operators_for(spec))
        shown = field["operators"]
        assert shown and len(shown) == len(set(shown)), f"{scope}.{name}: invalid operator menu"
        assert set(shown) <= allowed, f"{scope}.{name}: unsupported browser operator"
        if field["declaredOperators"] is not None:
            assert set(field["declaredOperators"]) <= allowed, (
                f"{scope}.{name}: an explicitly declared browser operator is unsupported"
            )
        if spec.kind == "enum":
            options = [value.casefold() for value in field["options"]]
            assert options and len(options) == len(set(options)), (
                f"{scope}.{name}: empty or duplicate browser enum choices"
            )
            assert set(options) <= {value.casefold() for value in spec.options}, (
                f"{scope}.{name}: unsupported browser enum choice"
            )
