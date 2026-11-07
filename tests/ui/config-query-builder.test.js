import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import vm from "node:vm";
import {
  renderQueryBuilder,
  handleQueryBuilderAction,
  handleQueryBuilderInput,
  applyQueryBuilder,
  getAppliedQuery,
  compileQueryExpression,
  resetAllQueryBuilders,
} from "../../app/static/query-builder.js";
import {
  natQuerySchema,
  wireGuardQuerySchema,
  captureQuerySchema,
} from "../../app/static/config-filter-schemas.js";
import { isReadAction } from "../../app/static/access-ui.js";

afterEach(() => resetAllQueryBuilders());

function edit(scope, path, part, value) {
  const region = {
    dataset: { queryBuilder: scope },
    querySelector: () => null,
  };
  return handleQueryBuilderInput({
    target: {
      dataset: { queryPart: part, queryPath: path },
      value,
      closest: () => region,
    },
  });
}
function add(scope, path = "", kind = "condition") {
  return handleQueryBuilderAction({
    dataset: { action: "query-builder-add", scope, queryPath: path, kind },
  });
}

test("NAT builder alone applies grouped criteria and clearing remains a draft until Apply", () => {
  const source = readFileSync(
    new URL("../../app/static/app.js", import.meta.url),
    "utf8",
  );
  const predicate = source.slice(
    source.indexOf("function filteredRules()"),
    source.indexOf("function renderRules()"),
  );
  const rules = [
    { id: "web", name: "Web", chain: "dstnat", protocol: "tcp" },
    { id: "dns", name: "DNS", chain: "dstnat", protocol: "udp" },
    { id: "other", name: "Other", chain: "srcnat", protocol: "tcp" },
  ];
  renderQueryBuilder("nat", natQuerySchema(), {
    applyAction: "nat-query-apply",
  });
  add("nat");
  edit("nat", "0", "field", "name");
  edit("nat", "0", "op", "contains");
  edit("nat", "0", "value", "web");
  add("nat");
  edit("nat", "1", "field", "name");
  edit("nat", "1", "op", "contains");
  edit("nat", "1", "value", "dns");
  edit("nat", "", "join", "or");
  const context = vm.createContext({
    state: { config: { rules } },
    getAppliedQuery,
    compileQueryExpression,
    natQuerySchema,
  });
  vm.runInContext(predicate, context);
  const selected = () =>
    Array.from(vm.runInContext("filteredRules().map(row=>row.id)", context));
  assert.deepEqual(selected(), ["web", "dns", "other"]);
  applyQueryBuilder("nat");
  assert.deepEqual(selected(), ["web", "dns"]);
  edit("nat", "1", "value", "");
  assert.throws(() => applyQueryBuilder("nat"));
  assert.deepEqual(
    selected(),
    ["web", "dns"],
    "Invalid edits preserve the last applied filter",
  );
  handleQueryBuilderAction({
    dataset: { action: "query-builder-clear", scope: "nat" },
  });
  assert.deepEqual(selected(), ["web", "dns"]);
  applyQueryBuilder("nat");
  assert.deepEqual(selected(), ["web", "dns", "other"]);
  assert.ok(rules.every((row) => !("expression" in row)));
  assert.equal(isReadAction("nat-query-apply"), true);
});

test("configuration schemas filter IPv4 lists, booleans and port ranges without evaluating user code", () => {
  const node = (field, op, value) => ({ kind: "condition", field, op, value });
  const peers = [
    {
      name: "Alice",
      enabled: true,
      allowed_ips: ["10.7.0.2/32", "192.168.3.0/24"],
      endpoint_port: 51820,
    },
    {
      name: "Bob",
      enabled: false,
      allowed_ips: ["10.8.0.2/32"],
      endpoint_port: 443,
    },
  ];
  const ast = {
    kind: "group",
    join: "and",
    children: [
      node("allowed_ips", "in", "192.168.0.0/16"),
      node("enabled", "eq", "true"),
    ],
  };
  const matches = compileQueryExpression(ast, wireGuardQuerySchema());
  assert.deepEqual(
    peers.filter(matches).map((row) => row.name),
    ["Alice"],
  );
  assert.equal(
    compileQueryExpression(
      node("src_ports", "in", "400-500"),
      natQuerySchema(),
    )({ src_ports: "80,443" }),
    true,
  );
  assert.equal(
    compileQueryExpression(
      node("src_ports", "not_in", "400-500"),
      natQuerySchema(),
    )({ src_ports: "80,443" }),
    false,
  );
  assert.throws(() =>
    compileQueryExpression(node("__proto__", "eq", "x"), natQuerySchema()),
  );
});

test("capture query schema excludes acquisition interfaces and impossible empty-header operators", () => {
  const scope = "packet-capture";
  const markup = renderQueryBuilder(scope, captureQuerySchema(), {
    applyAction: "capture-query-apply",
  });
  assert.doesNotMatch(markup, /data-action="(?:apply|confirm)"/);
  add(scope);
  edit(scope, "0", "field", "source");
  edit(scope, "0", "op", "not_in");
  edit(scope, "0", "value", "192.0.2.0/24");
  const raw = applyQueryBuilder(scope);
  assert.equal(JSON.parse(raw).children[0].value, "192.0.2.0/24");
  assert.throws(() =>
    compileQueryExpression(
      { kind: "condition", field: "interface", op: "eq", value: "eth0" },
      captureQuerySchema(),
    ),
  );
  assert.throws(() =>
    compileQueryExpression(
      { kind: "condition", field: "source", op: "empty", value: "" },
      captureQuerySchema(),
    ),
  );
  assert.equal(isReadAction("capture-start"), false);
});
