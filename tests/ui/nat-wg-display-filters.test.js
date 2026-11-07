import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import vm from "node:vm";
import {
  renderWireGuard,
  handleWireGuardAction,
  resetWireGuard,
} from "../../app/static/wireguard-ui.js";
import { isReadAction } from "../../app/static/access-ui.js";
import { html, t } from "../../app/static/i18n.js";
import {
  compileQueryExpression,
  getAppliedQuery,
  handleQueryBuilderAction,
  handleQueryBuilderInput,
  resetAllQueryBuilders,
} from "../../app/static/query-builder.js";
import { natQuerySchema } from "../../app/static/config-filter-schemas.js";

const originalDocument = globalThis.document;
afterEach(() => {
  globalThis.document = originalDocument;
  resetWireGuard();
  resetAllQueryBuilders();
});
const source = readFileSync(
  new URL("../../app/static/app.js", import.meta.url),
  "utf8",
);
const functions = source.slice(
  source.indexOf("function filteredRules()"),
  source.indexOf("function updateRuleTable()"),
);
const rules = [
  { id: "web", name: "Public Web", chain: "dstnat", protocol: "tcp" },
  { id: "dns", name: "Local DNS", chain: "dstnat", protocol: "udp" },
  { id: "wan", name: "WAN", chain: "srcnat", protocol: "any" },
];
const node = (field, op, value) => ({ kind: "condition", field, op, value });
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

test("NAT uses only the applied Boolean builder and never mutates router rule data", () => {
  const before = globalThis.structuredClone(rules);
  let applied = null;
  const context = vm.createContext({
    state: { config: { rules } },
    getAppliedQuery: () => applied,
    compileQueryExpression,
    natQuerySchema,
  });
  vm.runInContext(functions, context);
  const selected = () =>
    Array.from(vm.runInContext("filteredRules().map(row => row.id)", context));
  assert.deepEqual(selected(), ["web", "dns", "wan"]);
  applied = {
    kind: "group",
    join: "or",
    children: [
      {
        kind: "group",
        join: "and",
        children: [
          node("chain", "eq", "dstnat"),
          node("protocol", "neq", "tcp"),
        ],
      },
      node("name", "contains", "wan"),
    ],
  };
  assert.deepEqual(selected(), ["dns", "wan"]);
  applied = null;
  assert.deepEqual(selected(), ["web", "dns", "wan"]);
  assert.deepEqual(rules, before);
  assert.equal(isReadAction("nat-query-apply"), true);
  assert.equal(isReadAction("apply"), false);
});

test("NAT renders one builder without legacy quick search, selectors or ! buttons", () => {
  const context = vm.createContext({
    state: { config: { rules }, pending: null },
    selected: new Set(),
    offline: false,
    canWrite: () => false,
    icon: () => "",
    html,
    t,
    getAppliedQuery: () => null,
    compileQueryExpression,
    natQuerySchema,
    renderQueryBuilder: (scope) =>
      `<details data-query-builder="${scope}"></details>`,
    ruleColumns: [],
    visibleColumns: new Set(),
    renderRuleRows: () => "",
    empty: () => "",
    isDemo: () => false,
  });
  vm.runInContext(functions, context);
  const markup = vm.runInContext("renderRules()", context);
  assert.equal((markup.match(/data-query-builder="nat"/g) || []).length, 1);
  assert.doesNotMatch(
    markup,
    /id="(?:search|chain-filter|protocol-filter)"|data-display-negate/,
  );
  assert.match(markup, /data-action="add" disabled/);
});

test("read users apply and clear grouped WireGuard peer criteria without APIs or old controls", async () => {
  const rows = {
    one: { hidden: false },
    two: { hidden: false },
    three: { hidden: false },
  };
  const count = { textContent: "" },
    empty = { hidden: true };
  globalThis.document = {
    querySelector(selector) {
      if (selector === "[data-wg-filter-count]") return count;
      if (selector === "[data-wg-filter-empty]") return empty;
      return rows[/data-wg-peer-row="([^"]+)"/.exec(selector)?.[1]] || null;
    },
  };
  const ctx = {
    state: {
      config: {
        network: {
          wireguard_interfaces: [{ name: "wg0" }, { name: "wg1" }],
          wireguard_peers: [
            {
              id: "one",
              name: "Alice",
              interface: "wg0",
              allowed_ips: ["10.7.0.2/32"],
            },
            {
              id: "two",
              name: "Bob",
              interface: "wg1",
              allowed_ips: ["10.8.0.2/32"],
            },
            {
              id: "three",
              name: "Carol",
              interface: "wg0",
              allowed_ips: ["10.9.0.2/32"],
            },
          ],
        },
      },
    },
    canWrite: () => false,
    e: String,
    icon: () => "",
    empty: () => "",
    api() {
      throw new Error("Display filtering must not invoke any API");
    },
  };
  const before = globalThis.structuredClone(ctx.state.config);
  const markup = renderWireGuard(ctx, true);
  assert.match(markup, /data-query-builder="wg-peers"/);
  assert.doesNotMatch(
    markup,
    /wg-peer-search|wg-peer-interface|wg-peer-negate|data-display-negate/,
  );
  add("wg-peers");
  edit("wg-peers", "0", "field", "interface");
  edit("wg-peers", "0", "op", "eq");
  edit("wg-peers", "0", "value", "wg0");
  add("wg-peers", "", "group");
  edit("wg-peers", "1", "join", "or");
  add("wg-peers", "1");
  edit("wg-peers", "1.0", "field", "allowed_ips");
  edit("wg-peers", "1.0", "op", "in");
  edit("wg-peers", "1.0", "value", "10.7.0.0/24");
  add("wg-peers", "1");
  edit("wg-peers", "1.1", "field", "name");
  edit("wg-peers", "1.1", "op", "eq");
  edit("wg-peers", "1.1", "value", "Bob");
  const apply = () =>
    handleWireGuardAction({ dataset: { action: "wg-query-apply" } }, ctx);
  await apply();
  assert.equal(rows.one.hidden, false);
  assert.equal(rows.two.hidden, true);
  assert.equal(rows.three.hidden, true);
  assert.equal(count.textContent, "1 / 3");
  assert.equal(empty.hidden, true);
  handleQueryBuilderAction({
    dataset: { action: "query-builder-clear", scope: "wg-peers" },
  });
  assert.equal(rows.two.hidden, true, "Clear remains a draft until Apply");
  await apply();
  assert.ok(Object.values(rows).every((row) => !row.hidden));
  assert.equal(count.textContent, "3 / 3");
  assert.equal(getAppliedQuery("wg-peers"), null);
  assert.deepEqual(ctx.state.config, before);
  assert.equal(isReadAction("wg-query-apply"), true);
  await assert.rejects(
    handleWireGuardAction({ dataset: { action: "wg-peer-new" } }, ctx),
    /full|read/,
  );
});
