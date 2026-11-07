import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import vm from "node:vm";
import {
  matchesWireGuardPeer,
  renderWireGuard,
  handleWireGuardAction,
  handleWireGuardFilter,
  resetWireGuard,
} from "../../app/static/wireguard-ui.js";
import { isReadAction } from "../../app/static/access-ui.js";

const source = readFileSync(
  new URL("../../app/static/app.js", import.meta.url),
  "utf8",
);
const natPredicate = source.slice(
  source.indexOf("function filteredRules()"),
  source.indexOf("function syncNatFilterControls()"),
);
const rules = [
  { id: "web", name: "Public Web", chain: "dstnat", protocol: "tcp" },
  { id: "dns", name: "Local DNS", chain: "dstnat", protocol: "udp" },
  { id: "wan", name: "WAN", chain: "srcnat", protocol: "any" },
];

test("NAT table exclusions combine by criterion and leave router rule data untouched", () => {
  const context = vm.createContext({
    state: { config: { rules } },
    search: "",
    chainFilter: "",
    protocolFilter: "",
    natFilterNegations: new Set(),
  });
  vm.runInContext(natPredicate, context);
  const select = (search, chain, protocol, negate) => {
    Object.assign(context, {
      search,
      chainFilter: chain,
      protocolFilter: protocol,
      natFilterNegations: new Set(negate),
    });
    return Array.from(
      vm.runInContext("filteredRules().map(item => item.id)", context),
    );
  };
  assert.deepEqual(select("", "", "", []), ["web", "dns", "wan"]);
  assert.deepEqual(select("", "dstnat", "tcp", []), ["web"]);
  assert.deepEqual(select("", "dstnat", "tcp", ["protocol"]), ["dns"]);
  assert.deepEqual(select("", "dstnat", "", ["chain"]), ["wan"]);
  assert.deepEqual(select("web", "", "", ["search"]), ["dns", "wan"]);
  assert.deepEqual(
    select("dns", "srcnat", "tcp", ["search", "chain", "protocol"]),
    [],
  );
  assert.deepEqual(select("", "", "", ["search", "chain", "protocol"]), [
    "web",
    "dns",
    "wan",
  ]);
  assert.deepEqual(
    rules.map((row) => row.id),
    ["web", "dns", "wan"],
  );
  assert.ok(rules.every((row) => !("negate" in row)));
  assert.equal(isReadAction("nat-filter-negate"), true);
});

test("WireGuard peer exclusions preserve positive search and combine interface and query inversions", () => {
  const alice = {
    name: "Alice",
    interface: "wg0",
    allowed_ips: ["10.7.0.2/32"],
    comment: "admin",
  };
  const bob = { name: "Bob", interface: "wg1", allowed_ips: ["10.8.0.2/32"] };
  assert.equal(
    matchesWireGuardPeer(alice, { query: "ADMIN", interface: "wg0" }),
    true,
  );
  assert.equal(
    matchesWireGuardPeer(alice, { query: "admin", negate: ["query"] }),
    false,
  );
  assert.equal(
    matchesWireGuardPeer(bob, { query: "admin", negate: ["query"] }),
    true,
  );
  assert.equal(
    matchesWireGuardPeer(bob, { interface: "wg0", negate: ["interface"] }),
    true,
  );
  assert.equal(
    matchesWireGuardPeer(alice, {
      query: "Bob",
      interface: "wg1",
      negate: ["query", "interface"],
    }),
    true,
  );
  assert.equal(
    matchesWireGuardPeer(bob, {
      query: "",
      interface: "",
      negate: ["query", "interface"],
    }),
    true,
  );
});

test("Enter in a search form dispatches Search, never the first ! control", () => {
  const start = source.indexOf("function formSubmitAction(event)");
  const end = source.indexOf('document.addEventListener("submit"', start);
  const context = vm.createContext({});
  vm.runInContext(source.slice(start, end), context);
  const search = { matches: () => true };
  const negative = { matches: () => false };
  const legacySave = {};
  const form = {
    querySelector(selector) {
      if (selector.includes('[type="button"]')) return search;
      if (selector.includes("[data-display-negate]")) return legacySave;
      return negative;
    },
  };
  for (const submitter of [search, negative, undefined]) {
    context.event = { target: form, submitter };
    assert.equal(vm.runInContext("formSubmitAction(event)", context), search);
  }
  context.event = {
    target: {
      querySelector: (selector) =>
        selector.includes('[type="button"]') ? null : legacySave,
    },
  };
  assert.equal(vm.runInContext("formSubmitAction(event)", context), legacySave);
});

test("read users toggle peer display exclusions without replacing inputs or invoking any API", async () => {
  resetWireGuard();
  const originalDocument = globalThis.document;
  const controls = {
    "#wg-peer-search": { value: "Alice" },
    "#wg-peer-interface": { value: "" },
  };
  const buttons = {};
  for (const name of ["query", "interface"])
    buttons[name] = {
      disabled: true,
      setAttribute(name, value) {
        this[name] = value;
      },
    };
  const container = {
    querySelector(selector) {
      return (
        buttons[/data-display-negate="([^"]+)"/.exec(selector)?.[1]] || null
      );
    },
  };
  const rows = { one: { hidden: false }, two: { hidden: false } };
  const count = { textContent: "" },
    empty = { hidden: true };
  globalThis.document = {
    querySelector(selector) {
      if (selector === "#wg-display-filters") return container;
      if (selector === "[data-wg-filter-count]") return count;
      if (selector === "[data-wg-filter-empty]") return empty;
      const id = /data-wg-peer-row="([^"]+)"/.exec(selector)?.[1];
      return rows[id] || controls[selector] || null;
    },
  };
  const ctx = {
    state: {
      config: {
        network: {
          wireguard_interfaces: [{ name: "wg0" }],
          wireguard_peers: [
            { id: "one", name: "Alice", interface: "wg0", allowed_ips: [] },
            { id: "two", name: "Bob", interface: "wg0", allowed_ips: [] },
          ],
        },
      },
    },
    canWrite: () => false,
    e: String,
    icon: () => "",
    empty: () => "",
    api() {
      throw new Error("No API mutation allowed");
    },
  };
  try {
    handleWireGuardFilter({ target: { id: "wg-peer-search" } }, ctx);
    assert.equal(rows.one.hidden, false);
    assert.equal(rows.two.hidden, true);
    await handleWireGuardAction(
      { dataset: { action: "wg-peer-negate", displayNegate: "query" } },
      ctx,
    );
    assert.equal(rows.one.hidden, true);
    assert.equal(rows.two.hidden, false);
    assert.equal(controls["#wg-peer-search"].value, "Alice");
    assert.equal(buttons.query["aria-pressed"], "true");
    assert.equal(isReadAction("wg-peer-negate"), true);
    assert.match(
      renderWireGuard(ctx, true),
      /data-display-negate="query" aria-pressed="true"/,
    );
    controls["#wg-peer-search"].value = "";
    handleWireGuardFilter({ target: { id: "wg-peer-search" } }, ctx);
    assert.equal(buttons.query.disabled, true);
    assert.equal(buttons.query["aria-pressed"], "false");
    assert.equal(rows.one.hidden, false);
    assert.equal(rows.two.hidden, false);
  } finally {
    globalThis.document = originalDocument;
    resetWireGuard();
  }
});
