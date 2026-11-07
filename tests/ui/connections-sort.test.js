import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  handleConnectionsAction,
  refreshConnections,
  renderConnections,
  resetConnections,
  sortConnectionRows,
} from "../../app/static/connections-ui.js";
import { setLanguage } from "../../app/static/i18n.js";

const originalDocument = globalThis.document;
afterEach(() => {
  resetConnections();
  globalThis.document = originalDocument;
  setLanguage("ru");
});
const ids = (items) => items.map((item) => item.id);
const sort = (items, column, direction = "ascending", kind) =>
  sortConnectionRows(items, { column, direction }, kind);
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );

test("IPv4 endpoint columns sort numerically by address then port in both directions", () => {
  for (const [column, port] of [
    ["source", "source_port"],
    ["destination", "destination_port"],
    ["translated_destination", "translated_port"],
  ]) {
    const items = [
      { id: "ten", [column]: "10.0.0.10", [port]: 22 },
      { id: "two100", [column]: "10.0.0.2", [port]: 100 },
      { id: "two9", [column]: "10.0.0.2", [port]: 9 },
      { id: "two-none", [column]: "10.0.0.2", [port]: null },
      { id: "next", [column]: "10.0.1.1", [port]: 1 },
      { id: "none", [column]: "", [port]: 1 },
    ];
    assert.deepEqual(ids(sort(items, column)), [
      "two9",
      "two100",
      "two-none",
      "ten",
      "next",
      "none",
    ]);
    assert.deepEqual(ids(sort(items, column, "descending")), [
      "next",
      "ten",
      "two100",
      "two9",
      "two-none",
      "none",
    ]);
  }
});

test("numeric counters and active/attempt time use raw numbers with absent values always last", () => {
  for (const [column, key, kind] of [
    ["packets", "packets", "active"],
    ["bytes", "bytes", "active"],
    ["time", "expires_in", "active"],
    ["time", "last_seen", "attempts"],
  ]) {
    const items = [
      { id: "hundred", [key]: 100 },
      { id: "two", [key]: 2 },
      { id: "none", [key]: null },
      { id: "zero", [key]: 0 },
      { id: "missing" },
    ];
    assert.deepEqual(ids(sort(items, column, "ascending", kind)), [
      "zero",
      "two",
      "hundred",
      "none",
      "missing",
    ]);
    assert.deepEqual(ids(sort(items, column, "descending", kind)), [
      "hundred",
      "two",
      "zero",
      "none",
      "missing",
    ]);
  }
});

test("text columns use natural order, equal rows remain stable and server snapshots are not modified", () => {
  const items = Object.freeze([
    Object.freeze({
      id: "ten",
      interface: "vmbr10",
      protocol: "udp",
      state: "TIME_WAIT",
    }),
    Object.freeze({
      id: "first",
      interface: "vmbr2",
      protocol: "tcp",
      state: "ESTABLISHED",
    }),
    Object.freeze({
      id: "second",
      interface: "vmbr2",
      protocol: "tcp",
      state: "ESTABLISHED",
    }),
    Object.freeze({ id: "none", interface: "", protocol: "", state: "" }),
  ]);
  for (const column of ["interface", "protocol", "state"]) {
    assert.deepEqual(ids(sort(items, column)), [
      "first",
      "second",
      "ten",
      "none",
    ]);
    assert.deepEqual(ids(sort(items, column, "descending")), [
      "ten",
      "first",
      "second",
      "none",
    ]);
  }
  assert.deepEqual(ids(items), ["ten", "first", "second", "none"]);
  const unchanged = sort(items, "not-a-column");
  assert.deepEqual(unchanged, items);
  assert.notEqual(unchanged, items);
});

function fixture(items) {
  const result = {
    items,
    calls: 0,
    focuses: 0,
    scroll: { scrollLeft: 177, scrollTop: 41 },
    html: "",
  };
  const target = {
    contains: () => true,
    querySelector: (selector) =>
      selector === ".table-scroll"
        ? result.scroll
        : { focus: () => result.focuses++ },
    get innerHTML() {
      return result.html;
    },
    set innerHTML(value) {
      result.html = value;
      result.scroll = { scrollLeft: 0, scrollTop: 0 };
    },
  };
  globalThis.document = {
    documentElement: {},
    activeElement: { dataset: { sortColumn: "source" } },
    querySelector: () => target,
  };
  result.ctx = {
    e: escape,
    icon: () => "",
    generation: 1,
    getGeneration: () => 1,
    isCurrentView: () => true,
    api: async () => {
      result.calls++;
      return {
        available: true,
        items: result.items,
        timestamp: 1700000000,
        matched: result.items.length,
        total: result.items.length,
      };
    },
    run: async (work) => work(),
  };
  return result;
}
const row = (source, id = source) => ({
  id,
  source,
  source_port: 22,
  destination: "192.0.2.1",
  destination_port: 443,
  protocol: "tcp",
  state: "ESTABLISHED",
  packets: 1,
  bytes: 64,
  expires_in: 30,
});
const displayedSources = (markup) =>
  [...markup.matchAll(/<tr><td>TCP<\/td><td class="mono">([^<]+)<\/td>/g)].map(
    (match) => match[1],
  );

test("header clicks toggle locally, survive polling, and retain table scroll and keyboard focus", async () => {
  const f = fixture([row("10.0.0.10"), row("10.0.0.2"), row("10.0.0.1")]);
  await refreshConnections(f.ctx);
  assert.equal(f.calls, 1);
  assert.equal((f.html.match(/scope="col" aria-sort="none"/g) || []).length, 9);
  const action = {
    dataset: { action: "connections-sort", sortColumn: "source" },
  };
  assert.equal(await handleConnectionsAction(action, f.ctx), true);
  assert.equal(f.calls, 1, "sorting must not make a server request");
  assert.deepEqual(displayedSources(f.html), [
    "10.0.0.1:22",
    "10.0.0.2:22",
    "10.0.0.10:22",
  ]);
  assert.match(
    f.html,
    /aria-sort="ascending"><button[^>]+data-sort-column="source"/,
  );
  f.items = [row("10.0.0.10"), row("10.0.0.3"), row("10.0.0.2")];
  await refreshConnections(f.ctx);
  assert.deepEqual(displayedSources(f.html), [
    "10.0.0.2:22",
    "10.0.0.3:22",
    "10.0.0.10:22",
  ]);
  await handleConnectionsAction(action, f.ctx);
  assert.deepEqual(displayedSources(f.html), [
    "10.0.0.10:22",
    "10.0.0.3:22",
    "10.0.0.2:22",
  ]);
  assert.match(
    f.html,
    /aria-sort="descending"><button[^>]+data-sort-column="source"/,
  );
  assert.deepEqual(f.scroll, { scrollLeft: 177, scrollTop: 41 });
  assert.ok(f.focuses >= 4);
  await handleConnectionsAction(
    { dataset: { action: "connections-sort", sortColumn: "<bad>" } },
    f.ctx,
  );
  assert.equal(f.calls, 2);
});

test("headers follow RU/EN profile language and packet text remains escaped while sorted", async () => {
  const f = fixture([row('<img src=x onerror="bad">')]);
  await refreshConnections(f.ctx);
  assert.match(f.html, />Источник<span/);
  setLanguage("en");
  await handleConnectionsAction(
    { dataset: { action: "connections-sort", sortColumn: "source" } },
    f.ctx,
  );
  assert.match(renderConnections(f.ctx), />Source<span/);
  assert.ok(f.html.includes("&lt;img") && !f.html.includes("<img"));
  resetConnections();
  assert.match(renderConnections(f.ctx), /Loading connections/);
});
