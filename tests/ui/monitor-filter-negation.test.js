import test from "node:test";
import assert from "node:assert/strict";
import { URL } from "node:url";
import { setLanguage } from "../../app/static/i18n.js";
import { applyReadAccess, isReadAction } from "../../app/static/access-ui.js";
import {
  handleConnectionsAction,
  handleConnectionsInput,
  refreshConnections,
  renderConnections,
  resetConnections,
  setConnectionSource,
} from "../../app/static/connections-ui.js";
import {
  handleDiscoveryAction,
  handleDiscoveryInput,
  refreshDiscovery,
  renderDiscovery,
  resetDiscovery,
} from "../../app/static/discovery-ui.js";
import {
  handleProtectionAction,
  handleProtectionInput,
  refreshProtection,
  renderProtection,
  resetProtection,
} from "../../app/static/protection-ui.js";

const originalDocument = globalThis.document;
test.afterEach(() => {
  resetConnections();
  resetDiscovery();
  resetProtection();
  globalThis.document = originalDocument;
  setLanguage("ru");
});
const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const params = (path) => new URL(path, "http://localhost").searchParams;
function form(id, values, dataset = {}) {
  const buttons = Object.fromEntries(
    Object.keys(values).map((name) => [
      name,
      {
        dataset: { displayNegate: name },
        disabled: !values[name],
        attrs: { "aria-pressed": "false" },
        setAttribute(key, value) {
          this.attrs[key] = value;
        },
        getAttribute(key) {
          return this.attrs[key];
        },
      },
    ]),
  );
  return {
    id,
    values,
    dataset,
    buttons,
    innerHTML: "must stay intact",
    querySelector(selector) {
      const name = /data-display-negate="([^"]+)"/.exec(selector)?.[1];
      return name ? buttons[name] : null;
    },
  };
}
function edit(form, name, value, handler) {
  form.values[name] = value;
  const input = {
    name,
    value,
    selectionStart: Math.min(3, value.length),
    closest: (selector) =>
      selector === `#${form.id}` ||
      (selector === "[data-protection-search]" && form.dataset.protectionSearch)
        ? form
        : null,
  };
  const before = { value: input.value, selectionStart: input.selectionStart };
  assert.equal(handler({ target: input }), true);
  assert.deepEqual(
    { value: input.value, selectionStart: input.selectionStart },
    before,
  );
}
function mockForms(t) {
  t.mock.method(globalThis, "FormData", function (mounted) {
    return new Map(Object.entries(mounted.values));
  });
}
function context() {
  return {
    e,
    icon: () => "",
    generation: 1,
    getGeneration: () => 1,
    canWrite: () => false,
    offline: false,
    run: async (work) => work(),
    isCurrentView: () => true,
    state: {
      revision: 2,
      config: {
        network: {},
        rules: [],
        filter_rules: [],
        address_lists: [],
        system_lists: [],
        discovery: { enabled: false, interfaces: ["eth0"] },
        scanning: { enabled: false, interfaces: ["eth0"] },
        fail2ban: {
          enabled: false,
          profiles: [],
          trusted_proxies: [],
          access_mode: "direct",
        },
        geoip: { auto_update: false, check_hours: 24 },
      },
    },
    interfaces: [{ name: "eth0" }],
  };
}
const action = (name, data = {}, mounted) => ({
  dataset: { action: name, ...data },
  closest: () => mounted,
});

test("Connections sends all seven typed exclusions, keeps polling/sorting and pending input stable, and preserves them across kinds", async (t) => {
  mockForms(t);
  const values = {
    source: "192.0.2.1/32",
    destination: "198.51.100.1",
    port: "443,8000-8010",
    protocol: "tcp",
    state: "ESTABLISHED",
    interface: "eth0",
    search: "needle",
  };
  const mounted = form("connections-filter", values);
  const region = {
    innerHTML: "",
    querySelector: () => null,
    contains: () => false,
  };
  globalThis.document = {
    querySelector: (selector) =>
      selector === "#connections-filter"
        ? mounted
        : selector === "#connections-results"
          ? region
          : null,
  };
  const paths = [],
    ctx = context();
  let renders = 0;
  ctx.render = () => {
    renders++;
  };
  ctx.api = async (path) => {
    paths.push(path);
    return { available: true, items: [], matched: 0, total: 0, timestamp: 1 };
  };
  for (const [name, value] of Object.entries(values)) {
    edit(mounted, name, value, handleConnectionsInput);
    await handleConnectionsAction(
      action("connections-negate", { displayNegate: name }),
      ctx,
    );
    assert.equal(mounted.buttons[name].getAttribute("aria-pressed"), "true");
  }
  assert.equal(
    paths.length,
    0,
    "editing display filters must not make requests",
  );
  assert.equal(renders, 0, "! must not replace fields or reset the caret");
  await handleConnectionsAction(action("connections-filter"), ctx);
  assert.equal(
    params(paths.at(-1)).get("negate"),
    Object.keys(values).join(","),
  );
  assert.equal(params(paths.at(-1)).get("source"), "192.0.2.1/32");
  const before = renderConnections(ctx);
  await refreshConnections(ctx);
  assert.equal(renderConnections(ctx), before);
  assert.equal(mounted.innerHTML, "must stay intact");
  edit(mounted, "source", "203.0.113.5", handleConnectionsInput);
  await refreshConnections(ctx);
  assert.equal(
    params(paths.at(-1)).get("source"),
    "192.0.2.1/32",
    "polling uses the applied filter",
  );
  await handleConnectionsAction(
    action("connections-sort", { sortColumn: "source" }),
    ctx,
  );
  assert.equal(mounted.buttons.source.getAttribute("aria-pressed"), "true");
  await handleConnectionsAction(
    action("connections-kind", { kind: "attempts" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("kind"), "attempts");
  assert.equal(params(paths.at(-1)).get("source"), "203.0.113.5");
  assert.equal(
    params(paths.at(-1)).get("negate"),
    Object.keys(values).join(","),
  );
  assert.match(renderConnections(ctx), /name="source" value="203.0.113.5"/);
});

test("Connections ignores empty/unknown exclusions, clearing a field removes !, and Reset clears values and flags", async (t) => {
  mockForms(t);
  const mounted = form("connections-filter", {
    source: "",
    destination: "",
    port: "",
    protocol: "",
    state: "",
    interface: "",
    search: "",
  });
  globalThis.document = {
    querySelector: (selector) =>
      selector === "#connections-filter" ? mounted : null,
  };
  const ctx = context(),
    paths = [];
  ctx.render = () => {};
  ctx.api = async (path) => {
    paths.push(path);
    return { available: true, items: [], matched: 0, total: 0, timestamp: 1 };
  };
  await handleConnectionsAction(
    action("connections-negate", { displayNegate: "source" }),
    ctx,
  );
  await handleConnectionsAction(
    action("connections-negate", { displayNegate: "__proto__" }),
    ctx,
  );
  assert.equal(mounted.buttons.source.disabled, true);
  edit(mounted, "source", "192.0.2.1", handleConnectionsInput);
  await handleConnectionsAction(
    action("connections-negate", { displayNegate: "source" }),
    ctx,
  );
  edit(mounted, "source", "", handleConnectionsInput);
  assert.equal(mounted.buttons.source.getAttribute("aria-pressed"), "false");
  await handleConnectionsAction(action("connections-filter"), ctx);
  assert.equal(params(paths.at(-1)).has("negate"), false);
  edit(mounted, "search", "<host>", handleConnectionsInput);
  await handleConnectionsAction(
    action("connections-negate", { displayNegate: "search" }),
    ctx,
  );
  await handleConnectionsAction(action("connections-filter"), ctx);
  await handleConnectionsAction(action("connections-reset"), ctx);
  assert.equal(params(paths.at(-1)).has("negate"), false);
  assert.equal(params(paths.at(-1)).has("search"), false);
  assert.doesNotMatch(renderConnections(ctx), /aria-pressed="true"/);
  assert.doesNotMatch(renderConnections(ctx), /&lt;host&gt;/);
  setConnectionSource("192.0.2.7");
  await refreshConnections(ctx);
  assert.equal(params(paths.at(-1)).get("source"), "192.0.2.7");
  assert.equal(params(paths.at(-1)).has("negate"), false);
});

test("display ! is usable by read users and all Connections controls translate without changing their contracts", () => {
  const actions = [
    "connections-negate",
    "discovery-negate",
    "protection-negate",
    "system-list-negate",
    "nat-filter-negate",
    "wg-peer-negate",
  ];
  for (const name of actions) assert.equal(isReadAction(name), true, name);
  assert.equal(isReadAction("capture-negate"), false);
  const buttons = actions.map((name) => ({
    dataset: { action: name },
    disabled: false,
  }));
  const scope = {
    querySelectorAll: (selector) =>
      selector === "button[data-action]" ? buttons : [],
    querySelector: () => null,
  };
  applyReadAccess(scope, {
    auth_enabled: true,
    current_user: { role: "read" },
  });
  assert.ok(buttons.every((button) => !button.disabled));
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const html = renderConnections(context());
    assert.equal((html.match(/data-display-negate=/g) || []).length, 7);
    for (const name of [
      "source",
      "destination",
      "port",
      "protocol",
      "state",
      "interface",
      "search",
    ])
      assert.match(html, new RegExp(`<label for="connections-${name}">`));
    if (language === "en") assert.doesNotMatch(html, /[А-Яа-яЁё]/u);
  }
});

test("Discovery query/interface exclusions are read-only display filters applied before paging and retained while polling", async (t) => {
  mockForms(t);
  const mounted = form("discovery-search", {
    query: "printer",
    interface: "eth0",
  });
  const region = { innerHTML: "" },
    paths = [],
    ctx = context();
  ctx.isCurrentView = (name) => name === "hosts";
  globalThis.document = {
    querySelector: (selector) =>
      selector === "#discovery-search"
        ? mounted
        : selector === "#discovery-results"
          ? region
          : null,
  };
  ctx.api = async (path) => {
    paths.push(path);
    return path === "discovery/status"
      ? { settings: { enabled: true }, errors: {} }
      : { items: [], total: 100 };
  };
  for (const [name, value] of Object.entries(mounted.values)) {
    edit(mounted, name, value, handleDiscoveryInput);
    await handleDiscoveryAction(
      action("discovery-negate", { displayNegate: name }),
      ctx,
    );
  }
  assert.equal(paths.length, 0);
  await handleDiscoveryAction(action("discovery-search"), ctx);
  assert.equal(params(paths.at(-1)).get("negate"), "query,interface");
  await handleDiscoveryAction(action("discovery-page", { offset: "50" }), ctx);
  assert.equal(params(paths.at(-1)).get("offset"), "50");
  assert.equal(params(paths.at(-1)).get("negate"), "query,interface");
  const before = renderDiscovery("hosts", ctx);
  await refreshDiscovery(ctx);
  assert.equal(renderDiscovery("hosts", ctx), before);
  assert.equal(mounted.innerHTML, "must stay intact");
  edit(mounted, "query", "", handleDiscoveryInput);
  await handleDiscoveryAction(action("discovery-search"), ctx);
  assert.equal(params(paths.at(-1)).get("negate"), "interface");
  assert.equal(params(paths.at(-1)).get("offset"), "0");
  resetDiscovery();
  await refreshDiscovery(ctx);
  assert.equal(params(paths.at(-1)).has("negate"), false);
  assert.doesNotMatch(renderDiscovery("hosts", ctx), /aria-pressed="true"/);
});

test("Fail2ban and GeoIP searches retain independent exclusions through polling/pagination without applying unsaved input", async (t) => {
  mockForms(t);
  const mounted = form(
    "protection-search",
    { query: "192.0.2" },
    { protectionSearch: "fail2ban" },
  );
  const ctx = context(),
    paths = [];
  let view = "fail2ban";
  ctx.isCurrentView = (name) => name === view;
  globalThis.document = { documentElement: {}, querySelector: () => null };
  ctx.api = async (path) => {
    paths.push(path);
    return path.includes("bans?") || path.includes("countries?")
      ? { items: [], total: 100 }
      : { profiles: [], warnings: [] };
  };
  edit(mounted, "query", mounted.values.query, handleProtectionInput);
  await handleProtectionAction(action("protection-negate", {}, mounted), ctx);
  assert.equal(paths.length, 0);
  await handleProtectionAction(
    action("protection-search", { kind: "fail2ban" }, mounted),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("negate"), "query");
  assert.equal(params(paths.at(-1)).get("query"), "192.0.2");
  edit(mounted, "query", "203.0.113", handleProtectionInput);
  await refreshProtection(ctx, { force: true });
  assert.equal(params(paths.at(-1)).get("query"), "192.0.2");
  await handleProtectionAction(
    action("protection-page", { kind: "fail2ban", offset: "50" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("negate"), "query");
  assert.equal(params(paths.at(-1)).get("offset"), "50");
  view = "geoip";
  await refreshProtection(ctx, { force: true });
  assert.equal(params(paths.at(-1)).has("negate"), false);
  const country = form(
    "geoip-search",
    { query: "MD" },
    { protectionSearch: "geoip" },
  );
  edit(country, "query", "MD", handleProtectionInput);
  await handleProtectionAction(action("protection-negate", {}, country), ctx);
  await handleProtectionAction(
    action("protection-search", { kind: "geoip" }, country),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("negate"), "query");
  assert.equal(params(paths.at(-1)).get("query"), "MD");
  setLanguage("en");
  assert.doesNotMatch(renderProtection("geoip", ctx), /[А-Яа-яЁё]/u);
  edit(country, "query", "", handleProtectionInput);
  await handleProtectionAction(
    action("protection-search", { kind: "geoip" }, country),
    ctx,
  );
  assert.equal(params(paths.at(-1)).has("negate"), false);
  view = "fail2ban";
  assert.match(
    renderProtection("fail2ban", ctx),
    /data-display-negate="query" aria-pressed="true"/,
  );
  assert.match(renderProtection("fail2ban", ctx), /value="203.0.113"/);
});

test("system-list entry search keeps ! through pagination and opening another list clears its local filter", async (t) => {
  mockForms(t);
  const mounted = form("system-list-search", { query: "" });
  const paths = [],
    ctx = context();
  let body = "";
  ctx.isCurrentView = (name) => name === "lists";
  ctx.dialog = { open: true, querySelector: () => mounted };
  ctx.dialogFrame = (_title, _subtitle, content) => {
    body = content;
  };
  ctx.api = async (path) => {
    paths.push(path);
    return { items: ["192.0.2.1"], total: 100 };
  };
  await handleProtectionAction(
    action("system-list-open", { name: "geo_MD" }),
    ctx,
  );
  assert.match(
    body,
    /data-display-negate="query" aria-pressed="false"[^>]*disabled/,
  );
  edit(mounted, "query", "192.0.2", handleProtectionInput);
  const count = paths.length;
  await handleProtectionAction(action("system-list-negate"), ctx);
  assert.equal(paths.length, count);
  await handleProtectionAction(action("system-list-search"), ctx);
  assert.equal(params(paths.at(-1)).get("negate"), "query");
  assert.match(body, /data-display-negate="query" aria-pressed="true"/);
  await handleProtectionAction(
    action("system-list-page", { offset: "50" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("negate"), "query");
  assert.equal(params(paths.at(-1)).get("offset"), "50");
  edit(mounted, "query", "", handleProtectionInput);
  await handleProtectionAction(action("system-list-search"), ctx);
  assert.equal(params(paths.at(-1)).has("negate"), false);
  await handleProtectionAction(
    action("system-list-open", { name: "f2b_web" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).has("negate"), false);
  assert.equal(params(paths.at(-1)).get("query"), "");
  assert.match(
    body,
    /data-display-negate="query" aria-pressed="false"[^>]*disabled/,
  );
});
