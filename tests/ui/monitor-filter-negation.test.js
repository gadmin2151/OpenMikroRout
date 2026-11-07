import test from "node:test";
import assert from "node:assert/strict";
import { URL } from "node:url";
import { setLanguage } from "../../app/static/i18n.js";
import {
  handleQueryBuilderAction,
  handleQueryBuilderInput,
  getAppliedExpression,
} from "../../app/static/query-builder.js";
import { applyReadAccess, isReadAction } from "../../app/static/access-ui.js";
import {
  handleConnectionsAction,
  refreshConnections,
  renderConnections,
  resetConnections,
  setConnectionSource,
} from "../../app/static/connections-ui.js";
import {
  handleDiscoveryAction,
  refreshDiscovery,
  renderDiscovery,
  resetDiscovery,
} from "../../app/static/discovery-ui.js";
import {
  handleProtectionAction,
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
const noLegacyParams = (path) => {
  const query = params(path);
  for (const name of [
    "source",
    "destination",
    "port",
    "protocol",
    "state",
    "interface",
    "search",
    "query",
    "negate",
  ])
    assert.equal(query.has(name), false, `${name}: ${path}`);
};
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
const action = (name, data = {}) => ({ dataset: { action: name, ...data } });
function condition(scope, field, op, value, path = "0") {
  handleQueryBuilderAction({
    dataset: {
      action: "query-builder-add",
      scope,
      kind: "condition",
      queryPath: "",
    },
  });
  const element = {
    dataset: { queryBuilder: scope },
    querySelector: () => null,
  };
  for (const [part, entry] of [
    ["field", field],
    ["op", op],
    ["value", value],
  ]) {
    const input = {
      value: entry,
      selectionStart: 2,
      dataset: { queryPart: part, queryPath: path },
      closest: () => element,
    };
    assert.equal(handleQueryBuilderInput({ target: input }), true);
    assert.equal(input.value, entry);
    assert.equal(input.selectionStart, 2);
  }
}
function emptyDocument() {
  globalThis.document = { documentElement: {}, querySelector: () => null };
}

test("monitoring exposes only the opened builder, translates it and allows read users to filter", () => {
  const ctx = context();
  emptyDocument();
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const pages = [
      renderConnections(ctx),
      renderDiscovery("hosts", ctx),
      renderProtection("fail2ban", ctx),
      renderProtection("geoip", ctx),
    ];
    for (const html of pages) {
      assert.match(html, /data-query-builder="[^"]+" open/);
      assert.doesNotMatch(
        html,
        /id="connections-filter"|id="discovery-search"|data-protection-search=|data-display-negate=/,
      );
      assert.doesNotMatch(html, /быстрыми условиями|quick filters/);
      if (language === "en") assert.doesNotMatch(html, /[А-Яа-яЁё]/u);
    }
  }
  const actions = [
    "query-builder-add",
    "query-builder-remove",
    "query-builder-clear",
    "connections-filter",
    "discovery-search",
    "protection-search",
    "system-list-search",
  ];
  const buttons = actions.map((name) => ({
    dataset: { action: name },
    disabled: false,
  }));
  for (const name of actions) assert.equal(isReadAction(name), true, name);
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
  for (const name of [
    "connections-negate",
    "discovery-negate",
    "protection-negate",
    "system-list-negate",
  ])
    assert.equal(isReadAction(name), false, name);
});

test("Connections sends expression only; polling, sorting and kinds retain applied state without applying unfinished edits", async () => {
  emptyDocument();
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
  renderConnections(ctx);
  condition("connections", "translated_destination", "in", "10.77.0.4/32");
  assert.equal(paths.length, 0);
  await handleConnectionsAction(action("connections-filter"), ctx);
  noLegacyParams(paths.at(-1));
  const applied = params(paths.at(-1)).get("expression");
  assert.equal(JSON.parse(applied).children[0].field, "translated_destination");
  handleQueryBuilderAction({
    dataset: {
      action: "query-builder-add",
      scope: "connections",
      kind: "condition",
      queryPath: "",
    },
  });
  await refreshConnections(ctx);
  assert.equal(params(paths.at(-1)).get("expression"), applied);
  const count = paths.length;
  await handleConnectionsAction(
    action("connections-sort", { sortColumn: "source" }),
    ctx,
  );
  assert.equal(paths.length, count);
  await handleConnectionsAction(
    action("connections-kind", { kind: "attempts" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("kind"), "attempts");
  assert.equal(params(paths.at(-1)).get("expression"), applied);
  assert.equal(renders, 1);
  const pending = paths.length;
  await assert.rejects(
    handleConnectionsAction(action("connections-filter"), ctx),
    /Завершите/,
  );
  assert.equal(paths.length, pending);
  assert.equal(getAppliedExpression("connections"), applied);
  handleQueryBuilderAction({
    dataset: { action: "query-builder-clear", scope: "connections" },
  });
  assert.equal(getAppliedExpression("connections"), applied);
  await handleConnectionsAction(action("connections-filter"), ctx);
  assert.equal(params(paths.at(-1)).has("expression"), false);
  noLegacyParams(paths.at(-1));
});

test("opening connections from a neighbor creates a visible applied source condition rather than a hidden quick filter", async () => {
  emptyDocument();
  const paths = [],
    ctx = context();
  ctx.api = async (path) => {
    paths.push(path);
    return { available: true, items: [], matched: 0, total: 0, timestamp: 1 };
  };
  setConnectionSource("192.0.2.7");
  await refreshConnections(ctx);
  const ast = JSON.parse(params(paths.at(-1)).get("expression"));
  assert.deepEqual(ast.children[0], {
    kind: "condition",
    field: "source",
    op: "eq",
    value: "192.0.2.7",
  });
  noLegacyParams(paths.at(-1));
  const markup = renderConnections(ctx);
  assert.match(
    markup,
    /data-query-part="field"[^>]*>[\s\S]*value="source" selected/,
  );
  assert.match(markup, /value="192.0.2.7"/);
  resetConnections();
  await refreshConnections(ctx);
  assert.equal(params(paths.at(-1)).has("expression"), false);
});

test("Discovery applies only the builder and retains its expression through polling and paging", async () => {
  emptyDocument();
  const ctx = context(),
    paths = [];
  ctx.isCurrentView = (name) => name === "hosts";
  ctx.api = async (path) => {
    paths.push(path);
    return path === "discovery/status"
      ? { settings: { enabled: true }, errors: {} }
      : { items: [], total: 100 };
  };
  renderDiscovery("hosts", ctx);
  condition("hosts", "address", "not_in", "192.0.2.10/24");
  await handleDiscoveryAction(action("discovery-search"), ctx);
  const applied = params(paths.at(-1)).get("expression");
  assert.equal(JSON.parse(applied).children[0].value, "192.0.2.0/24");
  noLegacyParams(paths.at(-1));
  await handleDiscoveryAction(action("discovery-page", { offset: "50" }), ctx);
  assert.equal(params(paths.at(-1)).get("expression"), applied);
  assert.equal(params(paths.at(-1)).get("offset"), "50");
  await refreshDiscovery(ctx);
  assert.equal(params(paths.at(-1)).get("expression"), applied);
  handleQueryBuilderAction({
    dataset: { action: "query-builder-clear", scope: "hosts" },
  });
  await handleDiscoveryAction(action("discovery-search"), ctx);
  assert.equal(params(paths.at(-1)).has("expression"), false);
  assert.equal(params(paths.at(-1)).get("offset"), "0");
});

test("Fail2ban and country lists keep independent applied builders without hidden query/negate parameters", async () => {
  emptyDocument();
  const ctx = context(),
    paths = [];
  let view = "fail2ban";
  ctx.isCurrentView = (name) => name === view;
  ctx.api = async (path) => {
    paths.push(path);
    return path.includes("bans?") || path.includes("countries?")
      ? { items: [], total: 100 }
      : { profiles: [], warnings: [] };
  };
  renderProtection("fail2ban", ctx);
  condition("protection-fail2ban", "remaining_seconds", "gt", "300");
  await handleProtectionAction(
    action("protection-search", { kind: "fail2ban" }),
    ctx,
  );
  const applied = params(paths.at(-1)).get("expression");
  assert.equal(JSON.parse(applied).children[0].value, "300");
  noLegacyParams(paths.at(-1));
  await handleProtectionAction(
    action("protection-page", { kind: "fail2ban", offset: "50" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("expression"), applied);
  view = "geoip";
  renderProtection("geoip", ctx);
  condition("protection-geoip", "country", "neq", "MD");
  await handleProtectionAction(
    action("protection-search", { kind: "geoip" }),
    ctx,
  );
  assert.equal(
    JSON.parse(params(paths.at(-1)).get("expression")).children[0].value,
    "MD",
  );
  noLegacyParams(paths.at(-1));
  await refreshProtection(ctx, { force: true });
  assert.ok(params(paths.at(-1)).has("expression"));
  view = "fail2ban";
  assert.equal(getAppliedExpression("protection-fail2ban"), applied);
  resetProtection();
  assert.equal(getAppliedExpression("protection-fail2ban"), "");
});

test("system-list entries expose a single typed builder and opening another resource clears its filter", async () => {
  emptyDocument();
  const paths = [],
    ctx = context();
  let body = "";
  ctx.isCurrentView = (name) => name === "lists";
  ctx.dialog = { open: true };
  ctx.dialogFrame = (_title, _subtitle, content) => {
    body = content;
  };
  ctx.api = async (path) => {
    paths.push(path);
    return { items: [], total: 100 };
  };
  await handleProtectionAction(
    action("system-list-open", { name: "geo_MD" }),
    ctx,
  );
  assert.match(body, /data-query-builder="system-list" open/);
  assert.doesNotMatch(body, /id="system-list-search"|data-display-negate=/);
  condition("system-list", "address", "not_in", "192.0.2.0/24");
  await handleProtectionAction(action("system-list-search"), ctx);
  const applied = params(paths.at(-1)).get("expression");
  assert.equal(JSON.parse(applied).children[0].op, "not_in");
  noLegacyParams(paths.at(-1));
  await handleProtectionAction(
    action("system-list-page", { offset: "50" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).get("expression"), applied);
  await handleProtectionAction(
    action("system-list-open", { name: "f2b_web" }),
    ctx,
  );
  assert.equal(params(paths.at(-1)).has("expression"), false);
  noLegacyParams(paths.at(-1));
});

test("resetting Connections aborts old requests and a late result cannot restore a previous account's data", async () => {
  emptyDocument();
  const ctx = context();
  let resolve, signal;
  ctx.api = (_path, options) => {
    signal = options.signal;
    return new Promise((done) => {
      resolve = done;
    });
  };
  const pending = refreshConnections(ctx);
  resetConnections();
  assert.equal(signal.aborted, true);
  ctx.getGeneration = () => 2;
  resolve({
    available: true,
    timestamp: 1,
    matched: 1,
    total: 1,
    items: [{ protocol: "tcp", source: "PRIVATE-DATA" }],
  });
  await pending;
  assert.doesNotMatch(renderConnections(ctx), /PRIVATE-DATA/);
});
