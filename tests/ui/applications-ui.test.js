import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import {
  applicationViews,
  applicationCatalogQuerySchema,
  renderApplications,
  refreshApplications,
  resetApplications,
  handleApplicationsAction,
  handleApplicationsInput,
  installApplicationsEvents,
} from "../../app/static/applications-ui.js";
import { setLanguage } from "../../app/static/i18n.js";
import { isReadAction } from "../../app/static/access-ui.js";
import { navigationItems } from "../../app/static/navigation-ui.js";
import {
  renderQueryBuilder,
  setQueryBuilderExpression,
  handleQueryBuilderAction,
  handleQueryBuilderInput,
} from "../../app/static/query-builder.js";

const originalDocument = globalThis.document;
const originalFormData = globalThis.FormData;
afterEach(() => {
  resetApplications();
  globalThis.document = originalDocument;
  globalThis.FormData = originalFormData;
  setLanguage("ru");
});
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );
const leaf = (id, text = id) => ({
  id,
  kind: "application",
  name: text,
  name_ru: text,
  name_en: text,
  category: "messaging",
  capabilities: {
    observable: false,
    block_validated: false,
    allow_over_port_deny: false,
  },
});
const catalog = [
  {
    id: "app.chat",
    kind: "family",
    name: "Chat",
    children: ["app.chat.messages", "app.chat.calls"],
    concrete_ids: ["app.chat.messages", "app.chat.calls"],
  },
  leaf("app.chat.messages", "Chat messages"),
  leaf("app.chat.calls", "Chat calls"),
];
const appRule = (id, overrides = {}) => ({
  id,
  name: `Rule ${id}`,
  enabled: true,
  application_ids: ["app.chat.messages"],
  action: "block",
  src_address: "",
  src_list: "",
  dst_address: "",
  dst_list: "",
  in_interface: "",
  in_interface_list: "",
  out_interface: "",
  out_interface_list: "",
  connection_states: ["NEW", "ESTABLISHED", "RELATED"],
  comment: "",
  ...overrides,
});
const scope = "applications-catalog";
const flush = async () => {
  for (let i = 0; i < 12; i++) await Promise.resolve();
};

function fixture(write = true) {
  let view = "applications_rules",
    generation = 1;
  const calls = [],
    saves = [],
    frames = [],
    nodes = {};
  const state = {
    revision: 4,
    auth_enabled: true,
    pending: null,
    config: {
      rules: [],
      filter_rules: [],
      address_lists: [],
      system_lists: [],
      network: { interface_lists: [] },
      applications: {
        enabled: false,
        mode: "observe",
        interfaces: ["eth1"],
        source_networks: ["192.168.10.0/24"],
        catalog_version: "seed-2026-11-08",
        catalog_auto_update: false,
        catalog_check_hours: 24,
        rules: [],
        unknown_policy: "firewall",
        failure_policy: "block",
        probe_timeout_ms: 2000,
        probe_packets: 32,
        probe_bytes: 65536,
        max_pending: 512,
        max_pending_per_client: 32,
        queue_limit: 256,
        verdict_timeout_ms: 250,
      },
    },
  };
  const settings = {
    fields: {
      ...state.config.applications,
      interfaces: ["eth1"],
      source_networks: "192.168.10.0/24",
      override_rule_ids: [],
    },
    dataset: { revision: "4" },
    reportValidity: () => true,
  };
  const form = {
    fields: { ...appRule("form"), enabled: "on" },
    reportValidity: () => true,
    querySelector: () => null,
    dataset: {},
  };
  for (const id of [
    "#applications-status",
    "#applications-results",
    "#applications-update-status",
    "#apps-picker-results",
  ])
    nodes[id] = { innerHTML: "", textContent: "", contains: () => false };
  nodes["#application-settings-form"] = settings;
  nodes["#application-rule-form"] = form;
  nodes['#application-settings-form [value="enforce"]'] = { disabled: true };
  globalThis.document = {
    documentElement: {},
    activeElement: null,
    querySelector: (selector) => nodes[selector] || null,
  };
  globalThis.FormData = class {
    constructor(form) {
      this.fields = form.fields;
    }
    get(name) {
      const value = this.fields[name];
      return Array.isArray(value)
        ? value[0] || null
        : value == null || value === false
          ? null
          : value;
    }
    getAll(name) {
      const value = this.fields[name];
      return value == null || value === false
        ? []
        : Array.isArray(value)
          ? value
          : [value];
    }
    has(name) {
      return this.fields[name] != null && this.fields[name] !== false;
    }
  };
  const ctx = {
    state,
    writable: write,
    offline: false,
    busy: false,
    generation: 1,
    getGeneration: () => generation,
    isCurrentView: (name) => view === name,
    e: escape,
    icon: () => "",
    interfaces: [{ name: "eth1" }, { name: "eth0" }],
    canWrite: () => ctx.writable,
    render: () => {},
    toast: () => {},
    run: (operation) => operation(),
    dialog: {
      open: false,
      querySelector: (selector) => nodes[selector] || null,
      querySelectorAll: () => [],
      close() {
        this.open = false;
      },
    },
    dialogFrame: (...args) => {
      frames.push(args);
      ctx.dialog.open = true;
    },
    api: async (path, options = {}) => {
      calls.push({ path, options });
      if (path === "applications/status")
        return {
          enabled: false,
          mode: "observe",
          available: false,
          healthy: false,
          engine: {
            name: "nDPI",
            available: false,
            capabilities: { enforce: false },
          },
          catalog: {
            active_version: "seed-2026-11-08",
            entries: catalog.length,
          },
        };
      if (path.startsWith("applications/catalog?")) {
        const query = new URL(path, "http://fixture/").searchParams;
        const expression =
          query.get("expression") && JSON.parse(query.get("expression"));
        const identifiers =
          expression?.kind === "group" &&
          expression.children.every(
            (item) => item.field === "id" && item.op === "eq",
          )
            ? new Set(expression.children.map((item) => item.value))
            : null;
        const items = identifiers
          ? catalog.filter((entry) => identifiers.has(entry.id))
          : catalog;
        return {
          items,
          total: items.length,
          version: "seed-2026-11-08",
        };
      }
      if (path.startsWith("applications/connections?"))
        return { items: [], total: 0, updated_at: 1700000000 };
      if (path.startsWith("applications/catalog/"))
        return catalog.find((entry) => path.endsWith(entry.id));
      throw new Error(`Unexpected API path ${path}`);
    },
    saveConfig: async (next, revision) => {
      assert.equal(revision, state.revision);
      saves.push(globalThis.structuredClone(next));
      state.config = next;
      state.revision++;
    },
  };
  return {
    ctx,
    state,
    calls,
    saves,
    frames,
    nodes,
    form,
    settings,
    setView: (value) => {
      view = value;
    },
    expire: () => {
      generation++;
    },
  };
}
const action = (name, data = {}) => ({ dataset: { action: name, ...data } });
async function seedStatus(f, view = "applications_rules") {
  f.setView(view);
  await refreshApplications(f.ctx, { force: true });
}
function selectRule(f, id, value = true) {
  handleApplicationsInput(
    { target: { dataset: { appSelect: id }, checked: value } },
    f.ctx,
  );
}

test("Applications has one top-level destination after WireGuard and four classic tabs", () => {
  const f = fixture();
  const items = navigationItems(f.ctx);
  assert.equal(
    items.findIndex((item) => item.view === "applications_rules"),
    items.findIndex((item) => item.view === "wireguard") + 1,
  );
  const entry = items.find((item) => item.view === "applications_rules");
  assert.deepEqual(entry.views, Object.keys(applicationViews));
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    for (const view of Object.keys(applicationViews)) {
      const markup = renderApplications(f.ctx, view);
      assert.equal((markup.match(/role="tab"/g) || []).length, 4);
      assert.doesNotMatch(
        markup,
        /iframe|workspace-frame|id="connections-filter"|type="search"/,
      );
    }
  }
});

test("missing engine is honestly unavailable and Enforce stays disabled", async () => {
  const f = fixture();
  await seedStatus(f, "applications_settings");
  const markup = renderApplications(f.ctx, "applications_settings");
  assert.match(markup, /Движок DPI недоступен/);
  assert.match(markup, /value="enforce"[^>]*disabled/);
  assert.match(
    markup,
    /Без совместимого движка распознавание и блокировка не работают/,
  );
  assert.doesNotMatch(markup, /Прикладная фильтрация активна/);
  f.settings.fields.enabled = "on";
  f.settings.fields.mode = "enforce";
  await assert.rejects(
    handleApplicationsAction(action("apps-settings-save"), f.ctx),
    /Enforce/,
  );
  assert.equal(f.saves.length, 0);
});

test("intentional demo unavailability is localized information while real engine errors remain alerts", async () => {
  for (const language of ["ru", "en"]) {
    const f = fixture();
    setLanguage(language);
    const originalApi = f.ctx.api;
    let demo = true;
    f.ctx.api = async (path, options) => {
      const result = await originalApi(path, options);
      return path === "applications/status"
        ? {
            ...result,
            demo,
            error: demo
              ? "Demo mode does not inspect host packets or simulate application detection"
              : "Native classifier failed to start",
          }
        : result;
    };
    await seedStatus(f, "applications_settings");
    let markup = renderApplications(f.ctx, "applications_settings");
    assert.match(
      markup,
      language === "ru" ? /Демонстрационный режим/ : /Demo mode/,
    );
    assert.match(
      markup,
      language === "ru"
        ? /Распознавание и блокировка приложений не выполняются/
        : /Application detection and blocking are inactive/,
    );
    assert.doesNotMatch(
      markup,
      /role="alert"|apps-status-warning|simulate application detection/,
    );
    assert.match(markup, /value="enforce"[^>]*disabled/);
    demo = false;
    await refreshApplications(f.ctx, { force: true });
    markup = renderApplications(f.ctx, "applications_settings");
    assert.match(markup, /role="alert">Native classifier failed to start/);
    assert.match(markup, /apps-status-warning/);
    assert.doesNotMatch(markup, /class="apps-mode">DEMO/);
    resetApplications();
  }
});

test("read users inspect and filter but cannot forge any application mutation", async () => {
  const f = fixture(false);
  for (const name of [
    "apps-refresh",
    "apps-catalog-filter",
    "apps-connections-filter",
    "apps-rules-filter",
    "apps-page",
    "apps-sort",
    "apps-rule-edit",
    "apps-editor-tab",
    "apps-catalog-detail",
    "apps-picker-filter",
    "apps-picker-page",
  ])
    assert.equal(isReadAction(name), true, name);
  for (const name of [
    "apps-rule-new",
    "apps-rule-save",
    "apps-rule-delete",
    "apps-rule-enable",
    "apps-rule-disable",
    "apps-rule-copy",
    "apps-rule-up",
    "apps-rule-down",
    "apps-settings-save",
    "apps-picker-all",
    "apps-picker-clear",
    "apps-catalog-check",
    "apps-catalog-download",
  ]) {
    assert.equal(isReadAction(name), false, name);
    await assert.rejects(handleApplicationsAction(action(name), f.ctx), /full/);
  }
  assert.equal(f.calls.length, 0);
  assert.equal(f.saves.length, 0);
  assert.match(
    renderApplications(f.ctx, "applications_settings"),
    /fieldset disabled/,
  );
});

test("catalog filtering sends only bounded expression and page fields, with no legacy filters", async () => {
  const f = fixture(false);
  f.setView("applications_catalog");
  renderApplications(f.ctx, "applications_catalog");
  setQueryBuilderExpression(
    scope,
    applicationCatalogQuerySchema,
    { kind: "condition", field: "name", op: "not_contains", value: "Chat" },
    { applyAction: "apps-catalog-filter" },
  );
  await handleApplicationsAction(action("apps-catalog-filter"), f.ctx);
  const query = new URL(
    f.calls.find((call) => call.path.startsWith("applications/catalog?")).path,
    "https://router.test",
  ).searchParams;
  assert.deepEqual([...query.keys()].sort(), ["expression", "limit", "offset"]);
  assert.match(query.get("expression"), /not_contains/);
  assert.equal(query.get("limit"), "50");
});

test("refresh preserves draft forms, focused table controls, and unchanged response markup", async () => {
  const f = fixture();
  await seedStatus(f, "applications_catalog");
  const results = f.nodes["#applications-results"];
  results.innerHTML = "FOCUSED";
  results.contains = () => true;
  f.settings.fields.source_networks = "UNSAVED";
  await refreshApplications(f.ctx, { force: true });
  assert.equal(results.innerHTML, "FOCUSED");
  assert.equal(f.settings.fields.source_networks, "UNSAVED");
});

test("late responses after logout cannot repopulate catalog or status", async () => {
  const f = fixture();
  f.setView("applications_catalog");
  const resolvers = [];
  f.ctx.api = (path, options) => {
    f.calls.push({ path, options });
    return new Promise((resolve) => resolvers.push(resolve));
  };
  const pending = refreshApplications(f.ctx, { force: true });
  await flush();
  resetApplications();
  assert.equal(f.calls[0].options.signal.aborted, true);
  resolvers[0]({ enabled: true, available: true, engine: { available: true } });
  resolvers[1]({ items: [leaf("app.late")], total: 1 });
  await pending;
  assert.equal(f.nodes["#applications-status"].innerHTML, "");
  assert.doesNotMatch(
    renderApplications(f.ctx, "applications_catalog"),
    /app.late/,
  );
});

test("catalog metadata and flow fields are escaped and raw payload secrets never render", async () => {
  const f = fixture();
  const unsafe = '<img src=x onerror="bad()">';
  f.ctx.api = async (path) =>
    path === "applications/status"
      ? { available: false, engine: { available: false } }
      : path.startsWith("applications/catalog?")
        ? {
            items: [
              {
                ...leaf("app.unsafe", unsafe),
                source: unsafe,
                private_key: "SECRET-MUST-NOT-RENDER",
              },
            ],
            total: 1,
          }
        : {
            items: [
              {
                application_id: "app.unsafe",
                source: unsafe,
                destination: unsafe,
                state: unsafe,
                classification_state: "unknown",
                reason: unsafe,
                payload: "SECRET-MUST-NOT-RENDER",
              },
            ],
            total: 1,
          };
  await seedStatus(f, "applications_catalog");
  let markup = renderApplications(f.ctx, "applications_catalog");
  assert.doesNotMatch(markup, /<img|SECRET-MUST/);
  assert.match(markup, /&lt;img/);
  await seedStatus(f, "applications_connections");
  markup = renderApplications(f.ctx, "applications_connections");
  assert.doesNotMatch(markup, /<img|SECRET-MUST/);
  assert.match(markup, /&lt;img/);
});

test("a family checkbox saves pinned concrete children, including selections off the current page", async () => {
  const f = fixture();
  await handleApplicationsAction(action("apps-rule-new"), f.ctx);
  handleApplicationsInput(
    { target: { dataset: { appPicker: "app.chat" }, checked: true } },
    f.ctx,
  );
  f.ctx.api = async () => ({
    items: [leaf("app.remote", "Remote")],
    total: 100,
  });
  await handleApplicationsAction(
    action("apps-picker-page", { offset: "50" }),
    f.ctx,
  );
  handleApplicationsInput(
    { target: { dataset: { appPicker: "app.remote" }, checked: true } },
    f.ctx,
  );
  f.form.fields.name = "Pinned family";
  await handleApplicationsAction(action("apps-rule-save"), f.ctx);
  const rule = f.saves[0].applications.rules[0];
  assert.deepEqual(rule.application_ids, [
    "app.chat.messages",
    "app.chat.calls",
    "app.remote",
  ]);
  assert.equal(rule.application_ids.includes("app.chat"), false);
  assert.deepEqual(f.saves[0].network, f.state.config.network);
});

test("rule editors retain entered fields when a stale revision blocks saving", async () => {
  const f = fixture();
  await handleApplicationsAction(action("apps-rule-new"), f.ctx);
  handleApplicationsInput(
    { target: { dataset: { appPicker: "app.chat.messages" }, checked: true } },
    f.ctx,
  );
  f.form.fields.name = "Keep my draft";
  f.state.revision++;
  await assert.rejects(
    handleApplicationsAction(action("apps-rule-save"), f.ctx),
    /Конфигурация изменилась/,
  );
  assert.equal(f.form.fields.name, "Keep my draft");
  assert.equal(f.ctx.dialog.open, true);
  assert.equal(f.saves.length, 0);
});

test("rule mutations save only the shared draft and preserve other configuration", async () => {
  const f = fixture();
  f.state.config.applications.rules = [
    appRule("one"),
    appRule("two"),
    appRule("three"),
  ];
  const other = globalThis.structuredClone(f.state.config.network);
  selectRule(f, "two");
  await handleApplicationsAction(action("apps-rule-up"), f.ctx);
  assert.deepEqual(
    f.saves[0].applications.rules.map((rule) => rule.id),
    ["two", "one", "three"],
  );
  assert.deepEqual(f.saves[0].network, other);
  await handleApplicationsAction(action("apps-rule-disable"), f.ctx);
  assert.equal(f.saves[1].applications.rules[0].enabled, false);
  assert.equal(
    f.calls.length,
    0,
    "Saving a draft cannot start the runtime or call apply",
  );
});

test("HTTP browsers can add and duplicate application rules without randomUUID", async (t) => {
  const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  t.after(() => {
    if (originalCrypto)
      Object.defineProperty(globalThis, "crypto", originalCrypto);
    else delete globalThis.crypto;
  });
  let fill = 0;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: { getRandomValues: (bytes) => bytes.fill(++fill) },
  });

  const f = fixture();
  await handleApplicationsAction(action("apps-rule-new"), f.ctx);
  handleApplicationsInput(
    { target: { dataset: { appPicker: "app.chat.messages" }, checked: true } },
    f.ctx,
  );
  f.form.fields.name = "HTTP rule";
  await handleApplicationsAction(action("apps-rule-save"), f.ctx);
  const [original] = f.saves[0].applications.rules;
  selectRule(f, original.id);
  await handleApplicationsAction(action("apps-rule-copy"), f.ctx);

  const uuidV4 =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const [retained, copy] = f.saves[1].applications.rules;
  assert.match(original.id, uuidV4);
  assert.match(copy.id, uuidV4);
  assert.notEqual(copy.id, original.id);
  assert.deepEqual(retained, original);
  assert.deepEqual(copy, { ...original, id: copy.id, name: "HTTP rule копия" });
});

test("settings opt in only eligible ordinary port denies and preserve protected rules", async () => {
  const f = fixture();
  f.state.config.filter_rules = [
    {
      id: "port",
      name: "HTTPS",
      chain: "forward",
      protocol: "tcp",
      action: "drop",
      dst_ports: "443",
      application_override_eligible: false,
    },
    {
      id: "address",
      name: "Protected",
      chain: "forward",
      protocol: "tcp",
      action: "drop",
      dst_address: "192.0.2.0/24",
      application_override_eligible: false,
    },
    {
      id: "host",
      name: "Host",
      chain: "input",
      protocol: "tcp",
      action: "drop",
      dst_ports: "22",
      application_override_eligible: false,
    },
  ];
  f.settings.fields.override_rule_ids = ["port", "host", "address"];
  f.settings.fields.catalog_auto_update = "on";
  await handleApplicationsAction(action("apps-settings-save"), f.ctx);
  assert.deepEqual(
    f.saves[0].filter_rules.map((rule) => rule.application_override_eligible),
    [true, false, false],
  );
  assert.equal(f.saves[0].applications.catalog_auto_update, true);
  assert.equal(f.saves[0].applications.catalog_check_hours, 24);
});

test("empty selection and impossible Allow states are rejected before a save", async () => {
  const f = fixture();
  await handleApplicationsAction(action("apps-rule-new"), f.ctx);
  await assert.rejects(
    handleApplicationsAction(action("apps-rule-save"), f.ctx),
    /хотя бы одно/,
  );
  handleApplicationsInput(
    { target: { dataset: { appPicker: "app.chat.messages" }, checked: true } },
    f.ctx,
  );
  f.form.fields.action = "allow";
  f.form.fields.connection_states = ["NEW"];
  await assert.rejects(
    handleApplicationsAction(action("apps-rule-save"), f.ctx),
    /NEW.*ESTABLISHED/,
  );
  assert.equal(f.saves.length, 0);
});

test("incomplete builder input never issues a request and previous applied expressions survive edits", async () => {
  const f = fixture(false);
  f.setView("applications_catalog");
  renderQueryBuilder(scope, applicationCatalogQuerySchema, {
    applyAction: "apps-catalog-filter",
  });
  handleQueryBuilderAction({
    dataset: {
      action: "query-builder-add",
      scope,
      kind: "condition",
      queryPath: "",
    },
  });
  handleQueryBuilderInput({
    target: {
      dataset: { queryPart: "field", queryPath: "0" },
      value: "name",
      closest: () => ({
        dataset: { queryBuilder: scope },
        querySelector: () => null,
      }),
    },
  });
  await assert.rejects(
    handleApplicationsAction(action("apps-catalog-filter"), f.ctx),
  );
  assert.equal(f.calls.length, 0);
});

test("catalog errors remain visible without discarding a previously received catalog", async () => {
  const f = fixture();
  await seedStatus(f, "applications_catalog");
  f.ctx.api = async () => {
    throw new Error("Temporary catalog failure");
  };
  await refreshApplications(f.ctx, { force: true });
  const markup = renderApplications(f.ctx, "applications_catalog");
  assert.match(markup, /Temporary catalog failure/);
  assert.match(markup, /Chat messages/);
});

test("catalog updates are fixed server operations and errors never claim activation", async () => {
  const f = fixture();
  f.ctx.api = async (path, options) => {
    f.calls.push({ path, options });
    throw new Error("Catalog signing key is not configured");
  };
  await assert.rejects(
    handleApplicationsAction(action("apps-catalog-download"), f.ctx),
    /signing key/,
  );
  assert.equal(f.calls[0].path, "applications/catalog/download");
  assert.deepEqual(JSON.parse(f.calls[0].options.body), {});
  assert.equal(f.saves.length, 0);
});

test("native app data uses existing RU/EN profile and missing engine never becomes a green active claim", async () => {
  const f = fixture();
  await seedStatus(f, "applications_connections");
  setLanguage("en");
  const markup = renderApplications(f.ctx, "applications_connections");
  assert.match(markup, /DPI engine unavailable/);
  assert.match(markup, /Classification|classif/);
  assert.match(markup, /Connections/);
  assert.doesNotMatch(markup, /Прикладная|распознавание|Движок/);
});

test("Observe shows escaped unmapped DPI protocols and never presents a calculated Block as applied", async () => {
  for (const language of ["ru", "en"]) {
    resetApplications();
    setLanguage(language);
    const f = fixture();
    const originalApi = f.ctx.api;
    let mode = "observe";
    f.ctx.api = async (path, options) => {
      const result = await originalApi(path, options);
      if (path === "applications/status")
        return {
          ...result,
          mode,
          enabled: true,
          healthy: true,
          available: true,
          engine: { available: true, name: "nDPI", version: "6.0" },
        };
      if (path.startsWith("applications/connections?"))
        return {
          ...result,
          counters_scope: "analyzed",
          items: ["SSH", '<img src=x onerror="bad()">'].map(
            (protocol_name) => ({
              application_id: "",
              protocol_name,
              protocol: "tcp",
              classification_state: "unknown",
              decision: "block",
              state: "UNKNOWN",
              interface: "vmbr0",
              source: "192.0.2.1",
              destination: "198.51.100.1",
            }),
          ),
          total: 2,
        };
      return result;
    };
    await seedStatus(f, "applications_connections");
    let markup = renderApplications(f.ctx, "applications_connections");
    assert.match(markup, /<strong>SSH<\/strong>/);
    assert.match(markup, /&lt;img src=x onerror=&quot;bad\(\)&quot;&gt;/);
    assert.doesNotMatch(markup, /<img src=x/);
    assert.match(
      markup,
      language === "ru"
        ? /Протокол DPI вне каталога/
        : /DPI protocol outside the catalog/,
    );
    assert.match(markup, language === "ru" ? /Не применяется/ : /Not applied/);
    assert.match(
      markup,
      language === "ru" ? /захват интерфейсов/ : /interface capture/,
    );
    assert.match(
      markup,
      language === "ru" ? /до и после NAT/ : /before and after NAT/,
    );
    assert.doesNotMatch(markup, /class="apps-decision block"|IPv4 FORWARD/);
    mode = "enforce";
    await refreshApplications(f.ctx, { force: true });
    markup = renderApplications(f.ctx, "applications_connections");
    assert.match(markup, /class="apps-decision block"/);
    assert.match(markup, /IPv4 FORWARD/);
    assert.doesNotMatch(markup, /class="apps-decision observe"/);
  }
});

test("direct Connections loads localized catalog names once per version without per-poll requests", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  f.ctx.api = async (path, options) => {
    const result = await originalApi(path, options);
    if (path.startsWith("applications/connections?"))
      return {
        ...result,
        items: [{ application_id: "app.chat.messages", protocol: "tcp" }],
        total: 1,
      };
    return result;
  };
  await seedStatus(f, "applications_connections");
  assert.match(
    renderApplications(f.ctx, "applications_connections"),
    /<strong>Chat messages<\/strong>/,
  );
  await refreshApplications(f.ctx, { force: true });
  const catalogs = () =>
    f.calls.filter((call) => call.path.startsWith("applications/catalog?"));
  assert.equal(catalogs().length, 1);
  const query = new URL(catalogs()[0].path, "http://fixture/").searchParams;
  assert.equal(query.get("limit"), "1");
  assert.deepEqual(JSON.parse(query.get("expression")).children, [
    {
      kind: "condition",
      field: "id",
      op: "eq",
      value: "app.chat.messages",
    },
  ]);
  f.state.config.applications.catalog_version = "next-catalog";
  await refreshApplications(f.ctx, { force: true });
  assert.equal(catalogs().length, 2);
});

test("a large catalog resolves only visible monitor IDs in bounded cached batches", async () => {
  const f = fixture();
  f.state.config.applications.catalog_version = "large";
  const originalApi = f.ctx.api;
  const many = Array.from({ length: 5000 }, (_, index) =>
    leaf(`app.large.${index}`, `Service ${index}`),
  );
  let visible = many.slice(4400, 4450).map((entry) => entry.id);
  const metadataQueries = [];
  f.ctx.api = async (path, options) => {
    if (path.startsWith("applications/catalog?")) {
      const query = new URL(path, "http://fixture/").searchParams;
      const expression = JSON.parse(query.get("expression"));
      assert.equal(expression.kind, "group");
      assert.equal(expression.join, "or");
      assert.ok(expression.children.length <= 16);
      assert.ok(
        new globalThis.TextEncoder().encode(query.get("expression")).length <=
          4096,
      );
      assert.equal(Number(query.get("limit")), expression.children.length);
      assert.equal(query.get("offset"), "0");
      const ids = new Set(
        expression.children.map((node) => {
          assert.equal(node.field, "id");
          assert.equal(node.op, "eq");
          return node.value;
        }),
      );
      metadataQueries.push(ids);
      const items = many.filter((entry) => ids.has(entry.id));
      return { items, total: items.length, offset: 0, version: "large" };
    }
    if (path.startsWith("applications/connections?"))
      return {
        items: visible.map((application_id) => ({
          application_id,
          protocol: "tcp",
        })),
        total: visible.length,
      };
    return originalApi(path, options);
  };
  await seedStatus(f, "applications_connections");
  assert.equal(metadataQueries.length, 4);
  assert.equal(
    metadataQueries.reduce((sum, ids) => sum + ids.size, 0),
    50,
  );
  assert.match(
    renderApplications(f.ctx, "applications_connections"),
    /Service 4449/,
  );
  await refreshApplications(f.ctx, { force: true });
  assert.equal(metadataQueries.length, 4, "stable polling reuses labels");
  visible = [
    ...visible.slice(0, 40),
    ...many.slice(4900, 4910).map((entry) => entry.id),
  ];
  await refreshApplications(f.ctx, { force: true });
  assert.equal(
    metadataQueries.length,
    5,
    "only ten new visible IDs are fetched",
  );
  assert.equal(metadataQueries[4].size, 10);
  visible = ["app.removed"];
  await refreshApplications(f.ctx, { force: true });
  assert.equal(metadataQueries.length, 6);
  await refreshApplications(f.ctx, { force: true });
  assert.equal(
    metadataQueries.length,
    6,
    "negative lookups are cached for this catalog version",
  );
});

test("late sparse metadata cannot enter the cache or repaint after logout", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  let resolveMetadata, metadataSignal;
  f.ctx.api = async (path, options) => {
    if (path.startsWith("applications/connections?"))
      return { items: [{ application_id: "app.late" }], total: 1 };
    if (path.startsWith("applications/catalog?")) {
      metadataSignal = options.signal;
      return new Promise((resolve) => {
        resolveMetadata = resolve;
      });
    }
    return originalApi(path, options);
  };
  f.setView("applications_connections");
  const pending = refreshApplications(f.ctx, { force: true });
  await flush();
  assert.equal(typeof resolveMetadata, "function");
  resetApplications();
  f.expire();
  assert.equal(metadataSignal.aborted, true);
  resolveMetadata({ items: [leaf("app.late", "Private late name")], total: 1 });
  await pending;
  assert.equal(f.nodes["#applications-results"].innerHTML, "");
  assert.doesNotMatch(
    renderApplications(f.ctx, "applications_connections"),
    /Private late name/,
  );
});

test("catalog browsing retains only a bounded metadata working set", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  const entries = Array.from({ length: 3000 }, (_, index) =>
    leaf(`app.browse.${index}`, `Browse ${index}`),
  );
  let sparseRequests = 0;
  f.ctx.api = async (path, options) => {
    if (path.startsWith("applications/catalog?")) {
      const query = new URL(path, "http://fixture/").searchParams;
      const expression = query.get("expression");
      if (expression) {
        sparseRequests++;
        const ids = new Set(
          JSON.parse(expression).children.map((item) => item.value),
        );
        const items = entries.filter((entry) => ids.has(entry.id));
        return { items, total: items.length };
      }
      const offset = Number(query.get("offset")),
        limit = Number(query.get("limit"));
      assert.equal(limit, 50, "large catalogs stay paginated");
      return {
        items: entries.slice(offset, offset + limit),
        total: entries.length,
      };
    }
    if (path.startsWith("applications/connections?"))
      return { items: [{ application_id: entries[0].id }], total: 1 };
    return originalApi(path, options);
  };
  f.setView("applications_catalog");
  for (let offset = 0; offset < entries.length; offset += 50)
    await handleApplicationsAction(
      action("apps-page", { kind: "catalog", offset: String(offset) }),
      f.ctx,
    );
  assert.equal(sparseRequests, 0);
  await seedStatus(f, "applications_connections");
  assert.equal(
    sparseRequests,
    1,
    "the earliest page was evicted instead of retaining thousands of entries",
  );
  assert.match(
    renderApplications(f.ctx, "applications_connections"),
    /<strong>Browse 0<\/strong>/,
  );
});

test("catalog type totals are localized, distinct from filtered page totals and optional on older servers", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  let supported = true;
  f.ctx.api = async (path, options) => {
    const result = await originalApi(path, options);
    return path.startsWith("applications/catalog?") && supported
      ? {
          ...result,
          total: 1,
          items: [leaf("app.only")],
          counts_by_kind: {
            application: 1234,
            protocol: 320,
            family: 12,
            provider: 5,
            category: 0,
          },
        }
      : result;
  };
  await seedStatus(f, "applications_catalog");
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const markup = renderApplications(f.ctx, "applications_catalog");
    assert.match(
      markup,
      language === "ru" ? /Всего в каталоге/ : /Catalog totals/,
    );
    assert.match(
      markup,
      language === "ru" ? /Протоколы <strong>320/ : /Protocols <strong>320/,
    );
    assert.match(
      markup,
      language === "ru" ? /Семейства <strong>12/ : /Families <strong>12/,
    );
    assert.match(
      markup,
      language === "ru" ? /Категории <strong>0/ : /Categories <strong>0/,
    );
    assert.match(markup, /1.?234/);
    assert.match(markup, /1–1/);
  }
  supported = false;
  await refreshApplications(f.ctx, { force: true });
  assert.doesNotMatch(
    renderApplications(f.ctx, "applications_catalog"),
    /apps-catalog-counts/,
  );
});

test("hostname observation is never presented as validated DPI coverage", async () => {
  for (const language of ["ru", "en"]) {
    resetApplications();
    setLanguage(language);
    const f = fixture();
    const originalApi = f.ctx.api;
    const hinted = {
      ...leaf("app.domain", "Domain service"),
      hostname_observable: true,
      protocol_names: [],
      coverage: "Unverified domain hints",
      capabilities: {
        observable: true,
        block_validated: false,
        allow_over_port_deny: false,
      },
    };
    f.ctx.api = async (path, options) => {
      if (path.startsWith("applications/catalog?"))
        return { items: [hinted], total: 1 };
      if (path === "applications/catalog/app.domain") return hinted;
      return originalApi(path, options);
    };
    await seedStatus(f, "applications_catalog");
    const markup = renderApplications(f.ctx, "applications_catalog");
    assert.match(
      markup,
      language === "ru" ? /<th>Возможности/ : /<th>Capabilities/,
    );
    assert.match(
      markup,
      language === "ru"
        ? /title="Наблюдение доступно"/
        : /title="Observation available"/,
    );
    assert.doesNotMatch(
      markup,
      /title="Покрытие подтверждено"|title="Coverage validated"/,
    );
    await handleApplicationsAction(
      action("apps-catalog-detail", { id: hinted.id }),
      f.ctx,
    );
    const detail = f.frames.at(-1)[2];
    assert.match(
      detail,
      language === "ru" ? /Основание наблюдения/ : /Observation basis/,
    );
    assert.match(
      detail,
      language === "ru"
        ? /Имя узла · слабая подсказка/
        : /Hostname · weak hint/,
    );
    assert.match(
      detail,
      language === "ru" ? /не доказывает имя программы/ : /does not prove/,
    );
  }
});

test("large families and bulk page selection cannot silently exceed the rule's 64-app limit", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  const children = Array.from(
    { length: 65 },
    (_, index) => `app.group.${index}`,
  );
  const family = {
    id: "app.group",
    kind: "family",
    name: "Large family",
    concrete_ids: children,
    children,
  };
  f.ctx.api = async (path, options) =>
    path.startsWith("applications/catalog?")
      ? { items: [family, leaf(children[0], "First child")], total: 66 }
      : originalApi(path, options);
  await handleApplicationsAction(action("apps-rule-new"), f.ctx);
  assert.match(
    f.nodes["#apps-picker-results"].innerHTML,
    /data-app-picker="app.group"[^>]*disabled[^>]*64/,
  );
  handleApplicationsInput(
    { target: { dataset: { appPicker: family.id }, checked: true } },
    f.ctx,
  );
  assert.match(f.nodes["#apps-picker-results"].innerHTML, /до 64 приложений/);
  await assert.rejects(
    handleApplicationsAction(action("apps-rule-save"), f.ctx),
    /Выберите хотя бы одно/,
  );
  handleApplicationsInput(
    { target: { dataset: { appPicker: children[0] }, checked: true } },
    f.ctx,
  );
  await handleApplicationsAction(action("apps-picker-all"), f.ctx);
  assert.doesNotMatch(
    f.nodes["#apps-picker-results"].innerHTML,
    /role="alert"/,
  );
  await handleApplicationsAction(action("apps-rule-save"), f.ctx);
  assert.deepEqual(f.saves[0].applications.rules[0].application_ids, [
    children[0],
  ]);
});

test("bulk selection preserves earlier pages when selectable rows would exceed 64 applications", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  const selected = Array.from(
    { length: 20 },
    (_, index) => `app.selected.${index}`,
  );
  const shown = Array.from({ length: 50 }, (_, index) =>
    leaf(`app.shown.${index}`),
  );
  const all = [...selected.map((id) => leaf(id)), ...shown];
  f.state.config.applications.rules = [
    appRule("existing", { application_ids: selected }),
  ];
  f.ctx.api = async (path, options) => {
    if (!path.startsWith("applications/catalog?"))
      return originalApi(path, options);
    const expression = new URL(path, "http://fixture/").searchParams.get(
      "expression",
    );
    const ids =
      expression &&
      new Set(JSON.parse(expression).children.map((node) => node.value));
    const items = ids ? all.filter((entry) => ids.has(entry.id)) : shown;
    return { items, total: ids ? items.length : all.length };
  };
  await handleApplicationsAction(
    action("apps-rule-edit", { id: "existing" }),
    f.ctx,
  );
  await handleApplicationsAction(action("apps-picker-all"), f.ctx);
  assert.match(f.nodes["#apps-picker-results"].innerHTML, /role="alert"/);
  await handleApplicationsAction(action("apps-rule-save"), f.ctx);
  assert.deepEqual(f.saves[0].applications.rules[0].application_ids, selected);
});

test("rule duplication has its own localized label distinct from backup creation", () => {
  const f = fixture();
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const markup = renderApplications(f.ctx, "applications_rules");
    assert.match(
      markup,
      language === "ru"
        ? /data-action="apps-rule-copy" title="Дублировать правила"/
        : /data-action="apps-rule-copy" title="Duplicate rules"/,
    );
    assert.doesNotMatch(markup, /Create backup/);
  }
});

test("Settings scope and failure notes follow the draft mode and unsaved mode changes", () => {
  const f = fixture();
  const notes = { innerHTML: "" };
  f.nodes["#apps-settings-scope-notes"] = notes;
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    f.state.config.applications.mode = "observe";
    let markup = renderApplications(f.ctx, "applications_settings");
    assert.match(
      markup,
      language === "ru"
        ? /включая трафик самого роутера/
        : /including router traffic/,
    );
    assert.match(
      markup,
      language === "ru"
        ? /прекращаются только наблюдения/
        : /only stops observations/,
    );
    assert.doesNotMatch(
      markup,
      /INPUT\/OUTPUT|always blocks the managed scope|всегда закрывает управляемую область/,
    );
    const target = {
      name: "mode",
      value: "enforce",
      closest: () => f.settings,
    };
    assert.equal(handleApplicationsInput({ target }, f.ctx), true);
    assert.match(notes.innerHTML, /INPUT\/OUTPUT/);
    assert.match(
      notes.innerHTML,
      language === "ru"
        ? /всегда закрывает управляемую область/
        : /always blocks the managed scope/,
    );
    assert.equal(f.settings.dataset.dirty, "true");
    assert.equal(f.state.config.applications.mode, "observe");
    assert.equal(f.saves.length, 0);
    target.value = "observe";
    handleApplicationsInput({ target }, f.ctx);
    assert.doesNotMatch(notes.innerHTML, /INPUT\/OUTPUT/);
    f.state.config.applications.mode = "enforce";
    markup = renderApplications(f.ctx, "applications_settings");
    assert.match(markup, /INPUT\/OUTPUT/);
  }
});

test("DnD listeners are installed once and use a fresh context at drop time", () => {
  const f = fixture(),
    listeners = new Map();
  const fakeScope = {
    addEventListener: (name, handler) => listeners.set(name, handler),
    querySelectorAll: () => [],
  };
  installApplicationsEvents(() => f.ctx, fakeScope);
  assert.equal(listeners.size, 5);
  installApplicationsEvents(() => f.ctx, fakeScope);
  assert.equal(listeners.size, 5);
  f.ctx.writable = false;
  let prevented = false;
  const handle = { disabled: false, dataset: { appDrag: "one" } };
  listeners.get("dragstart")({
    target: { closest: () => handle },
    preventDefault: () => {
      prevented = true;
    },
  });
  assert.equal(prevented, true);
});

test("selection enables mutation controls without rebuilding or stealing focus from the table", () => {
  const f = fixture();
  f.state.config.applications.rules = [appRule("one")];
  const toggle = { disabled: true };
  f.nodes['[data-action="apps-rule-enable"]'] = toggle;
  f.nodes["#applications-results"].innerHTML = "UNCHANGED DOM";
  selectRule(f, "one");
  assert.equal(toggle.disabled, false);
  assert.equal(f.nodes["#applications-results"].innerHTML, "UNCHANGED DOM");
  f.ctx.writable = false;
  selectRule(f, "one");
  assert.equal(toggle.disabled, true);
});

test("drag reorder rejects a concurrent revision then preserves hidden-rule order on retry", async () => {
  const f = fixture(),
    listeners = new Map(),
    failures = [];
  f.state.config.applications.rules = [
    appRule("one"),
    appRule("hidden"),
    appRule("three"),
  ];
  f.ctx.run = async (operation) => {
    try {
      await operation();
    } catch (error) {
      failures.push(error.message);
    }
  };
  const classes = { add: () => {}, remove: () => {} };
  const row = {
    dataset: { appRule: "three" },
    classList: classes,
    getBoundingClientRect: () => ({ top: 0, height: 20 }),
  };
  const handle = {
    dataset: { appDrag: "one" },
    disabled: false,
    closest: () => ({ classList: classes }),
  };
  const fakeScope = {
    addEventListener: (name, handler) => listeners.set(name, handler),
    querySelectorAll: () => [row],
  };
  installApplicationsEvents(() => f.ctx, fakeScope);
  const start = () =>
    listeners.get("dragstart")({
      target: { closest: () => handle },
      dataTransfer: { setData: () => {} },
      preventDefault: () => {},
    });
  const drop = () =>
    listeners.get("drop")({
      target: { closest: () => row },
      clientY: 19,
      preventDefault: () => {},
    });
  start();
  f.state.revision++;
  drop();
  await flush();
  assert.equal(f.saves.length, 0);
  assert.match(failures[0], /Конфигурация изменилась/);
  start();
  drop();
  await flush();
  assert.deepEqual(
    f.saves[0].applications.rules.map((rule) => rule.id),
    ["hidden", "three", "one"],
  );
});

test("catalog details cannot replace an editor or appear in a different tab after a delayed response", async () => {
  const f = fixture();
  f.setView("applications_catalog");
  let finish;
  f.ctx.api = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  const pending = handleApplicationsAction(
    action("apps-catalog-detail", { id: "app.chat.messages" }),
    f.ctx,
  );
  f.setView("applications_settings");
  finish(catalog[1]);
  await pending;
  assert.equal(f.frames.length, 0);
});

test("all four screens translate complete visible labels into the selected English profile", async () => {
  const f = fixture();
  setLanguage("en");
  for (const view of Object.keys(applicationViews)) {
    await seedStatus(f, view);
    const text = renderApplications(f.ctx, view).replace(/<[^>]*>/g, "");
    assert.doesNotMatch(text, /[А-Яа-яЁё]/, view);
  }
});

test("mobile styles keep Applications in the classic bounded workspace", () => {
  const css = readFileSync(
    new URL("../../app/static/style.css", import.meta.url),
    "utf8",
  );
  assert.match(css, /\.apps-page[\s\S]*min-width: 0/);
  assert.match(
    css,
    /@media \(max-width: 620px\)[\s\S]*\.apps-tabs[\s\S]*minmax\(0, 1fr\)/,
  );
});

test("Applications sortable headers use the compact table control and preserve endpoint/numeric columns", async () => {
  const f = fixture();
  const originalApi = f.ctx.api;
  f.ctx.api = async (path, options) =>
    path.startsWith("applications/connections?")
      ? {
          items: [
            {
              source: "192.0.2.123",
              source_port: 65535,
              destination: "198.51.100.234",
              destination_port: 443,
              protocol: "tcp",
              protocol_name: "TLS",
              packets: 123456,
              bytes: 987654321,
            },
          ],
          total: 1,
        }
      : originalApi(path, options);
  await seedStatus(f, "applications_connections");
  let markup = renderApplications(f.ctx, "applications_connections");
  assert.equal(
    (markup.match(/class="connection-sort table-sort-button"/g) || []).length,
    9,
  );
  assert.match(markup, /class="mono apps-endpoint">192\.0\.2\.123:65535/);
  assert.match(markup, /class="mono apps-endpoint">198\.51\.100\.234:443/);
  assert.equal((markup.match(/<td class="mono numeric">/g) || []).length, 2);
  await handleApplicationsAction(
    action("apps-sort", { kind: "connections", key: "packets" }),
    f.ctx,
  );
  markup = renderApplications(f.ctx, "applications_connections");
  assert.match(
    markup,
    /class="numeric" aria-sort="ascending"[^]*data-key="packets"/,
  );
  await seedStatus(f, "applications_catalog");
  markup = renderApplications(f.ctx, "applications_catalog");
  assert.equal(
    (markup.match(/class="connection-sort table-sort-button"/g) || []).length,
    3,
  );
  const css = readFileSync(
    new URL("../../app/static/style.css", import.meta.url),
    "utf8",
  );
  assert.match(
    css,
    /\.apps-page \.table-sort-button \{[^}]*border: 0;[^}]*white-space: nowrap;[^}]*overflow-wrap: normal;/,
  );
  assert.match(css, /\.apps-connections-table \{[^}]*min-width: 1360px;/);
  assert.match(
    css,
    /\.apps-page \.table-scroll \{[^}]*min-width: 0;[^}]*overflow-x: auto;/,
  );
});
