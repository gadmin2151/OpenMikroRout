import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import {
  hasUnsavedWorkspaceForm,
  markWorkspaceFormDirty,
} from "../../app/static/workspace-shell.js";

// Exercise the actual application flow without booting a browser or its timers.
const application = readFileSync(
  new globalThis.URL("../../app/static/app.js", import.meta.url),
  "utf8",
);
const start = application.indexOf("async function refresh(manual = false)");
const end = application.indexOf("\nasync function handleAction", start);
assert.ok(
  start >= 0 && end > start,
  "the application refresh entry is present",
);
const refreshSource = application.slice(start, end);

function fixture(id = "router-dns-form", view = "dns") {
  const pending = new Map();
  let ready;
  const requestsReady = new Promise((resolve) => (ready = resolve));
  const form = {
    id,
    dataset: {},
    isConnected: true,
    value: "initial value",
    closest: () => null,
  };
  let renders = 0;
  const root = {
    forms: [form],
    querySelectorAll() {
      return this.forms.filter(
        (item) => item.dataset.workspaceDirty === "true",
      );
    },
  };
  const initial = { revision: 1, config: { rules: [] }, current_user: null };
  const context = vm.createContext({
    root,
    draggingId: null,
    document: {
      body: { classList: { contains: () => false } },
      querySelector: () => null,
    },
    dialog: { open: false },
    authGeneration: 1,
    state: initial,
    api: async (path) => {
      if (path === "state") return { ...initial, revision: 2 };
      return new Promise((resolve) => {
        pending.set(path, resolve);
        if (pending.size === 4) ready();
      });
    },
    offline: false,
    setLanguage: () => false,
    canWrite: () => true,
    selected: new Set(),
    workspaceFrame: { view },
    view,
    interfaces: [],
    forwarding: null,
    audit: [],
    statistics: {},
    networkStatus: {},
    hasUnsavedWorkspaceForm,
    applyAccessControls: () => {},
    render: () => {
      renders++;
      form.isConnected = false;
      root.forms = [];
    },
    routerContext: () => ({}),
    refreshTelemetry: async () => {},
    refreshTelemetryHistory: async () => {},
    refreshProtection: async () => {},
    refreshDiscovery: async () => {},
  });
  vm.runInContext(
    refreshSource + "\nglobalThis.callRefresh = refresh;",
    context,
  );
  return {
    context,
    form,
    root,
    pending,
    requestsReady,
    get renders() {
      return renders;
    },
    change() {
      markWorkspaceFormDirty({ target: { closest: () => form } });
      form.value = "unsaved value";
    },
    complete() {
      pending.get("interfaces")({ interfaces: [], forwarding: null });
      pending.get("audit")([]);
      pending.get("statistics")({ counters: {} });
      pending.get("network/status")({});
    },
  };
}

test("typing while auxiliary refresh requests are pending preserves every page editor", async () => {
  for (const [id, view] of [
    ["router-dns-form", "dns"],
    ["router-domain-form", "web_settings"],
    ["f2b-settings", "fail2ban"],
    ["geo-settings", "geoip"],
    ["discovery-settings", "hosts"],
    ["scan-settings", "port_scan"],
    ["backup-import-form", "backups"],
    ["preferences-form", "security"],
  ]) {
    const f = fixture(id, view);
    const operation = f.context.callRefresh();
    await f.requestsReady;
    f.change();
    f.complete();
    await operation;
    assert.equal(f.renders, 0, id);
    assert.equal(f.root.forms[0], f.form, "keep the live form and its focus");
    assert.equal(f.form.value, "unsaved value");
    assert.equal(
      f.context.state.revision,
      2,
      "revision conflicts stay visible",
    );
  }
});

test("a dirty language preference also blocks refresh before auxiliary reads", async () => {
  const f = fixture("preferences-form", "security");
  f.change();
  await f.context.callRefresh();
  assert.equal(f.pending.size, 0);
  assert.equal(f.renders, 0);
  assert.equal(f.form.value, "unsaved value");
  assert.equal(f.context.state.revision, 2);
});

test("a clean editor still renders a changed router revision", async () => {
  const f = fixture();
  const operation = f.context.callRefresh();
  await f.requestsReady;
  f.complete();
  await operation;
  assert.equal(f.renders, 1);
  assert.equal(f.context.state.revision, 2);
});

test("logout while auxiliary reads are pending cannot restore the old tool", async () => {
  const f = fixture();
  const operation = f.context.callRefresh();
  await f.requestsReady;
  f.context.authGeneration++;
  f.context.state = null;
  f.complete();
  await operation;
  assert.equal(f.context.state, null);
  assert.equal(f.renders, 0);
});
