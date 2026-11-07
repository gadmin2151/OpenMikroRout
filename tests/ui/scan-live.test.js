import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  resetDiscovery,
  scanInterfaceNames,
  scanBlockedReason,
  syncScanForm,
  handleDiscoveryAction,
  renderDiscovery,
} from "../../app/static/discovery-ui.js";

const originalDocument = globalThis.document;
afterEach(() => {
  resetDiscovery();
  globalThis.document = originalDocument;
});
const flush = async () => {
  for (let index = 0; index < 10; index++) await Promise.resolve();
};
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
function context() {
  return {
    state: {
      revision: 1,
      config: {
        network: {},
        scanning: { enabled: false, interfaces: [] },
        discovery: {},
      },
    },
    interfaces: [{ name: "eth0" }, { name: "eth1" }],
    e: escape,
    icon: () => "",
    canWrite: () => true,
    offline: false,
    generation: 0,
    getGeneration: () => 0,
    isCurrentView: (view) => view === "port_scan",
  };
}
function status(extra = {}) {
  return {
    available: true,
    settings: { enabled: true, interfaces: ["eth0"] },
    networks: { eth0: ["192.0.2.0/24"], eth1: ["198.51.100.0/24"] },
    ...extra,
  };
}
function scanForm() {
  const select = {
    value: "eth1",
    options: [{ value: "" }],
    dataset: {},
    innerHTML: "",
  };
  const target = { value: "198.51.100.25" };
  const profile = { value: "custom" };
  const ports = { value: "22,443" };
  const hint = { textContent: "" };
  const readiness = { innerHTML: "" };
  const start = { disabled: false, title: "" };
  const elements = {
    '[name="interface"]': select,
    '[name="target"]': target,
    '[name="profile"]': profile,
    '[name="ports"]': ports,
    "#scan-networks": hint,
    "#scan-readiness": readiness,
    '[data-action="scan-start"]': start,
  };
  return {
    form: { querySelector: (selector) => elements[selector] || null },
    select,
    target,
    profile,
    ports,
    hint,
    readiness,
    start,
  };
}
function job(updated = 1, extra = {}) {
  return {
    id: "scan-1",
    state: "running",
    target: "192.0.2.1",
    progress: 10,
    updated,
    created: 1,
    request: { kind: "ports", profile: "quick", interface: "eth0" },
    result: { phase: "scanning", elapsed_seconds: updated, hosts: [] },
    ...extra,
  };
}

test("connected scan interfaces remain visible with scanning off and an empty allowlist", () => {
  const ctx = context();
  const disabled = status({ settings: { enabled: false, interfaces: [] } });
  assert.deepEqual(scanInterfaceNames(ctx, disabled), ["eth0", "eth1"]);
  assert.match(scanBlockedReason(ctx, disabled, "eth0"), /выключено|disabled/i);
  const f = scanForm();
  syncScanForm(ctx, f.form, disabled);
  assert.match(f.select.innerHTML, /value="eth0"/);
  assert.match(f.select.innerHTML, /value="eth1"/);
  assert.match(f.select.innerHTML, /нужно разрешить|enable/i);
  assert.equal(f.start.disabled, true);
  assert.match(f.readiness.innerHTML, /data-action="scan-settings-open"/);
  assert.equal(f.target.value, "198.51.100.25");
  assert.equal(f.profile.value, "custom");
  assert.equal(f.ports.value, "22,443");
});

test("allowed but unavailable interfaces are retained with a clear reason instead of disappearing", () => {
  const ctx = context();
  const configured = status({
    settings: { enabled: true, interfaces: ["eth0", "br-lan"] },
  });
  assert.deepEqual(scanInterfaceNames(ctx, configured), [
    "br-lan",
    "eth0",
    "eth1",
  ]);
  assert.match(
    scanBlockedReason(ctx, configured, "br-lan"),
    /нет подключённой|no connected/i,
  );
  assert.match(
    scanBlockedReason(ctx, configured, "eth1"),
    /не разрешено|not allowed/i,
  );
  assert.equal(scanBlockedReason(ctx, configured, "eth0"), "");
  const f = scanForm();
  f.select.value = "eth0";
  syncScanForm(ctx, f.form, configured);
  assert.equal(f.start.disabled, false);
  assert.equal(f.hint.textContent, "192.0.2.0/24");
  assert.equal(f.target.value, "198.51.100.25");
});

test("scan readiness blocks pending, read, offline, unavailable-tool and no-interface states", () => {
  const ctx = context();
  for (const change of [
    (value) => {
      value.offline = true;
    },
    (value) => {
      value.canWrite = () => false;
    },
    (value) => {
      value.state.pending = { revision: 2 };
    },
  ]) {
    const value = { ...ctx, state: { ...ctx.state } };
    change(value);
    assert.notEqual(scanBlockedReason(value, status(), "eth0"), "");
  }
  assert.match(
    scanBlockedReason(ctx, status({ available: false }), "eth0"),
    /Nmap/,
  );
  assert.notEqual(
    scanBlockedReason(
      ctx,
      status({ networks: {}, settings: { enabled: true, interfaces: [] } }),
      "",
    ),
    "",
  );
  assert.match(scanBlockedReason(ctx, null), /Загрузка|Loading/i);
});

test("active scan polls its single job every 500ms and updates only the detail region", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const ctx = context();
  let detailHTML = "";
  let detailWrites = 0;
  const detail = {
    set innerHTML(value) {
      detailWrites++;
      detailHTML = value;
    },
  };
  const queries = [];
  globalThis.document = {
    hidden: false,
    querySelector: (selector) => {
      queries.push(selector);
      return selector === "#scan-detail" ? detail : null;
    },
  };
  const calls = [];
  ctx.api = async (path) => {
    calls.push(path);
    return calls.length === 1
      ? job()
      : job(2, {
          progress: 50,
          result: {
            phase: "services",
            elapsed_seconds: 2,
            partial: true,
            hosts: [
              {
                addresses: ["192.0.2.1"],
                state: "up",
                ports: [
                  {
                    port: 443,
                    protocol: "tcp",
                    state: "open",
                    service: '<img src=x onerror="bad()">',
                  },
                ],
              },
            ],
          },
        });
  };
  await handleDiscoveryAction(
    { dataset: { action: "scan-job", id: "scan-1" } },
    ctx,
  );
  assert.equal(detailWrites, 1);
  t.mock.timers.tick(499);
  await flush();
  assert.equal(calls.length, 1);
  t.mock.timers.tick(1);
  await flush();
  assert.deepEqual(calls, ["scans/jobs/scan-1", "scans/jobs/scan-1"]);
  assert.equal(detailWrites, 2);
  assert.match(detailHTML, /value="50"/);
  assert.match(detailHTML, /443\/tcp/);
  assert.match(detailHTML, /&lt;img/);
  assert.doesNotMatch(detailHTML, /<img/);
  assert.ok(queries.every((selector) => selector === "#scan-detail"));
  assert.doesNotMatch(renderDiscovery("port_scan", ctx), /<img/);
  resetDiscovery();
});

test("reset/logout aborts an in-flight scan update and ignores its late result", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const ctx = context();
  let writes = 0;
  const detail = {
    set innerHTML(_value) {
      writes++;
    },
  };
  globalThis.document = { hidden: false, querySelector: () => detail };
  let resolve;
  let signal;
  let calls = 0;
  ctx.api = (path, options) => {
    assert.equal(path, "scans/jobs/scan-1");
    calls++;
    if (calls === 1) return Promise.resolve(job());
    signal = options.signal;
    return new Promise((done) => {
      resolve = done;
    });
  };
  await handleDiscoveryAction(
    { dataset: { action: "scan-job", id: "scan-1" } },
    ctx,
  );
  t.mock.timers.tick(500);
  await flush();
  assert.equal(calls, 2);
  resetDiscovery();
  assert.equal(signal.aborted, true);
  ctx.getGeneration = () => 1;
  resolve(job(2, { progress: 90 }));
  await flush();
  assert.equal(writes, 1);
  t.mock.timers.tick(5000);
  await flush();
  assert.equal(calls, 2);
});

test("hidden or inactive scan views do not start a background progress timer", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const ctx = context();
  let calls = 0;
  ctx.api = async () => {
    calls++;
    return job();
  };
  globalThis.document = { hidden: true, querySelector: () => null };
  await handleDiscoveryAction(
    { dataset: { action: "scan-job", id: "scan-1" } },
    ctx,
  );
  t.mock.timers.tick(10000);
  await flush();
  assert.equal(calls, 1);
});
