import test from "node:test";
import assert from "node:assert/strict";
import {
  renderDiscovery,
  renderScanResult,
  refreshDiscovery,
  handleDiscoveryAction,
  syncScanForm,
  resetDiscovery,
} from "../../app/static/discovery-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
function context(write = true) {
  return {
    state: {
      revision: 7,
      config: {
        network: {},
        discovery: { enabled: false, interfaces: ["eth0"] },
        scanning: { enabled: false, interfaces: ["eth0"] },
      },
    },
    interfaces: [{ name: "eth0" }],
    canWrite: () => write,
    offline: false,
    e,
    icon: () => "",
    generation: 0,
    getGeneration: () => 0,
    isCurrentView: (name) => name === "hosts",
  };
}

test("discovery and scans clearly separate passive settings from explicit probes", () => {
  resetDiscovery();
  const ctx = context();
  const hosts = renderDiscovery("hosts", ctx);
  assert.match(hosts, /пассивное обнаружение/);
  assert.match(hosts, /Источники/);
  assert.match(hosts, /data-revision="7"/);
  assert.match(hosts, /после общего применения/);
  const network = renderDiscovery("network_scan", ctx);
  assert.match(network, /data-kind="network"/);
  assert.doesNotMatch(network, /name="service_detection"/);
  const ports = renderDiscovery("port_scan", ctx);
  assert.match(ports, /Все TCP 1–65535/);
  assert.match(ports, /Выбранные UDP/);
  assert.match(ports, /name="service_detection"/);
});

test("read accounts cannot mutate discovery settings or start scans", async () => {
  resetDiscovery();
  const ctx = context(false);
  assert.match(renderDiscovery("hosts", ctx), /<fieldset disabled>/);
  assert.match(renderDiscovery("port_scan", ctx), /<fieldset disabled>/);
  for (const name of [
    "scan-start",
    "scan-cancel",
    "discovery-save-settings",
    "discovery-confirm-block",
  ])
    await assert.rejects(
      handleDiscoveryAction({ dataset: { action: name } }, ctx),
      /full/,
    );
});

test("Nmap strings are escaped and ambiguous port states are preserved", () => {
  const unsafe = '<img src=x onerror="bad()">';
  const result = renderScanResult(
    {
      state: "completed",
      target: unsafe,
      progress: 100,
      result: {
        partial: true,
        hosts: [
          {
            addresses: ["10.0.0.2"],
            state: "up",
            os_guesses: [unsafe],
            ports: [
              {
                port: 53,
                protocol: "udp",
                state: "open|filtered",
                service: unsafe,
                product: unsafe,
                version: "1",
              },
            ],
            other_ports: [{ state: "closed", count: 99 }],
          },
        ],
      },
    },
    context(),
  );
  assert.doesNotMatch(result, /<img/);
  assert.match(result, /&lt;img/);
  assert.match(result, /open\|filtered/);
  assert.match(result, /неполные результаты/);
  assert.match(result, /Отсутствие ответа не означает/);
  assert.match(result, /Предполагаемая ОС \(по службе\)/);
  assert.match(result, /не подтверждённая ОС/);
});

test("refresh updates only the results region and preserves editable settings", async () => {
  resetDiscovery();
  const seen = [],
    region = { innerHTML: "" };
  const oldDocument = globalThis.document;
  globalThis.document = {
    querySelector: (selector) => {
      seen.push(selector);
      return region;
    },
  };
  const ctx = context();
  ctx.api = async (path) =>
    path === "discovery/status"
      ? { settings: { enabled: true }, errors: {} }
      : {
          items: [
            {
              id: "one",
              interface: "eth0",
              addresses: ["10.0.0.2"],
              hostname: "<script>",
              sources: ["arp"],
              last_seen: 1,
            },
          ],
          total: 1,
        };
  try {
    await refreshDiscovery(ctx);
    assert.deepEqual(seen, ["#discovery-results"]);
    assert.match(region.innerHTML, /&lt;script&gt;/);
    assert.doesNotMatch(region.innerHTML, /<script>/);
  } finally {
    globalThis.document = oldDocument;
    resetDiscovery();
  }
});

test("late host detail response cannot reopen data after logout", async () => {
  const ctx = context();
  let resolve;
  let dialogs = 0;
  ctx.api = () =>
    new Promise((done) => {
      resolve = done;
    });
  ctx.dialogFrame = () => {
    dialogs++;
  };
  const pending = handleDiscoveryAction(
    { dataset: { action: "discovery-host", id: "one" } },
    ctx,
  );
  ctx.getGeneration = () => 1;
  resolve({ id: "one", addresses: ["10.0.0.2"], observations: [] });
  await pending;
  assert.equal(dialogs, 0);
});

test("applied scan interfaces refresh without replacing typed target or profile", () => {
  resetDiscovery();
  const select = { value: "eth1", options: [{ value: "" }], innerHTML: "" };
  const hint = { textContent: "" };
  const target = { value: "10.1.0.25" },
    profile = { value: "custom" },
    ports = { value: "22,443" };
  const elements = {
    '[name="interface"]': select,
    "#scan-networks": hint,
    '[name="target"]': target,
    '[name="profile"]': profile,
    '[name="ports"]': ports,
  };
  const form = { querySelector: (selector) => elements[selector] };
  const ctx = context();
  syncScanForm(ctx, form, {
    settings: { interfaces: ["eth1"] },
    networks: { eth1: ["10.1.0.0/24"] },
  });
  assert.match(select.innerHTML, /value="eth1" selected/);
  assert.equal(select.value, "eth1");
  assert.equal(hint.textContent, "10.1.0.0/24");
  assert.equal(target.value, "10.1.0.25");
  assert.equal(profile.value, "custom");
  assert.equal(ports.value, "22,443");
  syncScanForm(ctx, form, {
    settings: { interfaces: ["eth2"] },
    networks: { eth2: ["10.2.0.0/24"] },
  });
  assert.equal(select.value, "");
  assert.equal(hint.textContent, "");
  assert.equal(target.value, "10.1.0.25");
  assert.doesNotMatch(
    renderDiscovery("port_scan", ctx),
    /value="eth1" selected/,
  );
});

test("switching hosts to scan aborts stale requests and loads the new view immediately", async () => {
  resetDiscovery();
  const oldDocument = globalThis.document;
  globalThis.document = { querySelector: () => null };
  const ctx = context();
  const deferred = [];
  ctx.api = (path, { signal }) =>
    path.startsWith("discovery/")
      ? new Promise((resolve) => deferred.push({ resolve, signal }))
      : Promise.resolve(
          path === "scans/status"
            ? { settings: { interfaces: ["eth1"] } }
            : { items: [], total: 0 },
        );
  try {
    const pendingHosts = refreshDiscovery(ctx);
    ctx.isCurrentView = (name) => name === "port_scan";
    await refreshDiscovery(ctx);
    assert.ok(deferred.every((item) => item.signal.aborted));
    deferred.forEach((item) => item.resolve({}));
    await pendingHosts;
    assert.match(renderDiscovery("port_scan", ctx), /value="eth1"/);
  } finally {
    globalThis.document = oldDocument;
    resetDiscovery();
  }
});
