import test from "node:test";
import assert from "node:assert/strict";
import {
  telemetryRenderSignature,
  telemetryLiveTargets,
  updateTelemetryView,
  stopTelemetryAnimation,
  formatBytes,
} from "../../app/static/telemetry-ui.js";
import { setLanguage } from "../../app/static/i18n.js";

function sample(timestamp = 10, interfaces = 1) {
  return {
    timestamp,
    sample_seconds: 0.2,
    demo: false,
    traffic: {
      scope: "physical",
      rx_bps: 8000000,
      tx_bps: 2000000,
      rx_bytes: 10000000,
      tx_bytes: 20000000,
      rx_packets: 120,
      tx_packets: 30,
      rx_pps: 15,
      tx_pps: 5,
    },
    interfaces: Array.from({ length: interfaces }, (_, index) => ({
      name: `eth${index}`,
      physical: true,
      state: "UP",
      rx_bps: 2000000,
      tx_bps: 1000000,
      rx_bytes: 4000000,
      tx_bytes: 5000000,
      rx_packets: 40,
      tx_packets: 50,
      rx_pps: 7,
      tx_pps: 3,
    })),
    devices: {
      available: true,
      count: 1,
      dhcp_leases: 1,
      items: [{ hostname: "client", address: "192.0.2.1" }],
    },
    top_destinations: {
      available: true,
      basis: "bytes",
      items: [
        {
          address: "198.51.100.1",
          port: 443,
          protocol: "tcp",
          connections: 2,
          packets: 4,
          bytes: 512,
        },
      ],
    },
    connections: { active: 10, limit: 10000 },
    system: {
      uptime_seconds: 120,
      cpu_percent: 12,
      memory_used_bytes: 1000000000,
      memory_total_bytes: 2000000000,
    },
  };
}
const context = (telemetry = sample()) => ({
  e: String,
  telemetry,
  telemetryHistory: [sample(9), sample(10)],
  telemetrySelection: "all",
});

test("fast rate, counter and system changes retain dashboard structure; inventory and state changes invalidate it", () => {
  const ctx = context();
  const signature = telemetryRenderSignature(ctx);
  const fast = { ...ctx, telemetry: globalThis.structuredClone(ctx.telemetry) };
  fast.e = String;
  fast.telemetry.timestamp += 0.2;
  fast.telemetry.traffic.rx_bps *= 2;
  fast.telemetry.interfaces[0].rx_bytes += 1000;
  fast.telemetry.connections.active++;
  fast.telemetry.system.cpu_percent++;
  assert.equal(telemetryRenderSignature(fast), signature);
  for (const change of [
    (copy) => (copy.telemetry.interfaces[0].state = "DOWN"),
    (copy) => copy.telemetry.interfaces.push({ name: "br-lan" }),
    (copy) => (copy.telemetry.devices.items[0].hostname = "renamed"),
    (copy) => copy.telemetry.top_destinations.items[0].bytes++,
    (copy) => (copy.telemetryError = "offline"),
    (copy) => (copy.telemetryHistoryError = "unavailable"),
    (copy) => (copy.telemetrySelection = "eth0"),
    (copy) => (copy.telemetryExpanded = { kind: "packets", period: 300 }),
    (copy) => (copy.telemetry.sample_seconds = null),
    (copy) => (copy.telemetry.traffic.partial = true),
  ]) {
    const copy = {
      ...ctx,
      telemetry: globalThis.structuredClone(ctx.telemetry),
    };
    change(copy);
    assert.notEqual(telemetryRenderSignature(copy), signature);
  }
});

test("live targets cover all summary and interface counters while preserving interface selection and missing readings", () => {
  const ctx = context();
  const before = JSON.stringify(ctx.telemetry);
  assert.equal(telemetryLiveTargets(ctx).get("summary-rx"), 8000000);
  ctx.telemetrySelection = "eth0";
  const targets = telemetryLiveTargets(ctx);
  assert.equal(targets.get("summary-rx"), 2000000);
  assert.equal(targets.get("summary-packets"), 10);
  assert.equal(targets.get("summary-devices"), 1);
  assert.equal(targets.get("eth0:rx_bytes"), 4000000);
  assert.equal(targets.size, 18);
  assert.equal(JSON.stringify(ctx.telemetry), before);
  ctx.telemetrySelection = "removed";
  assert.equal(telemetryLiveTargets(ctx).get("summary-rx"), 8000000);
  ctx.telemetry.traffic.rx_pps = null;
  assert.equal(telemetryLiveTargets(ctx).get("summary-packets"), null);
});

/** Small DOM instrumentation fixture: real updater and renderers execute; it
 * counts parsed regions/canvas allocations and exposes native-like live nodes. */
function instrumentedDashboard() {
  const parsed = [];
  const owner = {
    hidden: false,
    defaultView: {
      matchMedia: () => ({ matches: true }),
      cancelAnimationFrame() {},
      getComputedStyle: () => ({
        fontSize: "20px",
        fontStyle: "normal",
        fontWeight: "600",
        fontFamily: "sans-serif",
      }),
    },
  };
  const makeNode = (nodeName, attributes = {}) => {
    const attrs = new Map(Object.entries(attributes));
    const node = {
      nodeType: 1,
      nodeName,
      childNodes: [],
      ownerDocument: owner,
      textContent: "",
      clientWidth: 240,
      style: { removeProperty() {} },
      classList: {
        contains: (value) =>
          (attrs.get("class") || "").split(" ").includes(value),
      },
      getAttribute: (name) => attrs.get(name),
      hasAttribute: (name) => attrs.has(name),
      removeAttribute: (name) => attrs.delete(name),
      setAttribute: (name, value) => attrs.set(name, String(value)),
    };
    Object.defineProperty(node, "attributes", {
      get: () => [...attrs].map(([name, value]) => ({ name, value })),
    });
    node.dataset = new Proxy(
      {},
      {
        get: (_, key) =>
          attrs.get(
            `data-${String(key).replace(/[A-Z]/g, (char) => `-${char.toLowerCase()}`)}`,
          ),
        set: (_, key, value) => {
          attrs.set(
            `data-${String(key).replace(/[A-Z]/g, (char) => `-${char.toLowerCase()}`)}`,
            String(value),
          );
          return true;
        },
      },
    );
    return node;
  };
  let canvasAllocations = 0;
  let numbers = [];
  const charts = new Map(
    ["speed", "packets", "expanded-speed", "expanded-packets"].map((prefix) => [
      prefix,
      makeNode("ARTICLE", { "data-telemetry-chart": prefix }),
    ]),
  );
  owner.createElement = (tag) => {
    if (tag === "canvas") {
      canvasAllocations++;
      return {
        getContext: () => ({
          measureText: (label) => ({ width: label.length * 10 }),
        }),
      };
    }
    const template = { content: { firstElementChild: null } };
    Object.defineProperty(template, "innerHTML", {
      set(markup) {
        parsed.push(markup);
        const prefix = /data-telemetry-chart="([^"]+)"/.exec(markup)?.[1];
        template.content.firstElementChild = markup.includes(
          'class="telemetry-dashboard"',
        )
          ? makeNode("DIV", { class: "telemetry-dashboard" })
          : makeNode("ARTICLE", { "data-telemetry-chart": prefix });
        if (markup.includes('class="telemetry-dashboard"')) {
          numbers = [
            ...markup.matchAll(
              /<(span|strong|b)\s+([^>]*data-live-number[^>]*)>/g,
            ),
          ].map((match) => {
            const attrs = Object.fromEntries(
              [...match[2].matchAll(/([\w-]+)="([^"]*)"/g)].map((attribute) => [
                attribute[1],
                attribute[2],
              ]),
            );
            return makeNode(match[1].toUpperCase(), attrs);
          });
        }
      },
    });
    return template;
  };
  const container = {
    ownerDocument: owner,
    firstElementChild: null,
    isConnected: true,
    replaceChildren(fragment) {
      this.firstElementChild = fragment.firstElementChild;
    },
    querySelectorAll: (selector) =>
      selector === "[data-live-number]" ? numbers : [],
    querySelector: (selector) =>
      charts.get(/data-telemetry-chart="([^"]+)"/.exec(selector)?.[1]),
  };
  return {
    container,
    parsed,
    canvasAllocations: () => canvasAllocations,
    numbers: () => numbers,
  };
}

test("ordinary 5Hz updates parse only chart regions, keep live nodes and reuse the measuring canvas", (t) => {
  setLanguage("ru");
  const fixture = instrumentedDashboard();
  const ctx = context(sample(10, 128));
  updateTelemetryView(fixture.container, ctx);
  const firstMarkup = fixture.parsed[0].length;
  const before = fixture
    .numbers()
    .find((node) => node.dataset.liveNumber === "summary-rx");
  assert.match(before.textContent, /8/);
  const parsedBefore = fixture.parsed.length;
  for (let index = 0; index < 5; index++) {
    ctx.telemetry.timestamp += 0.2;
    ctx.telemetry.traffic.rx_bps += 1000000;
    updateTelemetryView(fixture.container, ctx);
  }
  assert.equal(fixture.parsed.length - parsedBefore, 10);
  const incrementalMarkup = fixture.parsed.slice(parsedBefore);
  assert.ok(
    incrementalMarkup.every(
      (markup) =>
        !markup.includes("telemetry-dashboard") &&
        !markup.includes("telemetry-interface-table") &&
        !markup.includes("telemetry-device-table"),
    ),
  );
  assert.ok(
    incrementalMarkup[0].length + incrementalMarkup[1].length < firstMarkup / 3,
    "Chart parsing must be substantially smaller than a 128-interface dashboard",
  );
  assert.equal(
    fixture.numbers().find((node) => node.dataset.liveNumber === "summary-rx"),
    before,
  );
  assert.equal(before.dataset.liveValue, "13000000");
  assert.match(before.textContent, /13/);
  assert.equal(fixture.canvasAllocations(), 1);
  t.diagnostic(
    `128 interfaces: ${firstMarkup} dashboard characters versus ${incrementalMarkup[0].length + incrementalMarkup[1].length} chart characters parsed per sample; canvas allocations over 6 samples: ${fixture.canvasAllocations()}`,
  );
  ctx.telemetry.interfaces[0].state = "DOWN";
  updateTelemetryView(fixture.container, ctx);
  assert.ok(fixture.parsed.at(-1).includes("telemetry-dashboard"));
  stopTelemetryAnimation(fixture.container);
});

test("language changes invalidate markup and switch cached numeric formatting immediately", () => {
  setLanguage("ru");
  const ctx = context();
  const signature = telemetryRenderSignature(ctx);
  const russian = formatBytes(1500000);
  setLanguage("en");
  assert.notEqual(telemetryRenderSignature(ctx), signature);
  const english = formatBytes(1500000);
  assert.match(russian, /1,5/);
  assert.match(english, /1\.5/);
  setLanguage("ru");
});
