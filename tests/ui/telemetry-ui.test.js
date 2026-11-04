import test from "node:test";
import assert from "node:assert/strict";
import {
  appendTelemetryHistory,
  formatBytes,
  formatRate,
  mergeTelemetrySnapshot,
  renderTelemetry,
} from "../../app/static/telemetry-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char],
  );
function sample(timestamp = 100) {
  return {
    demo: false,
    timestamp,
    sample_seconds: 5,
    traffic: {
      scope: "physical",
      available: true,
      rx_bps: 8000000,
      tx_bps: 2000000,
      rx_bytes: 8000000000,
      tx_bytes: 2000000000,
      rx_packets: 100,
      tx_packets: 40,
      rx_pps: 20,
      tx_pps: 8,
    },
    interfaces: [
      {
        name: "eth0",
        state: "UP",
        physical: true,
        rx_bps: 4000000,
        tx_bps: 1000000,
        rx_bytes: 1000000,
        tx_bytes: 2000000,
        rx_packets: 60,
        tx_packets: 20,
        rx_pps: 12,
        tx_pps: 4,
      },
    ],
    connections: { available: true, active: 12, limit: 65536 },
    devices: { available: true, count: 3, dhcp_leases: 2, items: [] },
    top_destinations: { available: true, basis: "connections", items: [] },
    system: {
      uptime_seconds: 90000,
      cpu_percent: 12,
      memory_used_bytes: 1000000000,
      memory_total_bytes: 4000000000,
    },
  };
}
function render(snapshot, selection = "all", extra = {}) {
  return renderTelemetry({
    e,
    telemetry: snapshot,
    telemetrySelection: selection,
    telemetryHistory: [],
    ...extra,
  });
}

test("network rates remain bits/s while cumulative traffic remains bytes", () => {
  assert.equal(formatRate(8000000), "8 Мбит/с");
  assert.equal(formatBytes(1000000), "1 МБ");
  assert.equal(formatRate(0), "0 бит/с");
  for (const value of [null, undefined, -1, Infinity, NaN, "10"])
    assert.equal(formatRate(value), "—");
});

test("history is bounded and detached from API snapshots; duplicate polls do not stretch the chart", () => {
  let history = [];
  for (let index = 1; index <= 80; index++)
    history = appendTelemetryHistory(history, sample(index * 5));
  assert.equal(history.length, 61);
  assert.equal(history[0].timestamp, 100);
  const same = appendTelemetryHistory(history, sample(400));
  assert.equal(same, history);
  const snapshot = sample(405);
  const next = appendTelemetryHistory(history, snapshot);
  snapshot.interfaces[0].rx_bps = 1;
  assert.equal(next.at(-1).interfaces[0].rx_bps, 4000000);
  assert.equal(history.at(-1).timestamp, 400);
});

test("collector restart, time reversal and demo/live transitions start new history windows", () => {
  const history = [sample(100), sample(105)].reduce(appendTelemetryHistory, []);
  assert.equal(appendTelemetryHistory(history, sample(50)).length, 1);
  const restarted = { ...sample(110), sample_seconds: null };
  assert.equal(appendTelemetryHistory(history, restarted).length, 1);
  assert.equal(
    appendTelemetryHistory(history, { ...sample(110), demo: true }).length,
    1,
  );
  assert.equal(
    appendTelemetryHistory(history, { timestamp: Infinity }),
    history,
  );
});

test("interface selection controls the summary and both charts without changing total device count", () => {
  const history = [sample(100), sample(105)].reduce(appendTelemetryHistory, []);
  const html = render(sample(105), "eth0", { telemetryHistory: history });
  assert.ok(html.includes('<option value="eth0" selected>'));
  assert.ok(html.includes('class="telemetry-value">4 Мбит/с'));
  assert.ok(html.includes('class="telemetry-value">3 МБ'));
  assert.ok(html.includes('class="telemetry-value">3</strong>'));
  assert.equal((html.match(/class="telemetry-chart"/g) || []).length, 2);
  assert.ok(!html.includes("NaN"));
  assert.ok(!html.includes("Infinity"));
  const removed = render(sample(105), "removed-interface");
  assert.ok(removed.includes('<option value="all" selected>'));
  assert.ok(removed.includes('class="telemetry-value">8 Мбит/с'));
});

test("unavailable and cold-start metrics have explicit states rather than fabricated zeros", () => {
  const loading = render(null);
  assert.ok(loading.includes("Загружаем показатели"));
  assert.ok(loading.includes("ОЖИДАНИЕ"));
  assert.ok(!loading.includes('class="telemetry-value">0'));
  const snapshot = sample();
  snapshot.sample_seconds = null;
  snapshot.traffic.rx_bps = null;
  snapshot.traffic.tx_bps = null;
  snapshot.connections = { available: false, active: null, limit: null };
  const cold = render(snapshot);
  assert.ok(cold.includes("Для вычисления скорости"));
  assert.ok(cold.includes("Собираем историю графика"));
  const stale = render(snapshot, "all", { telemetryError: "timeout" });
  assert.ok(stale.includes("НЕТ СВЯЗИ"));
  assert.ok(stale.includes("последние полученные данные"));
});

test("API-controlled names, addresses, sources and error strings are escaped", () => {
  const unsafe = '<img src=x onerror="alert(1)">';
  const snapshot = sample();
  snapshot.interfaces[0].name = unsafe;
  snapshot.top_destinations.items = [
    {
      address: unsafe,
      port: 443,
      protocol: unsafe,
      connections: 1,
      packets: null,
      bytes: null,
    },
  ];
  snapshot.devices.items = [
    {
      address: unsafe,
      mac: unsafe,
      hostname: unsafe,
      interface: unsafe,
      source: unsafe,
    },
  ];
  const html = render(snapshot, "all", { telemetryError: unsafe });
  assert.ok(!html.includes(unsafe));
  assert.ok(html.includes("&lt;img"));
  assert.ok(html.includes("&quot;"));
});

test("destination rankings identify current-flow basis and partial coverage; demo is explicit", () => {
  const snapshot = sample();
  snapshot.demo = true;
  snapshot.top_destinations = {
    available: true,
    basis: "bytes",
    partial: true,
    items: [
      {
        address: "203.0.113.8",
        port: 443,
        protocol: "tcp",
        connections: 3,
        packets: 40,
        bytes: 1000000,
      },
    ],
  };
  const html = render(snapshot);
  assert.ok(html.includes("Демонстрационные показатели"));
  assert.ok(html.includes("По байтам текущих соединений"));
  assert.ok(html.includes("ограниченная выборка"));
  assert.ok(html.includes("203.0.113.8:443"));
  assert.ok(html.includes("Наблюдаемые соседи IPv4"));
  assert.ok(html.includes('id="telemetry-content"'));
});

test("partial collection and bounded device tables disclose their coverage", () => {
  const snapshot = sample();
  snapshot.traffic.scope = "primary_interface_fallback";
  snapshot.traffic.partial = true;
  snapshot.devices.partial = true;
  snapshot.devices.items = Array.from({ length: 15 }, (_, index) => ({
    address: `192.0.2.${index + 1}`,
    hostname: `client-${index + 1}`,
    mac: "00:11:22:33:44:55",
    interface: "eth1",
    source: "dhcp",
  }));
  const html = render(snapshot);
  assert.ok(html.includes("Основной доступный интерфейс"));
  assert.ok(html.includes("ограниченный набор интерфейсов"));
  assert.ok(html.includes("ограниченную выборку устройств"));
  assert.ok(html.includes("первые 12 устройств"));
  assert.ok(html.includes("client-12"));
  assert.ok(!html.includes("client-13"));
  assert.ok(html.includes("в направлении к назначению"));
});

test("charts break their lines after missing polls instead of interpolating across an outage", () => {
  const history = [sample(100), sample(105), sample(130), sample(135)].reduce(
    appendTelemetryHistory,
    [],
  );
  const html = render(sample(135), "all", { telemetryHistory: history });
  const paths = [
    ...html.matchAll(/class="telemetry-(?:rx|tx)-line" d="([^"]*)"/g),
  ];
  assert.equal(paths.length, 4);
  for (const [, data] of paths) {
    assert.equal((data.match(/M/g) || []).length, 2);
    assert.equal((data.match(/L/g) || []).length, 2);
  }
});

test("200ms snapshots preserve a five minute history with one live point per second", () => {
  let history = [];
  for (let index = 0; index <= 2000; index++)
    history = appendTelemetryHistory(history, sample(100 + index / 5));
  assert.equal(history.length, 301);
  assert.ok(history[0].timestamp >= 200);
  assert.equal(history.at(-1).timestamp, 500);
  history = appendTelemetryHistory(history, sample(500.2));
  assert.equal(history.length, 301);
  assert.equal(history.at(-1).timestamp, 500.2);
});

test("fast telemetry preserves inventory and a late full response cannot roll counters back", () => {
  const original = sample(100);
  const fast = {
    ...sample(100.2),
    details_included: false,
    devices: {},
    top_destinations: {},
  };
  fast.traffic.rx_bytes = 9000000000;
  const merged = mergeTelemetrySnapshot(original, fast);
  assert.equal(merged.traffic.rx_bytes, 9000000000);
  assert.equal(merged.devices.count, 3);
  const late = sample(100.1);
  late.devices.count = 4;
  const updated = mergeTelemetrySnapshot(merged, late);
  assert.equal(updated.timestamp, 100.2);
  assert.equal(updated.traffic.rx_bytes, 9000000000);
  assert.equal(updated.devices.count, 4);
  assert.equal(
    mergeTelemetrySnapshot(updated, { ...sample(10), demo: true }).timestamp,
    10,
  );
});
