import test from "node:test";
import assert from "node:assert/strict";
import {
  appendTelemetryHistory,
  formatBytes,
  formatRate,
  mergeTelemetrySnapshot,
  interpolateTelemetryValue,
  telemetryPathTween,
  telemetryAxisMaximum,
  telemetryCurvePath,
  renderExpandedTelemetry,
  mergeStoredTelemetryHistory,
  downsampleTelemetryPoints,
  telemetryFittedFontSize,
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
  assert.equal(history.length, 80);
  assert.equal(history[0].timestamp, 5);
  const same = appendTelemetryHistory(history, sample(400));
  assert.equal(same, history);
  const snapshot = sample(405);
  const next = appendTelemetryHistory(history, snapshot);
  snapshot.interfaces[0].rx_bps = 1;
  assert.equal(next.at(-1).interfaces[0].rx_bps, 4000000);
  assert.equal(history.at(-1).timestamp, 400);
});

test("cold collector samples retain history; time reversal and demo/live transitions reset it", () => {
  const history = [sample(100), sample(105)].reduce(appendTelemetryHistory, []);
  assert.equal(appendTelemetryHistory(history, sample(50)).length, 1);
  const restarted = { ...sample(110), sample_seconds: null };
  assert.equal(appendTelemetryHistory(history, restarted).length, 3);
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
  assert.match(html, /class="telemetry-value"\s*>\s*4 Мбит\/с\s*<\/strong/);
  assert.match(html, /class="telemetry-value"\s*>\s*3 МБ\s*<\/strong/);
  assert.match(html, /class="telemetry-value"\s*>\s*3\s*<\/strong/);
  assert.equal((html.match(/class="telemetry-chart"/g) || []).length, 2);
  assert.ok(!html.includes("NaN"));
  assert.ok(!html.includes("Infinity"));
  const removed = render(sample(105), "removed-interface");
  assert.ok(removed.includes('<option value="all" selected>'));
  assert.match(removed, /class="telemetry-value"\s*>\s*8 Мбит\/с\s*<\/strong/);
});

test("unavailable and cold-start metrics have explicit states rather than fabricated zeros", () => {
  const loading = render(null);
  assert.ok(loading.includes("Загружаем показатели"));
  assert.ok(loading.includes("ОЖИДАНИЕ"));
  assert.doesNotMatch(loading, /class="telemetry-value"\s*>\s*0(?:\s|<)/);
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
    ...html.matchAll(/class="telemetry-(?:rx|tx)-line"\s+d="([^"]*)"/g),
  ];
  assert.equal(paths.length, 4);
  for (const [, data] of paths) {
    assert.equal((data.match(/M/g) || []).length, 2);
    assert.equal((data.match(/C/g) || []).length, 2);
  }
});

test("200ms snapshots coalesce seconds and retain at most one hour", () => {
  let history = [];
  for (let index = 0; index <= 5000; index++)
    history = appendTelemetryHistory(history, sample(100 + index / 5));
  assert.equal(history.length, 1001);
  assert.ok(history[0].timestamp >= 100);
  assert.equal(history.at(-1).timestamp, 1100);
  history = appendTelemetryHistory(history, sample(1100.2));
  assert.equal(history.length, 1001);
  assert.equal(history.at(-1).timestamp, 1100.2);
  assert.equal(appendTelemetryHistory(history, sample(4701)).length, 1);
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

test("animated values stay between measurements and settle on the exact target", () => {
  assert.equal(interpolateTelemetryValue(100, 300, 0), 100);
  assert.equal(interpolateTelemetryValue(100, 300, 0.5), 200);
  assert.equal(interpolateTelemetryValue(100, 300, 1), 300);
  assert.equal(interpolateTelemetryValue(100, 300, 2), 300);
  assert.equal(interpolateTelemetryValue(300, 100, 0.5), 200);
  // A burst retargets from the current presentation, without changing the raw target.
  const shown = interpolateTelemetryValue(100, 300, 0.5);
  assert.equal(interpolateTelemetryValue(shown, 400, 0.5), 300);
  assert.equal(interpolateTelemetryValue(shown, 400, 1), 400);
});

test("counter resets and unavailable readings are never animated into fabricated values", () => {
  assert.equal(interpolateTelemetryValue(1000, 25, 0.5, true), 25);
  assert.equal(interpolateTelemetryValue(null, 25, 0.5), 25);
  assert.equal(interpolateTelemetryValue(25, null, 0.5), null);
  assert.equal(interpolateTelemetryValue(25, undefined, 0.5), undefined);
  assert.equal(
    formatRate(interpolateTelemetryValue(900, 1100, 0.5)),
    "1 Кбит/с",
  );
});

test("SVG transitions interpolate scale changes and grow a new measured point", () => {
  assert.equal(telemetryPathTween(undefined, "M1,2 L3,4"), null);
  assert.equal(telemetryPathTween("M1,2 L3,4", null), null);
  const target = "M10.0,30.0 L30.0,50.0";
  const tween = telemetryPathTween("M0.0,10.0 L10.0,20.0", target);
  assert.equal(tween(0.5), "M5.0,20.0 L20.0,35.0");
  assert.equal(tween(1), target);
  const growing = telemetryPathTween("M0,0 L10,10", "M0,0 L10,20 L20,30");
  assert.equal(growing(0), "M0.0,0.0 L10.0,10.0 L10.0,10.0");
  assert.equal(growing(1), "M0,0 L10,20 L20,30");
});

test("SVG topology changes snap instead of joining missing-data gaps", () => {
  assert.equal(telemetryPathTween("M0,0 L10,10", "M0,0 M10,20"), null);
  assert.equal(telemetryPathTween("M0,0 L10,10", "M0,0 L10,10 M20,20"), null);
  assert.equal(telemetryPathTween("", "M0,0"), null);
  assert.equal(telemetryPathTween("M0,0 C1,1", "M0,0 L1,1"), null);
});

test("graph scales remain stable across small traffic fluctuations", () => {
  assert.equal(telemetryAxisMaximum([1100, 1900]), 2000);
  assert.equal(telemetryAxisMaximum([1100, 1950]), 2000);
  assert.equal(telemetryAxisMaximum([1100, 2050]), 5000);
  assert.equal(telemetryAxisMaximum([null, NaN, Infinity, 0]), 1);
});

test("monotone curves keep control points and sampled values within each measured interval", () => {
  const points = [
    { x: 0, y: 10 },
    { x: 10, y: 11 },
    { x: 20, y: 90 },
    { x: 30, y: 90 },
    { x: 40, y: 10 },
  ];
  const path = telemetryCurvePath(points);
  const curves = [...path.matchAll(/C([^MC]+)/g)].map(([, body]) =>
    body.trim().split(/[ ,]+/).map(Number),
  );
  assert.equal(curves.length, points.length - 1);
  for (let index = 0; index < curves.length; index++) {
    const from = points[index],
      to = points[index + 1];
    const [cx1, cy1, cx2, cy2, x, y] = curves[index];
    assert.ok(cx1 >= from.x && cx1 <= to.x && cx2 >= cx1 && cx2 <= to.x);
    assert.equal(x, to.x);
    assert.equal(y, to.y);
    const lower = Math.min(from.y, to.y),
      upper = Math.max(from.y, to.y);
    assert.ok(cy1 >= lower && cy1 <= upper && cy2 >= lower && cy2 <= upper);
    let previous = from.y;
    for (let step = 1; step <= 20; step++) {
      const t = step / 20,
        u = 1 - t;
      const value =
        u ** 3 * from.y +
        3 * u ** 2 * t * cy1 +
        3 * u * t ** 2 * cy2 +
        t ** 3 * to.y;
      assert.ok(value >= lower - 0.0001 && value <= upper + 0.0001);
      assert.ok(
        to.y >= from.y
          ? value >= previous - 0.0001
          : value <= previous + 0.0001,
      );
      previous = value;
    }
  }
  const broken = telemetryCurvePath([
    points[0],
    points[1],
    null,
    points[3],
    points[4],
  ]);
  assert.equal((broken.match(/M/g) || []).length, 2);
  assert.equal((broken.match(/C/g) || []).length, 2);
});

test("cubic animation grows the next segment and preserves exact final geometry", () => {
  const before = "M0,0 C3,0 7,10 10,10";
  const after = "M0,0 C3,0 7,20 10,20 C13,20 17,30 20,30";
  const tween = telemetryPathTween(before, after);
  assert.equal(
    tween(0),
    "M0.0,0.0 C3.0,0.0 7.0,10.0 10.0,10.0 C10.0,10.0 10.0,10.0 10.0,10.0",
  );
  assert.equal(tween(1), after);
  assert.equal(telemetryPathTween(before, "M0,0 C3,0 7,20 10,20 M20,30"), null);
});

test("overview charts keep a fixed one minute viewport with unmeasured time left blank", () => {
  const history = [sample(100), sample(101)].reduce(appendTelemetryHistory, []);
  const html = render(sample(101), "all", { telemetryHistory: history });
  assert.ok(html.includes("1 мин назад"));
  const [, path] = html.match(/class="telemetry-rx-line"\s+d="([^"]+)"/);
  const firstX = Number(path.match(/^M([\d.]+)/)[1]);
  assert.ok(firstX > 612 && firstX < 613);
  assert.ok(html.includes('class="telemetry-table telemetry-interface-table"'));
  assert.ok(html.includes('title="8 Мбит/с" class="telemetry-value"'));
});

test("expanded charts have independent paths and bounded selectable periods", () => {
  const history = [sample(100), sample(105)].reduce(appendTelemetryHistory, []);
  const html = render(sample(105), "eth0", {
    telemetryHistory: history,
    telemetryExpanded: { kind: "speed", period: 900 },
  });
  assert.match(html, /data-action="telemetry-expand"\s+data-kind="speed"/);
  assert.match(html, /role="dialog"\s+aria-modal="true"/);
  assert.ok(html.includes('data-live-path="expanded-speed-rx"'));
  assert.ok(html.includes('data-live-path="speed-rx"'));
  assert.match(html, /value="900"\s+selected(?:\s|>)/);
  assert.ok(html.includes("15 мин назад"));
  assert.ok(html.includes('data-action="telemetry-collapse"'));
  const invalidPeriod = renderExpandedTelemetry({
    e,
    telemetryHistory: history,
    telemetryExpanded: { kind: "packets", period: -20 },
  });
  assert.match(invalidPeriod, /value="60"\s+selected(?:\s|>)/);
  assert.equal(
    renderExpandedTelemetry({ telemetryExpanded: { kind: "<script>" } }),
    "",
  );
});

test("stored seconds replace provisional live buckets, reject invalid data, and survive cold samples", () => {
  const live = { ...sample(100.9), traffic: { rx_bps: 100 } };
  const stored = { ...sample(100.1), traffic: { rx_bps: 200 } };
  let history = mergeStoredTelemetryHistory([live], [stored, sample(101)]);
  assert.equal(history.length, 2);
  assert.equal(history[0].traffic.rx_bps, 200);
  const cold = {
    ...sample(102),
    sample_seconds: null,
    traffic: { rx_bps: null, tx_bps: null, rx_pps: null, tx_pps: null },
  };
  history = appendTelemetryHistory(history, cold);
  assert.equal(history.length, 3);
  assert.equal(history.at(-1).traffic.rx_bps, null);
  assert.equal(
    mergeStoredTelemetryHistory(history, [
      { timestamp: Infinity },
      { ...sample(103), demo: true },
    ]).length,
    3,
  );
  assert.equal(mergeStoredTelemetryHistory(history, [sample(4000)]).length, 1);
  assert.equal(
    mergeStoredTelemetryHistory(history, [sample(103)], { replace: true })
      .length,
    1,
  );
  const html = render(sample(103), "all", {
    telemetryHistoryError: '<img src=x onerror="x">',
  });
  assert.ok(html.includes("История временно недоступна:"));
  assert.ok(!html.includes('<img src=x onerror="x">'));
});

test("hour-long chart downsampling keeps original peaks, troughs, and gaps", () => {
  const points = Array.from({ length: 3601 }, (_, index) => ({
    x: index,
    y: index % 7,
  }));
  points[117] = { x: 117, y: 1000 };
  points[215] = { x: 215, y: -1000 };
  points[1500] = null;
  const reduced = downsampleTelemetryPoints(points);
  assert.ok(reduced.length < 650);
  assert.ok(reduced.includes(points[117]));
  assert.ok(reduced.includes(points[215]));
  assert.ok(reduced.includes(null));
  assert.equal(reduced[0], points[0]);
  assert.equal(reduced.at(-1), points.at(-1));
  for (const point of reduced)
    assert.ok(point === null || points.includes(point));
  const curve = telemetryCurvePath(reduced);
  assert.equal((curve.match(/M/g) || []).length, 2);
  const hour = renderExpandedTelemetry({
    e,
    telemetryHistory: [],
    telemetryExpanded: { kind: "speed", period: 3600 },
  });
  assert.match(hour, /value="3600"\s+selected\s*>\s*1 час\s*<\/option>/);
});

test("stored history keeps demo and live modes isolated without dropping demo history", () => {
  const demo = { ...sample(100), demo: true };
  const history = mergeStoredTelemetryHistory([], [demo, sample(101)]);
  assert.equal(history.length, 1);
  assert.equal(history[0].demo, true);
  const replacement = mergeStoredTelemetryHistory(history, [sample(102)], {
    replace: true,
  });
  assert.equal(replacement.length, 1);
  assert.equal(replacement[0].demo, false);
});

test("metric font fitting shrinks long values to one line without enlarging short values", () => {
  assert.equal(telemetryFittedFontSize(24, 120, 240), 12);
  assert.equal(telemetryFittedFontSize(24, 120, 100), 24);
  const size = telemetryFittedFontSize(22, 97, 173);
  assert.ok((size / 22) * 173 <= 97);
  assert.equal(telemetryFittedFontSize(24, 0, 240), 24);
  assert.equal(telemetryFittedFontSize(24, 120, NaN), 24);
  // Metadata retains its 12px base unless its complete label and counters need shrinking.
  assert.equal(telemetryFittedFontSize(12, 180, 150), 12);
  assert.equal(telemetryFittedFontSize(12, 150, 240), 7.5);
});
