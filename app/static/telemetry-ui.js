import { html, t, locale } from "./i18n.js";
/** Read-only network telemetry presentation. Rates are bits/s, byte counters are bytes. */
import {
  advanceTelemetryNumber,
  paintTelemetryNumber,
  telemetryUnit,
} from "./telemetry-motion.js?v=2";

const HISTORY_SECONDS = 3600;
const OVERVIEW_SECONDS = 60;
const PERIODS = [60, 300, 900, 3600];
const HISTORY_LIMIT = HISTORY_SECONDS + 1;
const INTERFACE_LIMIT = 128;
const MAX_GRAPH_GAP_SECONDS = 15;
const numberFormats = new Map();
function formats() {
  const language = locale();
  let cached = numberFormats.get(language);
  if (!cached) {
    cached = {
      count: new Intl.NumberFormat(language, { maximumFractionDigits: 0 }),
      decimal: new Intl.NumberFormat(language, { maximumFractionDigits: 1 }),
      liveDecimal: new Intl.NumberFormat(language, {
        minimumFractionDigits: 1,
        maximumFractionDigits: 1,
      }),
      compact: new Intl.NumberFormat(language, {
        notation: "compact",
        minimumFractionDigits: 1,
        maximumFractionDigits: 1,
      }),
    };
    numberFormats.set(language, cached);
  }
  return cached;
}

function finite(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : null;
}
function values(rows) {
  return Array.isArray(rows) ? rows : [];
}
function scaled(value, units) {
  let number = finite(value);
  if (number === null) return "—";
  let unit = 0;
  while (number >= 1000 && unit < units.length - 1) {
    number /= 1000;
    unit++;
  }
  return `${formats().decimal.format(number)} ${units[unit]}`;
}
export function formatRate(value) {
  return scaled(value, [
    t("бит/с"),
    t("Кбит/с"),
    t("Мбит/с"),
    t("Гбит/с"),
    t("Тбит/с"),
  ]);
}
export function formatBytes(value) {
  return scaled(value, [t("Б"), t("КБ"), t("МБ"), t("ГБ"), t("ТБ")]);
}
function count(value) {
  const number = finite(value);
  return number === null ? "—" : formats().count.format(number);
}
function sum(left, right) {
  const a = finite(left),
    b = finite(right);
  return a === null || b === null ? null : a + b;
}
function rates(source = {}) {
  return Object.fromEntries(
    ["rx_bps", "tx_bps", "rx_pps", "tx_pps"].map((key) => [
      key,
      finite(source?.[key]),
    ]),
  );
}

/** Keep a bounded browser-session window; never connect points across a collector restart. */
export function appendTelemetryHistory(history, snapshot) {
  const previous = values(history);
  const timestamp = finite(snapshot?.timestamp);
  if (timestamp === null) return previous;
  const last = previous.at(-1);
  if (last?.timestamp === timestamp) return previous;
  const current = {
    timestamp,
    demo: snapshot.demo === true,
    traffic: rates(snapshot.traffic),
    interfaces: values(snapshot.interfaces)
      .slice(0, INTERFACE_LIMIT)
      .filter((item) => typeof item?.name === "string")
      .map((item) => ({ name: item.name, ...rates(item) })),
  };
  const restarted =
    last && (timestamp < last.timestamp || current.demo !== last.demo);
  const window = restarted
    ? []
    : previous.filter(
        (point) => point.timestamp >= timestamp - HISTORY_SECONDS,
      );
  // Keep the newest live point within each second, preserving one hour at 5 Hz.
  if (
    window.length &&
    Math.floor(window.at(-1).timestamp) === Math.floor(timestamp)
  )
    return [...window.slice(0, -1), current];
  return [...window, current].slice(-HISTORY_LIMIT);
}

/** Stored completed seconds are authoritative; callers append the current live sample last. */
export function mergeStoredTelemetryHistory(
  existing,
  incoming,
  { replace = false } = {},
) {
  const buckets = new Map();
  const base = replace ? [] : values(existing);
  const mode =
    (
      base.find((point) => finite(point?.timestamp) !== null) ||
      values(incoming).find((point) => finite(point?.timestamp) !== null)
    )?.demo === true;
  for (const point of [...base, ...values(incoming)]) {
    if (finite(point?.timestamp) === null || (point.demo === true) !== mode)
      continue;
    const normalized = appendTelemetryHistory([], point)[0];
    if (normalized) buckets.set(Math.floor(point.timestamp), normalized);
  }
  const sorted = [...buckets.values()].sort(
    (a, b) => a.timestamp - b.timestamp,
  );
  const cutoff = (sorted.at(-1)?.timestamp || 0) - HISTORY_SECONDS;
  return sorted
    .filter((point) => point.timestamp >= cutoff)
    .slice(-HISTORY_LIMIT);
}

/** Full inventory can finish after a newer fast request; never roll counters back. */
export function mergeTelemetrySnapshot(previous, incoming) {
  if (!previous || previous.demo !== incoming.demo) return incoming;
  const latest = incoming.timestamp >= previous.timestamp ? incoming : previous;
  const details = incoming.details_included === false ? previous : incoming;
  return {
    ...latest,
    devices: details.devices,
    top_destinations: details.top_destinations,
  };
}

function patchTelemetryNode(current, next) {
  if (
    current.nodeType !== next.nodeType ||
    current.nodeName !== next.nodeName
  ) {
    current.replaceWith(next);
    return;
  }
  if (current.nodeType === 3) {
    if (current.textContent !== next.textContent)
      current.textContent = next.textContent;
    return;
  }
  if (current.nodeType !== 1) return;
  const liveNumber = current.hasAttribute("data-live-number");
  // Native select popup/focus and table scroll stay intact while counters change.
  if (
    ["telemetry-interface", "telemetry-period"].includes(current.id) &&
    current === current.ownerDocument.activeElement
  )
    return;
  for (const attribute of [...current.attributes])
    if (
      !next.hasAttribute(attribute.name) &&
      !(liveNumber && attribute.name === "style")
    )
      current.removeAttribute(attribute.name);
  for (const attribute of next.attributes)
    if (current.getAttribute(attribute.name) !== attribute.value)
      current.setAttribute(attribute.name, attribute.value);
  // Preserve the displayed reading while the shared number follower updates it.
  if (liveNumber) return;
  const existing = [...current.childNodes];
  const desired = [...next.childNodes];
  for (
    let index = 0;
    index < Math.max(existing.length, desired.length);
    index++
  ) {
    if (!desired[index]) existing[index].remove();
    else if (!existing[index]) current.append(desired[index]);
    else patchTelemetryNode(existing[index], desired[index]);
  }
}

const PATH_ANIMATION_MS = 240;
const NUMBER_PAINT_MS = 200;
const animations = new WeakMap();
const fontFits = new WeakMap();

/** Presentation interpolation only: callers retain the exact collected counters. */
export function interpolateTelemetryValue(
  from,
  to,
  progress,
  cumulative = false,
) {
  if (finite(from) === null || finite(to) === null || (cumulative && to < from))
    return to;
  const amount = Math.max(0, Math.min(1, progress));
  return amount === 1 ? to : from + (to - from) * amount;
}

/** Bound large SVGs while retaining actual extrema and every missing-data break. */
export function downsampleTelemetryPoints(points, maximum = 600) {
  if (points.length <= maximum) return points;
  const bucketSize = Math.max(
    1,
    Math.ceil(points.length / Math.max(1, Math.floor(maximum / 4))),
  );
  const result = [];
  let segment = [];
  const flush = () => {
    for (let start = 0; start < segment.length; start += bucketSize) {
      const bucket = segment.slice(start, start + bucketSize);
      let low = 0,
        high = 0;
      for (let index = 1; index < bucket.length; index++) {
        if (bucket[index].y < bucket[low].y) low = index;
        if (bucket[index].y > bucket[high].y) high = index;
      }
      for (const index of [...new Set([0, low, high, bucket.length - 1])].sort(
        (a, b) => a - b,
      ))
        result.push(bucket[index]);
    }
    segment = [];
  };
  for (const point of points) {
    if (point === null) {
      flush();
      if (result.length && result.at(-1) !== null) result.push(null);
    } else segment.push(point);
  }
  flush();
  return result;
}

/** Smooth measured points with monotone cubic slopes; never overshoot a local extreme. */
export function telemetryCurvePath(points) {
  const segments = [];
  let segment = [];
  for (const point of points) {
    if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) {
      if (segment.length) segments.push(segment);
      segment = [];
      continue;
    }
    if (segment.length && point.x <= segment.at(-1).x) {
      segments.push(segment);
      segment = [];
    }
    segment.push(point);
  }
  if (segment.length) segments.push(segment);
  return segments
    .map((rows) => {
      const deltas = rows
        .slice(1)
        .map(
          (point, index) =>
            (point.y - rows[index].y) / (point.x - rows[index].x),
        );
      const slopes = rows.map((_, index) => {
        if (!index) return deltas[0] || 0;
        if (index === rows.length - 1) return deltas.at(-1) || 0;
        return deltas[index - 1] * deltas[index] <= 0
          ? 0
          : (deltas[index - 1] + deltas[index]) / 2;
      });
      // Fritsch–Carlson limiting keeps both rising and falling intervals monotone.
      for (let index = 0; index < deltas.length; index++) {
        if (!deltas[index]) {
          slopes[index] = slopes[index + 1] = 0;
          continue;
        }
        const a = slopes[index] / deltas[index],
          b = slopes[index + 1] / deltas[index];
        const length = Math.hypot(a, b);
        if (length > 3) {
          slopes[index] = ((3 * a) / length) * deltas[index];
          slopes[index + 1] = ((3 * b) / length) * deltas[index];
        }
      }
      const path = [`M${rows[0].x.toFixed(1)},${rows[0].y.toFixed(1)}`];
      for (let index = 1; index < rows.length; index++) {
        const before = rows[index - 1],
          current = rows[index];
        const width = (current.x - before.x) / 3;
        const lower = Math.min(before.y, current.y),
          upper = Math.max(before.y, current.y);
        const bound = (value) => Math.max(lower, Math.min(upper, value));
        path.push(
          `C${(before.x + width).toFixed(1)},${bound(before.y + slopes[index - 1] * width).toFixed(1)} ${(current.x - width).toFixed(1)},${bound(current.y - slopes[index] * width).toFixed(1)} ${current.x.toFixed(1)},${current.y.toFixed(1)}`,
        );
      }
      return path.join(" ");
    })
    .join(" ");
}

/** Interpolate compatible measured curves without bridging missing-data gaps. */
export function telemetryPathTween(from, to) {
  if (typeof from !== "string" || typeof to !== "string") return null;
  const parse = (path) => {
    const chunks = [...path.matchAll(/([MLC])([^MLC]*)/g)];
    if (chunks.map((part) => part[0]).join("") !== path) return [];
    const result = [];
    for (const [, command, body] of chunks) {
      const numbers = body
        .trim()
        .split(/[\s,]+/)
        .map(Number);
      if (
        numbers.length !== (command === "C" ? 6 : 2) ||
        numbers.some((value) => !Number.isFinite(value))
      )
        return [];
      result.push({ command, numbers });
    }
    return result;
  };
  const before = parse(from),
    after = parse(to);
  // A new segment grows from the old endpoint, without inventing older measurements.
  if (
    after.length === before.length + 1 &&
    before.length &&
    ["L", "C"].includes(after.at(-1).command)
  ) {
    const endpoint = before.at(-1).numbers.slice(-2);
    before.push({
      command: after.at(-1).command,
      numbers:
        after.at(-1).command === "C"
          ? [...endpoint, ...endpoint, ...endpoint]
          : endpoint,
    });
  }
  if (
    !before.length ||
    before.length !== after.length ||
    after.some((point, index) => point.command !== before[index].command)
  )
    return null;
  return (progress) => {
    if (progress >= 1) return to;
    const amount = Math.max(0, progress);
    return after
      .map((point, index) => {
        const numbers = point.numbers.map((value, coordinate) => {
          const previous = before[index].numbers[coordinate];
          return (previous + (value - previous) * amount).toFixed(1);
        });
        return (
          point.command +
          numbers
            .map(
              (value, coordinate) =>
                `${coordinate ? (coordinate % 2 ? "," : " ") : ""}${value}`,
            )
            .join("")
        );
      })
      .join(" ");
  };
}

function numberAttributes(key, value, format, e, cumulative = false) {
  return `data-live-number="${e(key)}" data-live-value="${finite(value) ?? ""}" data-live-format="${format}"${cumulative ? ' data-live-counter="true"' : ""} `;
}
function liveNumber(key, value, format, e, cumulative = false) {
  return html`<span ${numberAttributes(key, value, format, e, cumulative)}
    >${e(formatLiveNumber(value, format))}</span
  >`;
}
function formatLiveNumber(value, format, unit) {
  if (finite(value) === null) return "—";
  if (format === "rate" || format === "bytes") {
    const units =
      format === "rate"
        ? [t("бит/с"), t("Кбит/с"), t("Мбит/с"), t("Гбит/с"), t("Тбит/с")]
        : [t("Б"), t("КБ"), t("МБ"), t("ГБ"), t("ТБ"), t("ПБ"), t("ЭБ")];
    const index = unit ?? telemetryUnit(value, undefined, units.length - 1);
    return `${(index ? formats().liveDecimal : formats().decimal).format(value / 1000 ** index)} ${units[index]}`;
  }
  if (format === "compact")
    return value < 100000 ? count(value) : formats().compact.format(value);
  if (format === "short")
    return value < 1000 ? count(value) : formats().compact.format(value);
  if (format === "pps") return html`${count(value)} пак/с`;
  if (format === "percent") return `${formats().decimal.format(value)}%`;
  return count(value);
}

export function telemetryFittedFontSize(baseSize, availableWidth, textWidth) {
  if (
    ![baseSize, availableWidth, textWidth].every(
      (value) => Number.isFinite(value) && value > 0,
    )
  )
    return baseSize;
  return Math.min(
    baseSize,
    Math.floor(baseSize * Math.min(1, availableWidth / textWidth) * 10) / 10,
  );
}

function fitTelemetryValue(node, labels, canvas) {
  if (!canvas || !node.classList.contains("telemetry-value")) return;
  const width = node.clientWidth;
  let cached = fontFits.get(node);
  if (!cached || cached.width !== width) {
    node.style.removeProperty("font-size");
    const style = node.ownerDocument.defaultView.getComputedStyle(node);
    cached = {
      width,
      baseSize: Number.parseFloat(style.fontSize),
      font: `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`,
      required: 0,
    };
    fontFits.set(node, cached);
  }
  canvas.font = cached.font;
  // Reserve tabular digit widths and a little space for the unit. Never resize
  // back and forth with each sample, and never replace moving DOM to measure it.
  const required = Math.max(
    cached.required,
    ...labels.map(
      (text) => canvas.measureText(text.replace(/\d/g, "0")).width * 1.06,
    ),
  );
  if (required <= cached.required) return;
  cached.required = required;
  const size = Math.max(
    16,
    telemetryFittedFontSize(cached.baseSize, width - 2, required),
  );
  node.style.fontSize = `${Math.min(cached.baseSize, size)}px`;
}

export function stopTelemetryAnimation(container) {
  const animation = container && animations.get(container);
  if (!animation) return;
  if (animation.frame !== null)
    container.ownerDocument.defaultView.cancelAnimationFrame(animation.frame);
  animation.finish?.();
  animations.delete(container);
}

/** Only UI structure and slow inventory belong in this signature. Fast counters
 * deliberately do not: changing one reading must not rebuild the dashboard. */
export function telemetryRenderSignature(ctx) {
  const snapshot = ctx.telemetry;
  const found = snapshot?.devices || {};
  const top = snapshot?.top_destinations || {};
  return JSON.stringify([
    locale(),
    ctx.telemetrySelection || "all",
    ctx.telemetryExpanded?.kind || "",
    ctx.telemetryExpanded?.period || "",
    ctx.telemetryError || "",
    ctx.telemetryHistoryError || "",
    !!snapshot,
    snapshot?.demo,
    snapshot?.sample_seconds === null,
    snapshot?.traffic?.scope,
    snapshot?.traffic?.partial,
    values(snapshot?.interfaces)
      .slice(0, INTERFACE_LIMIT)
      .map((item) => [item.name, item.state, item.physical]),
    [
      found.available,
      found.partial,
      found.count,
      found.dhcp_leases,
      values(found.items).length > 12,
      values(found.items).slice(0, 12),
    ],
    [top.available, top.partial, top.basis, values(top.items).slice(0, 10)],
  ]);
}

function effectiveTelemetrySelection(ctx) {
  const selection = ctx.telemetrySelection || "all";
  return selection === "all" ||
    values(ctx.telemetry?.interfaces)
      .slice(0, INTERFACE_LIMIT)
      .some((item) => item.name === selection)
    ? selection
    : "all";
}

/** Same names as data-live-number, keeping collected values separate from paint. */
export function telemetryLiveTargets(ctx) {
  const snapshot = ctx.telemetry;
  const stats = selectedMetrics(snapshot, effectiveTelemetrySelection(ctx));
  const result = new Map([
    ["summary-rx", stats.rx_bps],
    ["summary-tx", stats.tx_bps],
    ["summary-rx-bytes", stats.rx_bytes],
    ["summary-tx-bytes", stats.tx_bytes],
    ["summary-packets", sum(stats.rx_pps, stats.tx_pps)],
    ["summary-rx-packets", stats.rx_packets],
    ["summary-tx-packets", stats.tx_packets],
    ["summary-connections", snapshot?.connections?.active],
    ["summary-connection-limit", snapshot?.connections?.limit],
    ["summary-devices", snapshot?.devices?.count],
    ["summary-leases", snapshot?.devices?.dhcp_leases],
    ["summary-bytes", sum(stats.rx_bytes, stats.tx_bytes)],
  ]);
  for (const item of values(snapshot?.interfaces).slice(0, INTERFACE_LIMIT))
    for (const key of [
      "rx_bps",
      "tx_bps",
      "rx_bytes",
      "tx_bytes",
      "rx_packets",
      "tx_packets",
    ])
      result.set(`${item.name}:${key}`, item[key]);
  return result;
}

function updateTelemetryTargets(container, ctx, state) {
  const targets = telemetryLiveTargets(ctx);
  for (const node of state.numberNodes) {
    const key = node.dataset.liveNumber;
    if (!targets.has(key)) continue; // Chart legends are patched with the chart.
    const value = String(finite(targets.get(key)) ?? "");
    if (node.dataset.liveValue !== value) node.dataset.liveValue = value;
  }
  const selection = effectiveTelemetrySelection(ctx);
  const stats = selectedMetrics(ctx.telemetry, selection);
  const titles = [
    [formatRate(stats.rx_bps), html`Получено: ${formatBytes(stats.rx_bytes)}`],
    [
      formatRate(stats.tx_bps),
      html`Отправлено: ${formatBytes(stats.tx_bytes)}`,
    ],
    [
      count(sum(stats.rx_pps, stats.tx_pps)),
      html`Всего RX / TX: ${count(stats.rx_packets)} /
      ${count(stats.tx_packets)}`,
    ],
    [
      count(ctx.telemetry?.connections?.active),
      html`Лимит таблицы: ${count(ctx.telemetry?.connections?.limit)}`,
    ],
    [
      count(ctx.telemetry?.devices?.count),
      html`Действующих аренд DHCP: ${count(ctx.telemetry?.devices?.dhcp_leases)}`,
    ],
    [
      formatBytes(sum(stats.rx_bytes, stats.tx_bytes)),
      selection === "all"
        ? scopeLabel(ctx.telemetry?.traffic?.scope)
        : selection,
    ],
  ];
  for (const [index, [value, meta]] of titles.entries()) {
    const card = state.metricNodes[index];
    card?.querySelector(".telemetry-value")?.setAttribute("title", value);
    card?.querySelector(".telemetry-meta")?.setAttribute("title", meta);
  }
  const system = ctx.telemetry?.system || {};
  const memoryPercent =
    finite(system.memory_total_bytes) > 0 &&
    finite(system.memory_used_bytes) !== null
      ? (system.memory_used_bytes / system.memory_total_bytes) * 100
      : null;
  const labels = [
    duration(system.uptime_seconds),
    finite(system.cpu_percent) === null
      ? "—"
      : `${formats().decimal.format(system.cpu_percent)}%`,
    `${formatBytes(system.memory_used_bytes)} / ${formatBytes(system.memory_total_bytes)}${memoryPercent === null ? "" : ` · ${formats().decimal.format(memoryPercent)}%`}`,
  ];
  for (const [index, label] of labels.entries()) {
    const node = state.systemNodes[index];
    if (node && node.textContent !== label) node.textContent = label;
  }
  for (const [kind, period, expanded] of [
    ["speed", OVERVIEW_SECONDS, false],
    ["packets", OVERVIEW_SECONDS, false],
    ...(ctx.telemetryExpanded
      ? [
          [
            ctx.telemetryExpanded.kind,
            PERIODS.includes(ctx.telemetryExpanded.period)
              ? ctx.telemetryExpanded.period
              : OVERVIEW_SECONDS,
            true,
          ],
        ]
      : []),
  ]) {
    const prefix = `${expanded ? "expanded-" : ""}${kind}`;
    const current = container.querySelector(
      `[data-telemetry-chart="${prefix}"]`,
    );
    if (!current) continue;
    state.template.innerHTML = chart(
      ctx.telemetryHistory,
      selection,
      kind,
      ctx.e,
      period,
      expanded,
    );
    const next = state.template.content.firstElementChild;
    if (next) patchTelemetryNode(current, next);
  }
}

/** Samples update targets at 5 Hz; unchanged inventory never regenerates table HTML.
 * A single animation frame loop keeps the existing number and path followers. */
export function updateTelemetryView(container, ctx) {
  const owner = container.ownerDocument;
  const browser = owner.defaultView;
  const previous = animations.get(container);
  const state = previous || {
    frame: null,
    values: new Map(),
    paths: new Map(),
    template: owner.createElement("template"),
    canvas: owner.createElement("canvas").getContext("2d"),
  };
  const oldPaths = new Map(
    [...container.querySelectorAll("[data-live-path]")].map((node) => [
      node.dataset.livePath,
      node.getAttribute("d"),
    ]),
  );
  const signature = telemetryRenderSignature(ctx);
  if (
    previous?.signature === signature &&
    previous.root === container.firstElementChild
  ) {
    updateTelemetryTargets(container, ctx, state);
  } else {
    state.template.innerHTML = renderTelemetry(ctx);
    const next = state.template.content.firstElementChild;
    if (container.firstElementChild && next)
      patchTelemetryNode(container.firstElementChild, next);
    else container.replaceChildren(state.template.content);
    state.numberNodes = [...container.querySelectorAll("[data-live-number]")];
    state.metricNodes = [...container.querySelectorAll(".telemetry-metric")];
    state.systemNodes = [
      ...container.querySelectorAll(".telemetry-system strong"),
    ];
    state.root = container.firstElementChild;
    state.signature = signature;
  }

  const snapshot = ctx.telemetry;
  const selection = `${locale()}:${ctx.telemetrySelection || "all"}:${ctx.telemetryExpanded?.kind || ""}:${ctx.telemetryExpanded?.period || ""}`;
  const reduced = browser.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  const animate = Boolean(
    previous &&
    snapshot &&
    !ctx.telemetryError &&
    previous.selection === selection &&
    previous.demo === snapshot.demo &&
    snapshot.sample_seconds !== null &&
    snapshot.timestamp >= previous.timestamp &&
    snapshot.timestamp - previous.timestamp < MAX_GRAPH_GAP_SECONDS &&
    !owner.hidden &&
    !reduced,
  );
  const numbers = new Map();
  const paths = new Map();
  const canvas = state.canvas;
  for (const node of state.numberNodes) {
    const key = node.dataset.liveNumber;
    const format = node.dataset.liveFormat;
    const target =
      node.dataset.liveValue === "" ? null : Number(node.dataset.liveValue);
    const old = state.values.get(key);
    const cumulative = node.dataset.liveCounter === "true";
    const follow =
      animate &&
      old?.format === format &&
      finite(old.value) !== null &&
      finite(target) !== null &&
      !(cumulative && target < old.target);
    const record = {
      node,
      target,
      format,
      value: follow ? old.value : target,
      follower: follow ? old.follower : target,
      unit: follow ? old.unit : undefined,
    };
    if (format === "rate" || format === "bytes")
      record.unit = telemetryUnit(
        record.value,
        record.unit,
        format === "bytes" ? 6 : 4,
      );
    const label = formatLiveNumber(record.value, format, record.unit);
    const targetLabel = formatLiveNumber(target, format);
    fitTelemetryValue(node, [label, targetLabel], canvas);
    if (!animate || !old) paintTelemetryNumber(node, label);
    numbers.set(key, record);
  }
  for (const node of container.querySelectorAll("[data-live-path]")) {
    const key = node.dataset.livePath;
    const target = node.getAttribute("d");
    const old = state.paths.get(key);
    const from = oldPaths.get(key);
    if (animate && old?.target === target) {
      old.node = node;
      paths.set(key, old);
      if (from) node.setAttribute("d", from);
    } else {
      const tween =
        animate && from !== target ? telemetryPathTween(from, target) : null;
      const record = { node, target, tween, started: null };
      paths.set(key, record);
      if (tween) node.setAttribute("d", tween(0));
    }
  }
  Object.assign(state, {
    values: numbers,
    paths,
    selection,
    demo: snapshot?.demo,
    timestamp: snapshot?.timestamp,
  });
  const paintNumbers = () => {
    for (const item of state.values.values()) {
      if (item.format === "rate" || item.format === "bytes")
        item.unit = telemetryUnit(
          item.value,
          item.unit,
          item.format === "bytes" ? 6 : 4,
        );
      paintTelemetryNumber(
        item.node,
        formatLiveNumber(item.value, item.format, item.unit),
      );
    }
  };
  state.finish = () => {
    for (const item of state.values.values())
      item.value = item.follower = item.target;
    for (const item of state.paths.values()) {
      item.node.setAttribute("d", item.target);
      item.tween = null;
    }
    paintNumbers();
  };
  animations.set(container, state);
  if (!animate) {
    if (state.frame !== null) browser.cancelAnimationFrame(state.frame);
    state.frame = null;
    state.finish();
    return;
  }
  if (state.frame !== null) return;
  state.lastFrame = browser.performance.now();
  state.lastPaint = state.lastFrame;
  const frame = (now) => {
    if (!container.isConnected || owner.hidden) {
      stopTelemetryAnimation(container);
      return;
    }
    if (browser.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      state.frame = null;
      state.finish();
      return;
    }
    let moving = false;
    for (const item of state.values.values()) {
      const updated = advanceTelemetryNumber(
        item.value,
        item.follower,
        item.target,
        now - state.lastFrame,
      );
      item.value = updated.value;
      item.follower = updated.follower;
      moving ||= item.value !== item.target || item.follower !== item.target;
    }
    for (const item of state.paths.values()) {
      if (!item.tween) continue;
      item.started ??= now;
      const progress = Math.min(1, (now - item.started) / PATH_ANIMATION_MS);
      item.node.setAttribute("d", item.tween(progress));
      if (progress === 1) item.tween = null;
      else moving = true;
    }
    state.lastFrame = now;
    if (now - state.lastPaint >= NUMBER_PAINT_MS || !moving) {
      paintNumbers();
      state.lastPaint = now;
    }
    state.frame = moving ? browser.requestAnimationFrame(frame) : null;
  };
  state.frame = browser.requestAnimationFrame(frame);
}

function selectedMetrics(snapshot, selection) {
  if (!selection || selection === "all") return snapshot?.traffic || {};
  return (
    values(snapshot?.interfaces).find((item) => item.name === selection) || {}
  );
}
function metric(label, value, meta, e, animation = "", details = "") {
  return html`<article class="telemetry-metric">
    <span class="telemetry-label">${e(label)}</span
    ><strong ${animation}title="${e(value)}" class="telemetry-value"
      >${e(value)}</strong
    ><small title="${e(meta)}" class="telemetry-meta"
      >${details || e(meta)}</small
    >
  </article>`;
}
function metricDetails(label, content, e) {
  return html`<span class="telemetry-meta-label">${e(label)}</span
    ><span class="telemetry-meta-value">${content}</span>`;
}
function duration(value) {
  const seconds = finite(value);
  if (seconds === null) return "—";
  const days = Math.floor(seconds / 86400),
    hours = Math.floor((seconds % 86400) / 3600),
    minutes = Math.floor((seconds % 3600) / 60);
  return html`${days ? html`${days} д ` : ""}${hours} ч ${minutes} мин`;
}
function scopeLabel(scope) {
  return (
    {
      physical: t("Физические интерфейсы"),
      physical_interfaces: t("Физические интерфейсы"),
      non_loopback: t("Все интерфейсы без loopback"),
      all_non_loopback: t("Все интерфейсы без loopback"),
      fallback: t("Доступные интерфейсы"),
      primary_interface_fallback: t("Основной доступный интерфейс"),
      demo: t("Демонстрационные интерфейсы"),
    }[scope] || t("Группа интерфейсов")
  );
}

/** Coarse scale steps keep small new peaks from resizing the entire chart. */
export function telemetryAxisMaximum(observed) {
  const maximum = Math.max(
    1,
    ...observed.filter((value) => finite(value) !== null),
  );
  const magnitude = 10 ** Math.floor(Math.log10(maximum));
  const normalized = maximum / magnitude;
  const step =
    normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

function chart(
  history,
  selection,
  kind,
  e,
  period = OVERVIEW_SECONDS,
  expanded = false,
) {
  const prefix = `${expanded ? "expanded-" : ""}${kind}`;
  const packet = kind === "packets";
  const keys = packet ? ["rx_pps", "tx_pps"] : ["rx_bps", "tx_bps"];
  const title = packet ? t("Пакеты в секунду") : t("Скорость трафика");
  const format = packet ? (value) => html`${count(value)} пак/с` : formatRate;
  const available = values(history).filter(
    (point) => finite(point?.timestamp) !== null,
  );
  const lastTime = available.at(-1)?.timestamp || 0;
  const rows = available
    .filter((point) => point.timestamp >= lastTime - period)
    .slice(-HISTORY_LIMIT)
    .map((point) => ({
      timestamp: point.timestamp,
      ...selectedMetrics(point, selection),
    }));
  const readings = rows.flatMap((point) =>
    keys.map((key) => finite(point[key])),
  );
  const observed = readings.filter((number) => number !== null);
  const maximum = telemetryAxisMaximum(observed);
  const left = 110,
    right = 621,
    top = 14,
    bottom = 150;
  const firstTime = lastTime - period;
  const span = period;
  const x = (point) =>
    left + ((point.timestamp - firstTime) / span) * (right - left);
  const y = (value) => bottom - (value / maximum) * (bottom - top);
  const path = (key) => {
    const points = [];
    let previousTime = null;
    for (const point of rows) {
      const value = finite(point[key]);
      if (value === null) {
        points.push(null);
        previousTime = null;
        continue;
      }
      if (
        previousTime !== null &&
        point.timestamp - previousTime > MAX_GRAPH_GAP_SECONDS
      )
        points.push(null);
      points.push({ x: x(point), y: y(value) });
      previousTime = point.timestamp;
    }
    return telemetryCurvePath(downsampleTelemetryPoints(points));
  };
  const sufficient =
    rows.filter((point) => keys.some((key) => finite(point[key]) !== null))
      .length >= 2;
  const grid = [0, 0.5, 1]
    .map((fraction) => {
      const height = y(maximum * fraction);
      return html`<line
          class="telemetry-grid-line"
          x1="${left}"
          y1="${height}"
          x2="${right}"
          y2="${height}"
        /><text
          class="telemetry-axis"
          x="${left - 10}"
          y="${height + 4}"
          text-anchor="end"
          >${e(packet ? count(maximum * fraction) : scaled(maximum * fraction, [t("бит"), t("Кбит"), t("Мбит"), t("Гбит"), t("Тбит")]))}</text
        >`;
    })
    .join("");
  const picture = sufficient
    ? html`<svg
        class="telemetry-chart"
        viewBox="0 0 640 180"
        role="img"
        aria-labelledby="telemetry-${prefix}-title telemetry-${prefix}-description"
      >
        <title id="telemetry-${prefix}-title">${title}</title>
        <desc id="telemetry-${prefix}-description">
          История RX и TX за ${Math.round(span)} секунд. RX — входящий, TX —
          исходящий трафик.
        </desc>
        ${grid}
        <path
          data-live-path="${prefix}-rx"
          class="telemetry-rx-line"
          d="${path(keys[0])}"
        />
        <path
          data-live-path="${prefix}-tx"
          class="telemetry-tx-line"
          d="${path(keys[1])}"
        />
        <text class="telemetry-axis" x="${left}" y="173">
          ${period === 3600 ? t("1 час") : html`${period / 60} мин`} назад
        </text>
        <text class="telemetry-axis" x="${right}" y="173" text-anchor="end">
          Сейчас
        </text>
      </svg>`
    : html`<div class="telemetry-chart-empty">
        Собираем историю графика…<small
          >График появится после двух измерений.</small
        >
      </div>`;
  const last = rows.at(-1) || {};
  return html`<article class="telemetry-panel" data-telemetry-chart="${prefix}">
    <div class="telemetry-panel-heading">
      <h3>${title}</h3>
      <small
        >${packet ? t("RX / TX · пак/с") : t("RX / TX · бит/с")} ·
        ${period === 3600 ? t("1 час") : html`${period / 60} мин`}</small
      >${expanded ? "" : html`<button type="button" class="small telemetry-expand-button" data-action="telemetry-expand" data-kind="${kind}" aria-label="Развернуть график: ${title}">Развернуть</button>`}
    </div>
    <div class="telemetry-chart-box">${picture}</div>
    <div class="telemetry-legend">
      <span class="telemetry-rx-key"
        >RX
        <b
          ${numberAttributes(`${prefix}-rx`, last[keys[0]], packet ? "pps" : "rate", e)}
          >${e(format(last[keys[0]]))}</b
        ></span
      ><span class="telemetry-tx-key"
        >TX
        <b
          ${numberAttributes(`${prefix}-tx`, last[keys[1]], packet ? "pps" : "rate", e)}
          >${e(format(last[keys[1]]))}</b
        ></span
      >
    </div>
  </article>`;
}

export function renderExpandedTelemetry(ctx) {
  const expanded = ctx.telemetryExpanded;
  if (!expanded || !["speed", "packets"].includes(expanded.kind)) return "";
  const period = PERIODS.includes(expanded.period)
    ? expanded.period
    : OVERVIEW_SECONDS;
  const title =
    expanded.kind === "packets" ? t("Пакеты в секунду") : t("Скорость трафика");
  return html`<div class="telemetry-expanded-backdrop">
    <section
      class="telemetry-expanded"
      role="dialog"
      aria-modal="true"
      aria-labelledby="telemetry-expanded-title"
      tabindex="-1"
    >
      <header class="telemetry-expanded-heading">
        <div>
          <h2 id="telemetry-expanded-title">${title}</h2>
          <p>
            ${ctx.e(ctx.telemetrySelection === "all" || !ctx.telemetrySelection ? t("Все выбранные интерфейсы") : ctx.telemetrySelection)}
          </p>
        </div>
        <div class="telemetry-expanded-controls">
          <label for="telemetry-period">Период</label
          ><select id="telemetry-period" aria-label="Период графика">
            ${PERIODS.map((value) => html`<option value="${value}" ${period === value ? " selected" : ""}>${value === 3600 ? t("1 час") : html`${value / 60} мин`}</option>`).join("")}</select
          ><button
            type="button"
            class="icon ghost"
            data-action="telemetry-collapse"
            aria-label="Закрыть график"
            title="Закрыть график"
          >
            ×
          </button>
        </div>
      </header>
      ${chart(ctx.telemetryHistory, ctx.telemetrySelection || "all", expanded.kind, ctx.e, period, true)}
      <p class="telemetry-note">
        История хранится в базе данных роутера до 1 часа. Пустая область
        означает отсутствие сохранённых измерений.
      </p>
    </section>
  </div>`;
}

function interfaceTable(snapshot, e) {
  const rows = values(snapshot?.interfaces).slice(0, INTERFACE_LIMIT);
  return html`<article class="telemetry-panel">
    <div class="telemetry-panel-heading">
      <h3>Трафик по интерфейсам</h3>
      <small>Скорость и накопленные счётчики</small>
    </div>
    <div class="telemetry-table-scroll">
      <table class="telemetry-table telemetry-interface-table">
        <thead>
          <tr>
            <th>Интерфейс</th>
            <th>Статус</th>
            <th class="numeric">RX · скорость</th>
            <th class="numeric">TX · скорость</th>
            <th class="numeric">Получено</th>
            <th class="numeric">Отправлено</th>
            <th class="numeric">Пакеты RX / TX</th>
          </tr>
        </thead>
        <tbody>
          ${
            rows
              .map(
                (item) =>
                  html`<tr>
                    <td>
                      <strong class="mono">${e(item.name)}</strong
                      ><small
                        >${item.physical ? t("Физический") : t("Виртуальный / системный")}</small
                      >
                    </td>
                    <td>
                      <span
                        class="telemetry-status ${item.state === "UP" ? "" : "down"}"
                        >${e(item.state || "UNKNOWN")}</span
                      >
                    </td>
                    <td class="numeric">
                      ${liveNumber(`${item.name}:rx_bps`, item.rx_bps, "rate", e)}
                    </td>
                    <td class="numeric">
                      ${liveNumber(`${item.name}:tx_bps`, item.tx_bps, "rate", e)}
                    </td>
                    <td class="numeric">
                      ${liveNumber(`${item.name}:rx_bytes`, item.rx_bytes, "bytes", e, true)}
                    </td>
                    <td class="numeric">
                      ${liveNumber(`${item.name}:tx_bytes`, item.tx_bytes, "bytes", e, true)}
                    </td>
                    <td class="numeric">
                      ${liveNumber(`${item.name}:rx_packets`, item.rx_packets, "count", e, true)}
                      /
                      ${liveNumber(`${item.name}:tx_packets`, item.tx_packets, "count", e, true)}
                    </td>
                  </tr>`,
              )
              .join("") ||
            html`<tr>
              <td colspan="7" class="telemetry-table-empty">
                Счётчики интерфейсов пока недоступны.
              </td>
            </tr>`
          }
        </tbody>
      </table>
    </div>
  </article>`;
}
function destinations(snapshot, e) {
  const top = snapshot?.top_destinations || {};
  const rows = values(top.items).slice(0, 10);
  const basis =
    top.basis === "bytes"
      ? t("По байтам текущих соединений")
      : t("По числу текущих соединений");
  return html`<article class="telemetry-panel">
    <div class="telemetry-panel-heading">
      <h3>Топ назначений</h3>
      <small>${basis}</small>
    </div>
    <div class="telemetry-table-scroll">
      <table class="telemetry-table">
        <thead>
          <tr>
            <th>Адрес / порт</th>
            <th>Протокол</th>
            <th class="numeric">Соединения</th>
            <th class="numeric">Пакеты</th>
            <th class="numeric">Трафик</th>
          </tr>
        </thead>
        <tbody>
          ${
            rows
              .map(
                (item) =>
                  html`<tr>
                    <td class="mono">
                      ${e(item.address)}${finite(item.port) === null ? "" : `:${e(item.port)}`}
                    </td>
                    <td>${e(String(item.protocol || "—").toUpperCase())}</td>
                    <td class="numeric">${e(count(item.connections))}</td>
                    <td class="numeric">${e(count(item.packets))}</td>
                    <td class="numeric">${e(formatBytes(item.bytes))}</td>
                  </tr>`,
              )
              .join("") ||
            html`<tr>
              <td colspan="5" class="telemetry-table-empty">
                ${top.available ? t("Текущих соединений нет.") : t("Список назначений недоступен на этом хосте.")}
              </td>
            </tr>`
          }
        </tbody>
      </table>
    </div>
    <p class="telemetry-note">
      Срез активных
      IPv4-соединений.${top.partial ? t(" Показана ограниченная выборка.") : ""}
      Пакеты и байты учитываются в направлении к назначению; значения зависят от
      доступности учёта соединений.
    </p>
  </article>`;
}
function devices(snapshot, e) {
  const found = snapshot?.devices || {};
  const rows = values(found.items).slice(0, 12);
  return html`<article class="telemetry-panel">
    <div class="telemetry-panel-heading">
      <h3>Устройства в сети</h3>
      <small>Обнаружено: ${e(count(found.count))}</small>
    </div>
    <div class="telemetry-table-scroll">
      <table class="telemetry-table telemetry-device-table">
        <thead>
          <tr>
            <th>Устройство</th>
            <th>IP-адрес</th>
            <th>Интерфейс / источник</th>
          </tr>
        </thead>
        <tbody>
          ${
            rows
              .map(
                (item) =>
                  html`<tr>
                    <td>
                      <strong>${e(item.hostname || t("Устройство"))}</strong
                      ><small class="mono">${e(item.mac || "—")}</small>
                    </td>
                    <td class="mono">${e(item.address || "—")}</td>
                    <td>
                      ${e(item.interface || "—")}<small
                        >${e(item.source || "—")}</small
                      >
                    </td>
                  </tr>`,
              )
              .join("") ||
            html`<tr>
              <td colspan="3" class="telemetry-table-empty">
                ${found.available ? t("Устройства пока не обнаружены.") : t("Данные об устройствах недоступны.")}
              </td>
            </tr>`
          }
        </tbody>
      </table>
    </div>
    <p class="telemetry-note">
      Наблюдаемые соседи IPv4 и действующие аренды DHCP. Устройства без обмена с
      роутером могут ещё не
      отображаться.${found.partial ? t(" Источники данных охватывают ограниченную выборку устройств.") : ""}${values(found.items).length > rows.length ? html` В таблице показаны первые ${rows.length} устройств.` : ""}
    </p>
  </article>`;
}

export function renderTelemetry(ctx) {
  const e = ctx.e;
  const snapshot = ctx.telemetry;
  const selection = ctx.telemetrySelection || "all";
  const links = values(snapshot?.interfaces).slice(0, INTERFACE_LIMIT);
  const effectiveSelection =
    selection === "all" || links.some((item) => item.name === selection)
      ? selection
      : "all";
  const stats = selectedMetrics(snapshot, effectiveSelection);
  const packetRate = sum(stats.rx_pps, stats.tx_pps);
  const connections = snapshot?.connections || {};
  const observed = snapshot?.devices || {};
  const system = snapshot?.system || {};
  const demo = snapshot?.demo === true;
  const scope = scopeLabel(snapshot?.traffic?.scope);
  const notice = ctx.telemetryError
    ? html`<p class="telemetry-notice" role="status">
        Мониторинг временно недоступен:
        ${e(ctx.telemetryError)}${snapshot ? t(" · Показаны последние полученные данные.") : ""}
      </p>`
    : !snapshot
      ? html`<p class="telemetry-notice" role="status">
          Загружаем показатели сети…
        </p>`
      : snapshot.sample_seconds === null
        ? html`<p class="telemetry-notice" role="status">
            Первое измерение получено. Для вычисления скорости ждём следующий
            срез.
          </p>`
        : "";
  const memoryPercent =
    finite(system.memory_total_bytes) > 0 &&
    finite(system.memory_used_bytes) !== null
      ? (system.memory_used_bytes / system.memory_total_bytes) * 100
      : null;
  return html`<div class="telemetry-dashboard">
    <div class="telemetry-heading">
      <div>
        <h2>Мониторинг сети</h2>
        <p>
          ${demo ? t("Демонстрационные показатели · сеть компьютера не измеряется") : t("Скорости и счётчики · каждые 0,2 с · устройства и топ назначений · каждые 5 с")}
        </p>
      </div>
      <div class="telemetry-controls">
        <label for="telemetry-interface">Интерфейс графика</label
        ><select id="telemetry-interface" aria-label="Интерфейс графика">
          <option value="all" ${effectiveSelection === "all" ? "selected" : ""}>
            ${e(scope)}
          </option>
          ${links.map((item) => html`<option value="${e(item.name)}" ${item.name === effectiveSelection ? "selected" : ""}>${e(item.name)}</option>`).join("")}</select
        ><span
          class="${demo ? "telemetry-demo" : ctx.telemetryError || !snapshot ? "telemetry-stale" : "telemetry-live"}"
          >${demo ? "DEMO" : ctx.telemetryError ? t("НЕТ СВЯЗИ") : !snapshot ? t("ОЖИДАНИЕ") : "LIVE"}</span
        >
      </div>
    </div>
    <div id="telemetry-content">
      ${notice}${snapshot?.traffic?.partial ? html`<p class="telemetry-note">Счётчики охватывают ограниченный набор интерфейсов.</p>` : ""}
      <div class="telemetry-metrics">
        ${[
          metric(
            t("Входящая скорость · RX"),
            formatRate(stats.rx_bps),
            html`Получено: ${formatBytes(stats.rx_bytes)}`,
            e,
            numberAttributes("summary-rx", stats.rx_bps, "rate", e),
            metricDetails(
              t("Получено"),
              liveNumber("summary-rx-bytes", stats.rx_bytes, "bytes", e, true),
              e,
            ),
          ),
          metric(
            t("Исходящая скорость · TX"),
            formatRate(stats.tx_bps),
            html`Отправлено: ${formatBytes(stats.tx_bytes)}`,
            e,
            numberAttributes("summary-tx", stats.tx_bps, "rate", e),
            metricDetails(
              t("Отправлено"),
              liveNumber("summary-tx-bytes", stats.tx_bytes, "bytes", e, true),
              e,
            ),
          ),
          metric(
            t("Пакеты / с"),
            count(packetRate),
            html`Всего RX / TX: ${count(stats.rx_packets)} /
            ${count(stats.tx_packets)}`,
            e,
            numberAttributes("summary-packets", packetRate, "short", e),
            metricDetails(
              t("Всего RX / TX"),
              `${liveNumber("summary-rx-packets", stats.rx_packets, "compact", e, true)} / ${liveNumber("summary-tx-packets", stats.tx_packets, "compact", e, true)}`,
              e,
            ),
          ),
          metric(
            t("Активные соединения"),
            count(connections.active),
            html`Лимит таблицы: ${count(connections.limit)}`,
            e,
            numberAttributes(
              "summary-connections",
              connections.active,
              "count",
              e,
            ),
            metricDetails(
              t("Лимит таблицы"),
              liveNumber(
                "summary-connection-limit",
                connections.limit,
                "count",
                e,
              ),
              e,
            ),
          ),
          metric(
            t("Устройства"),
            count(observed.count),
            html`Действующих аренд DHCP: ${count(observed.dhcp_leases)}`,
            e,
            numberAttributes("summary-devices", observed.count, "count", e),
            metricDetails(
              t("Аренд DHCP"),
              liveNumber("summary-leases", observed.dhcp_leases, "count", e),
              e,
            ),
          ),
          metric(
            t("Накопленный трафик"),
            formatBytes(sum(stats.rx_bytes, stats.tx_bytes)),
            effectiveSelection === "all" ? scope : effectiveSelection,
            e,
            numberAttributes(
              "summary-bytes",
              sum(stats.rx_bytes, stats.tx_bytes),
              "bytes",
              e,
              true,
            ),
            metricDetails(
              t("Интерфейс"),
              e(effectiveSelection === "all" ? scope : effectiveSelection),
              e,
            ),
          ),
        ].join("")}
      </div>
      <div class="telemetry-chart-grid">
        ${chart(ctx.telemetryHistory, effectiveSelection, "speed", e)}${chart(ctx.telemetryHistory, effectiveSelection, "packets", e)}
      </div>
      <p class="telemetry-chart-footer">
        RX — получено интерфейсом, TX — отправлено. В обзоре — последняя минута.
        Разверните график для выбора периода до 1 часа. История сохраняется в
        базе данных роутера, одна точка в секунду. Счётчики трафика накоплены с
        момента запуска / сброса интерфейса.<span
          class="telemetry-history-status"
          role="status"
          >${ctx.telemetryHistoryError ? html`История временно недоступна: ${e(ctx.telemetryHistoryError)}` : ""}</span
        >
      </p>
      ${interfaceTable(snapshot, e)}
      <div class="telemetry-detail-grid">
        ${destinations(snapshot, e)}${devices(snapshot, e)}
      </div>
      <div class="telemetry-system">
        <span
          >Время работы
          <strong>${e(duration(system.uptime_seconds))}</strong></span
        ><span
          >CPU
          <strong
            >${finite(system.cpu_percent) === null ? "—" : `${e(formats().decimal.format(system.cpu_percent))}%`}</strong
          ></span
        ><span
          >RAM
          <strong
            >${e(formatBytes(system.memory_used_bytes))} /
            ${e(formatBytes(system.memory_total_bytes))}${memoryPercent === null ? "" : ` · ${e(formats().decimal.format(memoryPercent))}%`}</strong
          ></span
        >
      </div>
    </div>
    ${renderExpandedTelemetry(ctx)}
  </div>`;
}
