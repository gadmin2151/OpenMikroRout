/** Read-only network telemetry presentation. Rates are bits/s, byte counters are bytes. */
const HISTORY_SECONDS = 3600;
const OVERVIEW_SECONDS = 60;
const PERIODS = [60, 300, 900, 3600];
const HISTORY_LIMIT = HISTORY_SECONDS + 1;
const INTERFACE_LIMIT = 128;
const MAX_GRAPH_GAP_SECONDS = 15;
const nf = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 0 });
const decimal = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 });

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
  return `${decimal.format(number)} ${units[unit]}`;
}
export function formatRate(value) {
  return scaled(value, ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с", "Тбит/с"]);
}
export function formatBytes(value) {
  return scaled(value, ["Б", "КБ", "МБ", "ГБ", "ТБ"]);
}
function count(value) {
  const number = finite(value);
  return number === null ? "—" : nf.format(number);
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
  // Native select popup/focus and table scroll stay intact while counters change.
  if (
    ["telemetry-interface", "telemetry-period"].includes(current.id) &&
    current === current.ownerDocument.activeElement
  )
    return;
  for (const attribute of [...current.attributes])
    if (!next.hasAttribute(attribute.name))
      current.removeAttribute(attribute.name);
  for (const attribute of next.attributes)
    if (current.getAttribute(attribute.name) !== attribute.value)
      current.setAttribute(attribute.name, attribute.value);
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

const ANIMATION_MS = 180;
const animations = new WeakMap();

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
  return `<span ${numberAttributes(key, value, format, e, cumulative)}>${e(formatLiveNumber(value, format))}</span>`;
}
function formatLiveNumber(value, format) {
  if (format === "rate") return formatRate(value);
  if (format === "bytes") return formatBytes(value);
  if (format === "pps") return `${count(value)} пак/с`;
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

function fitTelemetryValue(node, from, target, format, canvas) {
  if (!canvas || !node.classList.contains("telemetry-value")) return;
  const labels = [
    formatLiveNumber(from, format),
    formatLiveNumber(target, format),
  ];
  const representative = labels.map((text) => {
    if (text.startsWith("—")) return text;
    if (["rate", "bytes", "pps"].includes(format))
      return `999,9 ${text.slice(text.lastIndexOf(" ") + 1)}`;
    return text.replace(/\d/g, "9");
  });
  fitTelemetryText(node, [...labels, ...representative], canvas);
}

function fitTelemetryText(node, labels, canvas) {
  if (!canvas || !node.clientWidth) return;
  const style = node.ownerDocument.defaultView.getComputedStyle(node);
  const baseSize = Number.parseFloat(style.fontSize);
  canvas.font = `${style.fontStyle} ${style.fontWeight} ${baseSize}px ${style.fontFamily}`;
  const longest = labels.reduce(
    (previous, text) =>
      canvas.measureText(text).width > canvas.measureText(previous).width
        ? text
        : previous,
    "",
  );
  const actualText = node.textContent;
  // Verify using the real font features (including tabular digits), which Canvas
  // does not reproduce exactly. This runs at sample rate, never in the RAF loop.
  node.textContent = longest;
  let fontSize = baseSize;
  for (
    let attempt = 0;
    attempt < 3 && node.scrollWidth > node.clientWidth;
    attempt++
  ) {
    fontSize = telemetryFittedFontSize(
      fontSize,
      node.clientWidth - 1,
      node.scrollWidth,
    );
    node.style.fontSize = `${fontSize}px`;
  }
  node.textContent = actualText;
}

export function stopTelemetryAnimation(container) {
  const animation = container && animations.get(container);
  if (!animation) return;
  if (animation.frame !== null)
    container.ownerDocument.defaultView.cancelAnimationFrame(animation.frame);
  animation.finish?.();
  animations.delete(container);
}

/** Patch structure at 5 Hz; each animation frame touches only numbers and SVG paths. */
export function updateTelemetryView(container, ctx) {
  const owner = container.ownerDocument,
    browser = owner.defaultView;
  const previous = animations.get(container);
  if (previous?.frame !== null && previous?.frame !== undefined)
    browser.cancelAnimationFrame(previous.frame);
  const oldPaths = new Map(
    [...container.querySelectorAll("[data-live-path]")].map((node) => [
      node.dataset.livePath,
      node.getAttribute("d"),
    ]),
  );
  const template = owner.createElement("template");
  template.innerHTML = renderTelemetry(ctx);
  const next = template.content.firstElementChild;
  if (container.firstElementChild && next)
    patchTelemetryNode(container.firstElementChild, next);
  else container.replaceChildren(template.content);

  const snapshot = ctx.telemetry;
  const selection = `${ctx.telemetrySelection || "all"}:${ctx.telemetryExpanded?.kind || ""}:${ctx.telemetryExpanded?.period || ""}`;
  const animate =
    previous &&
    snapshot &&
    !ctx.telemetryError &&
    previous.selection === selection &&
    previous.demo === snapshot.demo &&
    snapshot.sample_seconds !== null &&
    snapshot.timestamp >= previous.timestamp &&
    snapshot.timestamp - previous.timestamp < MAX_GRAPH_GAP_SECONDS &&
    !owner.hidden &&
    !browser.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const state = {
    frame: null,
    values: new Map(),
    selection,
    demo: snapshot?.demo,
    timestamp: snapshot?.timestamp,
    finish: null,
  };
  const numbers = [],
    paths = [];
  const canvas = owner.createElement("canvas").getContext("2d");
  for (const node of container.querySelectorAll(".telemetry-meta")) {
    const text = node.textContent;
    fitTelemetryText(node, [text, text.replace(/\d/g, "9")], canvas);
  }
  for (const node of container.querySelectorAll("[data-live-number]")) {
    const key = node.dataset.liveNumber,
      format = node.dataset.liveFormat;
    const target =
      node.dataset.liveValue === "" ? null : Number(node.dataset.liveValue);
    const old = previous?.values.get(key);
    const cumulative = node.dataset.liveCounter === "true";
    const from =
      animate && old?.format === format && !(cumulative && target < old.target)
        ? old.value
        : target;
    fitTelemetryValue(node, from, target, format, canvas);
    const record = { value: target, target, format };
    state.values.set(key, record);
    if (finite(from) !== null && finite(target) !== null && from !== target) {
      numbers.push({ node, from, target, format, record });
      record.value = from;
      node.textContent = formatLiveNumber(from, format);
    }
  }
  if (animate)
    for (const node of container.querySelectorAll("[data-live-path]")) {
      const target = node.getAttribute("d"),
        from = oldPaths.get(node.dataset.livePath);
      const tween =
        from && from !== target ? telemetryPathTween(from, target) : null;
      if (tween) {
        paths.push({ node, target, tween });
        node.setAttribute("d", tween(0));
      }
    }
  const paint = (progress) => {
    for (const item of numbers) {
      item.record.value = interpolateTelemetryValue(
        item.from,
        item.target,
        progress,
      );
      const text = formatLiveNumber(item.record.value, item.format);
      if (item.node.textContent !== text) item.node.textContent = text;
    }
    for (const item of paths) item.node.setAttribute("d", item.tween(progress));
  };
  state.finish = () => paint(1);
  animations.set(container, state);
  if (!numbers.length && !paths.length) return;
  let started;
  const frame = (now) => {
    if (!container.isConnected || owner.hidden) {
      stopTelemetryAnimation(container);
      return;
    }
    started ??= now;
    const elapsed = Math.min(1, (now - started) / ANIMATION_MS);
    const done =
      elapsed === 1 ||
      browser.matchMedia("(prefers-reduced-motion: reduce)").matches;
    paint(done ? 1 : 1 - (1 - elapsed) ** 3);
    state.frame = done ? null : browser.requestAnimationFrame(frame);
  };
  state.frame = browser.requestAnimationFrame(frame);
}

function selectedMetrics(snapshot, selection) {
  if (!selection || selection === "all") return snapshot?.traffic || {};
  return (
    values(snapshot?.interfaces).find((item) => item.name === selection) || {}
  );
}
function metric(label, value, meta, e, animation = "") {
  return `<article class="telemetry-metric"><span class="telemetry-label">${e(label)}</span><strong ${animation}title="${e(value)}" class="telemetry-value">${e(value)}</strong><small title="${e(meta)}" class="telemetry-meta">${e(meta)}</small></article>`;
}
function duration(value) {
  const seconds = finite(value);
  if (seconds === null) return "—";
  const days = Math.floor(seconds / 86400),
    hours = Math.floor((seconds % 86400) / 3600),
    minutes = Math.floor((seconds % 3600) / 60);
  return `${days ? `${days} д ` : ""}${hours} ч ${minutes} мин`;
}
function scopeLabel(scope) {
  return (
    {
      physical: "Физические интерфейсы",
      physical_interfaces: "Физические интерфейсы",
      non_loopback: "Все интерфейсы без loopback",
      all_non_loopback: "Все интерфейсы без loopback",
      fallback: "Доступные интерфейсы",
      primary_interface_fallback: "Основной доступный интерфейс",
      demo: "Демонстрационные интерфейсы",
    }[scope] || "Группа интерфейсов"
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
  const title = packet ? "Пакеты в секунду" : "Скорость трафика";
  const format = packet ? (value) => `${count(value)} пак/с` : formatRate;
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
      return `<line class="telemetry-grid-line" x1="${left}" y1="${height}" x2="${right}" y2="${height}"/><text class="telemetry-axis" x="${left - 10}" y="${height + 4}" text-anchor="end">${e(packet ? count(maximum * fraction) : scaled(maximum * fraction, ["бит", "Кбит", "Мбит", "Гбит", "Тбит"]))}</text>`;
    })
    .join("");
  const picture = sufficient
    ? `<svg class="telemetry-chart" viewBox="0 0 640 180" role="img" aria-labelledby="telemetry-${prefix}-title telemetry-${prefix}-description"><title id="telemetry-${prefix}-title">${title}</title><desc id="telemetry-${prefix}-description">История RX и TX за ${Math.round(span)} секунд. RX — входящий, TX — исходящий трафик.</desc>${grid}<path data-live-path="${prefix}-rx" class="telemetry-rx-line" d="${path(keys[0])}"/><path data-live-path="${prefix}-tx" class="telemetry-tx-line" d="${path(keys[1])}"/><text class="telemetry-axis" x="${left}" y="173">${period === 3600 ? "1 час" : `${period / 60} мин`} назад</text><text class="telemetry-axis" x="${right}" y="173" text-anchor="end">Сейчас</text></svg>`
    : `<div class="telemetry-chart-empty">Собираем историю графика…<small>График появится после двух измерений.</small></div>`;
  const last = rows.at(-1) || {};
  return `<article class="telemetry-panel"><div class="telemetry-panel-heading"><h3>${title}</h3><small>${packet ? "RX / TX · пак/с" : "RX / TX · бит/с"} · ${period === 3600 ? "1 час" : `${period / 60} мин`}</small>${expanded ? "" : `<button type="button" class="small telemetry-expand-button" data-action="telemetry-expand" data-kind="${kind}" aria-label="Развернуть график: ${title}">Развернуть</button>`}</div><div class="telemetry-chart-box">${picture}</div><div class="telemetry-legend"><span class="telemetry-rx-key">RX <b ${numberAttributes(`${prefix}-rx`, last[keys[0]], packet ? "pps" : "rate", e)}>${e(format(last[keys[0]]))}</b></span><span class="telemetry-tx-key">TX <b ${numberAttributes(`${prefix}-tx`, last[keys[1]], packet ? "pps" : "rate", e)}>${e(format(last[keys[1]]))}</b></span></div></article>`;
}

export function renderExpandedTelemetry(ctx) {
  const expanded = ctx.telemetryExpanded;
  if (!expanded || !["speed", "packets"].includes(expanded.kind)) return "";
  const period = PERIODS.includes(expanded.period)
    ? expanded.period
    : OVERVIEW_SECONDS;
  const title =
    expanded.kind === "packets" ? "Пакеты в секунду" : "Скорость трафика";
  return `<div class="telemetry-expanded-backdrop"><section class="telemetry-expanded" role="dialog" aria-modal="true" aria-labelledby="telemetry-expanded-title" tabindex="-1"><header class="telemetry-expanded-heading"><div><h2 id="telemetry-expanded-title">${title}</h2><p>${ctx.e(ctx.telemetrySelection === "all" || !ctx.telemetrySelection ? "Все выбранные интерфейсы" : ctx.telemetrySelection)}</p></div><div class="telemetry-expanded-controls"><label for="telemetry-period">Период</label><select id="telemetry-period" aria-label="Период графика">${PERIODS.map((value) => `<option value="${value}"${period === value ? " selected" : ""}>${value === 3600 ? "1 час" : `${value / 60} мин`}</option>`).join("")}</select><button type="button" class="icon ghost" data-action="telemetry-collapse" aria-label="Закрыть график" title="Закрыть график">×</button></div></header>${chart(ctx.telemetryHistory, ctx.telemetrySelection || "all", expanded.kind, ctx.e, period, true)}<p class="telemetry-note">История хранится в базе данных роутера до 1 часа. Пустая область означает отсутствие сохранённых измерений.</p></section></div>`;
}

function interfaceTable(snapshot, e) {
  const rows = values(snapshot?.interfaces).slice(0, INTERFACE_LIMIT);
  return `<article class="telemetry-panel"><div class="telemetry-panel-heading"><h3>Трафик по интерфейсам</h3><small>Скорость и накопленные счётчики</small></div><div class="telemetry-table-scroll"><table class="telemetry-table telemetry-interface-table"><thead><tr><th>Интерфейс</th><th>Статус</th><th class="numeric">RX · скорость</th><th class="numeric">TX · скорость</th><th class="numeric">Получено</th><th class="numeric">Отправлено</th><th class="numeric">Пакеты RX / TX</th></tr></thead><tbody>${rows.map((item) => `<tr><td><strong class="mono">${e(item.name)}</strong><small>${item.physical ? "Физический" : "Виртуальный / системный"}</small></td><td><span class="telemetry-status ${item.state === "UP" ? "" : "down"}">${e(item.state || "UNKNOWN")}</span></td><td class="numeric">${liveNumber(`${item.name}:rx_bps`, item.rx_bps, "rate", e)}</td><td class="numeric">${liveNumber(`${item.name}:tx_bps`, item.tx_bps, "rate", e)}</td><td class="numeric">${liveNumber(`${item.name}:rx_bytes`, item.rx_bytes, "bytes", e, true)}</td><td class="numeric">${liveNumber(`${item.name}:tx_bytes`, item.tx_bytes, "bytes", e, true)}</td><td class="numeric">${liveNumber(`${item.name}:rx_packets`, item.rx_packets, "count", e, true)} / ${liveNumber(`${item.name}:tx_packets`, item.tx_packets, "count", e, true)}</td></tr>`).join("") || '<tr><td colspan="7" class="telemetry-table-empty">Счётчики интерфейсов пока недоступны.</td></tr>'}</tbody></table></div></article>`;
}
function destinations(snapshot, e) {
  const top = snapshot?.top_destinations || {};
  const rows = values(top.items).slice(0, 10);
  const basis =
    top.basis === "bytes"
      ? "По байтам текущих соединений"
      : "По числу текущих соединений";
  return `<article class="telemetry-panel"><div class="telemetry-panel-heading"><h3>Топ назначений</h3><small>${basis}</small></div><div class="telemetry-table-scroll"><table class="telemetry-table"><thead><tr><th>Адрес / порт</th><th>Протокол</th><th class="numeric">Соединения</th><th class="numeric">Пакеты</th><th class="numeric">Трафик</th></tr></thead><tbody>${rows.map((item) => `<tr><td class="mono">${e(item.address)}${finite(item.port) === null ? "" : `:${e(item.port)}`}</td><td>${e(String(item.protocol || "—").toUpperCase())}</td><td class="numeric">${e(count(item.connections))}</td><td class="numeric">${e(count(item.packets))}</td><td class="numeric">${e(formatBytes(item.bytes))}</td></tr>`).join("") || `<tr><td colspan="5" class="telemetry-table-empty">${top.available ? "Текущих соединений нет." : "Список назначений недоступен на этом хосте."}</td></tr>`}</tbody></table></div><p class="telemetry-note">Срез активных IPv4-соединений.${top.partial ? " Показана ограниченная выборка." : ""} Пакеты и байты учитываются в направлении к назначению; значения зависят от доступности учёта соединений.</p></article>`;
}
function devices(snapshot, e) {
  const found = snapshot?.devices || {};
  const rows = values(found.items).slice(0, 12);
  return `<article class="telemetry-panel"><div class="telemetry-panel-heading"><h3>Устройства в сети</h3><small>Обнаружено: ${e(count(found.count))}</small></div><div class="telemetry-table-scroll"><table class="telemetry-table telemetry-device-table"><thead><tr><th>Устройство</th><th>IP-адрес</th><th>Интерфейс / источник</th></tr></thead><tbody>${rows.map((item) => `<tr><td><strong>${e(item.hostname || "Устройство")}</strong><small class="mono">${e(item.mac || "—")}</small></td><td class="mono">${e(item.address || "—")}</td><td>${e(item.interface || "—")}<small>${e(item.source || "—")}</small></td></tr>`).join("") || `<tr><td colspan="3" class="telemetry-table-empty">${found.available ? "Устройства пока не обнаружены." : "Данные об устройствах недоступны."}</td></tr>`}</tbody></table></div><p class="telemetry-note">Наблюдаемые соседи IPv4 и действующие аренды DHCP. Устройства без обмена с роутером могут ещё не отображаться.${found.partial ? " Источники данных охватывают ограниченную выборку устройств." : ""}${values(found.items).length > rows.length ? ` В таблице показаны первые ${rows.length} устройств.` : ""}</p></article>`;
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
    ? `<p class="telemetry-notice" role="status">Мониторинг временно недоступен: ${e(ctx.telemetryError)}${snapshot ? " · Показаны последние полученные данные." : ""}</p>`
    : !snapshot
      ? '<p class="telemetry-notice" role="status">Загружаем показатели сети…</p>'
      : snapshot.sample_seconds === null
        ? '<p class="telemetry-notice" role="status">Первое измерение получено. Для вычисления скорости ждём следующий срез.</p>'
        : "";
  const memoryPercent =
    finite(system.memory_total_bytes) > 0 &&
    finite(system.memory_used_bytes) !== null
      ? (system.memory_used_bytes / system.memory_total_bytes) * 100
      : null;
  return `<div class="telemetry-dashboard"><div class="telemetry-heading"><div><h2>Мониторинг сети</h2><p>${demo ? "Демонстрационные показатели · сеть компьютера не измеряется" : "Скорости и счётчики · каждые 0,2 с · устройства и топ назначений · каждые 5 с"}</p></div><div class="telemetry-controls"><label for="telemetry-interface">Интерфейс графика</label><select id="telemetry-interface" aria-label="Интерфейс графика"><option value="all" ${effectiveSelection === "all" ? "selected" : ""}>${e(scope)}</option>${links.map((item) => `<option value="${e(item.name)}" ${item.name === effectiveSelection ? "selected" : ""}>${e(item.name)}</option>`).join("")}</select><span class="${demo ? "telemetry-demo" : ctx.telemetryError || !snapshot ? "telemetry-stale" : "telemetry-live"}">${demo ? "DEMO" : ctx.telemetryError ? "НЕТ СВЯЗИ" : !snapshot ? "ОЖИДАНИЕ" : "LIVE"}</span></div></div><div id="telemetry-content">${notice}${snapshot?.traffic?.partial ? '<p class="telemetry-note">Счётчики охватывают ограниченный набор интерфейсов.</p>' : ""}<div class="telemetry-metrics">${[
    metric(
      "Входящая скорость · RX",
      formatRate(stats.rx_bps),
      `Получено: ${formatBytes(stats.rx_bytes)}`,
      e,
      numberAttributes("summary-rx", stats.rx_bps, "rate", e),
    ),
    metric(
      "Исходящая скорость · TX",
      formatRate(stats.tx_bps),
      `Отправлено: ${formatBytes(stats.tx_bytes)}`,
      e,
      numberAttributes("summary-tx", stats.tx_bps, "rate", e),
    ),
    metric(
      "Пакеты / с",
      count(packetRate),
      `Всего RX / TX: ${count(stats.rx_packets)} / ${count(stats.tx_packets)}`,
      e,
      numberAttributes("summary-packets", packetRate, "count", e),
    ),
    metric(
      "Активные соединения",
      count(connections.active),
      `Лимит таблицы: ${count(connections.limit)}`,
      e,
      numberAttributes("summary-connections", connections.active, "count", e),
    ),
    metric(
      "Устройства",
      count(observed.count),
      `Действующих аренд DHCP: ${count(observed.dhcp_leases)}`,
      e,
      numberAttributes("summary-devices", observed.count, "count", e),
    ),
    metric(
      "Накопленный трафик",
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
    ),
  ].join(
    "",
  )}</div><div class="telemetry-chart-grid">${chart(ctx.telemetryHistory, effectiveSelection, "speed", e)}${chart(ctx.telemetryHistory, effectiveSelection, "packets", e)}</div><p class="telemetry-chart-footer">RX — получено интерфейсом, TX — отправлено. В обзоре — последняя минута. Разверните график для выбора периода до 1 часа. История сохраняется в базе данных роутера, одна точка в секунду. Счётчики трафика накоплены с момента запуска / сброса интерфейса.<span class="telemetry-history-status" role="status">${ctx.telemetryHistoryError ? `История временно недоступна: ${e(ctx.telemetryHistoryError)}` : ""}</span></p>${interfaceTable(snapshot, e)}<div class="telemetry-detail-grid">${destinations(snapshot, e)}${devices(snapshot, e)}</div><div class="telemetry-system"><span>Время работы <strong>${e(duration(system.uptime_seconds))}</strong></span><span>CPU <strong>${finite(system.cpu_percent) === null ? "—" : `${e(decimal.format(system.cpu_percent))}%`}</strong></span><span>RAM <strong>${e(formatBytes(system.memory_used_bytes))} / ${e(formatBytes(system.memory_total_bytes))}${memoryPercent === null ? "" : ` · ${e(decimal.format(memoryPercent))}%`}</strong></span></div></div>${renderExpandedTelemetry(ctx)}</div>`;
}
