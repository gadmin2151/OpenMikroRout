/** Read-only network telemetry presentation. Rates are bits/s, byte counters are bytes. */
const HISTORY_SECONDS = 300;
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
    last &&
    (timestamp < last.timestamp ||
      current.demo !== last.demo ||
      (snapshot.sample_seconds === null && previous.length > 1));
  const window = restarted
    ? []
    : previous.filter(
        (point) => point.timestamp >= timestamp - HISTORY_SECONDS,
      );
  // Keep the newest live point within each second, preserving five minutes at 5 Hz.
  if (
    window.length &&
    Math.floor(window.at(-1).timestamp) === Math.floor(timestamp)
  )
    return [...window.slice(0, -1), current];
  return [...window, current].slice(-HISTORY_LIMIT);
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
    current.id === "telemetry-interface" &&
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

/** Patch changed text/SVG attributes instead of recreating the dashboard at 5 Hz. */
export function updateTelemetryView(container, ctx) {
  const template = container.ownerDocument.createElement("template");
  template.innerHTML = renderTelemetry(ctx);
  const next = template.content.firstElementChild;
  if (container.firstElementChild && next)
    patchTelemetryNode(container.firstElementChild, next);
  else container.replaceChildren(template.content);
}

function selectedMetrics(snapshot, selection) {
  if (!selection || selection === "all") return snapshot?.traffic || {};
  return (
    values(snapshot?.interfaces).find((item) => item.name === selection) || {}
  );
}
function metric(label, value, meta, e) {
  return `<article class="telemetry-metric"><span class="telemetry-label">${e(label)}</span><strong class="telemetry-value">${e(value)}</strong><small class="telemetry-meta">${e(meta)}</small></article>`;
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

function chart(history, selection, kind, e) {
  const packet = kind === "packets";
  const keys = packet ? ["rx_pps", "tx_pps"] : ["rx_bps", "tx_bps"];
  const title = packet ? "Пакеты в секунду" : "Скорость трафика";
  const format = packet ? (value) => `${count(value)} пак/с` : formatRate;
  const rows = values(history)
    .filter((point) => finite(point?.timestamp) !== null)
    .slice(-HISTORY_LIMIT)
    .map((point) => ({
      timestamp: point.timestamp,
      ...selectedMetrics(point, selection),
    }));
  const readings = rows.flatMap((point) =>
    keys.map((key) => finite(point[key])),
  );
  const observed = readings.filter((number) => number !== null);
  const maximum = Math.max(1, ...observed);
  const left = 110,
    right = 621,
    top = 14,
    bottom = 150;
  const firstTime = rows[0]?.timestamp || 0;
  const span = Math.max(1, (rows.at(-1)?.timestamp || firstTime) - firstTime);
  const x = (point) =>
    left + ((point.timestamp - firstTime) / span) * (right - left);
  const y = (value) => bottom - (value / maximum) * (bottom - top);
  const path = (key) => {
    let move = true;
    let previousTime = null;
    return rows
      .map((point) => {
        const value = finite(point[key]);
        if (value === null) {
          move = true;
          previousTime = null;
          return "";
        }
        if (
          previousTime !== null &&
          point.timestamp - previousTime > MAX_GRAPH_GAP_SECONDS
        )
          move = true;
        const segment = `${move ? "M" : "L"}${x(point).toFixed(1)},${y(value).toFixed(1)}`;
        move = false;
        previousTime = point.timestamp;
        return segment;
      })
      .join(" ");
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
    ? `<svg class="telemetry-chart" viewBox="0 0 640 180" role="img" aria-labelledby="telemetry-${kind}-title telemetry-${kind}-description"><title id="telemetry-${kind}-title">${title}</title><desc id="telemetry-${kind}-description">История RX и TX за ${Math.round(span)} секунд. RX — входящий, TX — исходящий трафик.</desc>${grid}<path class="telemetry-rx-line" d="${path(keys[0])}"/><path class="telemetry-tx-line" d="${path(keys[1])}"/><text class="telemetry-axis" x="${left}" y="173">${Math.round(span)} с назад</text><text class="telemetry-axis" x="${right}" y="173" text-anchor="end">Сейчас</text></svg>`
    : `<div class="telemetry-chart-empty">Собираем историю графика…<small>График появится после двух измерений.</small></div>`;
  const last = rows.at(-1) || {};
  return `<article class="telemetry-panel"><div class="telemetry-panel-heading"><h3>${title}</h3><small>${packet ? "RX / TX · пак/с" : "RX / TX · бит/с"}</small></div><div class="telemetry-chart-box">${picture}</div><div class="telemetry-legend"><span class="telemetry-rx-key">RX <b>${e(format(last[keys[0]]))}</b></span><span class="telemetry-tx-key">TX <b>${e(format(last[keys[1]]))}</b></span></div></article>`;
}
function interfaceTable(snapshot, e) {
  const rows = values(snapshot?.interfaces).slice(0, INTERFACE_LIMIT);
  return `<article class="telemetry-panel"><div class="telemetry-panel-heading"><h3>Трафик по интерфейсам</h3><small>Скорость и накопленные счётчики</small></div><div class="telemetry-table-scroll"><table class="telemetry-table"><thead><tr><th>Интерфейс</th><th>Статус</th><th class="numeric">RX · скорость</th><th class="numeric">TX · скорость</th><th class="numeric">Получено</th><th class="numeric">Отправлено</th><th class="numeric">Пакеты RX / TX</th></tr></thead><tbody>${rows.map((item) => `<tr><td><strong class="mono">${e(item.name)}</strong><small>${item.physical ? "Физический" : "Виртуальный / системный"}</small></td><td><span class="telemetry-status ${item.state === "UP" ? "" : "down"}">${e(item.state || "UNKNOWN")}</span></td><td class="numeric">${e(formatRate(item.rx_bps))}</td><td class="numeric">${e(formatRate(item.tx_bps))}</td><td class="numeric">${e(formatBytes(item.rx_bytes))}</td><td class="numeric">${e(formatBytes(item.tx_bytes))}</td><td class="numeric">${e(count(item.rx_packets))} / ${e(count(item.tx_packets))}</td></tr>`).join("") || '<tr><td colspan="7" class="telemetry-table-empty">Счётчики интерфейсов пока недоступны.</td></tr>'}</tbody></table></div></article>`;
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
    ),
    metric(
      "Исходящая скорость · TX",
      formatRate(stats.tx_bps),
      `Отправлено: ${formatBytes(stats.tx_bytes)}`,
      e,
    ),
    metric(
      "Пакеты / с",
      count(packetRate),
      `Всего RX / TX: ${count(stats.rx_packets)} / ${count(stats.tx_packets)}`,
      e,
    ),
    metric(
      "Активные соединения",
      count(connections.active),
      `Лимит таблицы: ${count(connections.limit)}`,
      e,
    ),
    metric(
      "Устройства",
      count(observed.count),
      `Действующих аренд DHCP: ${count(observed.dhcp_leases)}`,
      e,
    ),
    metric(
      "Накопленный трафик",
      formatBytes(sum(stats.rx_bytes, stats.tx_bytes)),
      effectiveSelection === "all" ? scope : effectiveSelection,
      e,
    ),
  ].join(
    "",
  )}</div><div class="telemetry-chart-grid">${chart(ctx.telemetryHistory, effectiveSelection, "speed", e)}${chart(ctx.telemetryHistory, effectiveSelection, "packets", e)}</div><p class="telemetry-chart-footer">RX — получено интерфейсом, TX — отправлено. История хранится в этой вкладке: до 5 минут, одна точка в секунду. Счётчики трафика накоплены с момента запуска / сброса интерфейса.</p>${interfaceTable(snapshot, e)}<div class="telemetry-detail-grid">${destinations(snapshot, e)}${devices(snapshot, e)}</div><div class="telemetry-system"><span>Время работы <strong>${e(duration(system.uptime_seconds))}</strong></span><span>CPU <strong>${finite(system.cpu_percent) === null ? "—" : `${e(decimal.format(system.cpu_percent))}%`}</strong></span><span>RAM <strong>${e(formatBytes(system.memory_used_bytes))} / ${e(formatBytes(system.memory_total_bytes))}${memoryPercent === null ? "" : ` · ${e(decimal.format(memoryPercent))}%`}</strong></span></div></div></div>`;
}
