import { html, t, locale } from "./i18n.js";
import {
  displayFilterField,
  displayNegationQuery,
  syncDisplayFilterControl,
} from "./display-filter-ui.js";
/** Filters affect the monitoring view only; they never create firewall rules. */
let kind = "active",
  filters = {},
  snapshot = null,
  error = "",
  request = null,
  controller = null;
let draftFilters = {},
  negated = new Set();
const filterNames = [
  "source",
  "destination",
  "port",
  "protocol",
  "state",
  "interface",
  "search",
];
let sorting = { column: null, direction: "ascending" };
const sortColumns = new Set([
  "protocol",
  "source",
  "destination",
  "translated_destination",
  "state",
  "interface",
  "packets",
  "bytes",
  "time",
]);

function compareNullable(left, right, direction, compare) {
  const missingLeft = left == null || left === "";
  const missingRight = right == null || right === "";
  if (missingLeft || missingRight)
    return Number(missingLeft) - Number(missingRight);
  return direction * compare(left, right);
}

function ipv4(value) {
  if (typeof value !== "string" || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value))
    return null;
  const parts = value.split(".").map(Number);
  return parts.every((part) => part <= 255)
    ? parts.reduce((result, part) => result * 256 + part, 0)
    : null;
}

/** Sort only the returned monitoring sample, never router rules or API data. */
export function sortConnectionRows(items, order, viewKind = "active") {
  if (!sortColumns.has(order?.column)) return [...items];
  const column = order.column;
  const direction = order.direction === "descending" ? -1 : 1;
  const collator = new Intl.Collator(locale(), {
    numeric: true,
    sensitivity: "base",
  });
  const text = (left, right) => collator.compare(String(left), String(right));
  const numeric = (left, right) => Number(left) - Number(right);
  const endpointColumns = {
    source: "source_port",
    destination: "destination_port",
    translated_destination: "translated_port",
  };
  const compare = (left, right) => {
    if (column in endpointColumns) {
      const address = compareNullable(
        left[column],
        right[column],
        direction,
        (a, b) => {
          const one = ipv4(a),
            two = ipv4(b);
          return one !== null && two !== null ? one - two : text(a, b);
        },
      );
      if (address) return address;
      // A missing endpoint's port has no meaning.
      if (!left[column] || !right[column]) return 0;
      return compareNullable(
        left[endpointColumns[column]],
        right[endpointColumns[column]],
        direction,
        numeric,
      );
    }
    const key =
      column === "time"
        ? viewKind === "attempts"
          ? "last_seen"
          : "expires_in"
        : column;
    const numbers = ["packets", "bytes", "time"].includes(column);
    return compareNullable(
      left[key],
      right[key],
      direction,
      numbers ? numeric : text,
    );
  };
  return items
    .map((row, index) => ({ row, index }))
    .sort(
      (left, right) => compare(left.row, right.row) || left.index - right.index,
    )
    .map(({ row }) => row);
}

function columnHeader(column, label) {
  const selected = sorting.column === column;
  const state = selected ? sorting.direction : "none";
  const arrow = selected
    ? sorting.direction === "ascending"
      ? "▲"
      : "▼"
    : "↕";
  return html`<th scope="col" aria-sort="${state}"><button type="button" class="connection-sort" data-action="connections-sort" data-sort-column="${column}">${t(label)}<span aria-hidden="true">${arrow}</span></button></th>`;
}

export function resetConnections() {
  controller?.abort();
  kind = "active";
  filters = {};
  draftFilters = {};
  negated = new Set();
  snapshot = null;
  error = "";
  request = null;
  sorting = { column: null, direction: "ascending" };
}

function endpoint(address, port) {
  return port == null ? address : `${address}:${port}`;
}
function number(value) {
  return value == null ? "—" : Number(value).toLocaleString(locale());
}
function rows(ctx) {
  const e = ctx.e;
  if (error)
    return html`<div class="connection-error" role="alert">${e(error)}</div>`;
  if (!snapshot) return html`<div class="empty">Загружаем соединения…</div>`;
  const notice = snapshot.demo
    ? html`<div class="read-only-banner">Демонстрационные данные · сеть компьютера не используется</div>`
    : "";
  if (!snapshot.available)
    return (
      notice +
      html`<div class="empty">${e(snapshot.error || t("Источник данных недоступен"))}</div>`
    );
  const body = sortConnectionRows(snapshot.items, sorting, kind)
    .map(
      (row) =>
        html`<tr><td>${e(row.protocol.toUpperCase())}</td><td class="mono">${e(endpoint(row.source, row.source_port))}</td><td class="mono">${e(endpoint(row.destination, row.destination_port))}</td><td class="mono">${row.translated_destination ? e(endpoint(row.translated_destination, row.translated_port)) : "—"}</td><td>${e(row.state)}</td><td class="mono">${e(row.interface || "—")}</td><td class="numeric">${number(row.packets)}</td><td class="numeric">${number(row.bytes)}</td><td>${kind === "attempts" ? e(new Date(row.last_seen * 1000).toLocaleTimeString(locale())) : row.expires_in == null ? "—" : e(row.expires_in + t(" сек."))}</td></tr>`,
    )
    .join("");
  return html`${notice}<div class="monitor-summary"><strong>${number(snapshot.matched)} из ${number(snapshot.total)}</strong><span>Обновлено ${e(new Date(snapshot.timestamp * 1000).toLocaleTimeString(locale()))}</span>${snapshot.partial ? html`<span class="monitor-partial">Ограниченная выборка</span>` : ""}</div><div class="table-scroll"><table class="rules-table connections-table"><thead><tr>${[
    ["protocol", "Протокол"],
    ["source", "Источник"],
    ["destination", "Назначение"],
    ["translated_destination", "После DNAT"],
    ["state", "Состояние"],
    [
      "interface",
      kind === "active" ? "Интерфейс назначения" : "Входной интерфейс",
    ],
    ["packets", "Пакеты"],
    ["bytes", "Байты"],
    ["time", kind === "attempts" ? "Последний пакет" : "Таймаут"],
  ]
    .map(([column, label]) => columnHeader(column, label))
    .join(
      "",
    )}</tr></thead><tbody>${body || html`<tr><td colspan="9" class="users-empty">Подходящих соединений нет.</td></tr>`}</tbody></table></div>${snapshot.matched > snapshot.items.length ? html`<p class="feature-note">Показаны первые ${snapshot.items.length} записей. Уточните фильтры.</p>` : ""}`;
}

function updateResults(ctx, focusColumn) {
  const container = document.querySelector("#connections-results");
  if (!container) return;
  const focused =
    focusColumn ||
    (container.contains?.(document.activeElement)
      ? document.activeElement?.dataset?.sortColumn
      : null);
  const scroll = container.querySelector?.(".table-scroll");
  const left = scroll?.scrollLeft || 0,
    top = scroll?.scrollTop || 0;
  container.innerHTML = rows(ctx);
  const nextScroll = container.querySelector?.(".table-scroll");
  if (nextScroll) {
    nextScroll.scrollLeft = left;
    nextScroll.scrollTop = top;
  }
  if (sortColumns.has(focused))
    container
      .querySelector?.(`[data-sort-column="${focused}"]`)
      ?.focus({ preventScroll: true });
}

export function renderConnections(ctx) {
  const e = ctx.e;
  const fields = [
    html`<label class="field"><span>Источник IPv4 / сеть</span><input name="source" value="${e(draftFilters.source || "")}" placeholder="192.0.2.10/32" maxlength="32"></label>`,
    html`<label class="field"><span>Назначение IPv4 / сеть</span><input name="destination" value="${e(draftFilters.destination || "")}" placeholder="203.0.113.10" maxlength="32"></label>`,
    html`<label class="field"><span>Порт / диапазон</span><input name="port" value="${e(draftFilters.port || "")}" placeholder="3389,8000-8010" maxlength="200"></label>`,
    html`<label class="field"><span>Протокол</span><select name="protocol">${["", "tcp", "udp", "icmp", "gre", "esp", "ah"].map((value) => html`<option value="${value}" ${draftFilters.protocol === value ? "selected" : ""}>${value.toUpperCase() || t("Все")}</option>`).join("")}</select></label>`,
    html`<label class="field"><span>Состояние</span><select name="state">${["", "SYN", "DATAGRAM", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "UNREPLIED", "ASSURED", "TIME_WAIT", "CLOSE"].map((value) => html`<option value="${value}" ${draftFilters.state === value ? "selected" : ""}>${value || t("Все")}</option>`).join("")}</select></label>`,
    html`<label class="field"><span>Интерфейс</span><input name="interface" value="${e(draftFilters.interface || "")}" placeholder="vmbr0" maxlength="15"></label>`,
    html`<label class="field"><span>Поиск</span><input name="search" value="${e(draftFilters.search || "")}" maxlength="100" placeholder="Адрес, состояние…"></label>`,
  ]
    .map((markup, index) =>
      displayFilterField(markup, filterNames[index], {
        value: draftFilters[filterNames[index]],
        negated: negated.has(filterNames[index]),
        action: "connections-negate",
        idPrefix: "connections",
      }),
    )
    .join("");
  return html`<div class="feature-page"><div class="monitor-kind"><button data-action="connections-kind" data-kind="active" class="${kind === "active" ? "primary" : ""}">Активные соединения</button><button data-action="connections-kind" data-kind="attempts" class="${kind === "attempts" ? "primary" : ""}">Входящие попытки</button><button data-action="connections-refresh">${ctx.icon("refresh")}Обновить</button></div><form id="connections-filter" class="monitor-filters">${fields}<div class="monitor-filter-actions"><button class="primary" data-action="connections-filter" type="submit">Фильтровать</button><button data-action="connections-reset" type="button">Сбросить</button></div></form><p class="feature-note">Кнопка ! — всё, кроме указанного. Нажмите «Фильтровать», чтобы применить условия.</p><p class="feature-note">${kind === "active" ? t("Входящие IPv4-соединения conntrack: обращения к узлу и пробросы DNAT. Заблокированные до создания записи пакеты могут отсутствовать. Счётчики доступны, если их предоставляет ядро. Интерфейс определяется по локальному адресу назначения, а не по месту входа пакета.") : t("Входящие TCP SYN и UDP на интерфейсах default route, до проверки NAT/Firewall. Это наблюдение пакетов, а не решение «разрешено / заблокировано». Содержимое трафика не сохраняется. Повторные пакеты объединяются; история до 1000 записей за последний час.")} Фильтры меняют только отображение.</p><div id="connections-results">${rows(ctx)}</div></div>`;
}

function captureFilters(form = document.querySelector("#connections-filter")) {
  if (form?.id !== "connections-filter") return false;
  const values = new FormData(form);
  draftFilters = Object.fromEntries(
    filterNames.map((name) => [name, String(values.get(name) || "").trim()]),
  );
  for (const name of negated) if (!draftFilters[name]) negated.delete(name);
  return true;
}

function applyFilters() {
  filters = Object.fromEntries(
    filterNames
      .filter((name) => draftFilters[name])
      .map((name) => [name, draftFilters[name]]),
  );
  const exclusion = displayNegationQuery(negated, draftFilters, filterNames);
  if (exclusion) filters.negate = exclusion;
}

export function handleConnectionsInput(event) {
  const form = event.target?.closest?.("#connections-filter");
  const name = event.target?.name;
  if (!form || !filterNames.includes(name)) return false;
  draftFilters[name] = String(event.target.value || "").trim();
  if (!draftFilters[name]) negated.delete(name);
  syncDisplayFilterControl(form, name, draftFilters[name], negated.has(name));
  return true;
}

export async function refreshConnections(ctx) {
  if (request || !ctx.isCurrentView("connections")) return request;
  const generation = ctx.generation;
  const activeController = new AbortController();
  controller = activeController;
  const operation = (async () => {
    try {
      const query = new URLSearchParams({ ...filters, kind, limit: "200" });
      const result = await ctx.api(`connections?${query}`, {
        signal: AbortSignal.any([
          activeController.signal,
          AbortSignal.timeout(8000),
        ]),
      });
      if (activeController.signal.aborted || generation !== ctx.getGeneration())
        return;
      snapshot = result;
      error = "";
    } catch (failure) {
      if (
        !activeController.signal.aborted &&
        generation === ctx.getGeneration()
      )
        error = failure.message;
    } finally {
      if (request === operation) request = null;
      if (
        ctx.isCurrentView("connections") &&
        generation === ctx.getGeneration()
      ) {
        updateResults(ctx);
      }
    }
  })();
  request = operation;
  return operation;
}

export async function handleConnectionsAction(button, ctx) {
  const action = button.dataset.action;
  if (
    ![
      "connections-kind",
      "connections-filter",
      "connections-reset",
      "connections-refresh",
      "connections-sort",
      "connections-negate",
    ].includes(action)
  )
    return false;
  if (action === "connections-negate") {
    const name = button.dataset.displayNegate;
    if (!filterNames.includes(name) || !captureFilters()) return true;
    if (draftFilters[name]) {
      if (negated.has(name)) negated.delete(name);
      else negated.add(name);
    }
    syncDisplayFilterControl(
      document.querySelector("#connections-filter"),
      name,
      draftFilters[name],
      negated.has(name),
    );
    return true;
  }
  if (action === "connections-sort") {
    const column = button.dataset.sortColumn;
    if (!sortColumns.has(column)) return true;
    sorting = {
      column,
      direction:
        sorting.column === column && sorting.direction === "ascending"
          ? "descending"
          : "ascending",
    };
    updateResults(ctx, column);
    return true;
  }
  await ctx.run(async () => {
    controller?.abort();
    request = null;
    if (action === "connections-kind") {
      captureFilters();
      applyFilters();
      kind = button.dataset.kind === "attempts" ? "attempts" : "active";
      snapshot = null;
      error = "";
      ctx.render();
    }
    if (action === "connections-reset") {
      filters = {};
      draftFilters = {};
      negated = new Set();
      snapshot = null;
      error = "";
      ctx.render();
    }
    if (action === "connections-filter") {
      if (!captureFilters()) return;
      applyFilters();
    }
    await refreshConnections(ctx);
  });
  return true;
}

export function setConnectionSource(address) {
  controller?.abort();
  request = null;
  snapshot = null;
  error = "";
  kind = "active";
  filters = { source: address };
  draftFilters = { source: address };
  negated = new Set();
}
