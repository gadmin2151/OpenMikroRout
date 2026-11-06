/** Filters affect the monitoring view only; they never create firewall rules. */
let kind = "active",
  filters = {},
  snapshot = null,
  error = "",
  request = null,
  controller = null;

export function resetConnections() {
  controller?.abort();
  kind = "active";
  filters = {};
  snapshot = null;
  error = "";
  request = null;
}

function endpoint(address, port) {
  return port == null ? address : `${address}:${port}`;
}
function number(value) {
  return value == null ? "—" : Number(value).toLocaleString("ru-RU");
}
function rows(ctx) {
  const e = ctx.e;
  if (error)
    return `<div class="connection-error" role="alert">${e(error)}</div>`;
  if (!snapshot) return '<div class="empty">Загружаем соединения…</div>';
  const notice = snapshot.demo
    ? '<div class="read-only-banner">Демонстрационные данные · сеть компьютера не используется</div>'
    : "";
  if (!snapshot.available)
    return (
      notice +
      `<div class="empty">${e(snapshot.error || "Источник данных недоступен")}</div>`
    );
  const body = snapshot.items
    .map(
      (row) =>
        `<tr><td>${e(row.protocol.toUpperCase())}</td><td class="mono">${e(endpoint(row.source, row.source_port))}</td><td class="mono">${e(endpoint(row.destination, row.destination_port))}</td><td class="mono">${row.translated_destination ? e(endpoint(row.translated_destination, row.translated_port)) : "—"}</td><td>${e(row.state)}</td><td class="mono">${e(row.interface || "—")}</td><td class="numeric">${number(row.packets)}</td><td class="numeric">${number(row.bytes)}</td><td>${kind === "attempts" ? e(new Date(row.last_seen * 1000).toLocaleTimeString("ru-RU")) : row.expires_in == null ? "—" : e(row.expires_in + " сек.")}</td></tr>`,
    )
    .join("");
  return `${notice}<div class="monitor-summary"><strong>${number(snapshot.matched)} из ${number(snapshot.total)}</strong><span>Обновлено ${e(new Date(snapshot.timestamp * 1000).toLocaleTimeString("ru-RU"))}</span>${snapshot.partial ? '<span class="monitor-partial">Ограниченная выборка</span>' : ""}</div><div class="table-scroll"><table class="rules-table connections-table"><thead><tr><th>Протокол</th><th>Источник</th><th>Назначение</th><th>После DNAT</th><th>Состояние</th><th>${kind === "active" ? "Интерфейс назначения" : "Входной интерфейс"}</th><th>Пакеты</th><th>Байты</th><th>${kind === "attempts" ? "Последний пакет" : "Таймаут"}</th></tr></thead><tbody>${body || '<tr><td colspan="9" class="users-empty">Подходящих соединений нет.</td></tr>'}</tbody></table></div>${snapshot.matched > snapshot.items.length ? `<p class="feature-note">Показаны первые ${snapshot.items.length} записей. Уточните фильтры.</p>` : ""}`;
}

export function renderConnections(ctx) {
  const e = ctx.e;
  return `<div class="feature-page"><div class="monitor-kind"><button data-action="connections-kind" data-kind="active" class="${kind === "active" ? "primary" : ""}">Активные соединения</button><button data-action="connections-kind" data-kind="attempts" class="${kind === "attempts" ? "primary" : ""}">Входящие попытки</button><button data-action="connections-refresh">${ctx.icon("refresh")}Обновить</button></div><form id="connections-filter" class="monitor-filters"><label class="field"><span>Источник IPv4 / сеть</span><input name="source" value="${e(filters.source || "")}" placeholder="192.0.2.10/32" maxlength="32"></label><label class="field"><span>Назначение IPv4 / сеть</span><input name="destination" value="${e(filters.destination || "")}" placeholder="203.0.113.10" maxlength="32"></label><label class="field"><span>Порт / диапазон</span><input name="port" value="${e(filters.port || "")}" placeholder="3389,8000-8010" maxlength="200"></label><label class="field"><span>Протокол</span><select name="protocol">${["", "tcp", "udp", "icmp", "gre", "esp", "ah"].map((value) => `<option value="${value}" ${filters.protocol === value ? "selected" : ""}>${value.toUpperCase() || "Все"}</option>`).join("")}</select></label><label class="field"><span>Состояние</span><select name="state">${["", "SYN", "DATAGRAM", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "UNREPLIED", "ASSURED", "TIME_WAIT", "CLOSE"].map((value) => `<option value="${value}" ${filters.state === value ? "selected" : ""}>${value || "Все"}</option>`).join("")}</select></label><label class="field"><span>Интерфейс</span><input name="interface" value="${e(filters.interface || "")}" placeholder="vmbr0" maxlength="15"></label><label class="field"><span>Поиск</span><input name="search" value="${e(filters.search || "")}" maxlength="100" placeholder="Адрес, состояние…"></label><div class="monitor-filter-actions"><button class="primary" data-action="connections-filter" type="submit">Фильтровать</button><button data-action="connections-reset" type="button">Сбросить</button></div></form><p class="feature-note">${kind === "active" ? "Входящие IPv4-соединения conntrack: обращения к узлу и пробросы DNAT. Заблокированные до создания записи пакеты могут отсутствовать. Счётчики доступны, если их предоставляет ядро. Интерфейс определяется по локальному адресу назначения, а не по месту входа пакета." : "Входящие TCP SYN и UDP на интерфейсах default route, до проверки NAT/Firewall. Это наблюдение пакетов, а не решение «разрешено / заблокировано». Содержимое трафика не сохраняется. Повторные пакеты объединяются; история до 1000 записей за последний час."} Фильтры меняют только отображение.</p><div id="connections-results">${rows(ctx)}</div></div>`;
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
        const container = document.querySelector("#connections-results");
        if (container) container.innerHTML = rows(ctx);
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
    ].includes(action)
  )
    return false;
  await ctx.run(async () => {
    controller?.abort();
    request = null;
    if (action === "connections-kind") {
      kind = button.dataset.kind === "attempts" ? "attempts" : "active";
      filters = {};
      snapshot = null;
      ctx.render();
    }
    if (action === "connections-reset") {
      filters = {};
      snapshot = null;
      ctx.render();
    }
    if (action === "connections-filter")
      filters = Object.fromEntries(
        new FormData(document.querySelector("#connections-filter")),
      );
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
}
