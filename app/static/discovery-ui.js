import { html, t, locale } from "./i18n.js";
import { checkboxSelect } from "./checkbox-select.js";
import { interfaceNames } from "./router-pages.js?v=13";

export const discoveryViews = {
  hosts: [
    "Hosts / Neighbors",
    t("Устройства, источники наблюдений и сведения о соседях."),
  ],
  network_scan: [
    t("Network Scan"),
    t("Поиск устройств в выбранной подключённой IPv4-сети."),
  ],
  port_scan: [
    t("Port Scan"),
    t("Порты и службы одного хоста в разрешённой сети."),
  ],
};
let renderedRegions = new WeakMap();
let hosts = null;
let jobs = null;
let scanStatus = null;
let discoveryStatus = null;
let loadError = "";
let request = null;
let requestKind = null;
let controller = null;
let selectedJob = null;
let detailEpoch = 0;
let filters = { query: "", interface: "", offset: 0 };
let scanInput = {
  interface: "",
  target: "",
  profile: "quick",
  ports: "",
  service_detection: false,
};

export function resetDiscovery() {
  renderedRegions = new WeakMap();
  detailEpoch++;
  controller?.abort();
  controller =
    request =
    requestKind =
    hosts =
    jobs =
    scanStatus =
    discoveryStatus =
    selectedJob =
      null;
  loadError = "";
  filters = { query: "", interface: "", offset: 0 };
  scanInput = {
    interface: "",
    target: "",
    profile: "quick",
    ports: "",
    service_detection: false,
  };
}
const readonly = (ctx) => !ctx.canWrite() || ctx.offline || !!ctx.state.pending;
const date = (value) =>
  value ? new Date(value * 1000).toLocaleString(locale()) : "—";
const stateLabel = (value) =>
  ({
    queued: t("В очереди"),
    running: t("Выполняется"),
    completed: t("Завершено"),
    cancelled: t("Отменено"),
    interrupted: t("Прервано перезапуском"),
    error: t("Ошибка"),
  })[value] || value;
const action = (id, label, extra = "") =>
  html`<button type="button" data-action="${id}" ${extra}>${t(label)}</button>`;
function options(ctx, names, selected = "", empty = t("Выберите интерфейс")) {
  return html`<option value="">${empty}</option>${names.map((name) => html`<option value="${ctx.e(name)}" ${name === selected ? "selected" : ""}>${ctx.e(name)}</option>`).join("")}`;
}
function choices(names, selected, name, label) {
  return checkboxSelect({
    name,
    label,
    options: names.map((value) => [value, value]),
    selected,
  });
}
function settingsForm(ctx, scanning) {
  const value = ctx.state.config[scanning ? "scanning" : "discovery"] || {};
  const names = [
    ...new Set([...interfaceNames(ctx), ...(value.interfaces || [])]),
  ].filter((name) => name !== "lo");
  const id = scanning ? "scan-settings" : "discovery-settings";
  return html`<details class="configuration-help"><summary>${scanning ? t("Настройки сканирования") : t("Настройки обнаружения")}</summary><form id="${id}" data-discovery-form data-revision="${ctx.state.revision}" class="discovery-settings-form"><fieldset ${readonly(ctx) ? "disabled" : ""}><label class="wg-check"><input name="enabled" type="checkbox" ${value.enabled ? "checked" : ""}><span>Включить ${scanning ? t("активное сканирование") : t("пассивное обнаружение")}</span></label>${choices(names, value.interfaces || [], "interfaces", t("Разрешённые интерфейсы"))}${scanning ? html`<div class="monitor-filters"><label class="field"><span>Максимум адресов</span><input name="max_hosts" type="number" min="1" max="1024" value="${value.max_hosts || 256}" required></label><label class="field"><span>Пакетов в секунду, не более</span><input name="max_rate" type="number" min="10" max="1000" value="${value.max_rate || 100}" required></label><label class="field"><span>Таймаут, с</span><input name="timeout_seconds" type="number" min="10" max="1800" value="${value.timeout_seconds || 300}" required></label><label class="field"><span>Заданий в истории</span><input name="history_limit" type="number" min="1" max="100" value="${value.history_limit || 50}" required></label></div>` : html`${choices(["arp", "dhcp", "lldp", "cdp", "mndp"], value.protocols || ["arp", "dhcp", "lldp", "cdp", "mndp"], "protocols", t("Источники"))}<label class="field"><span>Актуальность наблюдения, с</span><input name="stale_seconds" type="number" min="30" max="86400" value="${value.stale_seconds || 300}" required></label>`}<button class="primary" data-discovery-form data-action="${scanning ? "scan-save-settings" : "discovery-save-settings"}">Сохранить черновик</button></fieldset><p class="feature-note">Изменения вступают в силу после общего применения и подтверждения конфигурации.</p></form></details>`;
}
function hostRows(ctx) {
  if (loadError)
    return html`<p class="feature-note" role="alert">${ctx.e(loadError)}</p>`;
  if (!hosts)
    return html`<p class="feature-note" role="status">Загрузка устройств…</p>`;
  const problems = Object.values(discoveryStatus?.errors || {});
  return html`${problems.length ? html`<p class="feature-note" role="alert">${problems.map(ctx.e).join(" · ")}</p>` : ""}${!discoveryStatus?.settings?.enabled ? html`<p class="feature-note">Пассивное обнаружение выключено. Сохранённые наблюдения доступны ниже.</p>` : ""}<div class="table-scroll"><table><thead><tr><th>Устройство / IPv4</th><th>MAC / производитель</th><th>Интерфейс</th><th>Модель / платформа</th><th>Источник</th><th>Последнее наблюдение</th><th></th></tr></thead><tbody>${hosts.items.map((host) => html`<tr><td><strong>${ctx.e(host.hostname || host.addresses?.[0] || host.chassis_id || t("Без имени"))}</strong><small>${ctx.e((host.addresses || []).join(", "))}</small>${host.conflicting_addresses?.length ? html`<small>Конфликт IP: ${ctx.e(host.conflicting_addresses.join(", "))}</small>` : ""}</td><td>${ctx.e(host.mac || "—")}<small>${ctx.e(host.vendor || t("Производитель неизвестен"))}</small></td><td>${ctx.e(host.interface)}</td><td>${ctx.e(host.model || host.platform || "—")}</td><td>${ctx.e((host.sources || []).join(" · ").toUpperCase())}</td><td>${ctx.e(date(host.last_seen))}<small>${host.stale ? t("Сведения устарели") : t("Актуальное наблюдение")}</small></td><td>${action("discovery-host", t("Подробнее"), `data-id="${ctx.e(host.id)}"`)}</td></tr>`).join("") || html`<tr><td colspan="7">Устройства не обнаружены. LLDP/CDP и MNDP видят соседей только в выбранном L2-сегменте.</td></tr>`}</tbody></table></div><div class="toolbar">${action("discovery-page", t("Назад"), `data-offset="${Math.max(0, filters.offset - 50)}" ${filters.offset === 0 ? "disabled" : ""}`)}<span>${hosts.total ? filters.offset + 1 : 0}–${Math.min(filters.offset + 50, hosts.total)} из ${hosts.total}</span>${action("discovery-page", t("Далее"), `data-offset="${filters.offset + 50}" ${filters.offset + 50 >= hosts.total ? "disabled" : ""}`)}</div>`;
}
export function renderScanResult(job, ctx) {
  if (!job)
    return html`<p class="feature-note">Выберите задание в истории, чтобы посмотреть результат.</p>`;
  const result = job.result || {};
  return html`<div class="feature-heading"><h3>${ctx.e(stateLabel(job.state))} · ${ctx.e(job.target)}</h3><span>${Math.round(job.progress || 0)}%</span></div>${job.error ? html`<p role="alert">${ctx.e(job.error)}</p>` : ""}<p class="feature-note">${result.demo ? t("DEMO · сеть не опрашивалась. ") : ""}${result.partial ? t("Промежуточные / неполные результаты. ") : ""}Отсутствие ответа не означает, что устройства нет.</p>${(result.hosts || []).map((host) => html`<article class="tools-result"><h4>${ctx.e((host.addresses || []).join(", "))} · ${ctx.e(host.state)} ${host.mac ? `· ${ctx.e(host.mac)}` : ""}</h4>${host.os_guesses?.length ? html`<p class="feature-note">Предполагаемая ОС (по службе): ${ctx.e(host.os_guesses.join(", "))}. Это предположение сканера, а не подтверждённая ОС устройства.</p>` : ""}${host.ports?.length ? html`<div class="table-scroll"><table><thead><tr><th>Порт</th><th>Состояние</th><th>Служба</th><th>Продукт / версия</th><th>Метод</th></tr></thead><tbody>${host.ports.map((port) => html`<tr><td>${ctx.e(port.port)}/${ctx.e(port.protocol)}</td><td>${ctx.e(port.state)}</td><td>${ctx.e(port.service || "—")}</td><td>${ctx.e([port.product, port.version].filter(Boolean).join(" ") || "—")}</td><td>${ctx.e(port.method || port.reason || "—")}</td></tr>`).join("")}</tbody></table></div>` : html`<p class="feature-note">Нет отдельных записей о портах.</p>`}${host.other_ports?.length ? html`<p>${host.other_ports.map((item) => `${ctx.e(item.state)}: ${ctx.e(item.count)}`).join(" · ")}</p>` : ""}${host.ports_truncated ? html`<p role="status">Список портов сокращён до безопасного лимита.</p>` : ""}</article>`).join("") || html`<p class="feature-note">Результаты хостов пока отсутствуют.</p>`}`;
}
function scanRows(ctx) {
  return html`${loadError ? html`<p role="alert">${ctx.e(loadError)}</p>` : ""}${scanStatus?.error ? html`<p role="alert">${ctx.e(scanStatus.error)}</p>` : ""}<p class="feature-note">${scanStatus?.demo ? t("DEMO: реальные сетевые проверки отключены.") : scanStatus?.available === false ? t("Для запуска установите Nmap на сервере.") : t("Один активный запуск; результаты и история хранятся на сервере.")} ${scanStatus?.settings?.enabled ? "" : t("Сканирование выключено в применённой конфигурации.")}</p><div class="table-scroll"><table><thead><tr><th>Время</th><th>Цель</th><th>Профиль</th><th>Состояние</th><th></th></tr></thead><tbody>${jobs?.items.map((job) => html`<tr><td>${ctx.e(date(job.created))}</td><td>${ctx.e(job.target)}<small>${ctx.e(job.request.interface)}</small></td><td>${ctx.e(job.request.kind === "network" ? "Network discovery" : job.request.profile)}</td><td>${ctx.e(stateLabel(job.state))} · ${Math.round(job.progress || 0)}%</td><td>${action("scan-job", t("Результат"), `data-id="${ctx.e(job.id)}"`)}${["queued", "running"].includes(job.state) && ctx.canWrite() ? action("scan-cancel", t("Отменить"), `data-id="${ctx.e(job.id)}"`) : ""}</td></tr>`).join("") || html`<tr><td colspan="5">История пуста. Запустите проверку выбранной сети или хоста.</td></tr>`}</tbody></table></div><div id="scan-detail">${renderScanResult(selectedJob, ctx)}</div>`;
}
export function renderDiscovery(view, ctx) {
  if (view === "hosts")
    return html`<div class="feature-page discovery-page">${settingsForm(ctx, false)}<form data-discovery-form class="monitor-filters" id="discovery-search"><label class="field"><span>Поиск устройства</span><input name="query" maxlength="100" value="${ctx.e(filters.query)}" placeholder="Имя, IP, MAC, модель"></label><label class="field"><span>Интерфейс</span><select name="interface">${options(ctx, interfaceNames(ctx), filters.interface, t("Все интерфейсы"))}</select></label><button class="primary" data-discovery-form data-action="discovery-search">Найти</button>${action("discovery-refresh", t("Обновить"))}</form><div id="discovery-results">${hostRows(ctx)}</div><p class="feature-note">Сведения сообщаются устройствами и могут быть неточными. Источник и срок актуальности каждого поля доступны в карточке. Одинаковые MAC в разных сегментах не объединяются.</p></div>`;
  const network = view === "network_scan";
  const allowed =
    scanStatus?.settings?.interfaces ||
    ctx.state.config.scanning?.interfaces ||
    [];
  const networks = scanStatus?.networks?.[scanInput.interface] || [];
  return html`<div class="feature-page discovery-page">${settingsForm(ctx, true)}<form data-discovery-form id="scan-start" class="scan-start-form" data-kind="${network ? "network" : "ports"}"><fieldset ${!ctx.canWrite() || ctx.offline ? "disabled" : ""}><div class="scan-fields"><label class="field"><span>Интерфейс</span><select name="interface" required>${options(ctx, allowed, scanInput.interface)}</select></label><label class="field"><span>${network ? t("Подсеть IPv4 / CIDR") : t("IPv4 / DNS-имя хоста")}</span><input name="target" required maxlength="253" value="${ctx.e(scanInput.target)}" placeholder="${network ? "192.168.10.0/24" : "192.168.10.10"}"><small id="scan-networks">${ctx.e(networks.join(" · "))}</small></label>${
    network
      ? ""
      : html`<label class="field"><span>Профиль</span><select name="profile">${[
          ["quick", t("Популярные 100 TCP")],
          ["custom", t("Выбранные TCP")],
          ["full", t("Все TCP 1–65535")],
          ["udp", t("Выбранные UDP")],
        ]
          .map(
            ([id, label]) =>
              html`<option value="${id}" ${scanInput.profile === id ? "selected" : ""}>${t(label)}</option>`,
          )
          .join(
            "",
          )}</select></label><label class="field"><span>Порты / диапазоны</span><input name="ports" maxlength="200" value="${ctx.e(scanInput.ports)}" placeholder="22,80,443,8000-8010" ${["custom", "udp"].includes(scanInput.profile) ? "required" : "disabled"}></label>`
  }</div><div class="scan-actions">${network ? "" : html`<label class="wg-check"><input name="service_detection" type="checkbox" ${scanInput.service_detection ? "checked" : ""}><span>Определять службы и версии</span></label>`}<button type="button" class="primary" data-discovery-form data-action="scan-start">${ctx.icon("search")}Запустить сканирование</button></div></fieldset></form><p class="feature-note">Только непосредственно подключённые сети выбранного интерфейса. UDP: до 128 портов. Определение версий отправляет служебные запросы; результаты являются предположением Nmap.</p>${action("scan-refresh", t("Обновить историю"))}<div id="scan-results">${scanRows(ctx)}</div></div>`;
}
export async function refreshDiscovery(ctx) {
  const view = Object.keys(discoveryViews).find((name) =>
    ctx.isCurrentView(name),
  );
  if (request && requestKind === view) return request;
  if (request) {
    controller?.abort();
    controller = request = requestKind = null;
  }
  if (!view) return null;
  requestKind = view;
  controller = new AbortController();
  const activeController = controller;
  const signal = controller.signal;
  const generation = ctx.generation;
  request = (async () => {
    try {
      if (view === "hosts") {
        const query = new URLSearchParams({
          query: filters.query,
          interface: filters.interface,
          offset: String(filters.offset),
          limit: "50",
        });
        const values = await Promise.all([
          ctx.api("discovery/status", { signal }),
          ctx.api(`discovery/hosts?${query}`, { signal }),
        ]);
        if (signal.aborted || generation !== ctx.getGeneration()) return;
        [discoveryStatus, hosts] = values;
      } else {
        const values = await Promise.all([
          ctx.api("scans/status", { signal }),
          ctx.api("scans/jobs?limit=50", { signal }),
        ]);
        if (signal.aborted || generation !== ctx.getGeneration()) return;
        [scanStatus, jobs] = values;
        const selectedId = selectedJob?.id;
        if (selectedId) {
          const value = await ctx.api(
            `scans/jobs/${encodeURIComponent(selectedId)}`,
            { signal },
          );
          if (
            !signal.aborted &&
            generation === ctx.getGeneration() &&
            selectedJob?.id === selectedId
          )
            selectedJob = value;
        }
      }
      loadError = "";
    } catch (error) {
      if (signal.aborted || generation !== ctx.getGeneration()) return;
      loadError = error.message;
    } finally {
      if (
        !signal.aborted &&
        generation === ctx.getGeneration() &&
        ctx.isCurrentView(view)
      ) {
        const region = document.querySelector(
          view === "hosts" ? "#discovery-results" : "#scan-results",
        );
        if (region) {
          const markup = view === "hosts" ? hostRows(ctx) : scanRows(ctx);
          if (renderedRegions.get(region) !== markup) {
            region.innerHTML = markup;
            renderedRegions.set(region, markup);
          }
        }
        if (view !== "hosts")
          syncScanForm(ctx, document.querySelector("#scan-start"));
      }
      if (controller === activeController) request = requestKind = null;
    }
  })();
  return request;
}
async function refreshNow(ctx) {
  controller?.abort();
  controller = request = requestKind = null;
  return refreshDiscovery(ctx);
}
export function syncScanForm(ctx, form, status = scanStatus) {
  const select = form?.querySelector('[name="interface"]');
  if (!select || !status) return;
  const allowed = [...new Set(status.settings?.interfaces || [])];
  const previous = select.value || scanInput.interface;
  const selected = allowed.includes(previous) ? previous : "";
  const currentOptions = Array.from(select.options || []).map(
    (option) => option.value,
  );
  if (currentOptions.join("\0") !== ["", ...allowed].join("\0"))
    select.innerHTML = options(ctx, allowed, selected);
  select.value = selected;
  scanInput.interface = selected;
  const hint = form.querySelector("#scan-networks");
  if (hint) hint.textContent = (status.networks?.[selected] || []).join(" · ");
}
export function handleDiscoveryInput(event) {
  const form = event.target?.closest?.("#scan-start");
  if (!form) return false;
  const data = new FormData(form);
  scanInput = {
    interface: String(data.get("interface") || ""),
    target: String(data.get("target") || ""),
    profile: String(data.get("profile") || "quick"),
    ports: String(data.get("ports") || ""),
    service_detection: data.has("service_detection"),
  };
  const ports = form.querySelector('[name="ports"]');
  if (ports) {
    ports.disabled = !["custom", "udp"].includes(scanInput.profile);
    ports.required = !ports.disabled;
  }
  const networks = form.querySelector("#scan-networks");
  if (networks)
    networks.textContent = (
      scanStatus?.networks?.[scanInput.interface] || []
    ).join(" · ");
  return true;
}
export async function handleDiscoveryAction(button, ctx) {
  const name = button.dataset.action;
  const generation = ctx.generation;
  if (!name?.startsWith("discovery-") && !name?.startsWith("scan-"))
    return false;
  const reads = [
    "discovery-refresh",
    "discovery-search",
    "discovery-page",
    "discovery-host",
    "discovery-connections",
    "scan-refresh",
    "scan-job",
    "scan-page",
  ];
  if (!reads.includes(name) && !ctx.canWrite())
    throw new Error(t("Для этого действия нужна группа full."));
  if (["discovery-refresh", "scan-refresh"].includes(name)) {
    await refreshNow(ctx);
    return true;
  }
  if (name === "discovery-search") {
    const form = document.querySelector("#discovery-search");
    const data = new FormData(form);
    filters = {
      query: String(data.get("query") || ""),
      interface: String(data.get("interface") || ""),
      offset: 0,
    };
    await refreshNow(ctx);
  } else if (name === "discovery-page") {
    filters.offset = Number(button.dataset.offset || 0);
    await refreshNow(ctx);
  } else if (name.endsWith("save-settings")) {
    if (readonly(ctx))
      throw new Error(t("Сначала завершите текущее применение конфигурации."));
    const scanning = name === "scan-save-settings";
    const form = document.querySelector(
      scanning ? "#scan-settings" : "#discovery-settings",
    );
    if (!form?.reportValidity()) return true;
    const data = new FormData(form),
      config = structuredClone(ctx.state.config);
    const value = {
      enabled: data.has("enabled"),
      interfaces: data.getAll("interfaces").map(String),
    };
    if (scanning)
      for (const key of [
        "max_hosts",
        "max_rate",
        "timeout_seconds",
        "history_limit",
      ])
        value[key] = Number(data.get(key));
    else {
      value.protocols = data.getAll("protocols").map(String);
      value.stale_seconds = Number(data.get("stale_seconds"));
    }
    config[scanning ? "scanning" : "discovery"] = value;
    await ctx.run(async () => {
      await ctx.saveConfig(config, Number(form.dataset.revision));
      ctx.render();
      ctx.toast(t("Настройки сохранены в черновик"));
    });
  } else if (name === "scan-start") {
    const form = document.querySelector("#scan-start");
    if (!form?.reportValidity()) return true;
    handleDiscoveryInput({ target: form.querySelector("input") });
    const network = form.dataset.kind === "network";
    const payload = {
      ...scanInput,
      kind: form.dataset.kind,
      profile: network ? "quick" : scanInput.profile,
      ports:
        network || !["custom", "udp"].includes(scanInput.profile)
          ? ""
          : scanInput.ports,
      service_detection: !network && scanInput.service_detection,
    };
    await ctx.run(async () => {
      const job = await ctx.api("scans/jobs", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (generation !== ctx.getGeneration()) return;
      selectedJob = job;
      await refreshNow(ctx);
    });
  } else if (name === "scan-cancel") {
    await ctx.run(async () => {
      await ctx.api(
        `scans/jobs/${encodeURIComponent(button.dataset.id)}/cancel`,
        { method: "POST" },
      );
      if (generation === ctx.getGeneration()) await refreshNow(ctx);
    });
  } else if (name === "scan-job") {
    const epoch = ++detailEpoch;
    const job = await ctx.api(
      `scans/jobs/${encodeURIComponent(button.dataset.id)}`,
    );
    if (generation !== ctx.getGeneration() || epoch !== detailEpoch)
      return true;
    selectedJob = job;
    const region = document.querySelector("#scan-detail");
    if (region) region.innerHTML = renderScanResult(selectedJob, ctx);
  } else if (name === "discovery-host") {
    const epoch = ++detailEpoch;
    const host = await ctx.api(
      `discovery/hosts/${encodeURIComponent(button.dataset.id)}`,
    );
    if (
      generation !== ctx.getGeneration() ||
      epoch !== detailEpoch ||
      !ctx.isCurrentView("hosts")
    )
      return true;
    const ip = host.addresses?.[0] || "";
    const fields = [
      "hostname",
      "mac",
      "addresses",
      "vendor",
      "vendor_source",
      "platform",
      "model",
      "version",
      "uptime_seconds",
      "chassis_id",
      "remote_port",
      "port_description",
      "capabilities",
      "os_guesses",
    ];
    ctx.dialogFrame(
      host.hostname || ip || "Host",
      html`Интерфейс ${host.interface}`,
      html`<div class="feature-note">Первое наблюдение: ${ctx.e(date(host.first_seen))} · последнее: ${ctx.e(date(host.last_seen))}</div>${host.observations
        .map(
          (item) =>
            html`<article class="tools-result"><h3>${ctx.e(item.source.toUpperCase())} · ${item.stale ? t("устарело") : t("актуально")}</h3><p>${ctx.e(date(item.observed_at))} · до ${ctx.e(date(item.expires_at))}</p><dl>${fields
              .filter(
                (key) =>
                  item.fields[key] !== undefined && item.fields[key] !== "",
              )
              .map(
                (key) =>
                  html`<dt>${ctx.e(key === "os_guesses" ? t("Предполагаемая ОС (по службе, не подтверждена)") : key)}</dt><dd>${ctx.e(Array.isArray(item.fields[key]) ? item.fields[key].join(", ") : item.fields[key])}</dd>`,
              )
              .join(
                "",
              )}</dl>${item.fields.ports?.length ? html`<p>Последняя проверка портов: ${item.fields.ports.map((port) => `${ctx.e(port.port)}/${ctx.e(port.protocol || "tcp")} · ${ctx.e(port.state)} ${ctx.e(port.service || "")}`).join(", ")}</p>` : ""}</article>`,
        )
        .join("")}`,
      `${ip ? action("discovery-connections", t("Соединения"), `data-ip="${ctx.e(ip)}"`) : ""}${ip && ctx.canWrite() ? action("discovery-scan-host", t("Проверить порты"), `data-ip="${ctx.e(ip)}" data-interface="${ctx.e(host.interface)}"`) + action("discovery-block-host", t("Создать блокировку"), `data-ip="${ctx.e(ip)}" data-interface="${ctx.e(host.interface)}"`) : ""}${action("close", t("Закрыть"))}`,
      "",
      { rawTitle: true },
    );
  } else if (name === "discovery-connections") {
    ctx.dialog.close();
    await ctx.showHostConnections(button.dataset.ip);
  } else if (name === "discovery-scan-host") {
    scanInput = {
      interface: button.dataset.interface,
      target: button.dataset.ip,
      profile: "quick",
      ports: "",
      service_detection: false,
    };
    ctx.dialog.close();
    await ctx.navigate("port_scan");
  } else if (name === "discovery-block-host") {
    ctx.dialogFrame(
      t("Блокировка хоста"),
      t(
        "Будут созданы два правила Filter: INPUT и FORWARD. Они начнут действовать только после применения черновика.",
      ),
      html`<p>Источник ${ctx.e(button.dataset.ip)} · интерфейс ${ctx.e(button.dataset.interface)}</p>`,
      `${action("close", t("Отмена"))}${action("discovery-confirm-block", t("Добавить в черновик"), `data-ip="${ctx.e(button.dataset.ip)}" data-interface="${ctx.e(button.dataset.interface)}" data-revision="${ctx.state.revision}"`)}`,
    );
  } else if (name === "discovery-confirm-block") {
    const config = structuredClone(ctx.state.config);
    config.filter_rules.unshift(
      ...["input", "forward"].map((chain) => ({
        id: crypto.randomUUID(),
        name: `Block ${button.dataset.ip}`,
        enabled: true,
        chain,
        action: "drop",
        protocol: "any",
        src_address: `${button.dataset.ip}/32`,
        in_interface: button.dataset.interface,
        comment: "Created from Hosts / Neighbors",
      })),
    );
    await ctx.run(async () => {
      await ctx.saveConfig(config, Number(button.dataset.revision));
      ctx.dialog.close();
      ctx.toast(t("Блокировка добавлена в черновик"));
    });
  }
  return true;
}
