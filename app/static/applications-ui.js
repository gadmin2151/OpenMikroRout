import { html, t, locale, getLanguage } from "./i18n.js";
import { checkboxSelect } from "./checkbox-select.js";
import { assertDraftRevision } from "./draft-guards.js";
import { reorderRules } from "./rule-order.js";
import { addressListChoices } from "./protection-ui.js?v=3";
import {
  renderQueryBuilder,
  applyQueryBuilder,
  getAppliedExpression,
  getAppliedQuery,
  compileQueryExpression,
  resetQueryBuilder,
} from "./query-builder.js";

export const applicationViews = {
  applications_rules: [
    "Applications",
    "Правила доступа приложений и сервисов · IPv4 FORWARD.",
  ],
  applications_catalog: [
    "Applications",
    "Каталог приложений, источники и проверенное покрытие.",
  ],
  applications_connections: [
    "Applications",
    "Прикладные потоки, состояния и наблюдаемые решения роутера.",
  ],
  applications_settings: [
    "Applications",
    "Движок, управляемые сети и обновления каталога.",
  ],
};
export const applicationCatalogQuerySchema = [
  { field: "id", label: "ID приложения", type: "text" },
  { field: "name", label: "Приложение", type: "text" },
  {
    field: "kind",
    label: "Тип",
    type: "enum",
    options: ["application", "family", "provider", "category", "protocol"],
  },
  { field: "category", label: "Категория", type: "text" },
  ...["observable", "block_validated", "allow_over_port_deny"].map(
    (field, index) => ({
      field,
      label: [
        "Проверено наблюдение",
        "Проверена блокировка",
        "Allow выше запрета порта",
      ][index],
      type: "enum",
      options: ["true", "false"],
    }),
  ),
];
export const applicationConnectionQuerySchema = [
  { field: "application_id", label: "ID приложения", type: "text" },
  { field: "source", label: "Клиент IPv4 / сеть", type: "ipv4" },
  { field: "destination", label: "Назначение IPv4 / сеть", type: "ipv4" },
  {
    field: "protocol",
    label: "Протокол",
    type: "enum",
    options: ["tcp", "udp"],
  },
  {
    field: "classification_state",
    label: "Распознавание",
    type: "enum",
    options: ["pending", "detected", "unknown", "unsupported"],
  },
  {
    field: "decision",
    label: "Решение приложения",
    type: "enum",
    options: ["allow", "block", "probe", "fallback"],
  },
  { field: "state", label: "Connection State", type: "text" },
  { field: "interface", label: "Интерфейс", type: "text" },
  { field: "packets", label: "Пакеты", type: "number" },
  { field: "bytes", label: "Байты", type: "number" },
];
const ruleQuerySchema = () => [
  { field: "name", label: "Название", type: "text" },
  {
    field: "applications",
    label: "Приложения",
    type: "text",
    get: (rule) =>
      rule.application_ids?.flatMap((id) => [
        id,
        entryName(catalogEntries.get(id)),
      ]) || [],
  },
  {
    field: "action",
    label: "Действие",
    type: "enum",
    options: ["allow", "block"],
  },
  {
    field: "enabled",
    label: "Включён",
    type: "enum",
    options: ["true", "false"],
  },
  { field: "src_address", label: "Клиент IPv4 / сеть", type: "ipv4" },
  { field: "src_list", label: "Список источников", type: "text" },
  { field: "in_interface", label: "Входной интерфейс", type: "text" },
  { field: "comment", label: "Комментарий", type: "text" },
];
const tabs = [
  ["applications_rules", "Правила"],
  ["applications_catalog", "Каталог"],
  ["applications_connections", "Соединения"],
  ["applications_settings", "Настройки и обновления"],
];
const scopes = [
  "applications-rules",
  "applications-catalog",
  "applications-connections",
  "applications-picker",
];
const pageSize = 50;
const connStates = ["NEW", "ESTABLISHED", "RELATED"];
let status = null;
let errors = {};
let pages = {};
let offsets = { catalog: 0, connections: 0, picker: 0 };
let catalogEntries = new Map();
let selection = new Set();
let request = null;
let controller = null;
let requestView = null;
let lastRefresh = {};
let epoch = 0;
let editor = null;
let editorSerial = 0;
let pickerController = null;
let detailController = null;
let detailSerial = 0;
let pickerError = "";
let sorting = { catalog: null, connections: null };
let installed = new WeakSet();

const config = (ctx) =>
  ctx.state.config.applications || {
    enabled: false,
    mode: "observe",
    rules: [],
    interfaces: [],
    source_networks: [],
  };
const rules = (ctx) => config(ctx).rules || [];
const locked = (ctx) => !ctx.canWrite() || ctx.offline || !!ctx.state.pending;
const activeView = (ctx) =>
  Object.keys(applicationViews).find((view) => ctx.isCurrentView(view));
const selected = (value, current) => (value === current ? "selected" : "");
const checked = (value) => (value ? "checked" : "");
const stamp = (value) =>
  value ? new Date(value * 1000).toLocaleString(locale()) : "—";
const number = (value) =>
  Number.isFinite(value)
    ? value.toLocaleString(locale(), { maximumFractionDigits: 1 })
    : "—";
const endpoint = (address, port) =>
  address ? `${address}${port == null ? "" : `:${port}`}` : "—";
const array = (value) => (Array.isArray(value) ? value : []);
const split = (value) =>
  String(value || "")
    .split(/[\s,;]+/)
    .filter(Boolean);
function entryName(entry) {
  if (!entry) return "";
  if (typeof entry.name === "string")
    return (
      (getLanguage() === "en" ? entry.name_en : entry.name_ru) || entry.name
    );
  return (
    entry.name?.[getLanguage()] ||
    entry.name?.en ||
    entry.name_ru ||
    entry.name_en ||
    entry.id ||
    ""
  );
}
function remember(data) {
  for (const entry of array(data?.items))
    if (typeof entry?.id === "string") catalogEntries.set(entry.id, entry);
}
function entrySelectionIds(entry, visited = new Set()) {
  if (!entry || visited.has(entry.id)) return [];
  visited.add(entry.id);
  if (entry.kind !== "family")
    return entry.kind === "application" ? [entry.id] : [];
  const explicit = entry.concrete_ids || entry.leaf_ids;
  if (Array.isArray(explicit)) return explicit;
  return array(entry.children).flatMap((id) =>
    catalogEntries.has(id)
      ? entrySelectionIds(catalogEntries.get(id), visited)
      : [id],
  );
}
const cap = (entry, name) =>
  entry?.capabilities?.[name] === true || entry?.[name] === true;
const label = (value) =>
  ({
    allow: t("Разрешить"),
    block: t("Блокировать"),
    fallback: t("Обычный Firewall"),
    probe: t("Пробный пропуск"),
    pending: t("Определяется"),
    detected: t("Определено"),
    unknown: t("Не определено"),
    unsupported: t("Недоступно"),
    observe: t("Наблюдение"),
    enforce: t("Применение"),
    application: t("Приложение"),
    family: t("Семейство"),
    provider: t("Провайдер"),
    category: t("Категория"),
    protocol: t("Протокол"),
  })[value] ||
  value ||
  "—";
const button = (ctx, action, name, extra = "", icon = "") =>
  html`<button type="button" data-action="${action}" ${extra}>${icon ? ctx.icon(icon) : ""}${t(name)}</button>`;
const iconButton = (ctx, action, name, extra, icon) =>
  html`<button type="button" class="icon ghost" data-action="${action}" title="${ctx.e(t(name))}" aria-label="${ctx.e(t(name))}" ${extra}>${ctx.icon(icon)}</button>`;
function note(ctx, text) {
  return html`<p class="feature-note">${ctx.e(t(text))}</p>`;
}
function errorMarkup(ctx, text) {
  return text
    ? html`<div class="connection-error" role="alert">${ctx.e(text)}</div>`
    : "";
}
function engineReady() {
  return status?.engine?.available === true || status?.available === true;
}
function enforcementReady() {
  return engineReady() && status?.engine?.capabilities?.enforce === true;
}
function statusMarkup(ctx) {
  if (!status)
    return (
      errorMarkup(ctx, errors.status) ||
      html`<div class="security-status" role="status">Загрузка состояния…</div>`
    );
  if (status.demo === true)
    return html`<div class="apps-status" role="status"><div><strong>${t("Демонстрационный режим")}</strong><span>${t("Просмотр каталога и подготовка правил")}</span></div><span class="apps-mode">DEMO</span></div>${note(ctx, "В демо пакеты хоста не анализируются. Распознавание и блокировка приложений не выполняются.")}${errorMarkup(ctx, errors.status)}`;
  const title = !engineReady()
    ? t("Движок DPI недоступен")
    : !status.enabled
      ? t("Фильтрация приложений выключена")
      : status.mode === "observe"
        ? t(status.healthy ? "Режим наблюдения" : "Ожидание готовности движка")
        : status.healthy
          ? t("Прикладная фильтрация активна")
          : t("Прикладная фильтрация требует внимания");
  return html`<div class="apps-status ${!engineReady() || status.error ? "apps-status-warning" : ""}" role="status"><div><strong>${ctx.e(title)}</strong><span>${ctx.e(status.engine?.name || "DPI")} ${ctx.e(status.engine?.version || "")} · IPv4 FORWARD</span></div><span class="apps-mode">${ctx.e(label(status.mode || config(ctx).mode))}</span></div>${errorMarkup(ctx, errors.status || status.error)}${!engineReady() ? note(ctx, "Каталог доступен для подготовки правил. Без совместимого движка распознавание и блокировка не работают.") : ""}`;
}
function capabilities(ctx, entry) {
  return html`<span class="apps-capabilities">${[
    ["observable", "Наблюдение"],
    ["block_validated", "Блокировка"],
    ["allow_over_port_deny", "Allow выше порта"],
  ]
    .map(
      ([key, text]) =>
        html`<span class="apps-capability ${cap(entry, key) ? "available" : "unavailable"}" title="${ctx.e(t(cap(entry, key) ? "Покрытие подтверждено" : "Покрытие не подтверждено"))}">${cap(entry, key) ? "✓" : "—"} ${t(text)}</span>`,
    )
    .join("")}</span>`;
}
function pager(ctx, kind, data) {
  const total = Number(data?.total) || 0,
    offset = offsets[kind] || 0;
  return html`<div class="security-pagination"><span>${total ? html`${offset + 1}–${Math.min(offset + pageSize, total)} из ${total}` : t("0 записей")}</span>${button(ctx, kind === "picker" ? "apps-picker-page" : "apps-page", "Назад", `data-kind="${kind}" data-offset="${Math.max(0, offset - pageSize)}" ${offset ? "" : "disabled"}`)}${button(ctx, kind === "picker" ? "apps-picker-page" : "apps-page", "Далее", `data-kind="${kind}" data-offset="${offset + pageSize}" ${offset + pageSize < total ? "" : "disabled"}`)}</div>`;
}
function sortable(ctx, kind, key, text) {
  const order = sorting[kind],
    current = order?.key === key;
  return html`<th scope="col" aria-sort="${current ? order.direction : "none"}"><button type="button" class="connection-sort" data-action="apps-sort" data-kind="${kind}" data-key="${key}" title="Сортировка текущей страницы">${ctx.e(t(text))}<span aria-hidden="true">${current ? (order.direction === "ascending" ? "▲" : "▼") : "↕"}</span></button></th>`;
}
function sorted(items, kind) {
  const order = sorting[kind];
  if (!order) return items;
  const collator = new Intl.Collator(locale(), {
    numeric: true,
    sensitivity: "base",
  });
  const value = (entry) =>
    order.key === "name" ? entryName(entry) : entry[order.key];
  return items
    .map((entry, index) => ({ entry, index }))
    .sort((a, b) => {
      const left = value(a.entry),
        right = value(b.entry);
      if (left == null || right == null)
        return (left == null) - (right == null) || a.index - b.index;
      return (
        (order.direction === "descending" ? -1 : 1) *
          collator.compare(String(left), String(right)) || a.index - b.index
      );
    })
    .map(({ entry }) => entry);
}
function filteredRules(ctx) {
  const match = compileQueryExpression(
    getAppliedQuery("applications-rules"),
    ruleQuerySchema(),
  );
  return rules(ctx).filter(match);
}
function ruleRows(ctx) {
  const rows = filteredRules(ctx),
    disabled = locked(ctx);
  selection = new Set(
    [...selection].filter((id) => rules(ctx).some((rule) => rule.id === id)),
  );
  return html`<div class="table-scroll"><table class="rules-table apps-rules-table"><thead><tr><th><input type="checkbox" data-app-select-all aria-label="Выбрать все показанные правила" ${rows.length && rows.every((row) => selection.has(row.id)) ? "checked" : ""}></th><th class="drag-column"></th><th>#</th><th>Название</th><th>Клиент / Interface</th><th>Приложения</th><th>Action</th><th>Состояния</th><th></th></tr></thead><tbody>${
    rows
      .map(
        (rule) =>
          html`<tr data-app-rule="${ctx.e(rule.id)}" class="${selection.has(rule.id) ? "selected" : ""} ${rule.enabled ? "" : "disabled-row"}"><td><input type="checkbox" data-app-select="${ctx.e(rule.id)}" aria-label="${ctx.e(html`Выбрать ${rule.name}`)}" ${checked(selection.has(rule.id))}></td><td class="drag-column"><button type="button" class="drag-handle" draggable="${!disabled}" data-app-drag="${ctx.e(rule.id)}" aria-label="${ctx.e(html`Перетащить ${rule.name}`)}" ${disabled ? "disabled" : ""}>${ctx.icon("grip")}</button></td><td class="mono">${rules(ctx).findIndex((row) => row.id === rule.id) + 1}</td><td><strong>${ctx.e(rule.name)}</strong><small class="cell-note">${ctx.e(rule.comment || "")}</small></td><td class="mono">${ctx.e(rule.src_address || rule.src_list || t("Любой клиент"))}<small class="cell-note">${ctx.e(rule.in_interface || rule.in_interface_list || "—")}</small></td><td>${ctx.e(
            array(rule.application_ids)
              .map((id) => entryName(catalogEntries.get(id)) || id)
              .join(", "),
          )}</td><td><span class="apps-decision ${ctx.e(rule.action)}">${ctx.e(label(rule.action))}</span></td><td class="mono">${ctx.e(array(rule.connection_states).join(", ") || t("Все"))}</td><td>${button(ctx, "apps-rule-edit", "Настройки", `data-id="${ctx.e(rule.id)}"`, "edit")}</td></tr>`,
      )
      .join("") ||
    html`<tr><td colspan="9" class="users-empty">${rules(ctx).length ? t("По этому фильтру правила не найдены.") : t("Добавьте первое правило приложения.")}</td></tr>`
  }</tbody></table></div><div class="panel-footer"><span>${rows.length} из ${rules(ctx).length} правил</span><span>Первое совпавшее правило · общий черновик</span></div>`;
}
function updateRuleControls(ctx) {
  for (const control of document.querySelectorAll?.("[data-app-select]") || [])
    control.checked = selection.has(control.dataset.appSelect);
  for (const row of document.querySelectorAll?.("[data-app-rule]") || [])
    row.classList.toggle("selected", selection.has(row.dataset.appRule));
  const all = document.querySelector("[data-app-select-all]");
  const visible = filteredRules(ctx);
  if (all)
    all.checked =
      !!visible.length && visible.every((rule) => selection.has(rule.id));
  for (const action of ["delete", "enable", "disable", "copy", "up", "down"]) {
    const control = document.querySelector(
      `[data-action="apps-rule-${action}"]`,
    );
    if (control) control.disabled = locked(ctx) || !selection.size;
  }
}
function rulesPage(ctx) {
  const disabled = locked(ctx) || !selection.size ? "disabled" : "";
  return html`<div class="toolbar apps-toolbar"><div class="toolbar-start">${button(ctx, "apps-rule-new", "Добавить правило", `class="primary" ${locked(ctx) ? "disabled" : ""}`, "plus")}${[
    ["apps-rule-delete", "Удалить выбранные", "minus"],
    ["apps-rule-enable", "Включить", "check"],
    ["apps-rule-disable", "Отключить", "x"],
    ["apps-rule-copy", "Создать копию", "copy"],
    ["apps-rule-up", "Выше", "up"],
    ["apps-rule-down", "Ниже", "arrowdown"],
  ]
    .map(([action, text, icon]) =>
      iconButton(ctx, action, text, disabled, icon),
    )
    .join(
      "",
    )}</div>${button(ctx, "apps-refresh", "Обновить", "", "refresh")}</div>${note(ctx, "Allow пропускает только явно выбранные запреты портов. IP, GeoIP, WireGuard и Fail2ban продолжают проверяться.")}${renderQueryBuilder("applications-rules", ruleQuerySchema(), { applyAction: "apps-rules-filter" })}<div id="applications-results">${ruleRows(ctx)}</div>`;
}
function catalogRows(ctx) {
  const data = pages.catalog;
  if (!data)
    return errorMarkup(ctx, errors.catalog) || note(ctx, "Загрузка каталога…");
  return html`${errorMarkup(ctx, errors.catalog)}<div class="table-scroll"><table class="rules-table apps-catalog-table"><thead><tr>${sortable(ctx, "catalog", "name", "Приложение")}${sortable(ctx, "catalog", "kind", "Тип")}${sortable(ctx, "catalog", "category", "Категория")}<th>Проверенное покрытие</th><th></th></tr></thead><tbody>${
    sorted(array(data.items), "catalog")
      .map(
        (entry) =>
          html`<tr><td><strong>${ctx.e(entryName(entry))}</strong><small class="cell-note mono">${ctx.e(entry.id)}</small></td><td>${ctx.e(label(entry.kind))}</td><td>${ctx.e(entry.category || "—")}</td><td>${capabilities(ctx, entry)}</td><td>${button(ctx, "apps-catalog-detail", "Сведения", `data-id="${ctx.e(entry.id)}"`)}</td></tr>`,
      )
      .join("") ||
    html`<tr><td colspan="5" class="users-empty">По этому фильтру приложения не найдены.</td></tr>`
  }</tbody></table></div>${pager(ctx, "catalog", data)}<p class="feature-note">${ctx.e(data.version || status?.catalog?.active_version || "—")} · ${t("Наличие записи не доказывает распознавание или возможность блокировки.")}</p>`;
}
function connectionsRows(ctx) {
  const data = pages.connections;
  if (!data)
    return (
      errorMarkup(ctx, errors.connections) ||
      note(ctx, "Загрузка прикладных соединений…")
    );
  return html`${errorMarkup(ctx, errors.connections || data.error)}${note(ctx, "Решение OMR не доказывает доступность удалённого сервиса. Состояние TCP и распознавание приложения показаны отдельно.")}${data.counters_scope === "analyzed" ? note(ctx, "Счётчики относятся к анализируемым пакетам и не являются полными счётчиками соединения.") : ""}<div class="table-scroll"><table class="rules-table apps-connections-table"><thead><tr>${[
    ["application_id", "Приложение"],
    ["source", "Клиент"],
    ["destination", "Назначение"],
    ["protocol", "Протокол"],
    ["classification_state", "Распознавание"],
    ["decision", "Решение приложения"],
    ["state", "Connection State"],
    ["packets", "Пакеты"],
    ["bytes", "Байты"],
  ]
    .map(([key, name]) => sortable(ctx, "connections", key, name))
    .join("")}<th>Основание / Правило</th></tr></thead><tbody>${
    sorted(array(data.items), "connections")
      .map(
        (row) =>
          html`<tr><td><strong>${ctx.e(entryName(catalogEntries.get(row.application_id)) || row.application_name || row.application_id || t("Не определено"))}</strong><small class="cell-note">${ctx.e(row.interface || "—")}</small></td><td class="mono">${ctx.e(endpoint(row.source, row.source_port))}</td><td class="mono">${ctx.e(endpoint(row.destination, row.destination_port))}<small class="cell-note">${ctx.e(row.translated_destination || "")}</small></td><td>${ctx.e(String(row.protocol || "—").toUpperCase())}</td><td>${ctx.e(label(row.classification_state))}</td><td><span class="apps-decision ${["allow", "block", "probe", "fallback"].includes(row.decision) ? row.decision : ""}">${ctx.e(label(row.decision))}</span><small class="cell-note">${ctx.e(row.observed_verdict || row.effective_verdict || "—")}</small></td><td class="mono">${ctx.e(row.state || "—")}</td><td class="mono">${ctx.e(number(row.packets))}</td><td class="mono">${ctx.e(number(row.bytes))}</td><td>${ctx.e(row.method || "—")}<small class="cell-note">${ctx.e(row.rule_name || row.reason || "—")}</small></td></tr>`,
      )
      .join("") ||
    html`<tr><td colspan="10" class="users-empty">${engineReady() ? t("Прикладных соединений пока нет.") : t("Движок недоступен: реальные прикладные потоки не собираются.")}</td></tr>`
  }</tbody></table></div>${pager(ctx, "connections", data)}<p class="feature-note">${t("Обновлено")}: ${ctx.e(stamp(data.updated_at || data.timestamp))} · ${t("Сортировка текущей страницы")}</p>`;
}
function interfaceOptions(ctx) {
  return [
    ...new Set([
      ...(ctx.interfaces || []).map((entry) =>
        typeof entry === "string" ? entry : entry.name,
      ),
      ...(ctx.state.config.network?.bridges || []).map((entry) => entry.name),
      ...(ctx.state.config.network?.vlans || []).map((entry) => entry.name),
      ...(ctx.state.config.network?.wireguard_interfaces || []).map(
        (entry) => entry.name,
      ),
      ...array(config(ctx).interfaces),
    ]),
  ]
    .filter(Boolean)
    .sort();
}
function eligiblePortRules(ctx) {
  return (ctx.state.config.filter_rules || []).filter(
    (rule) =>
      rule.chain === "forward" &&
      ["tcp", "udp"].includes(rule.protocol) &&
      ["drop", "reject"].includes(rule.action) &&
      (rule.src_ports || rule.dst_ports) &&
      !array(rule.negate).length &&
      !array(rule.connection_states).some((state) =>
        ["INVALID", "UNTRACKED"].includes(state),
      ) &&
      !rule.f2b_profile &&
      !rule.protection?.enabled,
  );
}
function field(ctx, name, text, value, attributes = "") {
  return html`<label class="field"><span>${ctx.e(t(text))}</span><input name="${name}" value="${ctx.e(value ?? "")}" ${attributes}></label>`;
}
function choice(ctx, name, text, value, options) {
  const available =
    value && !options.some(([key]) => key === value)
      ? [...options, [value, value]]
      : options;
  return html`<label class="field"><span>${ctx.e(t(text))}</span><select name="${name}">${available.map(([key, text]) => html`<option value="${ctx.e(key)}" ${selected(key, value)}>${ctx.e(t(text))}</option>`).join("")}</select></label>`;
}
function catalogOptions(ctx, current) {
  return [
    ...new Set(
      [
        current,
        config(ctx).catalog_version,
        ...array(status?.catalog?.versions).map((entry) => entry.version),
      ].filter(Boolean),
    ),
  ]
    .map(
      (version) =>
        html`<option value="${ctx.e(version)}" ${selected(version, current)}>${ctx.e(version)}</option>`,
    )
    .join("");
}
function catalogJobMessage() {
  const job = status?.catalog?.job;
  return (
    job?.error ||
    job?.message ||
    (job
      ? `${job.phase || ""}${job.version ? ` · ${job.version}` : ""}`
      : "") ||
    status?.catalog?.error ||
    status?.catalog?.message ||
    ""
  );
}
function settingsPage(ctx) {
  const settings = config(ctx),
    disabled = locked(ctx) ? "disabled" : "";
  return html`<form id="application-settings-form" class="apps-settings" data-revision="${ctx.state.revision}"><fieldset ${disabled}><legend>Настройки приложений</legend><label class="checkbox-label"><input type="checkbox" name="enabled" ${checked(settings.enabled)}>Включено</label><div class="security-form-grid"><label class="field"><span>Режим</span><select name="mode"><option value="observe" ${selected("observe", settings.mode)}>Наблюдение</option><option value="enforce" ${selected("enforce", settings.mode)} ${enforcementReady() ? "" : "disabled"}>Применение</option></select></label>${checkboxSelect({ name: "interfaces", label: "Управляемые входные интерфейсы", selected: settings.interfaces || [], options: interfaceOptions(ctx).map((name) => [name, name]), disabled: !!disabled })}<label class="field"><span>Управляемые исходные сети · IPv4 / CIDR</span><textarea name="source_networks" rows="4" maxlength="8192" placeholder="192.168.10.0/24">${ctx.e(array(settings.source_networks).join("\n"))}</textarea><small>Исходный клиент потока. Ответные пакеты относятся к тому же соединению.</small></label>${choice(
    ctx,
    "unknown_policy",
    "Неопределённое приложение",
    settings.unknown_policy || "firewall",
    [
      ["firewall", "Обычный Firewall"],
      ["block", "Блокировать в управляемой области"],
    ],
  )}${choice(
    ctx,
    "failure_policy",
    "Ошибка анализа отдельного потока",
    settings.failure_policy || "block",
    [
      ["block", "Блокировать в управляемой области"],
      ["firewall", "Обычный Firewall"],
    ],
  )}</div>${note(ctx, "Управляются только выбранные транзитные сети. INPUT/OUTPUT и управление PVE не входят в эту область.")}${note(ctx, "Отказ обработчика всегда закрывает управляемую область. Эта настройка относится только к ошибке анализа отдельного потока.")}${!enforcementReady() ? note(ctx, "Enforce недоступен без проверенного совместимого движка. Сохранение черновика не включает блокировку.") : ""}<details><summary>Приоритет над запретами портов</summary>${checkboxSelect(
    {
      name: "override_rule_ids",
      label: "Applications имеют приоритет над этими запретами",
      selected: eligiblePortRules(ctx)
        .filter((rule) => rule.application_override_eligible)
        .map((rule) => rule.id),
      options: eligiblePortRules(ctx).map((rule) => [
        rule.id,
        `${rule.name} · ${rule.protocol.toUpperCase()} ${rule.dst_ports || rule.src_ports}`,
      ]),
      disabled: !!disabled,
    },
  )}${note(ctx, "Выбираются только обычные TCP/UDP port-DENY в FORWARD. Адресные ограничения и защитные правила сохраняются.")}</details><details><summary>Лимиты распознавания</summary><div class="security-form-grid apps-budgets">${[
    ["probe_timeout_ms", "Время определения, мс", 100, 10000, 2000],
    ["probe_packets", "Пакетов на определение", 3, 128, 32],
    ["probe_bytes", "Байт на определение", 1024, 262144, 65536],
    ["max_pending", "Pending: всего", 1, 2048, 512],
    ["max_pending_per_client", "Pending: на клиента", 1, 128, 32],
    ["queue_limit", "Пакетов в очереди", 16, 4096, 256],
    ["verdict_timeout_ms", "Deadline решения, мс", 10, 1000, 250],
  ]
    .map(([name, text, min, max, fallback]) =>
      field(
        ctx,
        name,
        text,
        settings[name] ?? fallback,
        `type="number" min="${min}" max="${max}" required`,
      ),
    )
    .join(
      "",
    )}</div>${note(ctx, "Определение приложения может потребовать начальные пакеты. Нулевой пропуск неизвестных данных не гарантируется.")}</details><div class="security-form-grid"><label class="field"><span>Версия каталога для применения</span><select name="catalog_version" data-app-catalog-version>${catalogOptions(ctx, settings.catalog_version)}</select><small>Смена версии входит в общий черновик и требует Apply.</small></label><label class="checkbox-label"><input type="checkbox" name="catalog_auto_update" ${checked(settings.catalog_auto_update)}>Проверять каталог автоматически</label>${field(ctx, "catalog_check_hours", "Интервал проверки · часы", settings.catalog_check_hours || 24, 'type="number" min="6" max="720" required')}</div><div class="settings-actions">${button(ctx, "apps-settings-save", "Сохранить в черновик", `class="primary" ${disabled}`)}</div></fieldset></form><section class="apps-catalog-update"><div class="feature-heading"><div><h3>Каталог и обновления</h3><p>${ctx.e(status?.catalog?.active_version || settings.catalog_version || "—")}</p></div>${button(ctx, "apps-refresh", "Обновить", "", "refresh")}</div>${note(ctx, "Обновление данных каталога не устанавливает код движка и не активирует новые разрешения автоматически.")}${status?.catalog?.sync_configured === false ? note(ctx, "Подписанные обновления каталога не настроены: требуется доверенный ключ данных на сервере.") : ""}<div class="settings-actions">${button(ctx, "apps-catalog-check", "Проверить каталог", disabled || status?.catalog?.sync_configured === false ? "disabled" : "", "refresh")}${button(ctx, "apps-catalog-download", "Подготовить обновление", disabled || status?.catalog?.sync_configured === false ? "disabled" : "", "download")}</div><div id="applications-update-status" role="status">${ctx.e(catalogJobMessage())}</div></section>`;
}
export function renderApplications(ctx, view = "applications_rules") {
  return html`<div class="feature-page apps-page"><div class="apps-tabs" role="tablist" aria-label="Applications">${tabs.map(([key, text]) => html`<button type="button" role="tab" aria-selected="${view === key}" class="${view === key ? "active" : ""}" data-action="view" data-view="${key}">${t(text)}</button>`).join("")}</div><div id="applications-status">${statusMarkup(ctx)}</div>${view === "applications_catalog" ? html`${renderQueryBuilder("applications-catalog", applicationCatalogQuerySchema, { applyAction: "apps-catalog-filter" })}<div class="apps-refresh">${button(ctx, "apps-refresh", "Обновить", "", "refresh")}</div><div id="applications-results">${catalogRows(ctx)}</div>` : view === "applications_connections" ? html`${renderQueryBuilder("applications-connections", applicationConnectionQuerySchema, { applyAction: "apps-connections-filter" })}<div class="apps-refresh">${button(ctx, "apps-refresh", "Обновить", "", "refresh")}</div><div id="applications-results">${connectionsRows(ctx)}</div>` : view === "applications_settings" ? settingsPage(ctx) : rulesPage(ctx)}</div>`;
}
function paint(ctx, view) {
  const node = document.querySelector("#applications-status");
  if (node) node.innerHTML = statusMarkup(ctx);
  const results = document.querySelector("#applications-results");
  if (results && !results.contains?.(document.activeElement)) {
    const markup =
      view === "applications_catalog"
        ? catalogRows(ctx)
        : view === "applications_connections"
          ? connectionsRows(ctx)
          : view === "applications_rules"
            ? ruleRows(ctx)
            : "";
    if (markup && results.innerHTML !== markup) results.innerHTML = markup;
  }
  if (view === "applications_rules") updateRuleControls(ctx);
  const update = document.querySelector("#applications-update-status");
  if (update) update.textContent = catalogJobMessage();
  const enforce = document.querySelector(
    '#application-settings-form [value="enforce"]',
  );
  if (enforce) enforce.disabled = !enforcementReady();
  const pin = document.querySelector("[data-app-catalog-version]");
  if (pin && document.activeElement !== pin) {
    const value = pin.value || config(ctx).catalog_version;
    const markup = catalogOptions(ctx, value);
    if (pin.innerHTML !== markup) {
      pin.innerHTML = markup;
      pin.value = value;
    }
  }
  for (const action of ["check", "download"]) {
    const control = document.querySelector(
      `[data-action="apps-catalog-${action}"]`,
    );
    if (control)
      control.disabled =
        locked(ctx) || status?.catalog?.sync_configured === false;
  }
}
export async function refreshApplications(ctx, { force = false } = {}) {
  const view = activeView(ctx);
  if (!view) return;
  if (!force && request && requestView === view) return request;
  if (
    !force &&
    Date.now() - (lastRefresh[view] || 0) <
      (view === "applications_connections" ? 900 : 4500)
  )
    return;
  controller?.abort();
  const control = new AbortController(),
    generation = ctx.generation,
    currentEpoch = epoch;
  controller = control;
  requestView = view;
  const kind =
    view === "applications_connections"
      ? "connections"
      : view === "applications_settings"
        ? null
        : "catalog";
  const query = new URLSearchParams({
    offset: String(view === "applications_rules" ? 0 : offsets[kind] || 0),
    limit: String(view === "applications_rules" ? 200 : pageSize),
  });
  if (kind && view !== "applications_rules") {
    const expression = getAppliedExpression(`applications-${kind}`);
    if (expression) query.set("expression", expression);
  }
  const operation = Promise.resolve()
    .then(async () => {
      const tasks = [
        ctx.api("applications/status", { signal: control.signal }),
      ];
      if (kind)
        tasks.push(
          ctx.api(`applications/${kind}?${query}`, { signal: control.signal }),
        );
      const results = await Promise.allSettled(tasks);
      if (
        control.signal.aborted ||
        epoch !== currentEpoch ||
        generation !== ctx.getGeneration() ||
        !ctx.isCurrentView(view)
      )
        return;
      if (
        results[0].status === "fulfilled" &&
        results[0].value &&
        typeof results[0].value === "object"
      ) {
        status = results[0].value;
        delete errors.status;
      } else
        errors.status =
          results[0].status === "rejected"
            ? results[0].reason.message
            : t("Некорректный ответ приложений.");
      if (kind) {
        const result = results[1];
        if (
          result.status === "fulfilled" &&
          Array.isArray(result.value?.items) &&
          Number.isFinite(result.value?.total)
        ) {
          if (view !== "applications_rules") pages[kind] = result.value;
          if (kind === "catalog") remember(result.value);
          delete errors[kind];
        } else
          errors[kind] =
            result.status === "rejected"
              ? result.reason.message
              : t("Некорректный ответ приложений.");
      }
      lastRefresh[view] = Date.now();
      paint(ctx, view);
    })
    .finally(() => {
      if (request === operation) request = null;
      if (controller === control) controller = null;
    });
  request = operation;
  return operation;
}
function blankRule() {
  return {
    id: crypto.randomUUID(),
    name: "",
    enabled: true,
    application_ids: [],
    action: "block",
    src_address: "",
    src_list: "",
    dst_address: "",
    dst_list: "",
    in_interface: "",
    in_interface_list: "",
    out_interface: "",
    out_interface_list: "",
    connection_states: ["NEW", "ESTABLISHED", "RELATED"],
    comment: "",
  };
}
function ruleEditorScope(ctx) {
  const rule = editor.rule,
    any = [["", "Любой"]],
    lists = [...any, ...addressListChoices(ctx.state.config)],
    interfaces = [...any, ...interfaceOptions(ctx).map((name) => [name, name])],
    interfaceLists = [
      ...any,
      ...(ctx.state.config.network?.interface_lists || []).map((item) => [
        item.name,
        item.name,
      ]),
    ];
  return html`<div class="security-form-grid">${field(ctx, "name", "Название", rule.name, 'required maxlength="80"')}${field(ctx, "src_address", "Клиент IPv4 / сеть", rule.src_address, 'maxlength="32" placeholder="192.168.10.0/24"')}${choice(ctx, "src_list", "Список источников", rule.src_list, lists)}${field(ctx, "dst_address", "Назначение IPv4 / сеть", rule.dst_address, 'maxlength="32"')}${choice(ctx, "dst_list", "Список назначений", rule.dst_list, lists)}${choice(ctx, "in_interface", "Входной интерфейс", rule.in_interface, interfaces)}${choice(ctx, "in_interface_list", "Список входных интерфейсов", rule.in_interface_list, interfaceLists)}${choice(ctx, "out_interface", "Выходной интерфейс", rule.out_interface, interfaces)}${choice(ctx, "out_interface_list", "Список выходных интерфейсов", rule.out_interface_list, interfaceLists)}</div><label class="checkbox-label"><input type="checkbox" name="enabled" ${checked(rule.enabled)}>Включено</label>${field(ctx, "comment", "Комментарий", rule.comment, 'maxlength="200"')}${note(ctx, "Source и интерфейсы относятся к инициатору потока. Ответные пакеты принадлежат тому же соединению.")}`;
}
function pickerRows(ctx) {
  const items = array(editor?.page?.items),
    chosen = editor?.selected || new Set();
  return html`${errorMarkup(ctx, pickerError)}<div class="checkbox-select apps-picker" role="group" aria-label="Приложения"><div class="checkbox-select-toolbar"><output>${chosen.size} ${t("выбрано")}</output>${button(ctx, "apps-picker-all", "Выбрать страницу", locked(ctx) ? "disabled" : "")}${button(ctx, "apps-picker-clear", "Очистить выбор", locked(ctx) ? "disabled" : "")}</div><div class="checkbox-select-options">${
    items
      .map((entry) => {
        const ids = entrySelectionIds(entry);
        return html`<label class="checkbox-select-option"><input type="checkbox" data-app-picker="${ctx.e(entry.id)}" name="application_ids" value="${ctx.e(entry.id)}" ${checked(ids.length && ids.every((id) => chosen.has(id)))} ${locked(ctx) || !ids.length ? "disabled" : ""}><span><strong>${ctx.e(entryName(entry))}</strong><small class="cell-note">${ctx.e(entry.id)} · ${ctx.e(label(entry.kind))}${entry.kind === "family" ? html` · ${ids.length} ${t("приложений")}` : ""}</small></span></label>`;
      })
      .join("") ||
    html`<span class="checkbox-select-empty">${editor?.page ? t("По этому фильтру приложения не найдены.") : t("Загрузка каталога…")}</span>`
  }</div></div>${pager(ctx, "picker", editor?.page)}<div class="apps-selected">${[...chosen].map((id) => html`<span>${ctx.e(entryName(catalogEntries.get(id)) || id)}${button(ctx, "apps-picker-remove", "Убрать", `data-id="${ctx.e(id)}" ${locked(ctx) ? "disabled" : ""}`)}</span>`).join("")}</div>`;
}
function paintPicker(ctx) {
  const region = ctx.dialog.querySelector("#apps-picker-results");
  if (!region || !editor) return;
  const focused = document.activeElement?.dataset?.appPicker;
  region.innerHTML = pickerRows(ctx);
  if (focused)
    for (const control of region.querySelectorAll?.("[data-app-picker]") || [])
      if (control.dataset.appPicker === focused)
        control.focus({ preventScroll: true });
}
function editorTab(ctx, tab) {
  for (const panel of ctx.dialog.querySelectorAll("[data-app-editor-tab]"))
    panel.hidden = panel.dataset.appEditorTab !== tab;
  for (const control of ctx.dialog.querySelectorAll(
    '[data-action="apps-editor-tab"]',
  ))
    control.classList.toggle("active", control.dataset.tab === tab);
}
function validateEditor(ctx, form) {
  if (form.checkValidity && !form.checkValidity()) {
    const panel = form
      .querySelector(":invalid")
      ?.closest("[data-app-editor-tab]");
    if (panel) editorTab(ctx, panel.dataset.appEditorTab);
  }
  return form.reportValidity();
}
function openEditor(ctx, id) {
  detailController?.abort();
  detailSerial++;
  const existing = rules(ctx).find((row) => row.id === id);
  if (id && !existing) throw new Error(t("Правило больше не существует."));
  const rule = structuredClone(existing || blankRule());
  editorSerial++;
  editor = {
    serial: editorSerial,
    rule,
    revision: ctx.state.revision,
    selected: new Set(rule.application_ids),
    page: null,
  };
  offsets.picker = 0;
  pickerError = "";
  resetQueryBuilder("applications-picker");
  ctx.dialogFrame(
    existing ? t("Правило приложения") : t("Новое правило приложения"),
    t("Изменения сохраняются в общий черновик."),
    html`<form id="application-rule-form" class="winbox-form apps-rule-editor"><div class="dialog-tabs" role="tablist"><button type="button" class="dialog-tab active" data-action="apps-editor-tab" data-tab="general">General</button><button type="button" class="dialog-tab" data-action="apps-editor-tab" data-tab="applications">Applications</button><button type="button" class="dialog-tab" data-action="apps-editor-tab" data-tab="advanced">Advanced</button><button type="button" class="dialog-tab" data-action="apps-editor-tab" data-tab="action">Action</button></div><fieldset ${locked(ctx) ? "disabled" : ""}><section data-app-editor-tab="general">${ruleEditorScope(ctx)}</section><section data-app-editor-tab="applications" hidden>${renderQueryBuilder("applications-picker", applicationCatalogQuerySchema, { applyAction: "apps-picker-filter" })}<div id="apps-picker-results">${pickerRows(ctx)}</div>${note(ctx, "Выбор семейства разворачивается в конкретные дочерние приложения при проверке правила. Покрытие видно в каталоге.")}</section><section data-app-editor-tab="advanced" hidden>${checkboxSelect({ name: "connection_states", label: "Connection State", selected: rule.connection_states, options: connStates.map((state) => [state, state]), required: true, disabled: locked(ctx), searchable: false })}${note(ctx, "Для DPI Allow нужны NEW и ESTABLISHED. Позднее распознавание не работает с правилом только NEW.")}</section><section data-app-editor-tab="action" hidden>${choice(
      ctx,
      "action",
      "Действие",
      rule.action,
      [
        ["block", "Блокировать"],
        ["allow", "Разрешить"],
      ],
    )}${note(ctx, "Allow пропускает только явно выбранные запреты портов. IP, GeoIP, WireGuard и Fail2ban продолжают проверяться.")}${note(ctx, "Правила проверяются сверху вниз до первого совпадения. Для исключения клиента поставьте его Allow выше общего Block.")}</section></fieldset><div class="dialog-error hidden" role="alert"></div></form>`,
    html`${button(ctx, "close", "Отмена")}${button(ctx, "apps-rule-save", "Сохранить в черновик", `class="primary" ${locked(ctx) ? "disabled" : ""}`)}`,
  );
  return loadPicker(ctx);
}
async function loadPicker(ctx) {
  if (!editor) return;
  pickerController?.abort();
  const control = new AbortController(),
    serial = editor.serial,
    generation = ctx.generation,
    currentEpoch = epoch;
  pickerController = control;
  const query = new URLSearchParams({
    offset: String(offsets.picker),
    limit: String(pageSize),
  });
  const expression = getAppliedExpression("applications-picker");
  if (expression) query.set("expression", expression);
  try {
    const data = await ctx.api(`applications/catalog?${query}`, {
      signal: control.signal,
    });
    if (!Array.isArray(data?.items) || !Number.isFinite(data?.total))
      throw new Error(t("Некорректный ответ приложений."));
    if (
      control.signal.aborted ||
      epoch !== currentEpoch ||
      generation !== ctx.getGeneration() ||
      editor?.serial !== serial
    )
      return;
    editor.page = data;
    remember(data);
    pickerError = "";
  } catch (error) {
    if (
      !control.signal.aborted &&
      epoch === currentEpoch &&
      generation === ctx.getGeneration() &&
      editor?.serial === serial
    )
      pickerError = error.message;
  } finally {
    if (pickerController === control) pickerController = null;
    if (
      editor?.serial === serial &&
      !control.signal.aborted &&
      epoch === currentEpoch &&
      generation === ctx.getGeneration()
    ) {
      paintPicker(ctx);
    }
  }
}
function requireWrite(ctx) {
  if (!ctx.canWrite()) throw new Error(t("Нужна группа full."));
  if (ctx.offline || ctx.state.pending)
    throw new Error(
      t("Сначала завершите применение и проверьте связь с сервером."),
    );
}
async function saveRules(ctx, updated, revision = ctx.state.revision) {
  requireWrite(ctx);
  assertDraftRevision(revision, ctx.state.revision);
  const next = structuredClone(ctx.state.config);
  next.applications ||= { ...config(ctx) };
  next.applications.rules = updated;
  await ctx.saveConfig(next, revision);
  ctx.render();
}
export function handleApplicationsInput(event, ctx) {
  const target = event.target;
  if (
    target?.dataset?.appSelect ||
    target?.hasAttribute?.("data-app-select-all")
  ) {
    if (target.hasAttribute?.("data-app-select-all"))
      selection = target.checked
        ? new Set(filteredRules(ctx).map((rule) => rule.id))
        : new Set();
    else
      target.checked
        ? selection.add(target.dataset.appSelect)
        : selection.delete(target.dataset.appSelect);
    updateRuleControls(ctx);
    return true;
  }
  if (target?.dataset?.appPicker) {
    if (editor && !locked(ctx)) {
      for (const id of entrySelectionIds(
        catalogEntries.get(target.dataset.appPicker),
      ))
        target.checked ? editor.selected.add(id) : editor.selected.delete(id);
      paintPicker(ctx);
    }
    return true;
  }
  const form = target?.closest?.(
    "#application-rule-form,#application-settings-form",
  );
  if (!form) return false;
  if (!locked(ctx)) form.dataset.dirty = "true";
  return true;
}
export async function handleApplicationsAction(control, ctx) {
  const action = control.dataset.action;
  if (!action?.startsWith("apps-")) return false;
  if (control.disabled) return true;
  if (action === "apps-refresh") {
    await refreshApplications(ctx, { force: true });
    return true;
  }
  if (action === "apps-editor-tab") {
    editorTab(ctx, control.dataset.tab);
    return true;
  }
  if (action === "apps-rule-edit") {
    await openEditor(ctx, control.dataset.id);
    return true;
  }
  if (
    [
      "apps-catalog-filter",
      "apps-connections-filter",
      "apps-rules-filter",
    ].includes(action)
  ) {
    const kind = action.split("-")[1];
    applyQueryBuilder(`applications-${kind}`);
    if (kind === "rules") paint(ctx, "applications_rules");
    else {
      offsets[kind] = 0;
      await refreshApplications(ctx, { force: true });
    }
    return true;
  }
  if (action === "apps-page") {
    const kind = control.dataset.kind,
      offset = Number(control.dataset.offset);
    if (
      ["catalog", "connections"].includes(kind) &&
      Number.isSafeInteger(offset) &&
      offset >= 0 &&
      offset <= 100000
    ) {
      offsets[kind] = offset;
      await refreshApplications(ctx, { force: true });
    }
    return true;
  }
  if (action === "apps-sort") {
    const kind = control.dataset.kind,
      key = control.dataset.key;
    if (
      !(kind in sorting) ||
      ![
        "name",
        "kind",
        "category",
        "application_id",
        "source",
        "destination",
        "protocol",
        "classification_state",
        "decision",
        "state",
        "packets",
        "bytes",
      ].includes(key)
    )
      return true;
    sorting[kind] = {
      key,
      direction:
        sorting[kind]?.key === key && sorting[kind].direction === "ascending"
          ? "descending"
          : "ascending",
    };
    paint(ctx, `applications_${kind}`);
    return true;
  }
  if (action === "apps-catalog-detail") {
    const generation = ctx.generation,
      currentEpoch = epoch,
      view = activeView(ctx),
      serial = ++detailSerial;
    detailController?.abort();
    const active = new AbortController();
    detailController = active;
    let entry;
    try {
      entry = await ctx.api(
        `applications/catalog/${encodeURIComponent(control.dataset.id)}`,
        { signal: active.signal },
      );
    } catch (error) {
      if (active.signal.aborted) return true;
      throw error;
    } finally {
      if (detailController === active) detailController = null;
    }
    if (
      active.signal.aborted ||
      serial !== detailSerial ||
      ctx.dialog.open ||
      generation !== ctx.getGeneration() ||
      epoch !== currentEpoch ||
      !view ||
      !ctx.isCurrentView(view)
    )
      return true;
    remember({ items: [entry] });
    ctx.dialogFrame(
      entryName(entry),
      entry.id,
      html`<div class="apps-entry-detail">${capabilities(ctx, entry)}<dl><dt>Тип</dt><dd>${ctx.e(label(entry.kind))}</dd><dt>Категория</dt><dd>${ctx.e(entry.category || "—")}</dd><dt>Покрытие</dt><dd>${ctx.e(entry.coverage || t("Покрытие не подтверждено"))}</dd><dt>Источник / Версия</dt><dd class="mono">${ctx.e(entry.source || entry.engine_mapping?.engine || "—")} ${ctx.e(entry.version || entry.engine_mapping?.version || "")}</dd><dt>Лицензия / Профиль</dt><dd>${ctx.e(entry.license_profile || entry.license || "—")}</dd></dl>${note(ctx, "IP/DNS-сопоставление не доказывает имя программы. Непроверенные возможности не используются для приоритетного Allow.")}</div>`,
      button(ctx, "close", "Закрыть"),
    );
    return true;
  }
  if (["apps-picker-filter", "apps-picker-page"].includes(action)) {
    if (action === "apps-picker-filter") {
      applyQueryBuilder("applications-picker");
      offsets.picker = 0;
    } else {
      const value = Number(control.dataset.offset);
      if (!Number.isSafeInteger(value) || value < 0 || value > 100000)
        return true;
      offsets.picker = value;
    }
    await loadPicker(ctx);
    return true;
  }
  requireWrite(ctx);
  if (action === "apps-rule-new") {
    await openEditor(ctx);
    return true;
  }
  if (
    ["apps-picker-all", "apps-picker-clear", "apps-picker-remove"].includes(
      action,
    )
  ) {
    if (!editor) return true;
    if (action === "apps-picker-all")
      for (const entry of array(editor.page?.items))
        for (const id of entrySelectionIds(entry)) editor.selected.add(id);
    else if (action === "apps-picker-remove")
      editor.selected.delete(control.dataset.id);
    else editor.selected.clear();
    paintPicker(ctx);
    return true;
  }
  if (action === "apps-rule-save") {
    const form = ctx.dialog.querySelector("#application-rule-form");
    if (!editor || !form || !validateEditor(ctx, form)) return true;
    assertDraftRevision(editor.revision, ctx.state.revision);
    if (!editor.selected.size)
      throw new Error(t("Выберите хотя бы одно приложение."));
    if (editor.selected.size > 64)
      throw new Error(t("В одном правиле допускается до 64 приложений."));
    const values = new FormData(form),
      rule = {
        ...editor.rule,
        application_ids: [...editor.selected],
        enabled: values.has("enabled"),
        connection_states: values.getAll("connection_states").map(String),
      };
    for (const key of [
      "name",
      "action",
      "src_address",
      "src_list",
      "dst_address",
      "dst_list",
      "in_interface",
      "in_interface_list",
      "out_interface",
      "out_interface_list",
      "comment",
    ])
      rule[key] = String(values.get(key) || "").trim();
    if (
      !rule.connection_states.length ||
      (rule.action === "allow" &&
        !["NEW", "ESTABLISHED"].every((state) =>
          rule.connection_states.includes(state),
        ))
    )
      throw new Error(t("Для DPI Allow нужны NEW и ESTABLISHED."));
    const updated = rules(ctx).some((row) => row.id === rule.id)
      ? rules(ctx).map((row) => (row.id === rule.id ? rule : row))
      : [...rules(ctx), rule];
    await saveRules(ctx, updated, editor.revision);
    editor = null;
    ctx.dialog.close();
    return true;
  }
  if (action === "apps-settings-save") {
    const form = document.querySelector("#application-settings-form");
    if (!form?.reportValidity()) return true;
    const revision = Number(form.dataset.revision);
    assertDraftRevision(revision, ctx.state.revision);
    const values = new FormData(form),
      next = structuredClone(ctx.state.config),
      settings = {
        ...config(ctx),
        enabled: values.has("enabled"),
        mode: String(values.get("mode") || config(ctx).mode || "observe"),
        interfaces: values.getAll("interfaces").map(String),
        source_networks: split(values.get("source_networks")),
        unknown_policy: String(values.get("unknown_policy") || "firewall"),
        failure_policy: String(values.get("failure_policy") || "block"),
        catalog_auto_update: values.has("catalog_auto_update"),
        catalog_check_hours: Number(values.get("catalog_check_hours")),
        catalog_version: String(
          values.get("catalog_version") || config(ctx).catalog_version,
        ),
      };
    for (const key of [
      "probe_timeout_ms",
      "probe_packets",
      "probe_bytes",
      "max_pending",
      "max_pending_per_client",
      "queue_limit",
      "verdict_timeout_ms",
    ])
      settings[key] = Number(values.get(key));
    if (settings.enabled && settings.mode === "enforce" && !enforcementReady())
      throw new Error(
        t("Enforce недоступен без проверенного совместимого движка."),
      );
    const candidates = new Set(eligiblePortRules(ctx).map((rule) => rule.id)),
      allowed = new Set(values.getAll("override_rule_ids").map(String));
    if (next.filter_rules)
      next.filter_rules = next.filter_rules.map((rule) =>
        candidates.has(rule.id)
          ? { ...rule, application_override_eligible: allowed.has(rule.id) }
          : rule,
      );
    next.applications = settings;
    await ctx.saveConfig(next, revision);
    ctx.render();
    return true;
  }
  if (["apps-catalog-check", "apps-catalog-download"].includes(action)) {
    const generation = ctx.generation;
    const result = await ctx.api(
      `applications/catalog/${action.endsWith("download") ? "download" : "check"}`,
      { method: "POST", body: "{}" },
    );
    if (generation === ctx.getGeneration()) {
      const node = document.querySelector("#applications-update-status");
      if (node)
        node.textContent =
          result.message ||
          result.status ||
          result.phase ||
          t("Операция принята");
      await refreshApplications(ctx, { force: true });
    }
    return true;
  }
  if (
    [
      "apps-rule-delete",
      "apps-rule-enable",
      "apps-rule-disable",
      "apps-rule-copy",
      "apps-rule-up",
      "apps-rule-down",
    ].includes(action)
  ) {
    const chosen = rules(ctx).filter((rule) => selection.has(rule.id));
    if (!chosen.length) return true;
    let updated = structuredClone(rules(ctx));
    if (action === "apps-rule-delete")
      updated = updated.filter((rule) => !selection.has(rule.id));
    else if (action === "apps-rule-enable" || action === "apps-rule-disable")
      updated = updated.map((rule) =>
        selection.has(rule.id)
          ? { ...rule, enabled: action === "apps-rule-enable" }
          : rule,
      );
    else if (action === "apps-rule-copy")
      updated.push(
        ...chosen.map((rule) => ({
          ...structuredClone(rule),
          id: crypto.randomUUID(),
          name: `${rule.name.slice(0, 70)} ${t("копия")}`,
        })),
      );
    else {
      const direction = action === "apps-rule-up" ? -1 : 1;
      const indexes = updated
        .map((rule, index) => (selection.has(rule.id) ? index : -1))
        .filter((index) => index >= 0);
      if (direction > 0) indexes.reverse();
      for (const index of indexes) {
        const target = index + direction;
        if (
          target >= 0 &&
          target < updated.length &&
          !selection.has(updated[target].id)
        )
          [updated[index], updated[target]] = [updated[target], updated[index]];
      }
    }
    await saveRules(ctx, updated);
    if (action === "apps-rule-delete") selection.clear();
    return true;
  }
  return false;
}
export function resetApplications() {
  epoch++;
  editorSerial++;
  controller?.abort();
  pickerController?.abort();
  detailController?.abort();
  detailSerial++;
  detailController = null;
  status =
    request =
    controller =
    requestView =
    editor =
    pickerController =
      null;
  pages = {};
  errors = {};
  offsets = { catalog: 0, connections: 0, picker: 0 };
  lastRefresh = {};
  catalogEntries = new Map();
  selection = new Set();
  sorting = { catalog: null, connections: null };
  pickerError = "";
  for (const scope of scopes) resetQueryBuilder(scope);
}
export function installApplicationsEvents(getContext, scope = document) {
  if (installed.has(scope)) return;
  installed.add(scope);
  let dragged = null,
    revision = null;
  const clear = () => {
    dragged = revision = null;
    for (const row of scope.querySelectorAll("[data-app-rule]"))
      row.classList.remove("dragging", "drop-before", "drop-after");
  };
  scope.addEventListener("dblclick", (event) => {
    const row = event.target.closest("[data-app-rule]");
    if (row && !event.target.closest("button,input"))
      void handleApplicationsAction(
        { dataset: { action: "apps-rule-edit", id: row.dataset.appRule } },
        getContext(),
      ).catch((error) => getContext().toast(error.message, true));
  });
  scope.addEventListener("dragstart", (event) => {
    const handle = event.target.closest("[data-app-drag]");
    if (!handle) return;
    const ctx = getContext();
    if (handle.disabled || locked(ctx) || ctx.busy) {
      event.preventDefault();
      return;
    }
    dragged = handle.dataset.appDrag;
    revision = ctx.state.revision;
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", dragged);
    handle.closest("[data-app-rule]").classList.add("dragging");
  });
  scope.addEventListener("dragover", (event) => {
    const row = event.target.closest("[data-app-rule]");
    if (
      !dragged ||
      !row ||
      row.dataset.appRule === dragged ||
      locked(getContext())
    )
      return;
    event.preventDefault();
    const rect = row.getBoundingClientRect();
    for (const item of scope.querySelectorAll("[data-app-rule]"))
      item.classList.remove("drop-before", "drop-after");
    row.classList.add(
      event.clientY < rect.top + rect.height / 2 ? "drop-before" : "drop-after",
    );
  });
  scope.addEventListener("drop", (event) => {
    const row = event.target.closest("[data-app-rule]"),
      ctx = getContext();
    if (!dragged || !row || locked(ctx) || ctx.busy) return;
    event.preventDefault();
    const from = dragged,
      target = row.dataset.appRule,
      expected = revision,
      rect = row.getBoundingClientRect(),
      after = event.clientY >= rect.top + rect.height / 2;
    clear();
    if (from === target) return;
    const updated = reorderRules(
      rules(ctx),
      from,
      target,
      after ? "after" : "before",
    );
    void ctx.run(() => saveRules(ctx, updated, expected));
  });
  scope.addEventListener("dragend", clear);
}
