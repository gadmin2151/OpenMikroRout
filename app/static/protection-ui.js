import { html, t, locale } from "./i18n.js";
/** Security configuration shares the router draft; operational data stays on the server. */
import { proofForm, proof, clearProof } from "./security-ui.js";
import { ruleServiceSummary } from "./rule-security-ui.js?v=3";
import {
  renderQueryBuilder,
  applyQueryBuilder,
  getAppliedExpression,
  resetQueryBuilder,
} from "./query-builder.js";
export const banQuerySchema = [
  { field: "query", label: "Поиск", type: "text" },
  { field: "profile", label: "Профиль", type: "text" },
  { field: "address", label: "IPv4 / CIDR", type: "ipv4" },
  { field: "country", label: "Страна", type: "text" },
  { field: "source", label: "Источник", type: "text" },
  { field: "remaining_seconds", label: "Осталось, с", type: "number" },
];
export const countryQuerySchema = [
  { field: "query", label: "Поиск", type: "text" },
  { field: "country", label: "Страна", type: "text" },
  { field: "ranges", label: "Диапазоны", type: "number" },
  { field: "networks", label: "Подсети", type: "number" },
];
export const systemListQuerySchema = (name) =>
  name.startsWith("geo_")
    ? [
        { field: "address", label: "IPv4 / CIDR", type: "ipv4" },
        { field: "first", label: "Первый IPv4", type: "ipv4" },
        { field: "last", label: "Последний IPv4", type: "ipv4" },
      ]
    : banQuerySchema.filter((field) => field.field !== "query");

export const protectionViews = {
  fail2ban: [
    "Fail2ban",
    t("Защита входа, временные блокировки и исключения · IPv4."),
  ],
  geoip: [
    "GeoIP",
    t("Локальная база стран и системные списки для Firewall и NAT."),
  ],
};
let snapshots = {},
  errors = {},
  request = null,
  controller = null,
  requestKind = null;
let offsets = { fail2ban: 0, geoip: 0, lists: 0 };
let lookup = null;
let editedProfile = null;
let editorRevision = null;
let pendingOperation = null;
let inspectedList = { name: "", offset: 0 };
const searchKinds = ["fail2ban", "geoip"];
const pageSize = 50;
const split = (text) =>
  String(text || "")
    .split(/[\s,;]+/)
    .filter(Boolean);
const when = (stamp) =>
  stamp ? new Date(stamp * 1000).toLocaleString(locale()) : "—";
const selected = (value, current) => (value === current ? "selected" : "");
const checked = (value) => (value ? "checked" : "");
function readonly(ctx) {
  return !ctx.canWrite() || ctx.offline || !!ctx.state.pending;
}
function note(text, ctx) {
  return html`<p class="feature-note">${ctx.e(text)}</p>`;
}
const attribution = () =>
  html`<p class="feature-note">IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a> · Country Lite · CC BY 4.0</p>`;
function field(ctx, label, name, value, type = "text", extra = "") {
  return html`<label class="field"><span>${ctx.e(t(label))}</span><input name="${name}" type="${type}" value="${ctx.e(value)}" ${extra}></label>`;
}
function toggle(ctx, label, name, value) {
  return html`<label class="checkbox-label"><input type="checkbox" name="${name}" ${checked(value)}>${ctx.e(t(label))}</label>`;
}
function pager(ctx, kind, total) {
  const offset = offsets[kind] || 0;
  return html`<div class="security-pagination"><span>${total ? html`${offset + 1}–${Math.min(offset + pageSize, total)} из ${total}` : t("0 записей")}</span><button data-action="protection-page" data-kind="${kind}" data-offset="${Math.max(0, offset - pageSize)}" ${offset ? "" : "disabled"}>Назад</button><button data-action="protection-page" data-kind="${kind}" data-offset="${offset + pageSize}" ${offset + pageSize < total ? "" : "disabled"}>Далее</button></div>`;
}
function filterBuilder(ctx, kind) {
  return html`<div class="security-actions"><button type="button" data-action="protection-refresh">${ctx.icon("refresh")}Обновить</button></div>${renderQueryBuilder(`protection-${kind}`, kind === "geoip" ? countryQuerySchema : banQuerySchema, { applyAction: "protection-search", applyData: { kind } })}`;
}
export function resetProtection() {
  for (const scope of [
    "protection-fail2ban",
    "protection-geoip",
    "system-list",
  ])
    resetQueryBuilder(scope);
  controller?.abort();
  snapshots = {};
  errors = {};
  request = null;
  controller = null;
  requestKind = null;
  offsets = { fail2ban: 0, geoip: 0, lists: 0 };
  lookup = null;
  editedProfile = null;
  editorRevision = null;
  pendingOperation = null;
  inspectedList = { name: "", offset: 0 };
}
function statusMarkup(ctx, kind) {
  if (errors[kind])
    return html`<div class="connection-error" role="alert">${ctx.e(errors[kind])}</div>`;
  const status = snapshots[kind]?.status;
  if (!status)
    return html`<div class="security-status" role="status">Загрузка состояния…</div>`;
  if (kind === "fail2ban")
    return html`<div class="security-status"><strong>${status.demo ? t("Деморежим") : status.effective ? t("Защита активна") : status.enabled ? t("Защита требует настройки") : t("Защита выключена")}</strong><span>IPv4 · ${ctx.e(status.access_mode || "direct")}</span></div>${(status.warnings || []).map((warning) => note(warning, ctx)).join("")}${status.error ? html`<div class="connection-error">${ctx.e(status.error)}</div>` : ""}`;
  return html`<div class="security-status"><strong>${ctx.e(status.version || status.active_version || t("База ещё не загружена"))}</strong><span>${status.demo ? t("DEMO · учебная выборка") : "DB-IP Country Lite"}</span></div>${note(html`Последняя проверка: ${when(status.last_check || status.checked_at)}. ${status.updating ? t("Загрузка и проверка базы…") : t("Определение страны работает локально.")}`, ctx)}${status.error ? html`<div class="connection-error">${ctx.e(status.error)}</div>` : ""}`;
}
function bansMarkup(ctx) {
  const data = snapshots.fail2ban?.bans;
  if (!data) return html`<div class="empty">Загружаем блокировки…</div>`;
  const profiles = new Map(
    (snapshots.fail2ban?.status?.profiles || []).map((profile) => [
      profile.id,
      profile.name,
    ]),
  );
  const rows = data.items
    .map(
      (row) =>
        html`<tr><td class="mono">${ctx.e(row.address)}</td><td>${ctx.e(profiles.get(row.profile) || row.profile)}<small class="cell-note mono">f2b_${ctx.e(row.profile)}</small></td><td>${ctx.e(row.country || "—")}</td><td>${ctx.e(row.source)}</td><td>${ctx.e(when(row.added_at))}</td><td>${ctx.e(when(row.expires_at))}<small class="cell-note">${Math.max(0, Math.ceil(row.remaining_seconds))} с осталось</small></td><td>${row.kernel_present ? t("В ядре") : t("Ожидает синхронизации")}</td><td><button data-action="f2b-unban" data-profile="${ctx.e(row.profile)}" data-address="${ctx.e(row.address)}" ${readonly(ctx) ? "disabled" : ""}>Разблокировать</button></td></tr>`,
    )
    .join("");
  return html`<div class="table-scroll"><table class="rules-table"><thead><tr><th>IPv4</th><th>Профиль</th><th>Страна</th><th>Источник</th><th>Добавлен</th><th>Истекает</th><th>Исполнение</th><th></th></tr></thead><tbody>${rows || html`<tr><td colspan="8" class="users-empty">Активных блокировок нет.</td></tr>`}</tbody></table></div>${pager(ctx, "fail2ban", data.total)}`;
}
function countryMarkup(ctx) {
  const data = snapshots.geoip?.countries;
  if (!data) return html`<div class="empty">Загружаем список стран…</div>`;
  const registered = new Set(
    (ctx.state.config.system_lists || []).map((list) => list.name),
  );
  return html`<div class="table-scroll"><table class="rules-table"><thead><tr><th>Страна</th><th>Список</th><th>Подсети</th><th></th></tr></thead><tbody>${
    data.items
      .map((row) => {
        const code = row.country || row.code;
        return html`<tr><td>${ctx.e(code)}</td><td class="mono">geo_${ctx.e(code)}</td><td>${ctx.e(row.networks ?? row.count ?? row.ranges ?? "—")}</td><td><button data-action="geo-register" data-country="${ctx.e(code)}" ${readonly(ctx) || registered.has(`geo_${code}`) ? "disabled" : ""}>${registered.has(`geo_${code}`) ? t("В черновике") : t("Добавить список")}</button></td></tr>`;
      })
      .join("") ||
    html`<tr><td colspan="4" class="users-empty">Загрузите базу или измените поиск.</td></tr>`
  }</tbody></table></div>${pager(ctx, "geoip", data.total)}`;
}
function inlineProfiles(ctx) {
  return [
    ...(ctx.state.config.rules || []).map((rule) => ({ rule, table: "nat" })),
    ...(ctx.state.config.filter_rules || []).map((rule) => ({
      rule,
      table: "filter",
    })),
  ].filter(({ rule }) => rule.protection?.enabled);
}
export function renderInlineProtection(ctx) {
  const rows = inlineProfiles(ctx)
    .map(({ rule, table }) => {
      const service = ruleServiceSummary(rule);
      const policy = rule.protection;
      const source =
        {
          connections: t("TCP-подключения"),
          web: t("Ошибки входа Web"),
          ssh: t("Ошибки SSH"),
        }[policy.event_source] || policy.event_source;
      return html`<tr><td>${ctx.e(rule.name)}<small class="cell-note">${table === "nat" ? "NAT" : t("Filter Rules")} · ${ctx.e(service.chain)}</small></td><td>${ctx.e(service.destination)}<small class="cell-note">TCP ${ctx.e(service.ports)} · ${ctx.e(service.incoming)}</small></td><td>${ctx.e(source)}</td><td>${ctx.e(policy.max_retry)} за ${ctx.e(policy.find_time)} с</td><td>${ctx.e(policy.ban_time)} с</td><td>${rule.enabled === false ? t("Правило выключено") : t("Включено в черновике")}</td><td><button data-action="rule-protection-open" data-table="${table}" data-id="${ctx.e(rule.id)}" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("edit")}Открыть правило</button></td></tr>`;
    })
    .join("");
  return html`<div class="feature-heading"><h2>Защита из NAT / Filter Rules</h2><span class="status-tag">Правил: ${inlineProfiles(ctx).length}</span></div>${note(t("Включается на вкладке Fail2ban самого правила. Сервис и профиль синхронизируются автоматически; здесь показан общий черновик."), ctx)}<div class="table-scroll"><table class="rules-table"><thead><tr><th>Правило</th><th>Защищаемый сервис</th><th>Источник попыток</th><th>Порог</th><th>Бан</th><th>Состояние</th><th></th></tr></thead><tbody>${rows || html`<tr><td colspan="7" class="users-empty">Откройте NAT или Filter Rule → Fail2ban и включите автоматическую блокировку.</td></tr>`}</tbody></table></div>`;
}
export function renderProtection(view, ctx) {
  const disabled = readonly(ctx) ? "disabled" : "";
  if (view === "fail2ban") {
    const config = ctx.state.config.fail2ban;
    return html`<div class="feature-page protection-page"><div id="protection-status">${statusMarkup(ctx, view)}</div>${renderInlineProtection(ctx)}<form id="f2b-settings" class="security-settings" data-revision="${ctx.state.revision}"><fieldset ${disabled}><legend>Ручные профили и доступ к Web</legend>${toggle(ctx, t("Включить ручные профили"), "enabled", config.enabled)}<div class="security-form-grid"><label class="field"><span>Способ подключения</span><select name="access_mode">${[
      ["direct", t("Прямое подключение")],
      ["local_proxy", t("Локальный доверенный proxy")],
      ["external_proxy", t("Внешний proxy · нужен внешний action")],
    ]
      .map(
        ([id, label]) =>
          html`<option value="${id}" ${selected(id, config.access_mode)}>${t(label)}</option>`,
      )
      .join(
        "",
      )}</select></label>${field(ctx, t("Доверенные proxy · IPv4 / CIDR"), "trusted_proxies", config.trusted_proxies.join(", "))}</div>${note(t("Для proxy укажите его адрес явно и настройте перезапись X-Forwarded-For. SSH-туннель скрывает исходный IP; loopback не блокируется. IPv6 этим модулем не защищается."), ctx)}<button class="primary" type="button" data-action="f2b-save">Сохранить в черновик</button></fieldset></form><div class="feature-heading"><h2>Ручные профили</h2><button data-action="f2b-edit" ${disabled}>${ctx.icon("plus")}Добавить вручную</button></div><div class="table-scroll"><table class="rules-table"><thead><tr><th>Профиль</th><th>Сервис</th><th>Порты</th><th>Порог</th><th>Окно / бан</th><th>Состояние</th><th></th></tr></thead><tbody>${config.profiles.map((item) => html`<tr><td>${ctx.e(item.name)}<small class="cell-note mono">f2b_${ctx.e(item.id)}</small></td><td>${ctx.e(item.service)} · ${ctx.e(item.chain)}</td><td>${ctx.e(item.ports.join(", "))}</td><td>${item.max_retry}</td><td>${item.find_time} / ${item.ban_time} с</td><td>${!config.enabled ? t("Ручные профили выключены") : item.enabled ? t("Включён в черновике") : t("Выключен")}</td><td><button data-action="f2b-edit" data-id="${ctx.e(item.id)}">${ctx.icon("edit")}Открыть</button></td></tr>`).join("")}</tbody></table></div>${note(t("Ручные профили — для отдельной защиты Web / SSH роутера. Их выключатель не отключает защиту, включённую в NAT / Filter Rules. Изменения начинают работать после применения общего черновика."), ctx)}<h2>Активные блокировки</h2>${filterBuilder(ctx, "fail2ban")}<div id="protection-results">${bansMarkup(ctx)}</div>${attribution()}</div>`;
  }
  return html`<div class="feature-page protection-page"><div id="protection-status">${statusMarkup(ctx, view)}</div><form id="geo-settings" class="security-settings" data-revision="${ctx.state.revision}"><fieldset ${disabled}><legend>Обновление базы</legend>${toggle(ctx, t("Проверять новые выпуски автоматически"), "auto_update", ctx.state.config.geoip.auto_update)}<div class="security-form-grid">${field(ctx, t("Интервал проверки · часы"), "check_hours", ctx.state.config.geoip.check_hours, "number", 'min="6" max="720"')}</div><div class="security-actions"><button class="primary" type="button" data-action="geo-save">Сохранить в черновик</button><button type="button" data-action="geo-update">${ctx.icon("download")}Загрузить / обновить базу</button></div></fieldset></form><form id="geo-lookup" class="security-search">${field(ctx, t("Определить страну IPv4"), "address", "", "text", 'placeholder="1.1.1.1" maxlength="15" required')}<button type="submit" data-action="geo-lookup">Проверить IP</button></form><div id="geo-lookup-result" aria-live="polite">${lookup ? note(`${lookup.address || lookup.ip}: ${lookup.country || t("не определена")} · ${lookup.reason || t("данные поставщика")}`, ctx) : ""}</div>${note(t("Страна определяется по IP, а не по местоположению человека. VPN и proxy влияют на результат. Страновое условие NAT выбирает трансляцию; само по себе оно не блокирует доступ."), ctx)}<h2>Страновые списки</h2>${filterBuilder(ctx, "geoip")}<div id="protection-results">${countryMarkup(ctx)}</div>${attribution()}</div>`;
}
export function renderSystemLists(ctx) {
  return html`<section class="system-lists"><div class="feature-heading"><div><h2>Системные списки</h2><p>Управляются GeoIP и Fail2ban. Пустые временные списки остаются доступными для правил.</p></div><button data-action="protection-refresh">${ctx.icon("refresh")}Обновить</button></div><div id="system-lists-results">${systemListsMarkup(ctx)}</div>${attribution()}</section>`;
}
function systemListsMarkup(ctx) {
  if (errors.lists)
    return html`<div class="connection-error">${ctx.e(errors.lists)}</div>`;
  const rows = snapshots.lists?.items || ctx.state.config.system_lists || [];
  return html`<div class="table-scroll"><table class="rules-table"><thead><tr><th>Список</th><th>Тип</th><th>Источник</th><th>Записи</th><th></th></tr></thead><tbody>${rows.map((row) => html`<tr><td class="mono">${ctx.e(row.name)}</td><td>${row.kind === "country" ? t("Страновой") : t("Временный")}</td><td>${ctx.e(row.country || row.profile || "—")}</td><td>${ctx.e(row.count ?? "—")}</td><td><button data-action="system-list-open" data-name="${ctx.e(row.name)}">Просмотр</button>${row.kind === "country" && (ctx.state.config.system_lists || []).some((item) => item.name === row.name) ? html`<button data-action="system-list-remove" data-name="${ctx.e(row.name)}" ${readonly(ctx) ? "disabled" : ""}>Убрать</button>` : ""}</td></tr>`).join("") || html`<tr><td colspan="5" class="users-empty">Добавьте страну в GeoIP или настройте профиль Fail2ban.</td></tr>`}</tbody></table></div>`;
}
export async function refreshProtection(ctx, { force = false } = {}) {
  const kind = ["fail2ban", "geoip", "lists"].find((id) =>
    ctx.isCurrentView(id),
  );
  if (!kind) return;
  if (!force && request && requestKind === kind) return request;
  controller?.abort();
  const active = new AbortController();
  controller = active;
  requestKind = kind;
  const query = new URLSearchParams({
    offset: String(offsets[kind]),
    limit: String(pageSize),
  });
  const expression = getAppliedExpression(`protection-${kind}`);
  if (expression) query.set("expression", expression);
  const generation = ctx.generation;
  const operation = (async () => {
    try {
      const options = {
        signal: AbortSignal.any([active.signal, AbortSignal.timeout(15000)]),
      };
      let result;
      if (kind === "lists") result = await ctx.api("security/lists", options);
      else {
        const [status, rows] = await Promise.all([
          ctx.api(`security/${kind}`, options),
          ctx.api(
            `security/${kind}/${kind === "geoip" ? "countries" : "bans"}?${query}`,
            options,
          ),
        ]);
        result = { status, [kind === "geoip" ? "countries" : "bans"]: rows };
      }
      if (active.signal.aborted || generation !== ctx.getGeneration()) return;
      snapshots[kind] = result;
      errors[kind] = "";
    } catch (error) {
      if (!active.signal.aborted && generation === ctx.getGeneration())
        errors[kind] = error.message;
    } finally {
      if (request === operation) request = null;
      if (
        !active.signal.aborted &&
        generation === ctx.getGeneration() &&
        ctx.isCurrentView(kind)
      ) {
        const status = document.querySelector("#protection-status");
        if (status) status.innerHTML = statusMarkup(ctx, kind);
        const result = document.querySelector(
          kind === "lists" ? "#system-lists-results" : "#protection-results",
        );
        if (result)
          result.innerHTML =
            kind === "lists"
              ? systemListsMarkup(ctx)
              : kind === "geoip"
                ? countryMarkup(ctx)
                : bansMarkup(ctx);
      }
    }
  })();
  request = operation;
  return operation;
}
function openProfile(ctx, id) {
  editedProfile = structuredClone(
    ctx.state.config.fail2ban.profiles.find((item) => item.id === id) || {
      id: "",
      name: "",
      service: "web",
      enabled: false,
      chain: "input",
      ports: [8088],
      in_interface: "",
      destination: "",
      max_retry: 5,
      find_time: 600,
      ban_time: 900,
      ignore_addresses: [],
      include_countries: [],
      exclude_countries: [],
      shared_listener: false,
    },
  );
  editorRevision = ctx.state.revision;
  const p = editedProfile;
  ctx.dialogFrame(
    t("Профиль Fail2ban"),
    t("Настройки сохраняются в общий черновик."),
    html`<form id="f2b-profile-form" class="winbox-form"><div class="security-form-grid">${field(ctx, t("ID профиля"), "id", p.id, "text", `required pattern="[a-z][a-z0-9_]{0,19}" maxlength="20" ${id ? "readonly" : ""}`)}${field(ctx, t("Название"), "name", p.name, "text", 'required maxlength="80"')}<label class="field"><span>Сервис</span><select name="service"><option value="web" ${selected("web", p.service)}>Вход в Web + 2FA</option><option value="ssh" ${selected("ssh", p.service)}>SSH этого узла</option></select></label><label class="field"><span>Цепочка</span><select name="chain"><option value="input" ${selected("input", p.chain)}>input</option><option value="forward" ${selected("forward", p.chain)}>forward</option></select></label>${field(ctx, t("TCP-порты listener"), "ports", p.ports.join(", "), "text", "required")}${field(ctx, t("Входной интерфейс · пусто = любой"), "in_interface", p.in_interface, "text", 'maxlength="15"')}${field(ctx, t("Адрес назначения · IPv4 / CIDR"), "destination", p.destination)}${field(ctx, t("Ошибок до бана"), "max_retry", p.max_retry, "number", 'min="1" max="100" required')}${field(ctx, t("Окно подсчёта · секунды"), "find_time", p.find_time, "number", 'min="10" max="86400" required')}${field(ctx, t("Время бана · секунды"), "ban_time", p.ban_time, "number", 'min="1" max="2147483" required')}${field(ctx, t("Исключения · IPv4 / CIDR"), "ignore_addresses", p.ignore_addresses.join(", "))}${field(ctx, t("Только страны · коды через запятую"), "include_countries", p.include_countries.join(", "))}${field(ctx, t("Исключить страны"), "exclude_countries", p.exclude_countries.join(", "))}</div>${toggle(ctx, t("Профиль включён"), "enabled", p.enabled)}${toggle(ctx, t("Listener используется несколькими сайтами"), "shared_listener", p.shared_listener)}${note(t("На общем listener блокировка IP/порта затронет все сайты. Для защиты отдельного сайта нужен выделенный listener. SSH-профиль читает журнал этого узла."), ctx)}</form>`,
    html`<button data-action="close">Отмена</button>${id ? html`<button data-action="f2b-remove" class="danger" ${readonly(ctx) ? "disabled" : ""}>Удалить</button>` : ""}<button data-action="f2b-profile-save" class="primary" ${readonly(ctx) ? "disabled" : ""}>Сохранить</button>`,
  );
}
export function handleProtectionInput(event) {
  const form = event.target?.closest?.("#f2b-settings,#geo-settings");
  if (!form) return false;
  form.dataset.dirty = "true";
  return true;
}
export async function handleProtectionAction(button, ctx) {
  const action = button.dataset.action;
  const generation = ctx.generation;
  if (!/^(f2b-|geo-|protection-|system-list-)/.test(action || "")) return false;
  await ctx.run(async () => {
    if (action === "f2b-edit") {
      openProfile(ctx, button.dataset.id);
      return;
    }
    if (
      ["protection-refresh", "protection-search", "protection-page"].includes(
        action,
      )
    ) {
      if (action === "protection-search") {
        const kind = button.dataset.kind;
        if (!searchKinds.includes(kind)) return;
        applyQueryBuilder(`protection-${kind}`);
        offsets[kind] = 0;
      }
      if (action === "protection-page")
        offsets[button.dataset.kind] = Number(button.dataset.offset);
      await refreshProtection(ctx, { force: true });
      return;
    }
    if (action === "geo-lookup") {
      const form = document.querySelector("#geo-lookup");
      if (!form.reportValidity()) return;
      const address = new FormData(form).get("address");
      const result = await ctx.api(
        `security/geoip/lookup?address=${encodeURIComponent(address)}`,
      );
      if (generation !== ctx.getGeneration() || !ctx.isCurrentView("geoip"))
        return;
      lookup = result;
      const region = document.querySelector("#geo-lookup-result");
      if (region)
        region.innerHTML = note(
          `${lookup.address || address}: ${lookup.country || t("не определена")} · ${lookup.reason || t("данные поставщика")}`,
          ctx,
        );
      return;
    }
    if (
      ["system-list-open", "system-list-page", "system-list-search"].includes(
        action,
      )
    ) {
      if (action === "system-list-open") {
        resetQueryBuilder("system-list");
        inspectedList = { name: button.dataset.name, offset: 0 };
      }
      if (action === "system-list-page")
        inspectedList.offset = Number(button.dataset.offset);
      if (action === "system-list-search") {
        applyQueryBuilder("system-list");
        inspectedList.offset = 0;
      }
      const query = new URLSearchParams({
        offset: String(inspectedList.offset),
        limit: "50",
      });
      const expression = getAppliedExpression("system-list");
      if (expression) query.set("expression", expression);
      const data = await ctx.api(
        `security/lists/${encodeURIComponent(inspectedList.name)}?${query}`,
      );
      if (generation !== ctx.getGeneration() || !ctx.isCurrentView("lists"))
        return;
      if (action !== "system-list-open" && !ctx.dialog.open) return;
      ctx.dialogFrame(
        inspectedList.name,
        `${data.source || "Fail2ban"} · ${data.version || t("Временные записи")}`,
        html`${renderQueryBuilder("system-list", systemListQuerySchema(inspectedList.name), { applyAction: "system-list-search" })}<div class="table-scroll"><table class="rules-table"><thead><tr><th>Адрес / диапазон</th><th>Истекает</th></tr></thead><tbody>${data.items.map((row) => html`<tr><td class="mono">${ctx.e(typeof row === "string" ? row : row.address || row.network || `${row.first} – ${row.last}`)}</td><td>${ctx.e(when(row.expires_at))}</td></tr>`).join("") || html`<tr><td colspan="2">Список пуст.</td></tr>`}</tbody></table></div><div class="security-pagination"><span>Всего: ${data.total}</span><button data-action="system-list-page" data-offset="${Math.max(0, inspectedList.offset - 50)}" ${inspectedList.offset ? "" : "disabled"}>Назад</button><button data-action="system-list-page" data-offset="${inspectedList.offset + 50}" ${inspectedList.offset + 50 < data.total ? "" : "disabled"}>Далее</button></div>${attribution()}`,
      );
      return;
    }
    if (!ctx.canWrite()) throw new Error(t("Нужна группа full."));
    if (action === "geo-update" || action === "f2b-unban") {
      pendingOperation =
        action === "geo-update"
          ? { path: "security/geoip/update", body: {} }
          : {
              path: "security/fail2ban/unban",
              body: {
                profile: button.dataset.profile,
                address: button.dataset.address,
              },
            };
      ctx.dialogFrame(
        action === "geo-update" ? t("Обновить GeoIP") : t("Снять блокировку"),
        t("Подтвердите действие."),
        ctx.state.auth_enabled
          ? proofForm(
              ctx,
              "protection-proof",
              t("Потребуется текущий пароль и код 2FA, если он включён."),
            )
          : html`<p>Операция будет выполнена в деморежиме.</p>`,
        html`<button data-action="close">Отмена</button><button class="primary" data-action="protection-confirm">Подтвердить</button>`,
      );
      return;
    }
    if (action === "protection-confirm") {
      if (!pendingOperation) return;
      const credentials = ctx.state.auth_enabled
        ? proof(ctx, "protection-proof")
        : null;
      if (ctx.state.auth_enabled && !credentials) return;
      await ctx.api(pendingOperation.path, {
        method: "POST",
        body: JSON.stringify({ ...pendingOperation.body, proof: credentials }),
      });
      clearProof(ctx);
      pendingOperation = null;
      ctx.dialog.close();
      await refreshProtection(ctx, { force: true });
      ctx.toast(t("Операция принята"));
      return;
    }
    const config = structuredClone(ctx.state.config);
    let revision = ctx.state.revision;
    if (action === "f2b-save" || action === "geo-save") {
      const form = document.querySelector(
        action === "f2b-save" ? "#f2b-settings" : "#geo-settings",
      );
      if (!form.reportValidity()) return;
      const values = new FormData(form);
      revision = Number(form.dataset.revision);
      if (action === "f2b-save")
        Object.assign(config.fail2ban, {
          enabled: values.has("enabled"),
          access_mode: String(values.get("access_mode")),
          trusted_proxies: split(values.get("trusted_proxies")),
        });
      else
        Object.assign(config.geoip, {
          auto_update: values.has("auto_update"),
          check_hours: Number(values.get("check_hours")),
        });
    } else if (action === "f2b-profile-save" || action === "f2b-remove") {
      if (!editedProfile) return;
      revision = editorRevision;
      const form = ctx.dialog.querySelector("#f2b-profile-form");
      if (action !== "f2b-remove" && !form.reportValidity()) return;
      config.fail2ban.profiles = config.fail2ban.profiles.filter(
        (item) => item.id !== editedProfile.id,
      );
      if (action !== "f2b-remove") {
        const values = new FormData(form);
        const p = { ...editedProfile };
        for (const key of [
          "id",
          "name",
          "service",
          "chain",
          "in_interface",
          "destination",
        ])
          p[key] = String(values.get(key) || "").trim();
        for (const key of ["max_retry", "find_time", "ban_time"])
          p[key] = Number(values.get(key));
        p.ports = split(values.get("ports")).map(Number);
        for (const key of [
          "ignore_addresses",
          "include_countries",
          "exclude_countries",
        ])
          p[key] = split(values.get(key));
        p.include_countries = p.include_countries.map((s) => s.toUpperCase());
        p.exclude_countries = p.exclude_countries.map((s) => s.toUpperCase());
        p.enabled = values.has("enabled");
        p.shared_listener = values.has("shared_listener");
        config.fail2ban.profiles.push(p);
      }
    } else if (action === "geo-register") {
      const country = button.dataset.country;
      config.system_lists ||= [];
      if (!config.system_lists.some((item) => item.name === `geo_${country}`))
        config.system_lists.push({
          name: `geo_${country}`,
          kind: "country",
          country,
          profile: "",
        });
    } else if (action === "system-list-remove") {
      config.system_lists = config.system_lists.filter(
        (item) => item.name !== button.dataset.name,
      );
    } else return;
    await ctx.saveConfig(config, revision);
    if (action === "f2b-profile-save" || action === "f2b-remove")
      ctx.dialog.close();
    ctx.toast(t("Сохранено в черновик. Проверьте и примените настройки."));
  });
  return true;
}

export function addressListChoices(config) {
  const names = new Set((config.address_lists || []).map((item) => item.name));
  for (const item of config.system_lists || []) names.add(item.name);
  for (const rule of [
    ...(config.rules || []),
    ...(config.filter_rules || []),
  ]) {
    for (const code of [rule.src_country, rule.dst_country])
      if (code) names.add(`geo_${code}`);
  }
  for (const profile of config.fail2ban?.profiles || []) {
    names.add(`f2b_${profile.id}`);
    for (const code of [
      ...(profile.include_countries || []),
      ...(profile.exclude_countries || []),
    ])
      names.add(`geo_${code}`);
  }
  return [...names].map((name) => [name, name]);
}
export function renderF2BRuleSummary(ctx) {
  const config = ctx.state.config.fail2ban;
  const inline = inlineProfiles(ctx).length
    ? html`<div class="system-firewall">${renderInlineProtection(ctx)}</div>`
    : "";
  if (!config?.enabled) return inline;
  return (
    inline +
    html`<div class="system-firewall"><div class="feature-heading"><h3>OMR_F2B <span class="status-tag">Управляется Fail2ban</span></h3><button data-action="view" data-view="fail2ban">Настроить</button></div>${note(t("Системная цепочка проверяется перед обычными правилами. Неподходящий трафик возвращается к обычной обработке."), ctx)}<div class="table-scroll"><table class="rules-table"><thead><tr><th>Профиль</th><th>Направление</th><th>Источник</th><th>Интерфейс / назначение</th><th>TCP-порты</th><th>Действие</th><th>Пакеты / байты</th></tr></thead><tbody>${config.profiles
      .filter((p) => p.enabled)
      .map(
        (p) =>
          html`<tr><td>${ctx.e(p.name)}</td><td>${ctx.e(p.chain)}</td><td class="mono">f2b_${ctx.e(p.id)}</td><td>${ctx.e(p.in_interface || "any")} / ${ctx.e(p.destination || "any")}</td><td>${ctx.e(p.ports.join(", "))}</td><td>DROP</td><td>${ctx.e(ctx.statistics?.[`f2b:${p.id}`]?.packets ?? "—")} / ${ctx.e(ctx.statistics?.[`f2b:${p.id}`]?.bytes ?? "—")}</td></tr>`,
      )
      .join("")}</tbody></table></div></div>`
  );
}
