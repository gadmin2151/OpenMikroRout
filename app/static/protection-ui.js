/** Security configuration shares the router draft; operational data stays on the server. */
import { proofForm, proof, clearProof } from "./security-ui.js";

export const protectionViews = {
  fail2ban: [
    "Fail2ban",
    "Защита входа, временные блокировки и исключения · IPv4.",
  ],
  geoip: [
    "GeoIP",
    "Локальная база стран и системные списки для Firewall и NAT.",
  ],
};
let snapshots = {},
  errors = {},
  request = null,
  controller = null,
  requestKind = null;
let queries = { fail2ban: "", geoip: "", lists: "" };
let offsets = { fail2ban: 0, geoip: 0, lists: 0 };
let lookup = null;
let editedProfile = null;
let editorRevision = null;
let pendingOperation = null;
let inspectedList = { name: "", offset: 0, query: "" };
const pageSize = 50;
const split = (text) =>
  String(text || "")
    .split(/[\s,;]+/)
    .filter(Boolean);
const when = (stamp) =>
  stamp ? new Date(stamp * 1000).toLocaleString("ru-RU") : "—";
const selected = (value, current) => (value === current ? "selected" : "");
const checked = (value) => (value ? "checked" : "");
function readonly(ctx) {
  return !ctx.canWrite() || ctx.offline || !!ctx.state.pending;
}
function note(text, ctx) {
  return `<p class="feature-note">${ctx.e(text)}</p>`;
}
const attribution =
  '<p class="feature-note">IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a> · Country Lite · CC BY 4.0</p>';
function field(ctx, label, name, value, type = "text", extra = "") {
  return `<label class="field"><span>${ctx.e(label)}</span><input name="${name}" type="${type}" value="${ctx.e(value)}" ${extra}></label>`;
}
function toggle(ctx, label, name, value) {
  return `<label class="checkbox-label"><input type="checkbox" name="${name}" ${checked(value)}>${ctx.e(label)}</label>`;
}
function pager(ctx, kind, total) {
  const offset = offsets[kind] || 0;
  return `<div class="security-pagination"><span>${total ? `${offset + 1}–${Math.min(offset + pageSize, total)} из ${total}` : "0 записей"}</span><button data-action="protection-page" data-kind="${kind}" data-offset="${Math.max(0, offset - pageSize)}" ${offset ? "" : "disabled"}>Назад</button><button data-action="protection-page" data-kind="${kind}" data-offset="${offset + pageSize}" ${offset + pageSize < total ? "" : "disabled"}>Далее</button></div>`;
}
function searchForm(ctx, kind, hint) {
  return `<form class="security-search" data-protection-search="${kind}"><label class="field"><span>Поиск</span><input name="query" value="${ctx.e(queries[kind])}" placeholder="${ctx.e(hint)}" maxlength="100"></label><button type="submit" data-action="protection-search" data-kind="${kind}">${ctx.icon("search")}Найти</button><button type="button" data-action="protection-refresh">${ctx.icon("refresh")}Обновить</button></form>`;
}
export function resetProtection() {
  controller?.abort();
  snapshots = {};
  errors = {};
  request = null;
  controller = null;
  requestKind = null;
  queries = { fail2ban: "", geoip: "", lists: "" };
  offsets = { fail2ban: 0, geoip: 0, lists: 0 };
  lookup = null;
  editedProfile = null;
  editorRevision = null;
  pendingOperation = null;
  inspectedList = { name: "", offset: 0, query: "" };
}
function statusMarkup(ctx, kind) {
  if (errors[kind])
    return `<div class="connection-error" role="alert">${ctx.e(errors[kind])}</div>`;
  const status = snapshots[kind]?.status;
  if (!status)
    return '<div class="security-status" role="status">Загрузка состояния…</div>';
  if (kind === "fail2ban")
    return `<div class="security-status"><strong>${status.demo ? "Деморежим" : status.effective ? "Защита активна" : status.enabled ? "Защита требует настройки" : "Защита выключена"}</strong><span>IPv4 · ${ctx.e(status.access_mode || "direct")}</span></div>${(status.warnings || []).map((warning) => note(warning, ctx)).join("")}${status.error ? `<div class="connection-error">${ctx.e(status.error)}</div>` : ""}`;
  return `<div class="security-status"><strong>${ctx.e(status.version || status.active_version || "База ещё не загружена")}</strong><span>${status.demo ? "DEMO · учебная выборка" : "DB-IP Country Lite"}</span></div>${note(`Последняя проверка: ${when(status.last_check || status.checked_at)}. ${status.updating ? "Загрузка и проверка базы…" : "Определение страны работает локально."}`, ctx)}${status.error ? `<div class="connection-error">${ctx.e(status.error)}</div>` : ""}`;
}
function bansMarkup(ctx) {
  const data = snapshots.fail2ban?.bans;
  if (!data) return '<div class="empty">Загружаем блокировки…</div>';
  const rows = data.items
    .map(
      (row) =>
        `<tr><td class="mono">${ctx.e(row.address)}</td><td>${ctx.e(row.profile)}</td><td>${ctx.e(row.country || "—")}</td><td>${ctx.e(row.source)}</td><td>${ctx.e(when(row.added_at))}</td><td>${ctx.e(when(row.expires_at))}<small class="cell-note">${Math.max(0, Math.ceil(row.remaining_seconds))} с осталось</small></td><td>${row.kernel_present ? "В ядре" : "Ожидает синхронизации"}</td><td><button data-action="f2b-unban" data-profile="${ctx.e(row.profile)}" data-address="${ctx.e(row.address)}" ${readonly(ctx) ? "disabled" : ""}>Разблокировать</button></td></tr>`,
    )
    .join("");
  return `<div class="table-scroll"><table class="rules-table"><thead><tr><th>IPv4</th><th>Профиль</th><th>Страна</th><th>Источник</th><th>Добавлен</th><th>Истекает</th><th>Исполнение</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="8" class="users-empty">Активных блокировок нет.</td></tr>'}</tbody></table></div>${pager(ctx, "fail2ban", data.total)}`;
}
function countryMarkup(ctx) {
  const data = snapshots.geoip?.countries;
  if (!data) return '<div class="empty">Загружаем список стран…</div>';
  const registered = new Set(
    (ctx.state.config.system_lists || []).map((list) => list.name),
  );
  return `<div class="table-scroll"><table class="rules-table"><thead><tr><th>Страна</th><th>Список</th><th>Подсети</th><th></th></tr></thead><tbody>${
    data.items
      .map((row) => {
        const code = row.country || row.code;
        return `<tr><td>${ctx.e(code)}</td><td class="mono">geo_${ctx.e(code)}</td><td>${ctx.e(row.networks ?? row.count ?? row.ranges ?? "—")}</td><td><button data-action="geo-register" data-country="${ctx.e(code)}" ${readonly(ctx) || registered.has(`geo_${code}`) ? "disabled" : ""}>${registered.has(`geo_${code}`) ? "В черновике" : "Добавить список"}</button></td></tr>`;
      })
      .join("") ||
    '<tr><td colspan="4" class="users-empty">Загрузите базу или измените поиск.</td></tr>'
  }</tbody></table></div>${pager(ctx, "geoip", data.total)}`;
}
export function renderProtection(view, ctx) {
  const disabled = readonly(ctx) ? "disabled" : "";
  if (view === "fail2ban") {
    const config = ctx.state.config.fail2ban;
    return `<div class="feature-page protection-page"><div id="protection-status">${statusMarkup(ctx, view)}</div><form id="f2b-settings" class="security-settings" data-revision="${ctx.state.revision}"><fieldset ${disabled}><legend>Доступ к защищаемому сервису</legend>${toggle(ctx, "Включить Fail2ban", "enabled", config.enabled)}<div class="security-form-grid"><label class="field"><span>Способ подключения</span><select name="access_mode">${[
      ["direct", "Прямое подключение"],
      ["local_proxy", "Локальный доверенный proxy"],
      ["external_proxy", "Внешний proxy · нужен внешний action"],
    ]
      .map(
        ([id, label]) =>
          `<option value="${id}" ${selected(id, config.access_mode)}>${label}</option>`,
      )
      .join(
        "",
      )}</select></label>${field(ctx, "Доверенные proxy · IPv4 / CIDR", "trusted_proxies", config.trusted_proxies.join(", "))}</div>${note("Для proxy укажите его адрес явно и настройте перезапись X-Forwarded-For. SSH-туннель скрывает исходный IP; loopback не блокируется. IPv6 этим модулем не защищается.", ctx)}<button class="primary" type="button" data-action="f2b-save">Сохранить в черновик</button></fieldset></form><div class="feature-heading"><h2>Профили защиты</h2><button data-action="f2b-edit" ${disabled}>${ctx.icon("plus")}Добавить профиль</button></div><div class="table-scroll"><table class="rules-table"><thead><tr><th>Профиль</th><th>Сервис</th><th>Порты</th><th>Порог</th><th>Окно / бан</th><th>Состояние</th><th></th></tr></thead><tbody>${config.profiles.map((item) => `<tr><td>${ctx.e(item.name)}<small class="cell-note mono">f2b_${ctx.e(item.id)}</small></td><td>${ctx.e(item.service)} · ${ctx.e(item.chain)}</td><td>${ctx.e(item.ports.join(", "))}</td><td>${item.max_retry}</td><td>${item.find_time} / ${item.ban_time} с</td><td>${item.enabled ? "Включён" : "Выключен"}</td><td><button data-action="f2b-edit" data-id="${ctx.e(item.id)}">${ctx.icon("edit")}Открыть</button></td></tr>`).join("")}</tbody></table></div>${note("Профили начинают работать после применения общего черновика. Бан относится только к выбранным адресам, интерфейсам и TCP-портам.", ctx)}<h2>Активные блокировки</h2>${searchForm(ctx, "fail2ban", "IP или профиль")}<div id="protection-results">${bansMarkup(ctx)}</div>${attribution}</div>`;
  }
  return `<div class="feature-page protection-page"><div id="protection-status">${statusMarkup(ctx, view)}</div><form id="geo-settings" class="security-settings" data-revision="${ctx.state.revision}"><fieldset ${disabled}><legend>Обновление базы</legend>${toggle(ctx, "Проверять новые выпуски автоматически", "auto_update", ctx.state.config.geoip.auto_update)}<div class="security-form-grid">${field(ctx, "Интервал проверки · часы", "check_hours", ctx.state.config.geoip.check_hours, "number", 'min="6" max="720"')}</div><div class="security-actions"><button class="primary" type="button" data-action="geo-save">Сохранить в черновик</button><button type="button" data-action="geo-update">${ctx.icon("download")}Загрузить / обновить базу</button></div></fieldset></form><form id="geo-lookup" class="security-search">${field(ctx, "Определить страну IPv4", "address", "", "text", 'placeholder="1.1.1.1" maxlength="15" required')}<button type="submit" data-action="geo-lookup">Проверить IP</button></form><div id="geo-lookup-result" aria-live="polite">${lookup ? note(`${lookup.address || lookup.ip}: ${lookup.country || "не определена"} · ${lookup.reason || "данные поставщика"}`, ctx) : ""}</div>${note("Страна определяется по IP, а не по местоположению человека. VPN и proxy влияют на результат. Страновое условие NAT выбирает трансляцию; само по себе оно не блокирует доступ.", ctx)}<h2>Страновые списки</h2>${searchForm(ctx, "geoip", "Код страны: MD, RO, DE…")}<div id="protection-results">${countryMarkup(ctx)}</div>${attribution}</div>`;
}
export function renderSystemLists(ctx) {
  return `<section class="system-lists"><div class="feature-heading"><div><h2>Системные списки</h2><p>Управляются GeoIP и Fail2ban. Пустые временные списки остаются доступными для правил.</p></div><button data-action="protection-refresh">${ctx.icon("refresh")}Обновить</button></div><div id="system-lists-results">${systemListsMarkup(ctx)}</div>${attribution}</section>`;
}
function systemListsMarkup(ctx) {
  if (errors.lists)
    return `<div class="connection-error">${ctx.e(errors.lists)}</div>`;
  const rows = snapshots.lists?.items || ctx.state.config.system_lists || [];
  return `<div class="table-scroll"><table class="rules-table"><thead><tr><th>Список</th><th>Тип</th><th>Источник</th><th>Записи</th><th></th></tr></thead><tbody>${rows.map((row) => `<tr><td class="mono">${ctx.e(row.name)}</td><td>${row.kind === "country" ? "Страновой" : "Временный"}</td><td>${ctx.e(row.country || row.profile || "—")}</td><td>${ctx.e(row.count ?? "—")}</td><td><button data-action="system-list-open" data-name="${ctx.e(row.name)}">Просмотр</button>${row.kind === "country" && (ctx.state.config.system_lists || []).some((item) => item.name === row.name) ? `<button data-action="system-list-remove" data-name="${ctx.e(row.name)}" ${readonly(ctx) ? "disabled" : ""}>Убрать</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="users-empty">Добавьте страну в GeoIP или настройте профиль Fail2ban.</td></tr>'}</tbody></table></div>`;
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
    query: queries[kind],
    offset: String(offsets[kind]),
    limit: String(pageSize),
  });
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
    "Профиль Fail2ban",
    "Настройки сохраняются в общий черновик.",
    `<form id="f2b-profile-form" class="winbox-form"><div class="security-form-grid">${field(ctx, "ID профиля", "id", p.id, "text", `required pattern="[a-z][a-z0-9_]{0,19}" maxlength="20" ${id ? "readonly" : ""}`)}${field(ctx, "Название", "name", p.name, "text", 'required maxlength="80"')}<label class="field"><span>Сервис</span><select name="service"><option value="web" ${selected("web", p.service)}>Вход в Web + 2FA</option><option value="ssh" ${selected("ssh", p.service)}>SSH этого узла</option></select></label><label class="field"><span>Цепочка</span><select name="chain"><option value="input" ${selected("input", p.chain)}>input</option><option value="forward" ${selected("forward", p.chain)}>forward</option></select></label>${field(ctx, "TCP-порты listener", "ports", p.ports.join(", "), "text", "required")}${field(ctx, "Входной интерфейс · пусто = любой", "in_interface", p.in_interface, "text", 'maxlength="15"')}${field(ctx, "Адрес назначения · IPv4 / CIDR", "destination", p.destination)}${field(ctx, "Ошибок до бана", "max_retry", p.max_retry, "number", 'min="1" max="100" required')}${field(ctx, "Окно подсчёта · секунды", "find_time", p.find_time, "number", 'min="10" max="86400" required')}${field(ctx, "Время бана · секунды", "ban_time", p.ban_time, "number", 'min="1" max="2147483" required')}${field(ctx, "Исключения · IPv4 / CIDR", "ignore_addresses", p.ignore_addresses.join(", "))}${field(ctx, "Только страны · коды через запятую", "include_countries", p.include_countries.join(", "))}${field(ctx, "Исключить страны", "exclude_countries", p.exclude_countries.join(", "))}</div>${toggle(ctx, "Профиль включён", "enabled", p.enabled)}${toggle(ctx, "Listener используется несколькими сайтами", "shared_listener", p.shared_listener)}${note("На общем listener блокировка IP/порта затронет все сайты. Для защиты отдельного сайта нужен выделенный listener. SSH-профиль читает журнал этого узла.", ctx)}</form>`,
    `<button data-action="close">Отмена</button>${id ? `<button data-action="f2b-remove" class="danger" ${readonly(ctx) ? "disabled" : ""}>Удалить</button>` : ""}<button data-action="f2b-profile-save" class="primary" ${readonly(ctx) ? "disabled" : ""}>Сохранить</button>`,
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
        queries[kind] = String(
          new FormData(button.closest("form")).get("query") || "",
        );
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
          `${lookup.address || address}: ${lookup.country || "не определена"} · ${lookup.reason || "данные поставщика"}`,
          ctx,
        );
      return;
    }
    if (
      ["system-list-open", "system-list-page", "system-list-search"].includes(
        action,
      )
    ) {
      if (action === "system-list-open")
        inspectedList = { name: button.dataset.name, offset: 0, query: "" };
      if (action === "system-list-page")
        inspectedList.offset = Number(button.dataset.offset);
      if (action === "system-list-search") {
        inspectedList.query = String(
          new FormData(ctx.dialog.querySelector("#system-list-search")).get(
            "query",
          ) || "",
        );
        inspectedList.offset = 0;
      }
      const query = new URLSearchParams({
        offset: String(inspectedList.offset),
        limit: "50",
        query: inspectedList.query,
      });
      const data = await ctx.api(
        `security/lists/${encodeURIComponent(inspectedList.name)}?${query}`,
      );
      if (generation !== ctx.getGeneration() || !ctx.isCurrentView("lists"))
        return;
      if (action !== "system-list-open" && !ctx.dialog.open) return;
      ctx.dialogFrame(
        inspectedList.name,
        `${data.source || "Fail2ban"} · ${data.version || "Временные записи"}`,
        `<form id="system-list-search" class="security-search">${field(ctx, "Поиск IPv4 / CIDR", "query", inspectedList.query)}<button type="submit" data-action="system-list-search">Найти</button></form><div class="table-scroll"><table class="rules-table"><thead><tr><th>Адрес / диапазон</th><th>Истекает</th></tr></thead><tbody>${data.items.map((row) => `<tr><td class="mono">${ctx.e(typeof row === "string" ? row : row.address || row.network || `${row.first} – ${row.last}`)}</td><td>${ctx.e(when(row.expires_at))}</td></tr>`).join("") || '<tr><td colspan="2">Список пуст.</td></tr>'}</tbody></table></div><div class="security-pagination"><span>Всего: ${data.total}</span><button data-action="system-list-page" data-offset="${Math.max(0, inspectedList.offset - 50)}" ${inspectedList.offset ? "" : "disabled"}>Назад</button><button data-action="system-list-page" data-offset="${inspectedList.offset + 50}" ${inspectedList.offset + 50 < data.total ? "" : "disabled"}>Далее</button></div>${attribution}`,
      );
      return;
    }
    if (!ctx.canWrite()) throw new Error("Нужна группа full.");
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
        action === "geo-update" ? "Обновить GeoIP" : "Снять блокировку",
        "Подтвердите действие.",
        ctx.state.auth_enabled
          ? proofForm(
              ctx,
              "protection-proof",
              "Потребуется текущий пароль и код 2FA, если он включён.",
            )
          : "<p>Операция будет выполнена в деморежиме.</p>",
        '<button data-action="close">Отмена</button><button class="primary" data-action="protection-confirm">Подтвердить</button>',
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
      ctx.toast("Операция принята");
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
    ctx.toast("Сохранено в черновик. Проверьте и примените настройки.");
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
  if (!config?.enabled) return "";
  return `<div class="system-firewall"><div class="feature-heading"><h3>OMR_F2B <span class="status-tag">Управляется Fail2ban</span></h3><button data-action="view" data-view="fail2ban">Настроить</button></div>${note("Системная цепочка проверяется перед обычными правилами. Неподходящий трафик возвращается к обычной обработке.", ctx)}<div class="table-scroll"><table class="rules-table"><thead><tr><th>Профиль</th><th>Направление</th><th>Источник</th><th>Интерфейс / назначение</th><th>TCP-порты</th><th>Действие</th><th>Пакеты / байты</th></tr></thead><tbody>${config.profiles
    .filter((p) => p.enabled)
    .map(
      (p) =>
        `<tr><td>${ctx.e(p.name)}</td><td>${ctx.e(p.chain)}</td><td class="mono">f2b_${ctx.e(p.id)}</td><td>${ctx.e(p.in_interface || "any")} / ${ctx.e(p.destination || "any")}</td><td>${ctx.e(p.ports.join(", "))}</td><td>DROP</td><td>${ctx.e(ctx.statistics?.[`f2b:${p.id}`]?.packets ?? "—")} / ${ctx.e(ctx.statistics?.[`f2b:${p.id}`]?.bytes ?? "—")}</td></tr>`,
    )
    .join("")}</tbody></table></div></div>`;
}
