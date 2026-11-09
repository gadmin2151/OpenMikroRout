import { t, html, locale } from "./i18n.js";
import { newUuid } from "./uuid.js";
import { assertDraftRevision, assertLinkRemoval } from "./draft-guards.js";
import { proofForm, proof, clearProof } from "./security-ui.js?v=1";
import { interfaceNames } from "./router-pages.js?v=10";
import {
  renderQueryBuilder,
  applyQueryBuilder,
  getAppliedQuery,
  compileQueryExpression,
  resetQueryBuilder,
} from "./query-builder.js";
import { wireGuardQuerySchema } from "./config-filter-schemas.js";

let editing = null;
let privateProfile = null;
let status = null;
let request = null;
let controller = null;

export function resetWireGuard() {
  controller?.abort();
  controller = request = editing = privateProfile = status = null;
  resetQueryBuilder("wg-peers");
}
export function clearWireGuardSecrets() {
  privateProfile = null;
}
export const splitNetworks = (value) =>
  String(value || "")
    .split(/[\s,;]+/)
    .filter(Boolean);
const network = (ctx) => ctx.state.config.network || {};
const collection = (ctx, kind) => network(ctx)[kind] || [];
const locked = (ctx) => ctx.offline || !!ctx.state.pending;
const role = (value) =>
  ({
    server: "Server",
    client: t("Client"),
    "site-to-site": t("Site-to-site"),
  })[value] || value;
const bytes = (value) => {
  if (!Number.isFinite(value)) return "—";
  const units = [t("Б"), t("КБ"), t("МБ"), t("ГБ"), t("ТБ")];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  return `${value.toLocaleString(locale(), { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
};
export function handshakeText(peer) {
  if (!peer?.latest_handshake) return t("Ожидание handshake");
  const age = Math.max(0, Math.floor(peer.handshake_age_seconds || 0));
  return age < 60
    ? html`${age} с назад`
    : age < 3600
      ? html`${Math.floor(age / 60)} мин назад`
      : html`${Math.floor(age / 3600)} ч назад`;
}
function peerStatus(peer) {
  return status?.interfaces
    ?.find((item) => item.name === peer.interface)
    ?.peers?.find((item) => item.public_key === peer.public_key);
}
function endpoint(peer) {
  return peer.endpoint_host
    ? `${peer.endpoint_host}:${peer.endpoint_port}`
    : t("Roaming · входящие");
}
function field(ctx, name, label, value = "", options = {}) {
  const attributes = `${options.required ? " required" : ""}${options.readonly ? " readonly" : ""}${options.max ? ` maxlength="${options.max}"` : ""}`;
  const input = options.lines
    ? html`<textarea spellcheck="false" autocapitalize="off" autocorrect="off" name="${name}" rows="${options.rows || 3}" ${attributes}>${ctx.e(Array.isArray(value) ? value.join("\n") : value)}</textarea>`
    : html`<input name="${name}" type="${options.type || "text"}" value="${ctx.e(value)}" ${attributes} ${options.placeholder ? `placeholder="${ctx.e(options.placeholder)}"` : ""}>`;
  return html`<label class="field ${options.wide ? "wg-wide" : ""}"><span>${t(label)}</span>${input}${options.note ? html`<small>${options.note}</small>` : ""}</label>`;
}
function check(ctx, name, label, value, note = "") {
  return html`<label class="wg-check"><input type="checkbox" name="${name}" ${value ? "checked" : ""}><span>${t(label)}${note ? html`<small>${ctx.e(note)}</small>` : ""}</span></label>`;
}
function interfaceSelect(ctx, name, selected = "", optional = true) {
  return html`<select name="${name}" ${optional ? "" : "required"}>${optional ? html`<option value="">— выбрать —</option>` : ""}${interfaceNames(
    ctx,
  )
    .map(
      (item) =>
        html`<option value="${ctx.e(item)}" ${item === selected ? "selected" : ""}>${ctx.e(item)}</option>`,
    )
    .join("")}</select>`;
}
function form(
  ctx,
  title,
  subtitle,
  content,
  action,
  label = t("Сохранить черновик"),
) {
  ctx.dialogFrame(
    title,
    subtitle,
    html`<form id="wg-form" class="winbox-form wg-form" autocomplete="off">${content}</form>`,
    html`<button data-action="close">Отмена</button><button class="primary" data-action="${action}">${t(label)}</button>`,
  );
}

function updatePeerRows(ctx) {
  const advanced = compileQueryExpression(
    getAppliedQuery("wg-peers"),
    wireGuardQuerySchema(),
  );
  let visible = 0;
  for (const peer of collection(ctx, "wireguard_peers")) {
    const row = document.querySelector(`[data-wg-peer-row="${peer.id}"]`);
    if (!row) continue;
    row.hidden = !advanced(peer);
    if (!row.hidden) visible++;
  }
  const empty = document.querySelector("[data-wg-filter-empty]");
  if (empty) empty.hidden = visible > 0;
  const count = document.querySelector("[data-wg-filter-count]");
  if (count)
    count.textContent = `${visible} / ${collection(ctx, "wireguard_peers").length}`;
  return true;
}

export function renderWireGuard(ctx, peers = false) {
  status ||= ctx.networkStatus?.wireguard || null;
  const interfaces = collection(ctx, "wireguard_interfaces");
  const entries = collection(ctx, "wireguard_peers");
  const advanced = compileQueryExpression(
    getAppliedQuery("wg-peers"),
    wireGuardQuerySchema(),
  );
  const matched = entries.filter(advanced).length;
  const disable = locked(ctx) ? "disabled" : "";
  const active =
    status?.interfaces
      ?.flatMap((item) => item.peers || [])
      .filter((item) => item.connected).length || 0;
  const toolbar = html`<div class="toolbar wg-toolbar">${
    peers
      ? html`<button class="primary" data-action="wg-peer-new" ${disable || !interfaces.length ? "disabled" : ""}>${ctx.icon("plus")}Добавить peer</button>`
      : html`<button class="primary" data-action="wg-server" ${disable}>${ctx.icon("plus")}Настроить сервер</button><button data-action="wg-import" ${disable}>${ctx.icon("upload")}Импорт клиента</button><button data-action="wg-interface-new" ${disable}>${ctx.icon("network")}Интерфейс</button>`
  }
    <span class="wg-toolbar-space"></span><button data-action="wg-refresh" title="Обновить состояние">${ctx.icon("refresh")}Статус</button></div>`;
  const summary = html`<div class="wg-summary"><span>${ctx.icon("lock")}<b>${interfaces.length}</b> интерфейсов</span><span><b>${entries.length}</b> peers</span><span><i class="dot"></i><b data-wg-active>${active}</b> с недавним handshake</span><span class="muted">${status?.demo ? t("DEMO · туннели не запускаются") : t("Состояние применённой конфигурации")}</span></div>`;
  const notice = html`<div class="wg-status-notice ${status?.error ? "connection-error" : "hidden"}" data-wg-error role="status">${ctx.e(status?.error || "")}</div>`;
  let table;
  if (peers) {
    table = html`<table class="rules-table wg-table"><thead><tr><th>Peer / Interface</th><th>Allowed IPs</th><th>Endpoint</th><th>Last handshake</th><th>RX / TX</th><th></th></tr></thead><tbody>${entries
      .map((peer) => {
        const live = peerStatus(peer);
        return html`<tr data-wg-peer-row="${ctx.e(peer.id)}" ${advanced(peer) ? "" : "hidden"} class="${peer.enabled ? "" : "disabled-row"}"><td><strong>${ctx.e(peer.name)}</strong><small class="wg-table-sub mono">${ctx.e(peer.interface)}</small></td><td><span class="mono wg-allowed-ips" title="${ctx.e(peer.allowed_ips.join(", "))}">${ctx.e(peer.allowed_ips.join(", "))}</span></td><td class="mono wg-endpoint" data-wg-endpoint="${ctx.e(peer.id)}">${ctx.e(live?.endpoint || endpoint(peer))}</td><td><span class="wg-peer-state ${live?.connected ? "connected" : ""}" data-wg-handshake="${ctx.e(peer.id)}">${ctx.e(peer.enabled ? handshakeText(live) : t("Отключён"))}</span></td><td class="mono wg-counter" data-wg-traffic="${ctx.e(peer.id)}">${bytes(live?.rx_bytes)} / ${bytes(live?.tx_bytes)}</td><td><div class="row-actions"><button class="icon ghost" data-action="wg-peer-edit" data-id="${ctx.e(peer.id)}" aria-label="Настройки peer ${ctx.e(peer.name)}">${ctx.icon("edit")}</button>${peer.client_private_key_id ? html`<button class="icon ghost" data-action="wg-export" data-client="true" data-id="${ctx.e(peer.id)}" aria-label="Конфигурация и QR ${ctx.e(peer.name)}">${ctx.icon("download")}</button>` : ""}<button class="icon ghost danger" data-action="wg-remove" data-kind="wireguard_peers" data-id="${ctx.e(peer.id)}" ${disable} aria-label="Удалить peer ${ctx.e(peer.name)}">${ctx.icon("minus")}</button></div></td></tr>`;
      })
      .join(
        "",
      )}${entries.length ? html`<tr data-wg-filter-empty ${matched ? "hidden" : ""}><td colspan="6" class="muted">По этому фильтру peers не найдены.</td></tr>` : ""}</tbody></table>`;
  } else {
    table = html`<table class="rules-table wg-table"><thead><tr><th>Name</th><th>Role</th><th>Listen Port</th><th>Public Key</th><th>Routing</th><th>Peers</th><th></th></tr></thead><tbody>${interfaces.map((item) => html`<tr class="${item.enabled ? "" : "disabled-row"}"><td><strong class="mono">${ctx.e(item.name)}</strong><small class="wg-table-sub">${item.enabled ? t("enabled") : t("disabled")} · MTU ${item.mtu}</small></td><td>${ctx.e(role(item.role))}</td><td class="mono">${item.listen_port || "auto"} / UDP</td><td><span class="wg-public-key mono" title="${ctx.e(item.public_key)}">${ctx.e(item.public_key)}</span></td><td>${item.route_allowed_ips ? html`<span class="wg-route-badge">Table ${item.routing_table}</span><small class="wg-table-sub wg-route-sources" title="${ctx.e(item.route_sources.join(", "))}">${ctx.e(item.route_sources.join(", "))}${item.kill_switch ? " · Kill switch" : ""}</small>` : html`<span class="muted">IP → Routes</span>`}</td><td>${entries.filter((peer) => peer.interface === item.name).length}</td><td><div class="row-actions">${item.role === "server" ? html`<button class="icon ghost" data-action="wg-server-access" data-id="${ctx.e(item.id)}" ${disable} aria-label="Доступ клиентов ${ctx.e(item.name)}">${ctx.icon("shield")}</button>` : ""}<button class="icon ghost" data-action="wg-interface-edit" data-id="${ctx.e(item.id)}" aria-label="Настройки ${ctx.e(item.name)}">${ctx.icon("edit")}</button><button class="icon ghost" data-action="wg-export" data-client="false" data-id="${ctx.e(item.id)}" aria-label="Экспорт ${ctx.e(item.name)}">${ctx.icon("download")}</button><button class="icon ghost danger" data-action="wg-remove" data-kind="wireguard_interfaces" data-id="${ctx.e(item.id)}" ${disable} aria-label="Удалить ${ctx.e(item.name)}">${ctx.icon("minus")}</button></div></td></tr>`).join("")}</tbody></table>`;
  }
  const empty = (peers ? entries : interfaces).length
    ? ""
    : ctx.empty(
        "lock",
        peers ? t("Подключите первое устройство") : "WireGuard VPN",
        peers
          ? t(
              "Добавьте peer с генерацией конфигурации и QR-кода или укажите публичный ключ удалённого роутера.",
            )
          : t(
              "Создайте сервер для доступа к своей сети или импортируйте профиль VPN-провайдера как клиент.",
            ),
      );
  return html`${toolbar}${summary}${notice}${peers ? html`${renderQueryBuilder("wg-peers", wireGuardQuerySchema(), { applyAction: "wg-query-apply" })}<p class="feature-note" data-wg-filter-count aria-live="polite">${matched} / ${entries.length}</p>` : ""}<div class="table-scroll router-table-scroll">${table}${empty}</div><div class="wg-guide"><div>${ctx.icon("server")}<strong>Сервер</strong><p>Мастер → peer → конфигурация или QR → применить и подтвердить.</p></div><div>${ctx.icon("swap")}<strong>Клиент</strong><p>Импорт .conf → исходные сети LAN → kill switch → предпросмотр.</p></div><div>${ctx.icon("shield")}<strong>Один черновик</strong><p>IP, маршруты и Firewall применяются вместе с автоматическим откатом.</p></div></div>`;
}

export async function refreshWireGuard(ctx) {
  if (
    request ||
    (!ctx.isCurrentView("wireguard") && !ctx.isCurrentView("wireguard_peers"))
  )
    return request;
  const generation = ctx.generation;
  controller = new AbortController();
  const current = (async () => {
    try {
      const result = await ctx.api("wireguard/status", {
        signal: controller.signal,
      });
      if (ctx.getGeneration() !== generation) return;
      status = result;
      const error = document.querySelector("[data-wg-error]");
      if (error) {
        error.textContent = result.error || "";
        error.classList.toggle("hidden", !result.error);
      }
      const active = document.querySelector("[data-wg-active]");
      if (active)
        active.textContent = result.interfaces
          .flatMap((item) => item.peers || [])
          .filter((item) => item.connected).length;
      for (const peer of collection(ctx, "wireguard_peers")) {
        const live = peerStatus(peer);
        const node = document.querySelector(`[data-wg-handshake="${peer.id}"]`);
        if (node) {
          node.textContent = peer.enabled ? handshakeText(live) : t("Отключён");
          node.classList.toggle("connected", !!live?.connected);
        }
        const traffic = document.querySelector(
          `[data-wg-traffic="${peer.id}"]`,
        );
        if (traffic)
          traffic.textContent = `${bytes(live?.rx_bytes)} / ${bytes(live?.tx_bytes)}`;
        const target = document.querySelector(
          `[data-wg-endpoint="${peer.id}"]`,
        );
        if (target) target.textContent = live?.endpoint || endpoint(peer);
      }
    } catch (error) {
      if (error.name !== "AbortError" && ctx.getGeneration() === generation) {
        const node = document.querySelector("[data-wg-error]");
        if (node) {
          node.textContent = error.message;
          node.classList.remove("hidden");
        }
      }
    } finally {
      if (request === current) {
        request = null;
        controller = null;
      }
    }
  })();
  request = current;
  return current;
}

function openServer(ctx) {
  editing = { revision: ctx.state.revision };
  form(
    ctx,
    t("WireGuard · новый сервер"),
    t("Создадим интерфейс, IP и выбранные правила доступа в общем черновике."),
    html`<div class="wg-form-grid">${field(ctx, "name", t("Interface Name"), "wg-server", { required: true, max: 13 })}${field(ctx, "address", t("VPN Address / Prefix"), "10.77.0.1/24", { required: true })}${field(ctx, "listen_port", t("Listen Port · UDP"), 51820, { type: "number", required: true })}${field(ctx, "endpoint", t("Public IP / DNS"), "", { placeholder: "vpn.example.com", note: t("Адрес для подключения клиентов. Нужен для экспорта QR / .conf.") })}${field(ctx, "dns", t("DNS для клиентов"), "", { placeholder: "1.1.1.1, 9.9.9.9" })}${field(ctx, "mtu", t("MTU"), 1420, { type: "number", required: true })}${field(ctx, "access_networks", t("Доступные клиентам сети LAN"), "", { lines: true, wide: true, note: t("Например, 192.168.10.0/24. Только эти назначения разрешим в Forward.") })}<label class="field wg-wide"><span>WAN Interface</span>${interfaceSelect(ctx, "wan_interface")}<small>Для входящего UDP и NAT, если нужен интернет через VPN.</small></label></div>${check(ctx, "internet_access", t("Разрешить интернет через этот WAN"), false, t("Добавит Forward и Masquerade только для VPN-подсети."))}${check(ctx, "router_access", t("Разрешить клиентам доступ к самому роутеру"), false, t("Добавит Input для VPN-подсети. Включайте только для доверенных устройств."))}`,
    "wg-server-save",
    t("Создать сервер"),
  );
}
function openImport(ctx) {
  editing = { revision: ctx.state.revision };
  form(
    ctx,
    t("WireGuard · импорт клиента"),
    t(
      "Стандартный IPv4 .conf. Команды PreUp / PostUp и другие hooks не исполняются.",
    ),
    html`<div class="wg-form-grid">${field(ctx, "name", t("Interface Name"), "wg-client", { required: true, max: 13 })}<label class="field"><span>Файл конфигурации</span><input type="file" id="wg-profile-file" accept=".conf,.txt"><small>До 64 КБ. Содержит закрытый ключ.</small></label>${field(ctx, "profile", t("WireGuard configuration"), "", { lines: true, rows: 9, wide: true, required: true })}${field(ctx, "route_sources", t("Исходные сети, направляемые в VPN"), "", { lines: true, wide: true, note: t("Например, 192.168.10.0/24. Пусто — только создать туннель; маршруты задаются в IP → Routes. Основной шлюз хоста не меняется.") })}</div>${check(ctx, "kill_switch", t("Kill switch для выбранных источников"), true, t("За пределами явных LAN / статических маршрутов трафик идёт только в VPN. При отключённом туннеле или удалённом peer выхода через обычный WAN не будет."))}${check(ctx, "masquerade", t("Masquerade в туннель"), true, t("Обычно нужен для VPN-провайдера. Для site-to-site с обратными маршрутами можно выключить."))}`,
    "wg-import-save",
    t("Импортировать"),
  );
}
function openServerAccess(ctx, item) {
  editing = { revision: ctx.state.revision, item: structuredClone(item) };
  const policy = item.server_access || {
    source_network:
      network(ctx).addresses?.find((address) => address.interface === item.name)
        ?.address || "",
    access_networks: [],
    router_access: false,
    wan_interface: "",
  };
  form(
    ctx,
    html`${item.name} · доступ клиентов`,
    item.server_access
      ? t(
          "Сервер ограничивает назначения независимо от маршрутов в клиентском профиле.",
        )
      : t(
          "Для этого сервера отдельные ограничения ещё не заданы. Сохранение включит выбранную политику после применения черновика.",
        ),
    html`<div class="wg-form-grid">${field(ctx, "source_network", t("VPN-подсеть клиентов"), policy.source_network, { required: true, wide: true })}${field(ctx, "access_networks", t("Разрешённые сети LAN"), policy.access_networks, { lines: true, wide: true })}<label class="field wg-wide"><span>Интернет через WAN · необязательно</span>${interfaceSelect(ctx, "wan_interface", policy.wan_interface)}<small>Пусто — доступ только к выбранным LAN. Маршруты, NAT и разрешения Firewall настраиваются отдельно.</small></label></div>${check(ctx, "router_access", t("Разрешить доступ к самому роутеру"), policy.router_access)}<p class="feature-note">Остальные назначения будут запрещены. Существующий Firewall продолжает проверять разрешённый здесь трафик.</p>`,
    "wg-server-access-save",
  );
}
function openInterface(ctx, item = null) {
  editing = {
    revision: ctx.state.revision,
    item: item ? structuredClone(item) : null,
  };
  const value = item || {
    name: "wg-link",
    role: "site-to-site",
    listen_port: 51820,
    mtu: 1420,
    enabled: true,
    client_dns: [],
    client_allowed_ips: [],
    route_sources: [],
    kill_switch: true,
    route_allowed_ips: false,
    routing_table: 20000,
    export_endpoint: "",
    comment: "",
  };
  const roleConfirmation = value.server_access
    ? check(
        ctx,
        "confirm_remove_server_access",
        t(
          "Подтверждаю снятие серверных ограничений при смене роли на Client или Site-to-site",
        ),
        false,
        t(
          "Смена роли удалит отдельную политику доступа клиентов только после применения черновика. Обычные правила Firewall сохраняются. Если роль остаётся Server, ограничения не меняются.",
        ),
      )
    : "";
  form(
    ctx,
    item ? `${item.name} · WireGuard Interface` : t("WireGuard · интерфейс"),
    t("Закрытый ключ хранится зашифрованным. IP назначается в IP → Addresses."),
    html`<div class="wg-form-grid">${field(ctx, "name", t("Name"), value.name, { required: true, readonly: !!item, max: 13 })}<label class="field"><span>Role</span><select name="role">${["server", "client", "site-to-site"].map((name) => html`<option value="${name}" ${name === value.role ? "selected" : ""}>${role(name)}</option>`).join("")}</select></label>${field(ctx, "listen_port", "Listen Port · UDP (0 = auto)", value.listen_port, { type: "number", required: true })}${field(ctx, "mtu", t("MTU"), value.mtu, { type: "number", required: true })}${field(ctx, "export_endpoint", t("Public endpoint для клиентов"), value.export_endpoint)}${field(ctx, "client_dns", t("DNS для клиентов"), value.client_dns.join(", "))}${item ? field(ctx, "public_key", t("Public Key"), item.public_key, { readonly: true, wide: true }) : field(ctx, "private_key", t("Private Key · необязательно"), "", { type: "password", wide: true, note: t("Пусто — сгенерировать новый. Ключ не появится в обычном Backup.") })}${field(ctx, "client_allowed_ips", t("Сети для новых клиентов · Allowed IPs"), value.client_allowed_ips || [], { lines: true, wide: true, note: t("Значение по умолчанию для генерируемых клиентских профилей.") })}${field(ctx, "route_sources", t("Source networks для VPN"), value.route_sources, { lines: true, wide: true })}${field(ctx, "routing_table", "Routing table · 20000–20999", value.routing_table, { type: "number" })}${field(ctx, "comment", t("Comment"), value.comment)}</div>${check(ctx, "enabled", t("Enabled"), value.enabled)}${check(ctx, "route_allowed_ips", t("Маршрутизировать источники к Allowed IPs peers"), value.route_allowed_ips, t("Явные маршруты из main сохраняют приоритет. Сети-источники должны быть заданы и не пересекаться."))}${check(ctx, "kill_switch", t("Kill switch · запретить выход вне VPN"), value.kill_switch, t("Для выбранных источников сохранится только VPN и явные маршруты LAN / main. Защита остаётся при отключении интерфейса или удалении peers."))}${roleConfirmation}`,
    "wg-interface-save",
  );
}
function openPeer(ctx, item = null) {
  editing = {
    revision: ctx.state.revision,
    item: item ? structuredClone(item) : null,
  };
  const interfaces = collection(ctx, "wireguard_interfaces");
  const value = item || {
    interface: interfaces[0]?.name || "",
    name: "",
    public_key: "",
    allowed_ips: [],
    client_address: "",
    client_allowed_ips: [],
    client_dns: [],
    endpoint_host: "",
    endpoint_port: 51820,
    persistent_keepalive: 0,
    enabled: true,
    comment: "",
  };
  form(
    ctx,
    item ? `${item.name} · WireGuard Peer` : t("WireGuard · новый peer"),
    item
      ? t(
          "Allowed IPs — разрешённые адреса источника и назначения для этого peer.",
        )
      : t(
          "Пустой Public Key — создадим ключ устройства и готовый клиентский профиль.",
        ),
    html`<div class="wg-form-grid"><label class="field"><span>Interface</span><select name="interface" required>${interfaces.map((iface) => html`<option value="${ctx.e(iface.name)}" ${value.interface === iface.name ? "selected" : ""}>${ctx.e(iface.name)}</option>`).join("")}</select></label>${field(ctx, "name", t("Name"), value.name, { required: true, max: 64 })}${field(ctx, "public_key", t("Peer Public Key"), value.public_key, { wide: true, readonly: !!item?.client_private_key_id, note: item?.client_private_key_id ? t("Ключ сгенерированного устройства. Смена — через создание нового peer.") : t("Для чужого роутера вставьте его публичный ключ. Закрытый ключ чужого устройства не нужен.") })}${field(ctx, "address", t("Client Address / Prefix"), value.client_address, { placeholder: "10.77.0.2/32", note: item ? t("Адрес в экспортируемом профиле.") : t("Пусто — свободный /32 из VPN-подсети интерфейса.") })}${field(ctx, "keepalive", t("Persistent Keepalive · seconds"), value.persistent_keepalive, { type: "number" })}${field(ctx, "allowed_ips", t("Allowed IPs · на этом роутере"), value.allowed_ips, { lines: true, wide: true, note: t("Для устройства — его /32; для site-to-site — удалённые сети. Пусто у нового устройства — его адрес /32.") })}${field(ctx, "endpoint_host", t("Endpoint · IPv4 / DNS"), value.endpoint_host, { placeholder: t("Пусто для входящих / roaming") })}${field(ctx, "endpoint_port", t("Endpoint Port"), value.endpoint_port, { type: "number" })}${field(ctx, "client_allowed_ips", t("Сети в экспортируемом профиле клиента"), value.client_allowed_ips, { lines: true, wide: true, note: t("0.0.0.0/0 — весь IPv4 через VPN. Пусто у нового peer — настройки клиентских маршрутов сервера.") })}${field(ctx, "client_dns", t("Client DNS"), value.client_dns.join(", "))}${field(ctx, "comment", t("Comment"), value.comment)}${field(ctx, "preshared_key", item ? t("Новый Preshared Key · необязательно") : t("Preshared Key · необязательно"), "", { type: "password", wide: true, note: item ? t("Пусто — сохранить существующий. Новый PSK нужно также настроить у удалённого peer.") : t("Для внешнего peer укажите общий PSK, если он настроен с другой стороны. Для генерируемого клиента ключ создаётся автоматически.") })}</div>${item ? check(ctx, "enabled", t("Enabled"), value.enabled) : check(ctx, "preshared", t("Дополнительный Preshared Key для генерируемого клиента"), true)}`,
    "wg-peer-save",
  );
}
function values(ctx) {
  const node = ctx.dialog.querySelector("#wg-form");
  if (!node?.reportValidity()) return null;
  assertDraftRevision(editing?.revision, ctx.state.revision);
  return new FormData(node);
}
function download(profile) {
  const url = URL.createObjectURL(
    new Blob([profile.configuration], { type: "text/plain;charset=utf-8" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = profile.filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function handleWireGuardAction(button, ctx) {
  const action = button.dataset.action;
  if (!action?.startsWith("wg-")) return false;
  if (action === "wg-query-apply") {
    applyQueryBuilder("wg-peers");
    updatePeerRows(ctx);
    return true;
  }
  if (action === "wg-refresh") {
    await refreshWireGuard(ctx);
    return true;
  }
  if (action === "wg-interface-edit" || action === "wg-peer-edit") {
    const kind =
      action === "wg-peer-edit" ? "wireguard_peers" : "wireguard_interfaces";
    const item = collection(ctx, kind).find(
      (item) => item.id === button.dataset.id,
    );
    if (!item)
      throw new Error(t("Запись больше не существует. Обновите черновик."));
    (kind === "wireguard_peers" ? openPeer : openInterface)(ctx, item);
    return true;
  }
  if (!ctx.canWrite())
    throw new Error(t("Для настройки WireGuard нужна группа full."));
  if (action === "wg-server-access") {
    const item = collection(ctx, "wireguard_interfaces").find(
      (row) => row.id === button.dataset.id,
    );
    if (!item || item.role !== "server")
      throw new Error(t("Выберите существующий сервер WireGuard."));
    openServerAccess(ctx, item);
    return true;
  }
  if (action === "wg-server") {
    openServer(ctx);
    return true;
  }
  if (action === "wg-import") {
    openImport(ctx);
    return true;
  }
  if (action === "wg-interface-new") {
    openInterface(ctx);
    return true;
  }
  if (action === "wg-peer-new") {
    openPeer(ctx);
    return true;
  }
  await ctx.run(async () => {
    const generation = ctx.generation;
    if (action === "wg-export") {
      editing = {
        object_id: button.dataset.id,
        client: button.dataset.client === "true",
      };
      privateProfile = null;
      ctx.dialogFrame(
        t("Экспорт WireGuard"),
        t(
          "Конфигурация содержит закрытый ключ. Передавайте её только владельцу устройства.",
        ),
        ctx.state.auth_enabled
          ? proofForm(
              ctx,
              "wg-export-proof",
              t("Подтвердите доступ к закрытым ключам."),
            )
          : html`<p class="preview-note">Деморежим: будут показаны только ключи тестового роутера.</p>`,
        html`<button data-action="close">Отмена</button><button class="primary" data-action="wg-export-confirm">Показать конфигурацию</button>`,
      );
      return;
    }
    if (action === "wg-export-confirm") {
      const credentials = ctx.state.auth_enabled
        ? proof(ctx, "wg-export-proof")
        : null;
      if (ctx.state.auth_enabled && !credentials) return;
      const result = await ctx.api("wireguard/export", {
        method: "POST",
        body: JSON.stringify({ ...editing, proof: credentials }),
      });
      if (ctx.getGeneration() !== generation) return;
      clearProof(ctx);
      privateProfile = result;
      ctx.dialogFrame(
        t("WireGuard · конфигурация устройства"),
        t("Сканируйте в приложении WireGuard или импортируйте файл .conf."),
        html`<div class="wg-private-profile" id="wg-private-profile">${result.qr_data_url ? html`<img class="wg-qr" src="${ctx.e(result.qr_data_url)}" alt="QR-код WireGuard с закрытым ключом">` : ""}<label class="field"><span>${ctx.e(result.filename)}</span><textarea rows="11" class="mono" readonly spellcheck="false">${ctx.e(result.configuration)}</textarea></label></div><p class="feature-note">Ключ будет убран с экрана после закрытия окна.</p>`,
        html`<button data-action="close">Закрыть</button><button class="primary" data-action="wg-download">Скачать .conf</button>`,
      );
      return;
    }
    if (action === "wg-download") {
      if (privateProfile) download(privateProfile);
      return;
    }
    if (action === "wg-remove") {
      assertLinkRemoval(
        ctx.state.config,
        button.dataset.kind,
        button.dataset.id,
      );
      editing = {
        revision: ctx.state.revision,
        id: button.dataset.id,
        kind: button.dataset.kind,
      };
      ctx.dialogFrame(
        t("Удалить WireGuard запись?"),
        t("Изменение попадёт в черновик. Применение выполняется отдельно."),
        html`<p class="preview-note">Открытые редакторы в других сессиях потребуют обновления. Связанные правила Firewall остаются видимыми в своих таблицах.</p>`,
        html`<button data-action="close">Отмена</button><button class="danger" data-action="wg-remove-confirm">Удалить</button>`,
      );
      return;
    }
    if (action === "wg-remove-confirm") {
      assertDraftRevision(editing.revision, ctx.state.revision);
      const config = structuredClone(ctx.state.config);
      assertLinkRemoval(config, editing.kind, editing.id);
      config.network[editing.kind] = config.network[editing.kind].filter(
        (item) => item.id !== editing.id,
      );
      await ctx.saveConfig(config, editing.revision);
    } else {
      const data = values(ctx);
      if (!data) return;
      const text = (key) => String(data.get(key) || "").trim();
      let result;
      if (action === "wg-server-save")
        result = await ctx.api("wireguard/server", {
          method: "POST",
          body: JSON.stringify({
            revision: editing.revision,
            name: text("name"),
            address: text("address"),
            listen_port: Number(text("listen_port")),
            endpoint: text("endpoint"),
            mtu: Number(text("mtu")),
            dns: splitNetworks(text("dns")),
            access_networks: splitNetworks(text("access_networks")),
            wan_interface: text("wan_interface"),
            internet_access: data.has("internet_access"),
            router_access: data.has("router_access"),
          }),
        });
      else if (action === "wg-server-access-save")
        result = await ctx.api("wireguard/server-access", {
          method: "POST",
          body: JSON.stringify({
            revision: editing.revision,
            interface: editing.item.name,
            policy: {
              source_network: text("source_network"),
              access_networks: splitNetworks(text("access_networks")),
              router_access: data.has("router_access"),
              wan_interface: text("wan_interface"),
            },
          }),
        });
      else if (action === "wg-import-save")
        result = await ctx.api("wireguard/import", {
          method: "POST",
          body: JSON.stringify({
            revision: editing.revision,
            name: text("name"),
            profile: text("profile"),
            route_sources: splitNetworks(text("route_sources")),
            kill_switch: data.has("kill_switch"),
            masquerade: data.has("masquerade"),
          }),
        });
      else if (action === "wg-peer-save" && !editing.item)
        result = await ctx.api("wireguard/peers", {
          method: "POST",
          body: JSON.stringify({
            revision: editing.revision,
            interface: text("interface"),
            name: text("name"),
            public_key: text("public_key"),
            address: text("address"),
            allowed_ips: splitNetworks(text("allowed_ips")),
            client_allowed_ips: splitNetworks(text("client_allowed_ips")),
            client_dns: splitNetworks(text("client_dns")),
            endpoint_host: text("endpoint_host"),
            endpoint_port: Number(text("endpoint_port")),
            keepalive: Number(text("keepalive")),
            preshared: data.has("preshared"),
            preshared_key: text("preshared_key") || null,
          }),
        });
      else {
        const config = structuredClone(ctx.state.config);
        if (action === "wg-interface-save") {
          const removeServerAccess =
            !!editing.item?.server_access && text("role") !== "server";
          if (removeServerAccess && !data.has("confirm_remove_server_access"))
            throw new Error(
              t(
                "Для смены роли подтвердите снятие серверных ограничений доступа после применения черновика.",
              ),
            );
          let key = null;
          if (!editing.item)
            key = await ctx.api("wireguard/keys", {
              method: "POST",
              body: JSON.stringify({
                kind: "interface",
                value: text("private_key") || null,
              }),
            });
          const item = {
            ...(editing.item || {
              id: newUuid(),
              private_key_id: key.id,
              public_key: key.public_key,
            }),
            name: text("name"),
            role: text("role"),
            ...(removeServerAccess ? { server_access: null } : {}),
            mtu: Number(text("mtu")),
            listen_port: Number(text("listen_port")),
            enabled: data.has("enabled"),
            route_allowed_ips: data.has("route_allowed_ips"),
            route_sources: splitNetworks(text("route_sources")),
            routing_table: Number(text("routing_table")),
            kill_switch: data.has("kill_switch"),
            export_endpoint: text("export_endpoint"),
            client_dns: splitNetworks(text("client_dns")),
            client_allowed_ips: splitNetworks(text("client_allowed_ips")),
            comment: text("comment"),
          };
          config.network.wireguard_interfaces ||= [];
          if (editing.item)
            config.network.wireguard_interfaces =
              config.network.wireguard_interfaces.map((row) =>
                row.id === item.id ? item : row,
              );
          else config.network.wireguard_interfaces.push(item);
        } else if (action === "wg-peer-save") {
          let psk = null;
          if (text("preshared_key"))
            psk = await ctx.api("wireguard/keys", {
              method: "POST",
              body: JSON.stringify({
                kind: "preshared",
                value: text("preshared_key"),
              }),
            });
          const item = {
            ...editing.item,
            name: text("name"),
            interface: text("interface"),
            public_key: text("public_key"),
            allowed_ips: splitNetworks(text("allowed_ips")),
            endpoint_host: text("endpoint_host"),
            endpoint_port: Number(text("endpoint_port")),
            persistent_keepalive: Number(text("keepalive")),
            enabled: data.has("enabled"),
            client_address: text("address"),
            client_allowed_ips: splitNetworks(text("client_allowed_ips")),
            client_dns: splitNetworks(text("client_dns")),
            comment: text("comment"),
          };
          if (psk) item.preshared_key_id = psk.id;
          config.network.wireguard_peers = config.network.wireguard_peers.map(
            (row) => (row.id === item.id ? item : row),
          );
        } else throw new Error(t("Неизвестное действие WireGuard."));
        if (ctx.getGeneration() !== generation) return;
        await ctx.saveConfig(config, editing.revision);
      }
      if (ctx.getGeneration() !== generation) return;
      if (result) ctx.acceptState(result);
    }
    if (ctx.getGeneration() !== generation) return;
    ctx.dialog.close();
    ctx.toast(
      t("WireGuard сохранён в черновик. Проверьте и примените настройки."),
    );
  });
  return true;
}

export async function handleWireGuardChange(event, ctx) {
  if (event.target?.id !== "wg-profile-file") return;
  const file = event.target.files?.[0];
  if (!file) return;
  if (file.size > 65536)
    throw new Error(t("Файл WireGuard должен быть не больше 64 КБ."));
  const generation = ctx.generation;
  const target = ctx.dialog.querySelector('[name="profile"]');
  const content = await file.text();
  if (generation === ctx.getGeneration() && target?.isConnected)
    target.value = content;
  event.target.value = "";
}
