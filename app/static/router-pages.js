import { t, html, locale } from "./i18n.js";
import { checkboxSelect } from "./checkbox-select.js";
import { addressListChoices } from "./protection-ui.js?v=3";
import { assertDraftRevision, assertLinkRemoval } from "./draft-guards.js";
import { reorderRules } from "./rule-order.js";
import { renderTelemetry } from "./telemetry-ui.js?v=7";
import {
  countryField,
  renderRuleFail2ban,
  renderLegacyBanMatch,
  collectRuleProtection,
  defaultRuleProtection,
} from "./rule-security-ui.js?v=3";

/** Router configuration views. All writes use the existing revisioned draft API. */

export const routerViews = {
  web_settings: [
    t("Web Interface"),
    t("Домен для доступа к панели OpenMikroRout."),
  ],
  bridge_ports: [
    t("Bridge Ports"),
    t(
      "Участники bridge и принадлежность физических / виртуальных интерфейсов.",
    ),
  ],
  dhcp_networks: [
    t("DHCP Networks"),
    t("Сетевые параметры DHCP-серверов: network, gateway и DNS."),
  ],
  overview: [
    t("Обзор роутера"),
    t("Состояние сети и основные настройки OpenMikroRout."),
  ],
  addresses: [
    t("IP Addresses"),
    t("Назначайте IPv4-адреса физическим, bridge и VLAN-интерфейсам."),
  ],
  bridges: [t("Bridge"), t("Объединяйте интерфейсы в общую локальную сеть.")],
  vlans: [
    t("VLAN"),
    t("Создавайте изолированные сети 802.1Q на выбранном интерфейсе."),
  ],
  virtual_interfaces: [
    t("Virtual Interfaces"),
    t("Программные dummy-интерфейсы для локальных адресов и маршрутизации."),
  ],
  routes: [t("IP Routes"), t("Статические маршруты и шлюз по умолчанию.")],
  dhcp_servers: [
    t("DHCP Server"),
    t("Выдавайте адреса клиентам на нужном интерфейсе."),
  ],
  pools: [t("IP Pools"), t("Пулы IPv4-адресов для DHCP-серверов.")],
  leases: [
    t("DHCP Leases"),
    t("Активные аренды и постоянные привязки IP к MAC-адресам."),
  ],
  dns: [
    t("DNS & Routing"),
    t("Кэширующий DNS, upstream-серверы и IPv4 forwarding."),
  ],
  dns_static: [
    t("DNS Static"),
    t("Локальные IPv4 A-записи для устройств и сервисов."),
  ],
  interface_lists: [
    t("Interface Lists"),
    t("Группы WAN, LAN и других интерфейсов для правил Firewall."),
  ],
  filter: [
    "Firewall Filter",
    t("Правила input, forward и output для защиты Linux-роутера."),
  ],
};

const itemSchemas = {
  dns_static: {
    title: t("Static DNS Record"),
    label: t("Добавить запись"),
    icon: "list",
    fields: [
      ["name", t("DNS Name"), "text", "nas.home", true],
      ["address", t("IPv4 Address"), "text", "192.168.10.20", true],
      ["ttl", t("TTL · seconds"), "number", 300, true],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["address", t("Address")],
      ["ttl", t("TTL")],
      ["enabled", t("Status")],
      ["comment", t("Comment")],
    ],
    note: t(
      "Записи обслуживаются локальным DNS OpenMikroRout. Включите DNS в Settings и настройте адрес роутера как DNS у клиентов. Допускается несколько A-записей с одним именем.",
    ),
  },
  addresses: {
    title: t("IP Address"),
    label: t("Назначить IP"),
    icon: "network",
    fields: [
      ["interface", t("Interface"), "interface", "", true],
      ["address", t("Address / Prefix"), "text", "192.168.10.1/24", true],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["address", t("Address")],
      ["interface", t("Interface")],
      ["enabled", t("Status")],
      ["comment", t("Comment")],
    ],
    note: t(
      "Укажите адрес с длиной префикса. Например, 192.168.10.1/24. Сначала создайте bridge / VLAN, если адрес должен находиться на нём.",
    ),
  },
  bridges: {
    title: t("Bridge"),
    label: t("Создать bridge"),
    icon: "network",
    fields: [
      ["name", t("Name"), "text", "bridge-lan", true],
      ["members", t("Ports"), "interfaces", []],
      ["stp", t("Spanning Tree"), "bool", true],
      ["mtu", t("MTU"), "number", 1500],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["members", t("Ports")],
      ["stp", t("STP")],
      ["mtu", t("MTU")],
      ["enabled", t("Status")],
    ],
    note: t(
      "Ports — интерфейсы, которые станут участниками bridge. IP и DHCP обычно назначаются на сам bridge. Интерфейс, уже включённый в чужой bridge, не будет захвачен автоматически.",
    ),
  },
  vlans: {
    title: t("VLAN Interface"),
    label: t("Создать VLAN"),
    icon: "network",
    fields: [
      ["name", t("Name"), "text", "vlan20", true],
      ["parent", t("Parent Interface"), "interface", "", true],
      ["vlan_id", t("VLAN ID"), "number", 20, true],
      ["mtu", t("MTU"), "number", 1500],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["parent", t("Parent")],
      ["vlan_id", t("VLAN ID")],
      ["mtu", t("MTU")],
      ["enabled", t("Status")],
    ],
    note: t(
      "Тег 802.1Q: VLAN ID от 1 до 4094. После создания назначьте IP-адрес и при необходимости DHCP на новый VLAN-интерфейс.",
    ),
  },
  virtual_interfaces: {
    title: t("Virtual Interface"),
    label: t("Создать интерфейс"),
    icon: "network",
    fields: [
      ["name", t("Name"), "text", "dummy0", true],
      ["kind", t("Type"), "dummy", "dummy"],
      ["mtu", t("MTU"), "number", 1500],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["kind", t("Type")],
      ["mtu", t("MTU")],
      ["enabled", t("Status")],
      ["comment", t("Comment")],
    ],
    note: t(
      "Dummy — программный интерфейс без физического порта. Подходит для локальных адресов и маршрутизации; это не VPN-туннель.",
    ),
  },
  routes: {
    title: t("Static Route"),
    label: t("Добавить маршрут"),
    icon: "arrow",
    fields: [
      ["destination", t("Dst. Address"), "text", "0.0.0.0/0", true],
      ["gateway", t("Gateway"), "text", ""],
      ["interface", t("Interface"), "interface", ""],
      ["metric", "Metric", "number", 100],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["destination", t("Dst. Address")],
      ["gateway", t("Gateway")],
      ["interface", t("Interface")],
      ["metric", "Metric"],
      ["enabled", t("Status")],
    ],
    note: t(
      "0.0.0.0/0 — маршрут по умолчанию. Укажите gateway и / или интерфейс. Системные маршруты показаны ниже отдельно и не редактируются этой таблицей.",
    ),
  },
  pools: {
    title: t("IP Pool"),
    label: t("Создать пул"),
    icon: "list",
    fields: [
      ["name", t("Name"), "text", "pool-lan", true],
      ["start", t("From Address"), "text", "192.168.10.100", true],
      ["end", t("To Address"), "text", "192.168.10.200", true],
    ],
    columns: [
      ["name", t("Name")],
      ["start", t("From Address")],
      ["end", t("To Address")],
    ],
    note: t(
      "Начальный и конечный адрес включены в диапазон. Не включайте адрес самого роутера, network и broadcast. Пул выбирается в настройках DHCP Server.",
    ),
  },
  dhcp_servers: {
    title: t("DHCP Server"),
    label: t("Создать DHCP"),
    icon: "server",
    fields: [
      ["name", t("Name"), "text", "dhcp-lan", true],
      ["interface", t("Interface"), "interface", "", true],
      ["pool", t("Address Pool"), "pool", "", true],
      ["network", t("Network"), "text", "192.168.10.0/24", true],
      ["gateway", t("Gateway"), "text", "192.168.10.1", true],
      ["dns_servers", t("DNS Servers"), "lines", []],
      ["lease_minutes", t("Lease Time (min)"), "number", 720],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["interface", t("Interface")],
      ["pool", t("Address Pool")],
      ["network", t("Network")],
      ["lease_minutes", "Lease, min"],
      ["enabled", t("Status")],
    ],
    note: t(
      "Назначьте статический IP выбранному интерфейсу и создайте пул. Укажите DNS Servers либо включите локальный DNS на этом интерфейсе. На одном интерфейсе должен работать один DHCP-сервер; существующие системные DHCP-службы приложение не останавливает.",
    ),
  },
  dhcp_reservations: {
    title: t("Static DHCP Lease"),
    label: t("Добавить привязку"),
    icon: "lock",
    fields: [
      ["server", t("DHCP Server"), "server", "", true],
      ["mac", t("MAC Address"), "text", "", true],
      ["address", t("IP Address"), "text", "", true],
      ["hostname", t("Hostname"), "text", ""],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["address", t("IP Address")],
      ["mac", t("MAC Address")],
      ["hostname", t("Hostname")],
      ["server", "Server"],
      ["enabled", t("Status")],
    ],
    note: t(
      "Клиент с этим MAC-адресом будет получать постоянный IP в сети указанного DHCP-сервера.",
    ),
  },
  interface_lists: {
    title: t("Interface List"),
    label: t("Создать список"),
    icon: "list",
    fields: [
      ["name", t("Name"), "text", t("LAN"), true],
      ["members", t("Interfaces"), "interfaces", []],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["members", t("Interfaces")],
      ["comment", t("Comment")],
    ],
    note: t(
      "Список объединяет интерфейсы логически и не соединяет их в bridge. Используйте WAN / LAN в условиях Firewall и NAT.",
    ),
  },
  filter: {
    title: t("Filter Rule"),
    label: t("Добавить правило"),
    icon: "shield",
    fields: [
      ["name", t("Name"), "text", "", true],
      ["chain", t("Chain"), "chain", "forward"],
      ["action", t("Action"), "filter-action", "accept"],
      ["protocol", t("Protocol"), "protocol", "any"],
      ["src_address", t("Src. Address"), "text", ""],
      ["dst_address", t("Dst. Address"), "text", ""],
      ["src_list", t("Src. Address List"), "address-list", ""],
      ["dst_list", t("Dst. Address List"), "address-list", ""],
      ["src_country", t("Src. Country"), "country", ""],
      ["dst_country", t("Dst. Country"), "country", ""],
      ["f2b_profile", t("Ban list · профиль"), "text", ""],
      ["f2b_match", "Source IP", "f2b-match", "not_banned"],
      ["src_ports", t("Src. Port"), "text", ""],
      ["dst_ports", t("Dst. Port"), "text", ""],
      ["in_interface", t("In. Interface"), "interface", ""],
      ["out_interface", t("Out. Interface"), "interface", ""],
      ["in_interface_list", t("In. Interface List"), "interface-list", ""],
      ["out_interface_list", t("Out. Interface List"), "interface-list", ""],
      ["connection_states", t("Connection State"), "states", []],
      ["enabled", t("Enabled"), "bool", true],
      ["comment", t("Comment"), "text", ""],
    ],
    columns: [
      ["name", t("Name")],
      ["chain", t("Chain")],
      ["action", t("Action")],
      ["protocol", t("Protocol")],
      ["src_address", t("Source")],
      ["dst_address", t("Destination")],
      ["dst_ports", t("Dst. Port")],
      ["enabled", t("Status")],
    ],
    note: t(
      "Input — к самому роутеру; Forward — транзитный трафик; Output — от роутера. Правила работают сверху вниз. Не блокируйте доступ к панели и SSH без разрешающего правила выше.",
    ),
  },
};

let editing = null;
const configNetwork = (ctx) => ctx.state.config.network || {};
const collection = (ctx, kind) =>
  kind === "filter"
    ? ctx.state.config.filter_rules || []
    : configNetwork(ctx)[kind] || [];
const splitValues = (value) =>
  String(value || "")
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);

export function networkFromAddress(value) {
  const parts = String(value).split("/");
  if (parts.length !== 2) return null;
  const [address, prefixText] = parts;
  const prefix = Number(prefixText);
  const octets = address.split(".").map(Number);
  if (
    !/^\d{1,2}$/.test(prefixText || "") ||
    address.split(".").some((part) => !/^(0|[1-9]\d{0,2})$/.test(part)) ||
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > 32 ||
    octets.length !== 4 ||
    octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  )
    return null;
  const integer = octets.reduce((total, part) => (total * 256 + part) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (integer & mask) >>> 0;
  return {
    network: `${[24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join(".")}/${prefix}`,
    gateway: address,
  };
}

export function interfaceNames(ctx) {
  const network = configNetwork(ctx);
  return [
    ...new Set([
      ...(ctx.interfaces || []).map((item) => item.name),
      ...[
        "bridges",
        "vlans",
        "virtual_interfaces",
        "wireguard_interfaces",
      ].flatMap((kind) => (network[kind] || []).map((item) => item.name)),
    ]),
  ];
}

function optionsFor(ctx, type, item) {
  const network = configNetwork(ctx);
  if (["interface", "interfaces"].includes(type))
    return interfaceNames(ctx)
      .filter((name) => name !== item.name)
      .map((name) => [name, name]);
  if (type === "pool")
    return (network.pools || []).map((pool) => [
      pool.name,
      `${pool.name} · ${pool.start}–${pool.end}`,
    ]);
  if (type === "server")
    return (network.dhcp_servers || []).map((server) => [
      server.name,
      server.name,
    ]);
  if (type === "address-list") return addressListChoices(ctx.state.config);
  if (type === "interface-list")
    return (network.interface_lists || []).map((list) => [
      list.name,
      list.name,
    ]);
  return (
    {
      dummy: [["dummy", t("dummy · программный интерфейс")]],
      chain: [
        ["input", "input"],
        ["forward", "forward"],
        ["output", "output"],
      ],
      "filter-action": [
        ["accept", "accept"],
        ["drop", "drop"],
        ["reject", "reject"],
      ],
      protocol: ["any", "tcp", "udp", "icmp", "gre", "esp", "ah"].map(
        (value) => [value, value],
      ),
      states: ["NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"].map(
        (value) => [value, value.toLowerCase()],
      ),
    }[type] || []
  );
}

function renderField(ctx, definition, item) {
  const [key, label, type, fallback, required] = definition;
  const e = ctx.e;
  const value = item[key] ?? fallback;
  if (type === "country") return countryField(ctx, key, value);
  if (type === "bool")
    return html`<div class="field router-checkbox"><span>${e(t(label))}</span><label class="checkbox-label"><input type="checkbox" name="${key}" ${value ? "checked" : ""}>${key === "stp" ? t("Защита от петель") : t("Включено")}</label></div>`;
  if (type === "lines")
    return html`<label class="field"><span>${e(t(label))}</span><textarea name="${key}" rows="3" placeholder="1.1.1.1&#10;9.9.9.9">${e(value.join("\n"))}</textarea><small>Один IPv4-адрес в строке.</small></label>`;
  const options = optionsFor(ctx, type, item);
  if (options.length || !["text", "number"].includes(type)) {
    const multiple = ["interfaces", "states"].includes(type);
    const values = multiple ? value : [value];
    const known = new Set(options.map(([id]) => id));
    for (const id of values)
      if (id && !known.has(id))
        options.push([id, html`${id} · из конфигурации`]);
    if (multiple)
      return checkboxSelect({
        name: key,
        label: t(label),
        options,
        selected: values,
        required,
      });
    return html`<label class="field"><span>${e(t(label))}</span><select name="${key}" ${required ? "required" : ""}><option value="">—</option>${options.map(([id, text]) => html`<option value="${e(id)}" ${values.includes(id) ? "selected" : ""}>${e(text)}</option>`).join("")}</select></label>`;
  }
  return html`<label class="field"><span>${e(t(label))}</span><input name="${key}" value="${e(value)}" type="${type}" placeholder="${e(type === "text" ? fallback : "")}" ${required ? "required" : ""} ${type === "number" ? 'step="1" min="0"' : 'maxlength="200"'}></label>`;
}

function toolbar(ctx, kind) {
  return html`<div class="toolbar"><button class="primary add" data-action="router-new" data-kind="${kind}" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("plus")}${t(itemSchemas[kind].label)}</button><span class="muted">${collection(ctx, kind).length} записей · черновик</span><button class="small" data-action="refresh">${ctx.icon("refresh")}Обновить</button></div>`;
}

function valueCell(ctx, key, item) {
  const value = item[key];
  if (key === "enabled")
    return html`<span class="status-tag ${value ? "on" : "off"}"><i class="dot ${value ? "" : "off"}"></i>${value ? t("enabled") : t("disabled")}</span>`;
  if (key === "stp") return value ? "on" : "off";
  if (key === "action") return ctx.actionBadge(value);
  if (key === "src_address" || key === "dst_address") {
    const source = key === "src_address";
    const country = item[source ? "src_country" : "dst_country"];
    const list = item[source ? "src_list" : "dst_list"];
    const details = [];
    if (country) details.push(`Country: ${country}`);
    if (source && item.protection?.enabled) details.push(t("Fail2ban · авто"));
    if (source && item.f2b_profile)
      details.push(
        `${item.f2b_match === "banned" ? "∈" : "∉"} f2b_${item.f2b_profile}`,
      );
    return `${ctx.e(list || value || "any")}${details.length ? html`<small class="cell-note">${ctx.e(details.join(" · "))}</small>` : ""}`;
  }
  return ctx.e(Array.isArray(value) ? value.join(", ") || "—" : (value ?? "—"));
}

function entityTable(ctx, kind) {
  const schema = itemSchemas[kind];
  const rows = collection(ctx, kind);
  const locked = ctx.state.pending || ctx.offline;
  return html`${toolbar(ctx, kind)}<div class="table-scroll router-table-scroll"><table class="rules-table router-table"><thead><tr><th>#</th>${schema.columns.map(([, label]) => html`<th>${ctx.e(t(label))}</th>`).join("")}<th></th></tr></thead><tbody>${rows.map((item, index) => html`<tr data-router-id="${ctx.e(item.id)}" data-kind="${kind}" tabindex="0" class="${item.enabled === false ? "disabled" : ""}"><td class="row-number">${kind === "filter" ? html`<button class="drag-handle" draggable="${!locked}" data-filter-drag="${ctx.e(item.id)}" aria-label="Перетащить ${ctx.e(item.name)}" title="Перетащить правило" ${locked ? "disabled" : ""}>${ctx.icon("grip")}</button>` : ""}${index}</td>${schema.columns.map(([key]) => html`<td>${valueCell(ctx, key, item)}</td>`).join("")}<td><div class="row-actions">${kind === "filter" ? html`<button class="icon ghost" data-action="router-move" data-kind="filter" data-id="${ctx.e(item.id)}" data-direction="-1" title="Выше" aria-label="Выше ${ctx.e(item.name)}" ${index === 0 || locked ? "disabled" : ""}>${ctx.icon("up")}</button><button class="icon ghost" data-action="router-move" data-kind="filter" data-id="${ctx.e(item.id)}" data-direction="1" title="Ниже" aria-label="Ниже ${ctx.e(item.name)}" ${index === rows.length - 1 || locked ? "disabled" : ""}>${ctx.icon("arrowdown")}</button>` : ""}${"enabled" in item ? html`<button class="icon ghost" data-action="router-toggle" data-kind="${kind}" data-id="${ctx.e(item.id)}" title="${item.enabled ? t("Отключить") : t("Включить")}" aria-label="${item.enabled ? t("Отключить") : t("Включить")} ${ctx.e(item.name || item.address || item.destination)}" ${locked ? "disabled" : ""}>${ctx.icon(item.enabled ? "x" : "check")}</button>` : ""}<button class="icon ghost" data-action="router-edit" data-kind="${kind}" data-id="${ctx.e(item.id)}" title="Редактировать" aria-label="Редактировать ${ctx.e(item.name || item.address || item.destination)}" ${locked ? "disabled" : ""}>${ctx.icon("edit")}</button><button class="icon ghost danger" data-action="router-remove" data-kind="${kind}" data-id="${ctx.e(item.id)}" title="Удалить из черновика" aria-label="Удалить ${ctx.e(item.name || item.address || item.destination)}" ${locked ? "disabled" : ""}>${ctx.icon("minus")}</button></div></td></tr>`).join("")}</tbody></table>${rows.length ? "" : ctx.empty(schema.icon, t("Пока нет записей"), t(schema.note))}</div><div class="router-section-note">${ctx.icon("info")}<span>${ctx.e(t(schema.note))}</span></div>`;
}

function actualRoutes(ctx) {
  const rows = ctx.networkStatus?.routes || [];
  if (!rows.length) return "";
  return html`<div class="router-subheading"><h3>Таблица маршрутизации хоста</h3><span>Только чтение${ctx.isDemo() ? t(" · пример") : ""}</span></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th>Owner</th></tr></thead><tbody>${rows.map((route) => html`<tr><td class="mono">${ctx.e(route.destination || route.dst || "default")}</td><td class="mono">${ctx.e(route.gateway || "—")}</td><td>${ctx.e(route.interface || route.dev || "—")}</td><td>${ctx.e(route.metric ?? "—")}</td><td>${route.managed ? "OpenMikroRout" : "system"}</td></tr>`).join("")}</tbody></table></div>`;
}

function renderLeases(ctx) {
  const leases = ctx.networkStatus?.leases || [];
  return html`<div class="router-subheading"><h3>Dynamic Leases</h3><button class="small" data-action="refresh">${ctx.icon("refresh")}Обновить</button></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Expires</th></tr></thead><tbody>${leases.map((lease) => html`<tr><td class="mono">${ctx.e(lease.address)}</td><td class="mono">${ctx.e(lease.mac)}</td><td>${ctx.e(lease.hostname || "—")}</td><td>${Number(lease.expires) > 0 ? ctx.e(new Date(Number(lease.expires) * 1000).toLocaleString(locale())) : "unlimited"}</td></tr>`).join("")}</tbody></table>${leases.length ? "" : ctx.empty("server", t("Нет активных аренд"), t("Здесь появятся адреса, выданные DHCP-серверами OpenMikroRout."))}</div><div class="router-subheading"><h3>Static Leases</h3><span>Постоянные привязки IP ↔ MAC</span></div>${entityTable(ctx, "dhcp_reservations")}`;
}

function renderDns(ctx) {
  const network = configNetwork(ctx);
  const dns = {
    enabled: false,
    listen_interfaces: [],
    servers: [],
    cache_size: 1000,
    local_domain: "",
    ...network.dns,
  };
  const item = { ...dns, forwarding: network.forwarding ?? null };
  const daemon =
    ctx.networkStatus?.dnsmasq?.dns || ctx.networkStatus?.dnsmasq || {};
  return html`<div class="toolbar"><span class="muted">DNS cache / forwarder</span><span class="status-tag ${daemon.running ? "on" : "off"}">${ctx.isDemo() ? "DEMO" : daemon.running ? t("Running") : t("Stopped")}</span><button class="small" data-action="router-reload-dns">Загрузить черновик</button></div><div class="view-panel router-settings"><form id="router-dns-form" class="form-grid" data-revision="${ctx.state.revision}">${[
    ["enabled", t("DNS Service"), "bool", false],
    ["listen_interfaces", t("Listen Interfaces"), "interfaces", []],
    ["servers", t("Upstream Servers"), "lines", []],
    ["cache_size", t("Cache Size"), "number", 1000],
    ["local_domain", t("Local Domain"), "text", ""],
  ]
    .map((field) => renderField(ctx, field, item))
    .join(
      "",
    )}<label class="field"><span>IPv4 Forwarding</span><select name="forwarding"><option value="preserve" ${item.forwarding === null ? "selected" : ""}>Не менять настройку хоста</option><option value="on" ${item.forwarding === true ? "selected" : ""}>Включить маршрутизацию</option><option value="off" ${item.forwarding === false ? "selected" : ""}>Выключить маршрутизацию</option></select><small>Для транзита между интерфейсами и NAT необходимо включить forwarding.</small></label><div class="field-note wide">DNS слушает только выбранные интерфейсы. Разрешите TCP / UDP 53 в Firewall для доверенной LAN. Системный resolv.conf и сторонние DNS-службы не заменяются.</div>${daemon.error ? html`<div class="connection-error wide">${ctx.e(daemon.error)}</div>` : ""}<div class="wide settings-actions"><button type="button" class="primary" data-action="router-save-dns" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("check")}Сохранить в черновик</button></div></form></div>`;
}

function renderWebSettings(ctx) {
  return html`<div class="view-panel router-settings"><form id="router-domain-form" class="form-grid" data-revision="${ctx.state.revision}"><label class="field wide"><span>Домен панели</span><input name="web_domain" type="text" value="${ctx.e(ctx.state.config.web_domain || "")}" placeholder="router.example.com" maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false"><small>Имя без протокола, порта и пути. Оставьте пустым, чтобы убрать дополнительный домен.</small></label><div class="field-note wide">Создайте DNS A-запись домена на IPv4-адрес роутера. Панель будет доступна по домену на текущем порту. Сохраните черновик, затем нажмите «Применить» и подтвердите связь.</div><div class="wide settings-actions"><button type="button" class="primary" data-action="router-save-domain" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("check")}Сохранить в черновик</button></div></form></div>`;
}

function renderOverview(ctx) {
  const network = configNetwork(ctx);
  const count = (kind) => (network[kind] || []).length;
  const cards = [
    [
      "addresses",
      "network",
      t("IP-адреса"),
      count("addresses"),
      t("Адреса на интерфейсах"),
    ],
    [
      "bridges",
      "network",
      t("Bridge"),
      count("bridges"),
      t("Объединение LAN-портов"),
    ],
    ["vlans", "swap", t("VLAN"), count("vlans"), t("Сети с тегами 802.1Q")],
    [
      "dhcp_servers",
      "server",
      t("DHCP Server"),
      count("dhcp_servers"),
      t("Автоматическая выдача IP"),
    ],
    [
      "routes",
      "arrow",
      t("Маршруты"),
      count("routes"),
      t("Шлюзы и статические сети"),
    ],
    [
      "filter",
      "shield",
      t("Firewall"),
      (ctx.state.config.filter_rules || []).length,
      t("Фильтрация входящего и транзитного трафика"),
    ],
  ];
  return html`<section id="telemetry-overview" aria-label="Мониторинг сети">${renderTelemetry(ctx)}</section><div class="overview-grid">${cards.map(([key, icon, title, total, description]) => html`<button class="overview-card" data-action="view" data-view="${key}"><div class="overview-card-top"><span>${ctx.icon(icon)}${t(title)}</span><b>${total}</b></div><p>${t(description)}</p><span class="overview-card-link">Настроить ${ctx.icon("arrow")}</span></button>`).join("")}</div><div class="router-quick-start"><h3>Быстрая настройка LAN</h3><ol><li><button data-action="view" data-view="bridges">Создайте bridge</button> и включите LAN-порты.</li><li><button data-action="view" data-view="addresses">Назначьте IP</button> bridge / VLAN-интерфейсу.</li><li><button data-action="view" data-view="pools">Создайте пул</button>, затем <button data-action="view" data-view="dhcp_servers">DHCP-сервер</button>.</li><li>Настройте <button data-action="view" data-view="routes">маршрут</button>, <button data-action="view" data-view="rules">NAT</button> и <button data-action="view" data-view="filter">Firewall</button>.</li></ol><p>Сохранение создаёт черновик. Работающая сеть изменится после применения и подтверждения связи.</p></div>`;
}

function renderBridgePorts(ctx) {
  const bridges = configNetwork(ctx).bridges || [];
  const ports = bridges.flatMap((bridge) =>
    (bridge.members || []).map((member) => ({ bridge, member })),
  );
  const locked = ctx.state.pending || ctx.offline;
  return html`<div class="toolbar"><button class="primary add" data-action="router-port-new" ${locked ? "disabled" : ""}>${ctx.icon("plus")}Добавить порт</button><span class="muted">${ports.length} участников bridge</span></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>#</th><th>Interface</th><th>Bridge</th><th>Status</th><th></th></tr></thead><tbody>${ports.map(({ bridge, member }, index) => html`<tr><td class="row-number">${index}</td><td class="mono">${ctx.e(member)}</td><td class="mono">${ctx.e(bridge.name)}</td><td>${bridge.enabled ? t("enabled") : t("disabled")}</td><td><div class="row-actions"><button class="icon ghost" data-action="router-port-edit" data-id="${ctx.e(bridge.id)}" data-member="${ctx.e(member)}" aria-label="Изменить порт ${ctx.e(member)}" ${locked ? "disabled" : ""}>${ctx.icon("edit")}</button><button class="icon ghost danger" data-action="router-port-remove" data-id="${ctx.e(bridge.id)}" data-member="${ctx.e(member)}" aria-label="Убрать порт ${ctx.e(member)}" ${locked ? "disabled" : ""}>${ctx.icon("minus")}</button></div></td></tr>`).join("")}</tbody></table>${ports.length ? "" : ctx.empty("network", t("В bridge пока нет портов"), t("Создайте bridge, затем добавьте физические или виртуальные интерфейсы."))}</div><div class="router-section-note">${ctx.icon("info")}<span>Добавление / удаление порта меняет members выбранного bridge в черновике. Сам интерфейс при удалении из bridge не удаляется.</span></div>`;
}
function renderDhcpNetworks(ctx) {
  const servers = configNetwork(ctx).dhcp_servers || [];
  return html`<div class="toolbar"><span class="muted">Параметры сетей берутся из DHCP Server</span><button class="small" data-action="view" data-view="dhcp_servers">${ctx.icon("server")}DHCP Server</button></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>Network</th><th>Gateway</th><th>DNS Servers</th><th>Interface</th><th>Server</th><th></th></tr></thead><tbody>${servers.map((server) => html`<tr data-router-id="${ctx.e(server.id)}" data-kind="dhcp_servers" tabindex="0"><td class="mono">${ctx.e(server.network)}</td><td class="mono">${ctx.e(server.gateway)}</td><td class="mono">${ctx.e((server.dns_servers || []).join(", ") || t("Local DNS"))}</td><td>${ctx.e(server.interface)}</td><td>${ctx.e(server.name)}</td><td><button class="icon ghost" data-action="router-edit" data-kind="dhcp_servers" data-id="${ctx.e(server.id)}" aria-label="Изменить сеть ${ctx.e(server.network)}" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("edit")}</button></td></tr>`).join("")}</tbody></table>${servers.length ? "" : ctx.empty("server", t("Нет DHCP-сетей"), t("Создайте DHCP Server на нужном интерфейсе и задайте сеть, gateway и DNS."))}</div>`;
}
function openPortEditor(ctx, bridgeId, member = "") {
  if (ctx.busy || ctx.state.pending || ctx.offline) return;
  const bridges = configNetwork(ctx).bridges || [];
  if (!bridges.length) {
    ctx.toast(t("Сначала создайте bridge."), true);
    return;
  }
  editing = {
    kind: "bridge_ports",
    bridgeId,
    member,
    revision: ctx.state.revision,
  };
  const item = {
    name: (bridges.find((bridge) => bridge.id === bridgeId) || bridges[0]).name,
    interface: member,
  };
  const bridgeOptions = bridges
    .map(
      (bridge) =>
        html`<option value="${ctx.e(bridge.id)}" ${bridge.id === bridgeId ? "selected" : ""}>${ctx.e(bridge.name)}</option>`,
    )
    .join("");
  ctx.dialogFrame(
    member ? t("Edit Bridge Port") : t("New Bridge Port"),
    t("Назначение интерфейса bridge сохраняется в черновик."),
    html`<div class="rule-editor-layout"><form id="router-port-form" class="winbox-form"><label class="field"><span>Bridge</span><select name="bridge_id" required>${bridgeOptions}</select></label>${renderField(ctx, ["interface", t("Interface"), "interface", "", true], item)}<div class="field-note">Один интерфейс может входить только в один bridge. Стороннее bridge-подключение не перехватывается.</div></form><aside class="rule-actions"><button class="primary" data-action="router-port-save">OK</button><button data-action="close">Cancel</button></aside></div>`,
    html`<span class="muted">Изменение портов bridge</span>`,
  );
  ctx.dialog.classList.add("winbox-editor");
}

export function renderRouterView(view, ctx) {
  if (view === "web_settings") return renderWebSettings(ctx);
  if (view === "overview") return renderOverview(ctx);
  if (view === "bridge_ports") return renderBridgePorts(ctx);
  if (view === "dhcp_networks") return renderDhcpNetworks(ctx);
  if (view === "dns") return renderDns(ctx);
  if (view === "leases") return renderLeases(ctx);
  if (itemSchemas[view])
    return (
      entityTable(ctx, view) + (view === "routes" ? actualRoutes(ctx) : "")
    );
  return "";
}

function newItem(ctx, kind) {
  const schema = itemSchemas[kind];
  const item = { id: crypto.randomUUID() };
  if (kind === "filter") item.protection = defaultRuleProtection();
  for (const [key, , type, value] of schema.fields)
    item[key] = type === "text" && key !== "kind" ? "" : structuredClone(value);
  if (kind === "routes") item.destination = "0.0.0.0/0";
  if (kind === "vlans") item.vlan_id = 20;
  if (kind === "dhcp_servers") {
    const network = configNetwork(ctx);
    const address = (network.addresses || []).find(
      (address) => address.enabled,
    );
    if (address)
      Object.assign(item, {
        interface: address.interface,
        ...networkFromAddress(address.address),
      });
    item.pool = network.pools?.[0]?.name || "";
  }
  if (kind === "dhcp_reservations")
    item.server = configNetwork(ctx).dhcp_servers?.[0]?.name || "";
  return item;
}

function showEntityEditor(
  ctx,
  kind,
  item,
  existing,
  revision = ctx.state.revision,
  tab = "general",
) {
  editing = { kind, id: item.id, item, revision, tab, existing };
  const tabs = [
    ["general", t("General")],
    ["advanced", t("Advanced")],
    ["fail2ban", "Fail2ban"],
    ["action", t("Action")],
  ];
  const advanced = new Set([
    "src_list",
    "dst_list",
    "src_country",
    "dst_country",
    "in_interface_list",
    "out_interface_list",
    "connection_states",
  ]);
  const security = new Set(["f2b_profile", "f2b_match"]);
  const fields = itemSchemas[kind].fields.filter(([key]) => {
    if (kind !== "filter") return true;
    if (tab === "advanced") return advanced.has(key);
    if (tab === "action") return key === "action";
    if (tab === "fail2ban") return false;
    return !advanced.has(key) && !security.has(key) && key !== "action";
  });
  let content =
    kind === "filter" && tab === "fail2ban"
      ? renderRuleFail2ban(ctx, item)
      : fields.map((field) => renderField(ctx, field, item)).join("");
  if (kind === "filter" && tab === "advanced")
    content += html`<details class="rule-condition-help" ${item.f2b_profile ? "open" : ""}><summary>Дополнительное условие по списку Fail2ban</summary>${renderLegacyBanMatch(ctx, item)}</details>`;
  const note =
    kind === "filter" && tab === "advanced"
      ? t(
          "Страна проверяется вместе с адресом или Address List (AND). GeoIP-список создаётся автоматически при применении. Требуется база GeoIP в Security → GeoIP. Для private IP страна неизвестна.",
        )
      : itemSchemas[kind].note;
  ctx.dialogFrame(
    `${existing ? t("Изменить") : t("Создать")}: ${t(itemSchemas[kind].title)}`,
    t("OK / Apply сохраняют настройки в общий черновик роутера."),
    html`<div class="rule-editor-layout"><form id="router-form" class="winbox-form" data-kind="${kind}" data-revision="${revision}">${content}${kind === "filter" && tab === "fail2ban" ? "" : html`<div class="field-note">${ctx.e(t(note))}</div>`}</form><aside class="rule-actions"><button class="primary" data-action="router-save">OK</button><button data-action="close">Cancel</button><button data-action="router-apply">Apply</button><div class="form-divider"></div><button data-action="router-editor-copy">${ctx.icon("copy")}Copy</button></aside></div>`,
    html`<span class="muted">Черновик · применение к сети отдельно</span>`,
    kind === "filter"
      ? html`<div class="dialog-tabs">${tabs.map(([key, label]) => html`<button class="dialog-tab ${tab === key ? "active" : ""}" data-action="router-editor-tab" data-tab="${key}">${t(label)}</button>`).join("")}</div>`
      : "",
  );
  ctx.dialog.classList.add("winbox-editor", "router-editor");
}
function openEditor(ctx, kind, id) {
  if (ctx.busy) return;
  if (ctx.state.pending || ctx.offline) {
    ctx.toast(
      t("Сначала завершите применение и восстановите связь с сервером."),
      true,
    );
    return;
  }
  const found = collection(ctx, kind).find((item) => item.id === id);
  showEntityEditor(
    ctx,
    kind,
    found ? structuredClone(found) : newItem(ctx, kind),
    !!found,
  );
}

function readForm(schema, form, original) {
  const values = new FormData(form);
  const result = structuredClone(original);
  for (const [key, , type] of schema.fields) {
    // Filter tabs mount only their own fields. Hidden conditions stay in the draft.
    if (!form.querySelector(`[name="${key}"]`)) continue;
    if (type === "bool") result[key] = values.has(key);
    else if (["interfaces", "states"].includes(type))
      result[key] = values.getAll(key).map(String);
    else if (type === "number") result[key] = Number(values.get(key));
    else if (type === "lines") result[key] = splitValues(values.get(key));
    else result[key] = String(values.get(key) || "").trim();
  }
  if (schema === itemSchemas.filter) {
    const protection = collectRuleProtection(form, original.protection);
    if (protection) result.protection = protection;
  }
  return result;
}

function updateNameReferences(config, kind, oldName, newName) {
  if (!oldName || oldName === newName) return;
  const network = config.network;
  if (kind === "pools")
    for (const server of network.dhcp_servers || [])
      if (server.pool === oldName) server.pool = newName;
  if (kind === "dhcp_servers")
    for (const lease of network.dhcp_reservations || [])
      if (lease.server === oldName) lease.server = newName;
  if (kind === "interface_lists")
    for (const rule of [...config.rules, ...(config.filter_rules || [])])
      for (const key of ["in_interface_list", "out_interface_list"])
        if (rule[key] === oldName) rule[key] = newName;
  if (["bridges", "vlans", "virtual_interfaces"].includes(kind)) {
    for (const item of [
      ...(network.addresses || []),
      ...(network.routes || []),
      ...(network.dhcp_servers || []),
    ])
      if (item.interface === oldName) item.interface = newName;
    for (const vlan of network.vlans || [])
      if (vlan.parent === oldName) vlan.parent = newName;
    for (const item of [
      ...(network.bridges || []),
      ...(network.interface_lists || []),
    ])
      item.members = item.members.map((name) =>
        name === oldName ? newName : name,
      );
    if (network.dns)
      network.dns.listen_interfaces = network.dns.listen_interfaces.map(
        (name) => (name === oldName ? newName : name),
      );
    for (const rule of [...config.rules, ...(config.filter_rules || [])])
      for (const key of ["in_interface", "out_interface"])
        if (rule[key] === oldName) rule[key] = newName;
  }
}

export async function handleRouterAction(button, ctx) {
  const { action, kind, id } = button.dataset;
  if (!action.startsWith("router-")) return false;
  if (action === "router-editor-tab") {
    if (
      editing?.kind !== "filter" ||
      !["general", "advanced", "fail2ban", "action"].includes(
        button.dataset.tab,
      )
    )
      return true;
    const item = ctx.canWrite()
      ? readForm(
          itemSchemas.filter,
          ctx.dialog.querySelector("#router-form"),
          editing.item,
        )
      : editing.item;
    showEntityEditor(
      ctx,
      "filter",
      item,
      editing.existing,
      editing.revision,
      button.dataset.tab,
    );
    return true;
  }
  if (action === "router-save-domain") {
    if (!ctx.canWrite()) throw new Error(t("Нужна учётная запись full."));
    const form = document.querySelector("#router-domain-form");
    if (!form?.reportValidity()) return true;
    const expectedRevision = Number(form.dataset.revision);
    assertDraftRevision(expectedRevision, ctx.state.revision);
    const config = structuredClone(ctx.state.config);
    config.web_domain = String(
      new FormData(form).get("web_domain") || "",
    ).trim();
    await ctx.run(async () => {
      await ctx.saveConfig(config, expectedRevision);
      ctx.toast(t("Домен сохранён в черновик"));
    });
    return true;
  }
  if (action === "router-reload-dns") {
    ctx.render();
    return true;
  }
  if (["router-port-new", "router-port-edit"].includes(action)) {
    openPortEditor(ctx, id, button.dataset.member || "");
    return true;
  }
  if (action === "router-port-remove") {
    editing = {
      kind: "bridge_ports",
      bridgeId: id,
      member: button.dataset.member,
      revision: ctx.state.revision,
    };
    ctx.dialogFrame(
      t("Убрать порт из bridge?"),
      t("Сам интерфейс не будет удалён."),
      html`<p class="preview-note">${ctx.e(button.dataset.member)} будет исключён из members выбранного bridge в черновике.</p>`,
      html`<button data-action="close">Cancel</button><button class="danger" data-action="router-port-remove-confirm">Убрать</button>`,
    );
    return true;
  }
  if (["router-port-save", "router-port-remove-confirm"].includes(action)) {
    await ctx.run(async () => {
      assertDraftRevision(editing.revision, ctx.state.revision);
      const config = structuredClone(ctx.state.config),
        bridges = config.network.bridges;
      const old = bridges.find((bridge) => bridge.id === editing.bridgeId);
      if (action === "router-port-save") {
        const form = ctx.dialog.querySelector("#router-port-form");
        if (!form.reportValidity()) return;
        const values = new FormData(form),
          target = bridges.find(
            (bridge) => bridge.id === values.get("bridge_id"),
          );
        if (!target)
          throw new Error(t("Bridge не найден. Обновите конфигурацию."));
        const name = String(values.get("interface"));
        if (old && editing.member)
          old.members = old.members.filter(
            (member) => member !== editing.member,
          );
        if (!target.members.includes(name)) target.members.push(name);
      } else if (old)
        old.members = old.members.filter((member) => member !== editing.member);
      await ctx.saveConfig(config, editing.revision);
      ctx.dialog.close();
      ctx.toast(t("Порты bridge сохранены в черновик"));
    });
    return true;
  }
  if (["router-new", "router-edit"].includes(action)) {
    openEditor(ctx, kind, id);
    return true;
  }
  if (action === "router-editor-copy") {
    const item = readForm(
      itemSchemas[editing.kind],
      ctx.dialog.querySelector("#router-form"),
      editing.item,
    );
    item.id = crypto.randomUUID();
    if (item.name)
      item.name =
        item.name.slice(
          0,
          ["bridges", "vlans", "virtual_interfaces"].includes(editing.kind)
            ? 10
            : 30,
        ) + "-copy";
    showEntityEditor(
      ctx,
      editing.kind,
      item,
      false,
      editing.revision,
      editing.tab,
    );
    return true;
  }
  if (action === "router-remove") {
    assertLinkRemoval(ctx.state.config, kind, id);
    editing = { kind, id, revision: ctx.state.revision };
    ctx.dialogFrame(
      t("Удалить запись?"),
      t("Работающая сеть изменится только после применения."),
      html`<p class="preview-note">Запись будет удалена из черновика. Если она используется другими настройками, сервер не разрешит удаление.</p>`,
      html`<button data-action="close">Cancel</button><button class="danger" data-action="router-remove-confirm">Удалить</button>`,
    );
    return true;
  }
  await ctx.run(async () => {
    let expectedRevision = ctx.state.revision;
    if (
      ["router-save", "router-apply", "router-remove-confirm"].includes(action)
    )
      expectedRevision = editing.revision;
    if (action === "router-save-dns")
      expectedRevision = Number(
        document.querySelector("#router-dns-form").dataset.revision,
      );
    assertDraftRevision(expectedRevision, ctx.state.revision);
    const config = structuredClone(ctx.state.config);
    config.network ||= {};
    if (action === "router-save-dns") {
      const form = document.querySelector("#router-dns-form");
      const values = new FormData(form);
      config.network.dns = {
        ...config.network.dns,
        enabled: values.has("enabled"),
        listen_interfaces: values.getAll("listen_interfaces").map(String),
        servers: splitValues(values.get("servers")),
        cache_size: Number(values.get("cache_size")),
        local_domain: String(values.get("local_domain") || "").trim(),
      };
      config.network.forwarding =
        values.get("forwarding") === "preserve"
          ? null
          : values.get("forwarding") === "on";
    } else {
      const currentKind = [
        "router-save",
        "router-apply",
        "router-remove-confirm",
      ].includes(action)
        ? editing.kind
        : kind;
      const currentId = [
        "router-save",
        "router-apply",
        "router-remove-confirm",
      ].includes(action)
        ? editing.id
        : id;
      const rows =
        currentKind === "filter"
          ? (config.filter_rules ||= [])
          : (config.network[currentKind] ||= []);
      const index = rows.findIndex((item) => item.id === currentId);
      if (["router-save", "router-apply"].includes(action)) {
        const form = ctx.dialog.querySelector("#router-form");
        if (!form.reportValidity()) return;
        const item = readForm(itemSchemas[currentKind], form, editing.item);
        if (index >= 0) {
          updateNameReferences(
            config,
            currentKind,
            rows[index].name,
            item.name,
          );
          rows[index] = item;
        } else rows.push(item);
      } else if (action === "router-remove-confirm") {
        assertLinkRemoval(config, currentKind, currentId);
        if (index >= 0) rows.splice(index, 1);
      } else if (action === "router-toggle") {
        if (index >= 0) rows[index].enabled = !rows[index].enabled;
      } else if (action === "router-move") {
        const target = index + Number(button.dataset.direction);
        if (index < 0 || target < 0 || target >= rows.length) return;
        [rows[index], rows[target]] = [rows[target], rows[index]];
      }
    }
    const saved = await ctx.saveConfig(config, expectedRevision);
    if (action === "router-apply") {
      editing.revision = saved.revision;
      const rows =
        editing.kind === "filter"
          ? saved.config.filter_rules
          : saved.config.network[editing.kind];
      editing.item = structuredClone(
        rows.find((item) => item.id === editing.id),
      );
      const form = ctx.dialog.querySelector("#router-form");
      if (form) form.dataset.revision = String(saved.revision);
    } else ctx.dialog.close();
    ctx.toast(t("Изменения роутера сохранены в черновик"));
  });
  return true;
}

export function handleRouterChange(event, ctx) {
  const dnsForm = event.target.closest("#router-dns-form");
  if (dnsForm) dnsForm.dataset.dirty = "true";
  const portForm = event.target.closest("#router-port-form");
  if (portForm && event.target.name === "bridge_id") {
    const bridge = (configNetwork(ctx).bridges || []).find(
      (item) => item.id === event.target.value,
    );
    const select = portForm.querySelector('[name="interface"]'),
      previous = select.value;
    select.innerHTML =
      html`<option value="">—</option>` +
      interfaceNames(ctx)
        .filter((name) => name !== bridge?.name)
        .map(
          (name) =>
            html`<option value="${ctx.e(name)}" ${name === previous ? "selected" : ""}>${ctx.e(name)}</option>`,
        )
        .join("");
    return;
  }
  const form = event.target.closest("#router-form");
  if (
    form?.dataset.kind === "filter" &&
    event.target.name === "f2b_profile" &&
    ctx.canWrite()
  ) {
    const item = readForm(itemSchemas.filter, form, editing.item);
    showEntityEditor(
      ctx,
      "filter",
      item,
      editing.existing,
      editing.revision,
      editing.tab,
    );
    return;
  }
  if (
    !form ||
    form.dataset.kind !== "dhcp_servers" ||
    event.target.name !== "interface"
  )
    return;
  const address = (configNetwork(ctx).addresses || []).find(
    (item) => item.enabled && item.interface === event.target.value,
  );
  const defaults = address && networkFromAddress(address.address);
  if (defaults)
    for (const key of ["network", "gateway"])
      form.querySelector(`[name="${key}"]`).value = defaults[key];
}

export function installRouterEvents(getContext) {
  let dragged = null;
  const clear = () => {
    dragged = null;
    document.body.classList.remove("router-drag-active");
    document
      .querySelectorAll(
        ".router-table .drop-before,.router-table .drop-after,.router-table .dragging",
      )
      .forEach((row) =>
        row.classList.remove("drop-before", "drop-after", "dragging"),
      );
  };
  document.addEventListener("dblclick", (event) => {
    const row = event.target.closest("[data-router-id]");
    if (row && !event.target.closest("button,input"))
      openEditor(getContext(), row.dataset.kind, row.dataset.routerId);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.target.matches("[data-router-id]")) {
      event.preventDefault();
      openEditor(
        getContext(),
        event.target.dataset.kind,
        event.target.dataset.routerId,
      );
    }
  });
  document.addEventListener("dragstart", (event) => {
    const grip = event.target.closest("[data-filter-drag]");
    if (!grip) return;
    const ctx = getContext();
    if (grip.disabled || ctx.state.pending || ctx.offline) {
      event.preventDefault();
      return;
    }
    dragged = grip.dataset.filterDrag;
    document.body.classList.add("router-drag-active");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", dragged);
    const row = grip.closest("[data-router-id]");
    event.dataTransfer.setDragImage(row, 30, row.offsetHeight / 2);
    row.classList.add("dragging");
  });
  document.addEventListener("dragover", (event) => {
    const row = event.target.closest('[data-router-id][data-kind="filter"]');
    if (!dragged || !row || row.dataset.routerId === dragged) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    document
      .querySelectorAll(".router-table .drop-before,.router-table .drop-after")
      .forEach((item) => item.classList.remove("drop-before", "drop-after"));
    const rect = row.getBoundingClientRect();
    row.classList.add(
      event.clientY < rect.top + rect.height / 2 ? "drop-before" : "drop-after",
    );
  });
  document.addEventListener("drop", (event) => {
    const row = event.target.closest('[data-router-id][data-kind="filter"]');
    if (!dragged || !row) return;
    event.preventDefault();
    const id = dragged,
      target = row.dataset.routerId,
      rect = row.getBoundingClientRect();
    const placement =
      event.clientY < rect.top + rect.height / 2 ? "before" : "after";
    clear();
    const ctx = getContext();
    if (ctx.state.pending || ctx.offline) return;
    void ctx.run(async () => {
      const config = structuredClone(ctx.state.config);
      const rows = config.filter_rules || [];
      const reordered = reorderRules(rows, id, target, placement);
      if (reordered.every((rule, index) => rule.id === rows[index].id)) return;
      config.filter_rules = reordered;
      await ctx.saveConfig(config);
      ctx.toast(t("Порядок Filter Rules сохранён в черновик"));
    });
  });
  document.addEventListener("dragend", clear);
}
