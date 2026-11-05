import { assertDraftRevision, assertLinkRemoval } from "./draft-guards.js";
import { reorderRules } from "./rule-order.js";
import { renderTelemetry } from "./telemetry-ui.js?v=7";

/** Router configuration views. All writes use the existing revisioned draft API. */

export const routerViews = {
  web_settings: ["Web Interface", "Домен для доступа к панели OpenMikroRout."],
  bridge_ports: [
    "Bridge Ports",
    "Участники bridge и принадлежность физических / виртуальных интерфейсов.",
  ],
  dhcp_networks: [
    "DHCP Networks",
    "Сетевые параметры DHCP-серверов: network, gateway и DNS.",
  ],
  overview: [
    "Обзор роутера",
    "Состояние сети и основные настройки OpenMikroRout.",
  ],
  addresses: [
    "IP Addresses",
    "Назначайте IPv4-адреса физическим, bridge и VLAN-интерфейсам.",
  ],
  bridges: ["Bridge", "Объединяйте интерфейсы в общую локальную сеть."],
  vlans: [
    "VLAN",
    "Создавайте изолированные сети 802.1Q на выбранном интерфейсе.",
  ],
  virtual_interfaces: [
    "Virtual Interfaces",
    "Программные dummy-интерфейсы для локальных адресов и маршрутизации.",
  ],
  routes: ["IP Routes", "Статические маршруты и шлюз по умолчанию."],
  dhcp_servers: [
    "DHCP Server",
    "Выдавайте адреса клиентам на нужном интерфейсе.",
  ],
  pools: ["IP Pools", "Пулы IPv4-адресов для DHCP-серверов."],
  leases: [
    "DHCP Leases",
    "Активные аренды и постоянные привязки IP к MAC-адресам.",
  ],
  dns: ["DNS & Routing", "Кэширующий DNS, upstream-серверы и IPv4 forwarding."],
  dns_static: [
    "DNS Static",
    "Локальные IPv4 A-записи для устройств и сервисов.",
  ],
  interface_lists: [
    "Interface Lists",
    "Группы WAN, LAN и других интерфейсов для правил Firewall.",
  ],
  filter: [
    "Firewall Filter",
    "Правила input, forward и output для защиты Linux-роутера.",
  ],
};

const itemSchemas = {
  dns_static: {
    title: "Static DNS Record",
    label: "Добавить запись",
    icon: "list",
    fields: [
      ["name", "DNS Name", "text", "nas.home", true],
      ["address", "IPv4 Address", "text", "192.168.10.20", true],
      ["ttl", "TTL · seconds", "number", 300, true],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["address", "Address"],
      ["ttl", "TTL"],
      ["enabled", "Status"],
      ["comment", "Comment"],
    ],
    note: "Записи обслуживаются локальным DNS OpenMikroRout. Включите DNS в Settings и настройте адрес роутера как DNS у клиентов. Допускается несколько A-записей с одним именем.",
  },
  addresses: {
    title: "IP Address",
    label: "Назначить IP",
    icon: "network",
    fields: [
      ["interface", "Interface", "interface", "", true],
      ["address", "Address / Prefix", "text", "192.168.10.1/24", true],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["address", "Address"],
      ["interface", "Interface"],
      ["enabled", "Status"],
      ["comment", "Comment"],
    ],
    note: "Укажите адрес с длиной префикса. Например, 192.168.10.1/24. Сначала создайте bridge / VLAN, если адрес должен находиться на нём.",
  },
  bridges: {
    title: "Bridge",
    label: "Создать bridge",
    icon: "network",
    fields: [
      ["name", "Name", "text", "bridge-lan", true],
      ["members", "Ports", "interfaces", []],
      ["stp", "Spanning Tree", "bool", true],
      ["mtu", "MTU", "number", 1500],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["members", "Ports"],
      ["stp", "STP"],
      ["mtu", "MTU"],
      ["enabled", "Status"],
    ],
    note: "Ports — интерфейсы, которые станут участниками bridge. IP и DHCP обычно назначаются на сам bridge. Интерфейс, уже включённый в чужой bridge, не будет захвачен автоматически.",
  },
  vlans: {
    title: "VLAN Interface",
    label: "Создать VLAN",
    icon: "network",
    fields: [
      ["name", "Name", "text", "vlan20", true],
      ["parent", "Parent Interface", "interface", "", true],
      ["vlan_id", "VLAN ID", "number", 20, true],
      ["mtu", "MTU", "number", 1500],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["parent", "Parent"],
      ["vlan_id", "VLAN ID"],
      ["mtu", "MTU"],
      ["enabled", "Status"],
    ],
    note: "Тег 802.1Q: VLAN ID от 1 до 4094. После создания назначьте IP-адрес и при необходимости DHCP на новый VLAN-интерфейс.",
  },
  virtual_interfaces: {
    title: "Virtual Interface",
    label: "Создать интерфейс",
    icon: "network",
    fields: [
      ["name", "Name", "text", "dummy0", true],
      ["kind", "Type", "dummy", "dummy"],
      ["mtu", "MTU", "number", 1500],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["kind", "Type"],
      ["mtu", "MTU"],
      ["enabled", "Status"],
      ["comment", "Comment"],
    ],
    note: "Dummy — программный интерфейс без физического порта. Подходит для локальных адресов и маршрутизации; это не VPN-туннель.",
  },
  routes: {
    title: "Static Route",
    label: "Добавить маршрут",
    icon: "arrow",
    fields: [
      ["destination", "Dst. Address", "text", "0.0.0.0/0", true],
      ["gateway", "Gateway", "text", ""],
      ["interface", "Interface", "interface", ""],
      ["metric", "Metric", "number", 100],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["destination", "Dst. Address"],
      ["gateway", "Gateway"],
      ["interface", "Interface"],
      ["metric", "Metric"],
      ["enabled", "Status"],
    ],
    note: "0.0.0.0/0 — маршрут по умолчанию. Укажите gateway и / или интерфейс. Системные маршруты показаны ниже отдельно и не редактируются этой таблицей.",
  },
  pools: {
    title: "IP Pool",
    label: "Создать пул",
    icon: "list",
    fields: [
      ["name", "Name", "text", "pool-lan", true],
      ["start", "From Address", "text", "192.168.10.100", true],
      ["end", "To Address", "text", "192.168.10.200", true],
    ],
    columns: [
      ["name", "Name"],
      ["start", "From Address"],
      ["end", "To Address"],
    ],
    note: "Начальный и конечный адрес включены в диапазон. Не включайте адрес самого роутера, network и broadcast. Пул выбирается в настройках DHCP Server.",
  },
  dhcp_servers: {
    title: "DHCP Server",
    label: "Создать DHCP",
    icon: "server",
    fields: [
      ["name", "Name", "text", "dhcp-lan", true],
      ["interface", "Interface", "interface", "", true],
      ["pool", "Address Pool", "pool", "", true],
      ["network", "Network", "text", "192.168.10.0/24", true],
      ["gateway", "Gateway", "text", "192.168.10.1", true],
      ["dns_servers", "DNS Servers", "lines", []],
      ["lease_minutes", "Lease Time (min)", "number", 720],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["interface", "Interface"],
      ["pool", "Address Pool"],
      ["network", "Network"],
      ["lease_minutes", "Lease, min"],
      ["enabled", "Status"],
    ],
    note: "Назначьте статический IP выбранному интерфейсу и создайте пул. Укажите DNS Servers либо включите локальный DNS на этом интерфейсе. На одном интерфейсе должен работать один DHCP-сервер; существующие системные DHCP-службы приложение не останавливает.",
  },
  dhcp_reservations: {
    title: "Static DHCP Lease",
    label: "Добавить привязку",
    icon: "lock",
    fields: [
      ["server", "DHCP Server", "server", "", true],
      ["mac", "MAC Address", "text", "", true],
      ["address", "IP Address", "text", "", true],
      ["hostname", "Hostname", "text", ""],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["address", "IP Address"],
      ["mac", "MAC Address"],
      ["hostname", "Hostname"],
      ["server", "Server"],
      ["enabled", "Status"],
    ],
    note: "Клиент с этим MAC-адресом будет получать постоянный IP в сети указанного DHCP-сервера.",
  },
  interface_lists: {
    title: "Interface List",
    label: "Создать список",
    icon: "list",
    fields: [
      ["name", "Name", "text", "LAN", true],
      ["members", "Interfaces", "interfaces", []],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["members", "Interfaces"],
      ["comment", "Comment"],
    ],
    note: "Список объединяет интерфейсы логически и не соединяет их в bridge. Используйте WAN / LAN в условиях Firewall и NAT.",
  },
  filter: {
    title: "Filter Rule",
    label: "Добавить правило",
    icon: "shield",
    fields: [
      ["name", "Name", "text", "", true],
      ["chain", "Chain", "chain", "forward"],
      ["action", "Action", "filter-action", "accept"],
      ["protocol", "Protocol", "protocol", "any"],
      ["src_address", "Src. Address", "text", ""],
      ["dst_address", "Dst. Address", "text", ""],
      ["src_list", "Src. Address List", "address-list", ""],
      ["dst_list", "Dst. Address List", "address-list", ""],
      ["src_ports", "Src. Port", "text", ""],
      ["dst_ports", "Dst. Port", "text", ""],
      ["in_interface", "In. Interface", "interface", ""],
      ["out_interface", "Out. Interface", "interface", ""],
      ["in_interface_list", "In. Interface List", "interface-list", ""],
      ["out_interface_list", "Out. Interface List", "interface-list", ""],
      ["connection_states", "Connection State", "states", []],
      ["enabled", "Enabled", "bool", true],
      ["comment", "Comment", "text", ""],
    ],
    columns: [
      ["name", "Name"],
      ["chain", "Chain"],
      ["action", "Action"],
      ["protocol", "Protocol"],
      ["src_address", "Source"],
      ["dst_address", "Destination"],
      ["dst_ports", "Dst. Port"],
      ["enabled", "Status"],
    ],
    note: "Input — к самому роутеру; Forward — транзитный трафик; Output — от роутера. Правила работают сверху вниз. Не блокируйте доступ к панели и SSH без разрешающего правила выше.",
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
  if (type === "address-list")
    return ctx.state.config.address_lists.map((list) => [list.name, list.name]);
  if (type === "interface-list")
    return (network.interface_lists || []).map((list) => [
      list.name,
      list.name,
    ]);
  return (
    {
      dummy: [["dummy", "dummy · программный интерфейс"]],
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
  if (type === "bool")
    return `<div class="field router-checkbox"><span>${e(label)}</span><label class="checkbox-label"><input type="checkbox" name="${key}" ${value ? "checked" : ""}>${key === "stp" ? "Защита от петель" : "Включено"}</label></div>`;
  if (type === "lines")
    return `<label class="field"><span>${e(label)}</span><textarea name="${key}" rows="3" placeholder="1.1.1.1&#10;9.9.9.9">${e(value.join("\n"))}</textarea><small>Один IPv4-адрес в строке.</small></label>`;
  const options = optionsFor(ctx, type, item);
  if (options.length || !["text", "number"].includes(type)) {
    const multiple = ["interfaces", "states"].includes(type);
    const values = multiple ? value : [value];
    const known = new Set(options.map(([id]) => id));
    for (const id of values)
      if (id && !known.has(id)) options.push([id, `${id} · из конфигурации`]);
    return `<label class="field"><span>${e(label)}</span><select name="${key}" ${multiple ? 'multiple size="5"' : ""} ${required ? "required" : ""}>${multiple ? "" : '<option value="">—</option>'}${options.map(([id, text]) => `<option value="${e(id)}" ${values.includes(id) ? "selected" : ""}>${e(text)}</option>`).join("")}</select>${multiple ? "<small>Ctrl / Cmd — выбрать несколько.</small>" : ""}</label>`;
  }
  return `<label class="field"><span>${e(label)}</span><input name="${key}" value="${e(value)}" type="${type}" placeholder="${e(type === "text" ? fallback : "")}" ${required ? "required" : ""} ${type === "number" ? 'step="1" min="0"' : 'maxlength="200"'}></label>`;
}

function toolbar(ctx, kind) {
  return `<div class="toolbar"><button class="primary add" data-action="router-new" data-kind="${kind}" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("plus")}${itemSchemas[kind].label}</button><span class="muted">${collection(ctx, kind).length} записей · черновик</span><button class="small" data-action="refresh">${ctx.icon("refresh")}Обновить</button></div>`;
}

function valueCell(ctx, key, item) {
  const value = item[key];
  if (key === "enabled")
    return `<span class="status-tag ${value ? "on" : "off"}"><i class="dot ${value ? "" : "off"}"></i>${value ? "enabled" : "disabled"}</span>`;
  if (key === "stp") return value ? "on" : "off";
  if (key === "action") return ctx.actionBadge(value);
  if (key === "src_address") return ctx.e(item.src_list || value || "any");
  if (key === "dst_address") return ctx.e(item.dst_list || value || "any");
  return ctx.e(Array.isArray(value) ? value.join(", ") || "—" : (value ?? "—"));
}

function entityTable(ctx, kind) {
  const schema = itemSchemas[kind];
  const rows = collection(ctx, kind);
  const locked = ctx.state.pending || ctx.offline;
  return `${toolbar(ctx, kind)}<div class="table-scroll router-table-scroll"><table class="rules-table router-table"><thead><tr><th>#</th>${schema.columns.map(([, label]) => `<th>${ctx.e(label)}</th>`).join("")}<th></th></tr></thead><tbody>${rows.map((item, index) => `<tr data-router-id="${ctx.e(item.id)}" data-kind="${kind}" tabindex="0" class="${item.enabled === false ? "disabled" : ""}"><td class="row-number">${kind === "filter" ? `<button class="drag-handle" draggable="${!locked}" data-filter-drag="${ctx.e(item.id)}" aria-label="Перетащить ${ctx.e(item.name)}" title="Перетащить правило" ${locked ? "disabled" : ""}>${ctx.icon("grip")}</button>` : ""}${index}</td>${schema.columns.map(([key]) => `<td>${valueCell(ctx, key, item)}</td>`).join("")}<td><div class="row-actions">${kind === "filter" ? `<button class="icon ghost" data-action="router-move" data-kind="filter" data-id="${ctx.e(item.id)}" data-direction="-1" title="Выше" aria-label="Выше ${ctx.e(item.name)}" ${index === 0 || locked ? "disabled" : ""}>${ctx.icon("up")}</button><button class="icon ghost" data-action="router-move" data-kind="filter" data-id="${ctx.e(item.id)}" data-direction="1" title="Ниже" aria-label="Ниже ${ctx.e(item.name)}" ${index === rows.length - 1 || locked ? "disabled" : ""}>${ctx.icon("arrowdown")}</button>` : ""}${"enabled" in item ? `<button class="icon ghost" data-action="router-toggle" data-kind="${kind}" data-id="${ctx.e(item.id)}" title="${item.enabled ? "Отключить" : "Включить"}" aria-label="${item.enabled ? "Отключить" : "Включить"} ${ctx.e(item.name || item.address || item.destination)}" ${locked ? "disabled" : ""}>${ctx.icon(item.enabled ? "x" : "check")}</button>` : ""}<button class="icon ghost" data-action="router-edit" data-kind="${kind}" data-id="${ctx.e(item.id)}" title="Редактировать" aria-label="Редактировать ${ctx.e(item.name || item.address || item.destination)}" ${locked ? "disabled" : ""}>${ctx.icon("edit")}</button><button class="icon ghost danger" data-action="router-remove" data-kind="${kind}" data-id="${ctx.e(item.id)}" title="Удалить из черновика" aria-label="Удалить ${ctx.e(item.name || item.address || item.destination)}" ${locked ? "disabled" : ""}>${ctx.icon("minus")}</button></div></td></tr>`).join("")}</tbody></table>${rows.length ? "" : ctx.empty(schema.icon, "Пока нет записей", schema.note)}</div><div class="router-section-note">${ctx.icon("info")}<span>${ctx.e(schema.note)}</span></div>`;
}

function actualRoutes(ctx) {
  const rows = ctx.networkStatus?.routes || [];
  if (!rows.length) return "";
  return `<div class="router-subheading"><h3>Таблица маршрутизации хоста</h3><span>Только чтение${ctx.isDemo() ? " · пример" : ""}</span></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th>Owner</th></tr></thead><tbody>${rows.map((route) => `<tr><td class="mono">${ctx.e(route.destination || route.dst || "default")}</td><td class="mono">${ctx.e(route.gateway || "—")}</td><td>${ctx.e(route.interface || route.dev || "—")}</td><td>${ctx.e(route.metric ?? "—")}</td><td>${route.managed ? "OpenMikroRout" : "system"}</td></tr>`).join("")}</tbody></table></div>`;
}

function renderLeases(ctx) {
  const leases = ctx.networkStatus?.leases || [];
  return `<div class="router-subheading"><h3>Dynamic Leases</h3><button class="small" data-action="refresh">${ctx.icon("refresh")}Обновить</button></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Expires</th></tr></thead><tbody>${leases.map((lease) => `<tr><td class="mono">${ctx.e(lease.address)}</td><td class="mono">${ctx.e(lease.mac)}</td><td>${ctx.e(lease.hostname || "—")}</td><td>${Number(lease.expires) > 0 ? ctx.e(new Date(Number(lease.expires) * 1000).toLocaleString("ru-RU")) : "unlimited"}</td></tr>`).join("")}</tbody></table>${leases.length ? "" : ctx.empty("server", "Нет активных аренд", "Здесь появятся адреса, выданные DHCP-серверами OpenMikroRout.")}</div><div class="router-subheading"><h3>Static Leases</h3><span>Постоянные привязки IP ↔ MAC</span></div>${entityTable(ctx, "dhcp_reservations")}`;
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
  return `<div class="toolbar"><span class="muted">DNS cache / forwarder</span><span class="status-tag ${daemon.running ? "on" : "off"}">${ctx.isDemo() ? "DEMO" : daemon.running ? "Running" : "Stopped"}</span><button class="small" data-action="router-reload-dns">Загрузить черновик</button></div><div class="view-panel router-settings"><form id="router-dns-form" class="form-grid" data-revision="${ctx.state.revision}">${[
    ["enabled", "DNS Service", "bool", false],
    ["listen_interfaces", "Listen Interfaces", "interfaces", []],
    ["servers", "Upstream Servers", "lines", []],
    ["cache_size", "Cache Size", "number", 1000],
    ["local_domain", "Local Domain", "text", ""],
  ]
    .map((field) => renderField(ctx, field, item))
    .join(
      "",
    )}<label class="field"><span>IPv4 Forwarding</span><select name="forwarding"><option value="preserve" ${item.forwarding === null ? "selected" : ""}>Не менять настройку хоста</option><option value="on" ${item.forwarding === true ? "selected" : ""}>Включить маршрутизацию</option><option value="off" ${item.forwarding === false ? "selected" : ""}>Выключить маршрутизацию</option></select><small>Для транзита между интерфейсами и NAT необходимо включить forwarding.</small></label><div class="field-note wide">DNS слушает только выбранные интерфейсы. Разрешите TCP / UDP 53 в Firewall для доверенной LAN. Системный resolv.conf и сторонние DNS-службы не заменяются.</div>${daemon.error ? `<div class="connection-error wide">${ctx.e(daemon.error)}</div>` : ""}<div class="wide settings-actions"><button type="button" class="primary" data-action="router-save-dns" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("check")}Сохранить в черновик</button></div></form></div>`;
}

function renderWebSettings(ctx) {
  return `<div class="view-panel router-settings"><form id="router-domain-form" class="form-grid" data-revision="${ctx.state.revision}"><label class="field wide"><span>Домен панели</span><input name="web_domain" type="text" value="${ctx.e(ctx.state.config.web_domain || "")}" placeholder="router.example.com" maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false"><small>Имя без протокола, порта и пути. Оставьте пустым, чтобы убрать дополнительный домен.</small></label><div class="field-note wide">Создайте DNS A-запись домена на IPv4-адрес роутера. Панель будет доступна по домену на текущем порту. Сохраните черновик, затем нажмите «Применить» и подтвердите связь.</div><div class="wide settings-actions"><button type="button" class="primary" data-action="router-save-domain" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("check")}Сохранить в черновик</button></div></form></div>`;
}

function renderOverview(ctx) {
  const network = configNetwork(ctx);
  const count = (kind) => (network[kind] || []).length;
  const cards = [
    [
      "addresses",
      "network",
      "IP-адреса",
      count("addresses"),
      "Адреса на интерфейсах",
    ],
    [
      "bridges",
      "network",
      "Bridge",
      count("bridges"),
      "Объединение LAN-портов",
    ],
    ["vlans", "swap", "VLAN", count("vlans"), "Сети с тегами 802.1Q"],
    [
      "dhcp_servers",
      "server",
      "DHCP Server",
      count("dhcp_servers"),
      "Автоматическая выдача IP",
    ],
    [
      "routes",
      "arrow",
      "Маршруты",
      count("routes"),
      "Шлюзы и статические сети",
    ],
    [
      "filter",
      "shield",
      "Firewall",
      (ctx.state.config.filter_rules || []).length,
      "Фильтрация входящего и транзитного трафика",
    ],
  ];
  return `<div class="overview-intro overview-intro-compact"><div class="overview-brand"><img src="/logo.png?v=5" alt="OpenMikroRout"><div><h2>${ctx.e(ctx.isDemo() ? "Demo Router" : ctx.state.hostname || "OpenMikroRout")}</h2><p>Интерфейсы и состояние сети</p></div></div><span class="mode-chip ${ctx.isDemo() ? "" : "live"}">${ctx.isDemo() ? "DEMO WORKSPACE" : "LINUX ROUTER"}</span></div><section id="telemetry-overview" aria-label="Мониторинг сети">${renderTelemetry(ctx)}</section><div class="overview-grid">${cards.map(([key, icon, title, total, description]) => `<button class="overview-card" data-action="view" data-view="${key}"><div class="overview-card-top"><span>${ctx.icon(icon)}${title}</span><b>${total}</b></div><p>${description}</p><span class="overview-card-link">Настроить ${ctx.icon("arrow")}</span></button>`).join("")}</div><div class="router-quick-start"><h3>Быстрая настройка LAN</h3><ol><li><button data-action="view" data-view="bridges">Создайте bridge</button> и включите LAN-порты.</li><li><button data-action="view" data-view="addresses">Назначьте IP</button> bridge / VLAN-интерфейсу.</li><li><button data-action="view" data-view="pools">Создайте пул</button>, затем <button data-action="view" data-view="dhcp_servers">DHCP-сервер</button>.</li><li>Настройте <button data-action="view" data-view="routes">маршрут</button>, <button data-action="view" data-view="rules">NAT</button> и <button data-action="view" data-view="filter">Firewall</button>.</li></ol><p>Сохранение создаёт черновик. Работающая сеть изменится после применения и подтверждения связи.</p></div>`;
}

function renderBridgePorts(ctx) {
  const bridges = configNetwork(ctx).bridges || [];
  const ports = bridges.flatMap((bridge) =>
    (bridge.members || []).map((member) => ({ bridge, member })),
  );
  const locked = ctx.state.pending || ctx.offline;
  return `<div class="toolbar"><button class="primary add" data-action="router-port-new" ${locked ? "disabled" : ""}>${ctx.icon("plus")}Добавить порт</button><span class="muted">${ports.length} участников bridge</span></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>#</th><th>Interface</th><th>Bridge</th><th>Status</th><th></th></tr></thead><tbody>${ports.map(({ bridge, member }, index) => `<tr><td class="row-number">${index}</td><td class="mono">${ctx.e(member)}</td><td class="mono">${ctx.e(bridge.name)}</td><td>${bridge.enabled ? "enabled" : "disabled"}</td><td><div class="row-actions"><button class="icon ghost" data-action="router-port-edit" data-id="${ctx.e(bridge.id)}" data-member="${ctx.e(member)}" aria-label="Изменить порт ${ctx.e(member)}" ${locked ? "disabled" : ""}>${ctx.icon("edit")}</button><button class="icon ghost danger" data-action="router-port-remove" data-id="${ctx.e(bridge.id)}" data-member="${ctx.e(member)}" aria-label="Убрать порт ${ctx.e(member)}" ${locked ? "disabled" : ""}>${ctx.icon("minus")}</button></div></td></tr>`).join("")}</tbody></table>${ports.length ? "" : ctx.empty("network", "В bridge пока нет портов", "Создайте bridge, затем добавьте физические или виртуальные интерфейсы.")}</div><div class="router-section-note">${ctx.icon("info")}<span>Добавление / удаление порта меняет members выбранного bridge в черновике. Сам интерфейс при удалении из bridge не удаляется.</span></div>`;
}
function renderDhcpNetworks(ctx) {
  const servers = configNetwork(ctx).dhcp_servers || [];
  return `<div class="toolbar"><span class="muted">Параметры сетей берутся из DHCP Server</span><button class="small" data-action="view" data-view="dhcp_servers">${ctx.icon("server")}DHCP Server</button></div><div class="table-scroll router-table-scroll"><table class="rules-table"><thead><tr><th>Network</th><th>Gateway</th><th>DNS Servers</th><th>Interface</th><th>Server</th><th></th></tr></thead><tbody>${servers.map((server) => `<tr data-router-id="${ctx.e(server.id)}" data-kind="dhcp_servers" tabindex="0"><td class="mono">${ctx.e(server.network)}</td><td class="mono">${ctx.e(server.gateway)}</td><td class="mono">${ctx.e((server.dns_servers || []).join(", ") || "Local DNS")}</td><td>${ctx.e(server.interface)}</td><td>${ctx.e(server.name)}</td><td><button class="icon ghost" data-action="router-edit" data-kind="dhcp_servers" data-id="${ctx.e(server.id)}" aria-label="Изменить сеть ${ctx.e(server.network)}" ${ctx.state.pending || ctx.offline ? "disabled" : ""}>${ctx.icon("edit")}</button></td></tr>`).join("")}</tbody></table>${servers.length ? "" : ctx.empty("server", "Нет DHCP-сетей", "Создайте DHCP Server на нужном интерфейсе и задайте сеть, gateway и DNS.")}</div>`;
}
function openPortEditor(ctx, bridgeId, member = "") {
  if (ctx.busy || ctx.state.pending || ctx.offline) return;
  const bridges = configNetwork(ctx).bridges || [];
  if (!bridges.length) {
    ctx.toast("Сначала создайте bridge.", true);
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
        `<option value="${ctx.e(bridge.id)}" ${bridge.id === bridgeId ? "selected" : ""}>${ctx.e(bridge.name)}</option>`,
    )
    .join("");
  ctx.dialogFrame(
    member ? "Edit Bridge Port" : "New Bridge Port",
    "Назначение интерфейса bridge сохраняется в черновик.",
    `<div class="rule-editor-layout"><form id="router-port-form" class="winbox-form"><label class="field"><span>Bridge</span><select name="bridge_id" required>${bridgeOptions}</select></label>${renderField(ctx, ["interface", "Interface", "interface", "", true], item)}<div class="field-note">Один интерфейс может входить только в один bridge. Стороннее bridge-подключение не перехватывается.</div></form><aside class="rule-actions"><button class="primary" data-action="router-port-save">OK</button><button data-action="close">Cancel</button></aside></div>`,
    '<span class="muted">Изменение портов bridge</span>',
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
) {
  editing = { kind, id: item.id, item, revision };
  ctx.dialogFrame(
    `${existing ? "Edit" : "New"} ${itemSchemas[kind].title}`,
    "OK / Apply сохраняют настройки в общий черновик роутера.",
    `<div class="rule-editor-layout"><form id="router-form" class="winbox-form" data-kind="${kind}" data-revision="${revision}">${itemSchemas[kind].fields.map((field) => renderField(ctx, field, item)).join("")}<div class="field-note">${ctx.e(itemSchemas[kind].note)}</div></form><aside class="rule-actions"><button class="primary" data-action="router-save">OK</button><button data-action="close">Cancel</button><button data-action="router-apply">Apply</button><div class="form-divider"></div><button data-action="router-editor-copy">${ctx.icon("copy")}Copy</button></aside></div>`,
    '<span class="muted">Черновик · применение к сети отдельно</span>',
  );
  ctx.dialog.classList.add("winbox-editor", "router-editor");
}
function openEditor(ctx, kind, id) {
  if (ctx.busy) return;
  if (ctx.state.pending || ctx.offline) {
    ctx.toast(
      "Сначала завершите применение и восстановите связь с сервером.",
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
    if (type === "bool") result[key] = values.has(key);
    else if (["interfaces", "states"].includes(type))
      result[key] = values.getAll(key).map(String);
    else if (type === "number") result[key] = Number(values.get(key));
    else if (type === "lines") result[key] = splitValues(values.get(key));
    else result[key] = String(values.get(key) || "").trim();
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
  if (action === "router-save-domain") {
    if (!ctx.canWrite()) throw new Error("Нужна учётная запись full.");
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
      ctx.toast("Домен сохранён в черновик");
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
      "Убрать порт из bridge?",
      "Сам интерфейс не будет удалён.",
      `<p class="preview-note">${ctx.e(button.dataset.member)} будет исключён из members выбранного bridge в черновике.</p>`,
      '<button data-action="close">Cancel</button><button class="danger" data-action="router-port-remove-confirm">Убрать</button>',
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
          throw new Error("Bridge не найден. Обновите конфигурацию.");
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
      ctx.toast("Порты bridge сохранены в черновик");
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
    showEntityEditor(ctx, editing.kind, item, false, editing.revision);
    return true;
  }
  if (action === "router-remove") {
    assertLinkRemoval(ctx.state.config, kind, id);
    editing = { kind, id, revision: ctx.state.revision };
    ctx.dialogFrame(
      "Удалить запись?",
      "Работающая сеть изменится только после применения.",
      `<p class="preview-note">Запись будет удалена из черновика. Если она используется другими настройками, сервер не разрешит удаление.</p>`,
      `<button data-action="close">Cancel</button><button class="danger" data-action="router-remove-confirm">Удалить</button>`,
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
    ctx.toast("Изменения роутера сохранены в черновик");
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
      '<option value="">—</option>' +
      interfaceNames(ctx)
        .filter((name) => name !== bridge?.name)
        .map(
          (name) =>
            `<option value="${ctx.e(name)}" ${name === previous ? "selected" : ""}>${ctx.e(name)}</option>`,
        )
        .join("");
    return;
  }
  const form = event.target.closest("#router-form");
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
      ctx.toast("Порядок Filter Rules сохранён в черновик");
    });
  });
  document.addEventListener("dragend", clear);
}
