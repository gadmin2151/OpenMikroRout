/** WinBox-style menu hierarchy. Counters describe records and interfaces, not service health. */
import { addressListChoices } from "./protection-ui.js?v=3";

export const navigationGroupIds = new Set([
  "ip",
  "firewall",
  "protection",
  "system",
  "tools-group",
]);

export function navigationItems({ state, interfaces = [], canWrite }) {
  const config = state.config || {};
  const network = config.network || {};
  const count = (name) => (network[name] || []).length;
  const item = (view, label, icon, hint, total, views = [view]) => ({
    view,
    label,
    icon,
    hint,
    total,
    views,
  });
  const group = (id, label, icon, hint, children) => ({
    id,
    label,
    icon,
    hint,
    children,
  });
  return [
    item("overview", "Обзор", "grid", "Трафик и состояние роутера"),
    item(
      "interfaces",
      "Interfaces",
      "network",
      "Ethernet · VLAN · списки",
      interfaces.length,
      ["interfaces", "vlans", "virtual_interfaces", "interface_lists"],
    ),
    item(
      "bridges",
      "Bridge",
      "network",
      "Мосты и участники",
      count("bridges"),
      ["bridges", "bridge_ports"],
    ),
    item(
      "wireguard",
      "WireGuard",
      "lock",
      "VPN-туннели и peers",
      count("wireguard_interfaces"),
      ["wireguard", "wireguard_peers"],
    ),
    group("ip", "IP", "network", "IPv4 · адреса и сервисы", [
      item(
        "addresses",
        "Addresses",
        "network",
        "IP-адреса на интерфейсах",
        count("addresses"),
      ),
      item("routes", "Routes", "arrow", "Маршруты и шлюзы", count("routes")),
      item(
        "dhcp_servers",
        "DHCP Server",
        "server",
        "Серверы · сети · аренды",
        count("dhcp_servers"),
        ["dhcp_servers", "dhcp_networks", "dhcp_reservations", "leases"],
      ),
      item("pools", "Pool", "list", "Пулы адресов DHCP", count("pools")),
      item(
        "dns",
        "DNS",
        "activity",
        "DNS, статические записи и IP Forwarding",
        undefined,
        ["dns", "dns_static"],
      ),
      item("hosts", "Neighbors", "network", "Обнаруженные устройства и соседи"),
      group("firewall", "Firewall", "shield", "Правила и соединения", [
        item(
          "filter",
          "Filter Rules",
          "shield",
          "Фильтрация input / forward / output",
          (config.filter_rules || []).length,
        ),
        item(
          "rules",
          "NAT",
          "swap",
          "Проброс портов и трансляция адресов",
          (config.rules || []).length,
        ),
        item(
          "lists",
          "Address Lists",
          "list",
          "Обычные, страновые и временные списки",
          addressListChoices(config).length,
        ),
        item(
          "connections",
          "Connections",
          "activity",
          "Соединения IPv4 и входящие попытки",
        ),
      ]),
    ]),
    group("protection", "Security", "shield", "Защита и база стран", [
      item(
        "fail2ban",
        "Fail2ban",
        "shield",
        "Блокировки, профили и исключения",
      ),
      item("geoip", "GeoIP", "network", "Страны IP-адресов и обновление базы"),
    ]),
    group("system", "System", "server", "Управление роутером", [
      ...(canWrite()
        ? [item("users", "Users", "user", "Учётные записи · read / full")]
        : []),
      ...(state.auth_enabled
        ? [
            item(
              "security",
              "My Account · 2FA",
              "lock",
              "Личная двухфакторная аутентификация",
            ),
          ]
        : []),
      item(
        "web_settings",
        "Web Interface",
        "network",
        "Домен панели управления",
      ),
      item(
        "backups",
        "Backup / Restore",
        "file",
        "RSC · экспорт · резервные копии",
      ),
      ...(canWrite()
        ? [
            item(
              "updates",
              "Updates",
              "download",
              "Версии и подписанные обновления",
            ),
          ]
        : []),
    ]),
    group("tools-group", "Tools", "terminal", "Диагностика сети", [
      item("tools", "Diagnostics", "terminal", "Ping · traceroute · DNS · TCP"),
      item(
        "network_scan",
        "Network Scan",
        "search",
        "Поиск устройств в локальной сети",
      ),
      item("port_scan", "Port Scan", "activity", "Проверка портов и служб"),
    ]),
    item("audit", "Log", "activity", "Журнал изменений и применения"),
  ];
}

export function navigationPath(items, view) {
  for (const item of items) {
    if (item.views?.includes(view)) return [item];
    if (item.children) {
      const child = navigationPath(item.children, view);
      if (child.length) return [item, ...child];
    }
  }
  return [];
}

export function expandNavigationForView(items, view, expanded) {
  for (const item of navigationPath(items, view))
    if (item.children) expanded.add(item.id);
}

export function renderSidebarNavigation(ctx) {
  const items = navigationItems(ctx);
  const active = navigationPath(items, ctx.view);
  const renderItems = (nodes, depth = 0) =>
    nodes
      .map((item) => {
        const current = active.includes(item);
        const label = `<span class="nav-copy"><span class="nav-title">${ctx.e(item.label)}</span>${depth === 0 ? `<small class="nav-hint">${ctx.e(item.hint)}</small>` : ""}</span>`;
        if (item.children) {
          const expanded = ctx.expandedGroups.has(item.id);
          return `<button class="nav-group-toggle ${current ? "active-branch" : ""}" data-action="nav-group" data-group="${item.id}" aria-expanded="${expanded}" aria-controls="nav-group-${item.id}" title="${ctx.e(item.hint)}">${ctx.icon(item.icon)}${label}<span class="nav-group-arrow">${ctx.icon("chevron")}</span></button><div class="nav-group-children" id="nav-group-${item.id}" ${expanded ? "" : "hidden"}>${renderItems(item.children, depth + 1)}</div>`;
        }
        return `<button class="nav-item ${current ? "active" : ""}" data-action="view" data-view="${item.view}" ${current ? 'aria-current="page"' : ""} title="${ctx.e(item.hint)}">${ctx.icon(item.icon)}${label}${item.total === undefined ? "" : `<span class="count" title="${item.view === "interfaces" ? "Обнаружено интерфейсов" : "Записей в черновике"}">${ctx.e(item.total)}</span>`}</button>`;
      })
      .join("");
  return `${renderItems(items)}<p class="navigation-legend">Числа: записи / интерфейсы</p>`;
}

export function renderNavigationBreadcrumbs(ctx, title) {
  const path = navigationPath(navigationItems(ctx), ctx.view);
  const parents = path.filter(
    (item) => item.children || item.view !== ctx.view,
  );
  return `${parents.map((item) => `<span class="breadcrumb-parent">${ctx.e(item.label)}</span>${ctx.icon("chevron")}`).join("")}<b>${ctx.e(title)}</b>`;
}
