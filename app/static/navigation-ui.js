import { t, html } from "./i18n.js";
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
    item("overview", t("Обзор"), "grid", t("Трафик и состояние роутера")),
    item(
      "interfaces",
      t("Interfaces"),
      "network",
      t("Ethernet · VLAN · списки"),
      interfaces.length,
      ["interfaces", "vlans", "virtual_interfaces", "interface_lists"],
    ),
    item(
      "bridges",
      t("Bridge"),
      "network",
      t("Мосты и участники"),
      count("bridges"),
      ["bridges", "bridge_ports"],
    ),
    item(
      "wireguard",
      t("WireGuard"),
      "lock",
      t("VPN-туннели и peers"),
      count("wireguard_interfaces"),
      ["wireguard", "wireguard_peers"],
    ),
    group("ip", t("IP"), "network", t("IPv4 · адреса и сервисы"), [
      item(
        "addresses",
        t("Addresses"),
        "network",
        t("IP-адреса на интерфейсах"),
        count("addresses"),
      ),
      item(
        "routes",
        t("Routes"),
        "arrow",
        t("Маршруты и шлюзы"),
        count("routes"),
      ),
      item(
        "dhcp_servers",
        t("DHCP Server"),
        "server",
        t("Серверы · сети · аренды"),
        count("dhcp_servers"),
        ["dhcp_servers", "dhcp_networks", "dhcp_reservations", "leases"],
      ),
      item("pools", t("Pool"), "list", t("Пулы адресов DHCP"), count("pools")),
      item(
        "dns",
        t("DNS"),
        "activity",
        t("DNS, статические записи и IP Forwarding"),
        undefined,
        ["dns", "dns_static"],
      ),
      item(
        "hosts",
        t("Neighbors"),
        "network",
        t("Обнаруженные устройства и соседи"),
      ),
      group("firewall", t("Firewall"), "shield", t("Правила и соединения"), [
        item(
          "filter",
          t("Filter Rules"),
          "shield",
          t("Фильтрация input / forward / output"),
          (config.filter_rules || []).length,
        ),
        item(
          "rules",
          "NAT",
          "swap",
          t("Проброс портов и трансляция адресов"),
          (config.rules || []).length,
        ),
        item(
          "lists",
          t("Address Lists"),
          "list",
          t("Обычные, страновые и временные списки"),
          addressListChoices(config).length,
        ),
        item(
          "connections",
          t("Connections"),
          "activity",
          t("Соединения IPv4 и входящие попытки"),
        ),
      ]),
    ]),
    group("protection", t("Security"), "shield", t("Защита и база стран"), [
      item(
        "fail2ban",
        "Fail2ban",
        "shield",
        t("Блокировки, профили и исключения"),
      ),
      item(
        "geoip",
        t("GeoIP"),
        "network",
        t("Страны IP-адресов и обновление базы"),
      ),
    ]),
    group("system", t("System"), "server", t("Управление роутером"), [
      ...(canWrite()
        ? [item("users", t("Users"), "user", t("Учётные записи · read / full"))]
        : []),
      ...(state.auth_enabled
        ? [
            item(
              "security",
              t("Мой профиль"),
              "lock",
              t("Личная двухфакторная аутентификация"),
            ),
          ]
        : []),
      item(
        "web_settings",
        t("Web Interface"),
        "network",
        t("Домен панели управления"),
      ),
      item(
        "backups",
        t("Backup / Restore"),
        "file",
        t("RSC · экспорт · резервные копии"),
      ),
      ...(canWrite()
        ? [
            item(
              "updates",
              t("Updates"),
              "download",
              t("Версии и подписанные обновления"),
            ),
          ]
        : []),
    ]),
    group("tools-group", t("Tools"), "terminal", t("Диагностика сети"), [
      item(
        "tools",
        t("Diagnostics"),
        "terminal",
        t("Ping · traceroute · DNS · TCP"),
      ),
      item(
        "network_scan",
        t("Network Scan"),
        "search",
        t("Поиск устройств в локальной сети"),
      ),
      item(
        "port_scan",
        t("Port Scan"),
        "activity",
        t("Проверка портов и служб"),
      ),
    ]),
    item("audit", t("Log"), "activity", t("Журнал изменений и применения")),
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
        const label = html`<span class="nav-copy"><span class="nav-title">${ctx.e(item.label)}</span>${depth === 0 ? html`<small class="nav-hint">${ctx.e(item.hint)}</small>` : ""}</span>`;
        if (item.children) {
          const expanded = ctx.expandedGroups.has(item.id);
          return html`<button class="nav-group-toggle ${current ? "active-branch" : ""}" data-action="nav-group" data-group="${item.id}" aria-expanded="${expanded}" aria-controls="nav-group-${item.id}" title="${ctx.e(item.hint)}">${ctx.icon(item.icon)}${t(label)}<span class="nav-group-arrow">${ctx.icon("chevron")}</span></button><div class="nav-group-children" id="nav-group-${item.id}" ${expanded ? "" : "hidden"}>${renderItems(item.children, depth + 1)}</div>`;
        }
        return html`<button class="nav-item ${current ? "active" : ""}" data-action="view" data-view="${item.view}" ${current ? 'aria-current="page"' : ""} title="${ctx.e(item.hint)}">${ctx.icon(item.icon)}${t(label)}${item.total === undefined ? "" : html`<span class="count" title="${item.view === "interfaces" ? t("Обнаружено интерфейсов") : t("Записей в черновике")}">${ctx.e(item.total)}</span>`}</button>`;
      })
      .join("");
  return html`${renderItems(items)}<p class="navigation-legend">Числа: записи / интерфейсы</p>`;
}

export function renderNavigationBreadcrumbs(ctx, title) {
  const path = navigationPath(navigationItems(ctx), ctx.view);
  const parents = path.filter(
    (item) => item.children || item.view !== ctx.view,
  );
  return html`${parents.map((item) => html`<span class="breadcrumb-parent">${ctx.e(item.label)}</span>${ctx.icon("chevron")}`).join("")}<b>${ctx.e(t(title))}</b>`;
}
