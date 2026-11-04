import { assertDraftRevision, prepareImportedConfig } from "./draft-guards.js";
import { reorderRules } from "./rule-order.js";
import {
  appendTelemetryHistory,
  mergeTelemetrySnapshot,
  mergeStoredTelemetryHistory,
  stopTelemetryAnimation,
  updateTelemetryView,
} from "./telemetry-ui.js?v=6";
import {
  hasWriteAccess,
  isReadAction,
  applyReadAccess,
} from "./access-ui.js?v=3";
import { renderUsers, handleUsersAction } from "./users-ui.js?v=2";
import { renderSecurity, handleSecurityAction } from "./security-ui.js?v=1";
import {
  renderUpdates,
  refreshUpdates,
  resetUpdates,
  handleUpdatesAction,
} from "./updates-ui.js?v=1";
import {
  renderConnections,
  refreshConnections,
  resetConnections,
  handleConnectionsAction,
} from "./connections-ui.js?v=1";
import {
  routerViews,
  renderRouterView,
  handleRouterAction,
  handleRouterChange,
  interfaceNames,
  installRouterEvents,
} from "./router-pages.js?v=9";

const paths = {
  grip: "M8 5h.01 M16 5h.01 M8 12h.01 M16 12h.01 M8 19h.01 M16 19h.01",
  grid: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  shield: "M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7z M8 12l3 3 5-6",
  list: "M9 6h12 M9 12h12 M9 18h12 M3 6h.01 M3 12h.01 M3 18h.01",
  network:
    "M4 4h16v5H4z M12 9v5 M4 17v-3h16v3 M1 17h6v4H1z M9 17h6v4H9z M17 17h6v4h-6z",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  help: "M9 9a3 3 0 0 1 6 0c0 2-3 2-3 4 M12 17h.01 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0",
  chevron: "m9 5 7 7-7 7",
  down: "m6 9 6 6 6-6",
  server: "M3 3h18v7H3z M3 14h18v7H3z M7 6h.01 M7 17h.01 M11 6h6 M11 17h6",
  plus: "M12 5v14 M5 12h14",
  minus: "M5 12h14",
  check: "m5 12 4 4L19 6",
  x: "m6 6 12 12 M6 18 18 6",
  copy: "M9 9h12v12H9z M15 9V3H3v12h6",
  up: "m6 12 6-6 6 6 M12 6v14",
  arrowdown: "m6 12 6 6 6-6 M12 18V4",
  search: "M21 21l-5-5 M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
  refresh: "M20 7a9 9 0 1 0 1 8 M20 2v6h-6",
  download: "M12 3v12 m-5-5 5 5 5-5 M4 16v5h16v-5",
  upload: "M12 16V3 m-5 5 5-5 5 5 M4 16v5h16v-5",
  terminal: "m4 6 6 6-6 6 M13 18h7",
  arrow: "M3 12h18 m-6-6 6 6-6 6",
  swap: "M3 7h18 m-5-4 5 4-5 4 M21 17H3 m5-4-5 4 5 4",
  lock: "M5 10h14v11H5z M8 10V6a4 4 0 0 1 8 0v4 M12 14v3",
  info: "M12 11v6 M12 7h.01 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0",
  clock: "M12 7v5l3 2 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0",
  edit: "m16 3 5 5-13 13H3v-5z M13 6l5 5",
  logout: "M9 3H3v18h6 M9 12h12 m-5-5 5 5-5 5",
  menu: "M3 6h18 M3 12h18 M3 18h18",
  file: "M14 2H4v20h16V8z M14 2v6h6 M8 13h8 M8 17h8",
  user: "M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M4 21v-2a8 8 0 0 1 16 0v2",
};
const icon = (name) =>
  `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[name] || paths.grid}"/></svg>`;
const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const root = document.querySelector("#app");
const dialog = document.querySelector("#editor");
let state,
  view = "overview",
  selected = new Set(),
  search = "",
  chainFilter = "",
  protocolFilter = "";
let interfaces = [],
  forwarding = null,
  audit = [],
  statistics = {},
  busy = false,
  offline = false,
  draft = null,
  editorTab = "general";
let draftRevision = null;
let confirmationRevision = null;
let draggingId = null;
let networkStatus = {};
let users = [],
  usersError = "",
  usersRequest = null,
  loginUsername = "admin",
  authGeneration = 0,
  sidebarScroll = 0;
let securityStatus = null;
const expandedGroups = new Set(["ip", "system"]);
let telemetry = null,
  telemetryHistory = [],
  telemetryError = "",
  telemetrySelection = "all",
  telemetryExpanded = null,
  telemetryHistoryError = "",
  historyController = null,
  historyCursor = null,
  historyPeriod = 60,
  telemetryRequest = null,
  telemetryController = null,
  fastTelemetryRequest = null,
  fastTelemetryController = null,
  pollInFlight = false;
let toastTimer,
  pollTimer,
  telemetryTimer,
  countdownTimer,
  alive = true;
const isDemo = () => state?.mode === "demo";
const canWrite = () => hasWriteAccess(state);
const currentUser = () => state?.current_user || null;
function requireWrite() {
  if (!canWrite())
    throw new Error(
      "Группа read: изменения доступны только пользователям full.",
    );
}
function applyAccessControls() {
  applyReadAccess(document, state);
}
function clearSession() {
  setNavigationOpen(false);
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  resetUpdates();
  resetConnections();
  loginUsername = currentUser()?.username || loginUsername;
  authGeneration++;
  state = null;
  users = [];
  usersError = "";
  usersRequest = null;
  securityStatus = null;
  telemetryController?.abort();
  fastTelemetryController?.abort();
  historyController?.abort();
  historyController = null;
  historyCursor = null;
  telemetryHistoryError = "";
  telemetryExpanded = null;
  document.body.classList.remove("telemetry-expanded-open");
  telemetry = null;
  telemetryHistory = [];
  telemetryError = "";
  telemetrySelection = "all";
  interfaces = [];
  networkStatus = {};
  statistics = {};
  audit = [];
  selected.clear();
  draft = null;
  draftRevision = null;
  confirmationRevision = null;
  sidebarScroll = 0;
  view = "overview";
  offline = false;
  if (dialog.open) dialog.close();
  dialog.innerHTML = "";
  endDrag();
  document.body.classList.remove("router-drag-active");
}
const ruleColumns = [
  ["name", "Comment / Name"],
  ["action", "Action"],
  ["chain", "Chain"],
  ["protocol", "Protocol"],
  ["src", "Src. Address / List"],
  ["dst", "Dst. Address / List"],
  ["src_ports", "Src. Port"],
  ["dst_ports", "Dst. Port"],
  ["in_interface", "In. Interface"],
  ["out_interface", "Out. Interface"],
  ["target", "To Addresses / Ports"],
  ["bytes", "Bytes"],
  ["packets", "Packets"],
];
const defaultColumns = ruleColumns
  .map(([key]) => key)
  .filter(
    (key) => !["src_ports", "in_interface", "out_interface"].includes(key),
  );
let visibleColumns = new Set(defaultColumns);
try {
  const stored = JSON.parse(
    localStorage.getItem("nat-panel.columns") || "null",
  );
  if (Array.isArray(stored)) {
    visibleColumns = new Set([
      "name",
      ...stored.filter((key) => ruleColumns.some(([known]) => key === known)),
    ]);
  }
} catch {
  // Preferences are optional; blocked storage must not prevent firewall administration.
  console.warn(
    "Column preferences could not be loaded; using default columns.",
  );
}

async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  if (
    !["GET", "HEAD"].includes(method) &&
    ![
      "login",
      "logout",
      "preview",
      "me/totp/setup",
      "me/totp/confirm",
      "me/totp/disable",
    ].includes(path)
  )
    requireWrite();
  const generation = authGeneration;
  const response = await fetch(`/api/${path}`, {
    credentials: "same-origin",
    signal: AbortSignal.timeout(path === "apply" ? 45000 : 20000),
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-NAT-Request": "1",
      ...options.headers,
    },
  });
  const data = await response.json();
  if (response.status === 401 && path !== "login") {
    if (generation === authGeneration) {
      clearSession();
      renderLogin();
    }
    throw new Error("Сессия завершена. Войдите снова.");
  }
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail
          .map((x) => `${x.field ? x.field + ": " : ""}${x.message}`)
          .join("\n")
      : data.detail;
    throw new Error(detail || `Ошибка HTTP ${response.status}`);
  }
  return data;
}
function toast(message, error = false) {
  const node = document.querySelector("#toast");
  clearTimeout(toastTimer);
  node.textContent = message;
  node.className = `visible${error ? " error" : ""}`;
  toastTimer = setTimeout(() => (node.className = ""), error ? 8000 : 4000);
}
async function run(task) {
  if (busy) return;
  busy = true;
  document.body.classList.add("is-busy");
  try {
    await task();
  } catch (error) {
    if (dialog.open) {
      const node = dialog.querySelector(".dialog-error");
      if (node) {
        node.textContent = error.message;
        node.classList.remove("hidden");
      } else toast(error.message, true);
    } else toast(error.message, true);
  } finally {
    busy = false;
    document.body.classList.remove("is-busy");
    if (
      state &&
      ["users", "updates", "security"].includes(view) &&
      !dialog.open
    )
      render();
  }
}
function acceptState(data) {
  state = { ...state, ...data };
  const ids = new Set(state.config.rules.map((r) => r.id));
  selected = new Set([...selected].filter((id) => ids.has(id)));
  render();
}
async function saveConfig(config, expectedRevision = state?.revision) {
  requireWrite();
  assertDraftRevision(expectedRevision, state.revision);
  const result = await api("config", {
    method: "PUT",
    body: JSON.stringify({ revision: expectedRevision, config }),
  });
  acceptState(result);
  return result;
}
function configCopy() {
  return structuredClone(state.config);
}
const fmtBytes = (bytes) =>
  bytes >= 1048576
    ? `${(bytes / 1048576).toFixed(1)} MB`
    : bytes >= 1024
      ? `${(bytes / 1024).toFixed(1)} KB`
      : `${bytes} B`;
function actionBadge(action) {
  return `<span class="action-badge ${e(action)}">${icon(action === "masquerade" ? "swap" : action === "accept" ? "check" : "arrow")}${e(action)}</span>`;
}
function listRef(name) {
  return `<span class="list-ref">${icon("list")}${e(name)}</span>`;
}
function addr(rule, side) {
  return rule[`${side}_list`]
    ? listRef(rule[`${side}_list`])
    : `<span class="mono ${rule[`${side}_address`] ? "" : "muted"}">${e(rule[`${side}_address`] || "any")}</span>`;
}
function target(rule) {
  return rule.to_address
    ? `${rule.to_address}${rule.to_ports ? ":" + rule.to_ports : ""}`
    : rule.to_ports
      ? `:${rule.to_ports}`
      : rule.action === "masquerade"
        ? rule.out_interface || "interface IP"
        : "—";
}
function navButton(id, label, ico, count = "", activeViews = [id]) {
  return `<button class="nav-item ${activeViews.includes(view) ? "active" : ""}" data-action="view" data-view="${id}">${icon(ico)}${label}${count !== "" ? `<span class="count">${count}</span>` : ""}</button>`;
}
function setNavigationOpen(open, focus = false) {
  const sidebar = document.querySelector("#sidebar");
  const mobile = window.matchMedia("(max-width: 680px)").matches;
  sidebar?.classList.toggle("open", open && mobile);
  document.body.classList.toggle("mobile-navigation-open", open && mobile);
  const main = document.querySelector("main");
  if (main) main.inert = open && mobile;
  const button = document.querySelector('[data-action="menu"].mobile-menu');
  button?.setAttribute("aria-expanded", String(open && mobile));
  if (focus)
    (open ? sidebar?.querySelector(".nav-item.active") : button)?.focus({
      preventScroll: true,
    });
}
function navGroup(id, label, ico, content) {
  const expanded = expandedGroups.has(id);
  return `<button class="nav-group-toggle" data-action="nav-group" data-group="${id}" aria-expanded="${expanded}" aria-controls="nav-group-${id}">${icon(ico)}${label}<span class="nav-group-arrow">${icon("chevron")}</span></button><div class="nav-group-children" id="nav-group-${id}" ${expanded ? "" : "hidden"}>${content}</div>`;
}
function renderNavigation(count) {
  return `${navButton("overview", "Обзор", "grid")}${navButton("interfaces", "Interfaces", "network", interfaces.length, ["interfaces", "vlans", "virtual_interfaces", "interface_lists"])}${navButton("bridges", "Bridge", "network", count("bridges"), ["bridges", "bridge_ports"])}${navGroup(
    "ip",
    "IP",
    "network",
    [
      navButton("addresses", "Addresses", "network", count("addresses")),
      navButton("routes", "Routes", "arrow", count("routes")),
      navButton(
        "dhcp_servers",
        "DHCP Server",
        "server",
        count("dhcp_servers"),
        ["dhcp_servers", "dhcp_networks", "leases"],
      ),
      navButton("pools", "Pool", "list", count("pools")),
      navButton("dns", "DNS & Forwarding", "activity"),
      navButton(
        "filter",
        "Firewall",
        "shield",
        state.config.rules.length + (state.config.filter_rules || []).length,
        ["filter", "rules", "lists", "connections"],
      ),
    ].join(""),
  )}${navGroup("system", "System", "server", `${state.auth_enabled ? navButton("security", "Security", "lock") : ""}${canWrite() ? navButton("users", "Users", "user") + navButton("updates", "Updates", "download") : ""}${navButton("audit", "Log", "activity")}<button class="nav-item" data-action="preview">${icon("terminal")}Предпросмотр</button>`)}`;
}
async function refreshSecurity() {
  if (state?.current_user) securityStatus = await api("me/totp");
}
async function refreshUsers() {
  if (!state || !canWrite() || !state.auth_enabled) {
    users = [];
    usersError = "";
    return;
  }
  if (usersRequest) return usersRequest;
  const generation = authGeneration;
  const request = (async () => {
    try {
      const result = await api("users");
      if (generation !== authGeneration || !state || !canWrite()) return;
      users = Array.isArray(result.users) ? result.users : [];
      usersError = "";
    } catch (error) {
      if (generation === authGeneration && state) usersError = error.message;
      throw error;
    } finally {
      if (usersRequest === request) usersRequest = null;
    }
  })();
  usersRequest = request;
  return request;
}
function stat(title, number, meta) {
  return `<div class="configuration-stat" title="${e(meta)}"><span>${e(title)}</span><strong>${e(number)}</strong></div>`;
}

function brandMarkup() {
  return `<div class="brand"><img src="/logo.png?v=5" alt="OpenMikroRout"><div class="brand-word"><strong>Open<span>Mikro</span>Rout</strong><small>OPEN NETWORK ROUTER</small></div></div>`;
}
function accountMarkup() {
  const user = currentUser();
  const authenticated = state.auth_enabled === true;
  const name = user?.username || "Локальный администратор";
  const role = canWrite() ? "full" : "read";
  const initials = user?.username
    ? user.username.slice(0, 2).toUpperCase()
    : isDemo()
      ? "DM"
      : "AD";
  return `<div class="account"><div class="avatar">${e(initials)}</div><div><strong>${e(name)}</strong><small>${authenticated ? `<span class="role-badge role-${role}">${role}</span> ${role === "full" ? "Полный доступ" : "Только просмотр"}` : "Авторизация отключена"}</small></div>${authenticated ? `<button class="icon ghost" title="Выйти" aria-label="Выйти" data-action="logout">${icon("logout")}</button>` : ""}</div>`;
}
function routerContext() {
  return {
    state,
    generation: authGeneration,
    getGeneration: () => authGeneration,
    isCurrentView: (name) => !!state && view === name,
    interfaces,
    networkStatus,
    offline,
    busy,
    statistics,
    telemetry,
    telemetryHistory,
    telemetryError,
    telemetrySelection,
    telemetryExpanded,
    telemetryHistoryError,
    users,
    usersError,
    securityStatus,
    refreshSecurity,
    refreshCurrentUser: () => refresh(true),
    currentUser: currentUser(),
    canWrite,
    api,
    refreshUsers,
    e,
    icon,
    isDemo,
    actionBadge,
    empty,
    dialog,
    dialogFrame,
    toast,
    run,
    saveConfig,
    render,
  };
}
function render() {
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  if (!state) return;
  const previousNavigation = document.querySelector(".sidebar-navigation");
  if (previousNavigation) sidebarScroll = previousNavigation.scrollTop;
  const sidebarOpen = document
    .querySelector("#sidebar")
    ?.classList.contains("open");
  if (["users", "updates"].includes(view) && !canWrite()) view = "overview";
  const cfg = state.config,
    network = cfg.network || {},
    rules = cfg.rules;
  const count = (key) => (network[key] || []).length;
  const [title, description] =
    routerViews[view] ||
    {
      rules: [
        "NAT Rules",
        "Трансляция адресов, проброс портов и управление доступом в интернет.",
      ],
      lists: ["Address Lists", "Списки адресов и подсетей для NAT и Firewall."],
      interfaces: [
        "Interfaces",
        "Обнаруженные физические и виртуальные интерфейсы Linux.",
      ],
      audit: [
        "Журнал изменений",
        "История сохранения, применения и восстановления конфигурации.",
      ],
      users: ["Users", "Учётные записи и группы доступа read / full."],
      security: [
        "Security",
        "Личная двухфакторная аутентификация и резервные коды.",
      ],
      connections: [
        "Connections",
        "Входящие соединения IPv4 и наблюдение попыток подключения.",
      ],
      updates: [
        "Updates",
        "Подписанные обновления из GitHub с резервной копией и откатом.",
      ],
    }[view] ||
    routerViews.overview;
  document.title = `OpenMikroRout · ${title}`;
  let tabs;
  if (["rules", "filter", "lists", "connections"].includes(view))
    tabs = [
      ["filter", "Filter Rules", "shield", (cfg.filter_rules || []).length],
      ["rules", "NAT", "swap", rules.length],
      ["lists", "Address Lists", "list", cfg.address_lists.length],
      ["connections", "Connections", "activity", ""],
    ];
  else if (
    ["interfaces", "vlans", "virtual_interfaces", "interface_lists"].includes(
      view,
    )
  )
    tabs = [
      ["interfaces", "Interfaces", "network", interfaces.length],
      ["vlans", "VLAN", "swap", count("vlans")],
      ["virtual_interfaces", "Virtual", "grid", count("virtual_interfaces")],
      [
        "interface_lists",
        "Interface Lists",
        "network",
        count("interface_lists"),
      ],
    ];
  else if (["bridges", "bridge_ports"].includes(view))
    tabs = [
      ["bridges", "Bridge", "network", count("bridges")],
      [
        "bridge_ports",
        "Ports",
        "network",
        (network.bridges || []).reduce(
          (total, bridge) => total + bridge.members.length,
          0,
        ),
      ],
    ];
  else if (["dhcp_servers", "dhcp_networks", "leases"].includes(view))
    tabs = [
      ["dhcp_servers", "DHCP Server", "server", count("dhcp_servers")],
      ["dhcp_networks", "Networks", "network", count("dhcp_servers")],
      ["leases", "Leases", "clock", (networkStatus.leases || []).length],
    ];
  else tabs = [];
  const body =
    view === "updates"
      ? renderUpdates(routerContext())
      : view === "connections"
        ? renderConnections(routerContext())
        : view === "security"
          ? renderSecurity(routerContext())
          : view === "rules"
            ? renderRules()
            : view === "lists"
              ? renderLists()
              : view === "interfaces"
                ? renderInterfaces()
                : view === "audit"
                  ? renderAudit()
                  : view === "users"
                    ? renderUsers(routerContext())
                    : renderRouterView(view, routerContext());
  root.innerHTML = `<div class="app-shell">
    <aside class="sidebar ${sidebarOpen ? "open" : ""}" id="sidebar">${brandMarkup()}
      <div class="workspace"><div class="workspace-icon">${icon("server")}</div><div><b>${isDemo() ? "Demo Router" : e(state.hostname)}</b><small>${isDemo() ? "DEMO WORKSPACE" : "LINUX GATEWAY"}</small></div></div>
      <nav class="sidebar-navigation" aria-label="Настройки роутера">${renderNavigation(count)}</nav>
      <div class="sidebar-bottom"><button class="nav-item" data-action="help">${icon("help")}Справка</button><div class="engine-card"><span class="version">v${e(state.version || "0.3.0")}</span><b><span class="dot"></span>${isDemo() ? "Demo engine" : "Linux router"}</b><br>${isDemo() ? "Сеть хоста не изменяется" : "IPv4 · iptables · dnsmasq"}</div>${accountMarkup()}</div>
    </aside><button class="sidebar-scrim" data-action="menu" aria-label="Закрыть меню" tabindex="-1"></button>
    <main class="main"><header class="topbar"><div class="breadcrumbs"><button class="icon ghost mobile-menu" aria-label="Открыть меню" aria-controls="sidebar" aria-expanded="false" data-action="menu">${icon("menu")}</button>${icon("network")}<span>OpenMikroRout</span>${icon("chevron")}<b>${e(title)}</b></div><div class="topbar-right"><span class="muted"><span class="dot"></span>${offline ? "Нет соединения" : "Сервер подключён"}</span><span class="divider"></span><span class="mode-chip ${isDemo() ? "" : "live"}">${isDemo() ? "DEMO MODE" : "LINUX · LIVE"}</span></div></header>
    <div class="content">${state.runtime_error ? `<div class="connection-error" role="alert">${icon("info")} Восстановление конфигурации требует внимания: ${e(state.runtime_error)}</div>` : ""}${offline ? '<div class="connection-error">Данные сервера недоступны. Изменения заблокированы до восстановления соединения.</div>' : ""}
      ${!canWrite() ? `<div class="read-only-banner">${icon("lock")}Группа read: настройки доступны для просмотра. Изменения выполняют пользователи full.</div>` : ""}
      <div class="page-heading"><div><h1>${e(title)}</h1><p>${e(description)}</p></div><div class="heading-buttons"><button data-action="import" title="Импорт конфигурации">${icon("upload")}<span class="btn-label">Импорт</span></button><button data-action="export" title="Экспорт конфигурации">${icon("download")}<span class="btn-label">Backup</span></button></div></div>
      ${["overview", "users", "security", "updates", "connections"].includes(view) ? "" : `<div class="configuration-summary" aria-label="Сводка конфигурации">${stat("Интерфейсы", interfaces.length, `${count("bridges")} bridge · ${count("vlans")} VLAN`)}${stat("IP-адреса", count("addresses"), "Назначены в конфигурации")}${stat("DHCP Servers", count("dhcp_servers"), `${count("pools")} пулов · ${(networkStatus.leases || []).length} аренд`)}${stat("Firewall Rules", rules.length + (cfg.filter_rules || []).length, `${rules.length} NAT · ${(cfg.filter_rules || []).length} Filter`)}</div>`}
      <section class="panel ${view === "overview" ? "overview-panel" : ""}">${tabs.length ? `<div class="panel-tabs">${tabs.map(([id, label, ico, total]) => `<button class="panel-tab ${view === id ? "active" : ""}" data-action="view" data-view="${id}">${icon(ico)}${label}<span class="tab-count">${total}</span></button>`).join("")}</div>` : ""}${body}</section>
      ${["overview", "users", "security", "updates", "connections"].includes(view) ? "" : `<details class="configuration-help"><summary>Работа с черновиком и применением</summary><div class="info-row"><div class="tip-card">${icon("info")}<div><h3>Один черновик для всего роутера</h3><p>Bridge → VLAN → IP-адрес → DHCP → маршруты и Firewall. Сначала сохраните настройки, затем проверьте общий предпросмотр.</p><button class="text-link" data-action="help">Как это работает ${icon("arrow")}</button></div></div><div class="tip-card">${icon("lock")}<div><h3>${isDemo() ? "Можно спокойно экспериментировать" : "Применение с контролем связи"}</h3><p>${isDemo() ? "Деморежим использует отдельную базу и симуляцию. Сетевые настройки компьютера не меняются." : "После применения подтвердите связь в течение 60 секунд. Без подтверждения сервер попытается восстановить предыдущую конфигурацию."}</p></div></div></div></details>`}
      <div class="page-footer"><span>${icon("shield")}OpenMikroRout · Your network. Your rules.</span><span>Lightweight Linux router · IPv4</span></div>
    </div><div id="statusbar">${renderStatus()}</div></main></div>`;
  const navigation = document.querySelector(".sidebar-navigation");
  if (navigation) navigation.scrollTop = sidebarScroll;
  setNavigationOpen(sidebarOpen);
  applyAccessControls();
}

function filteredRules() {
  const q = search.toLowerCase();
  return state.config.rules.filter(
    (r) =>
      (!chainFilter || r.chain === chainFilter) &&
      (!protocolFilter || r.protocol === protocolFilter) &&
      (!q || Object.values(r).join(" ").toLowerCase().includes(q)),
  );
}
function renderRules() {
  const rows = filteredRules(),
    locked = !!state.pending || offline || !canWrite();
  return `<div class="toolbar"><div class="toolbar-start"><button class="primary add" data-action="add" ${locked ? "disabled" : ""}>${icon("plus")}Добавить правило</button><span class="separator"></span>${[
    ["delete", "minus", "Удалить выбранные"],
    ["enable", "check", "Включить"],
    ["disable", "x", "Отключить"],
    ["comment", "edit", "Комментарий"],
    ["duplicate", "copy", "Создать копию"],
    ["move-up", "up", "Переместить выше"],
    ["move-down", "arrowdown", "Переместить ниже"],
  ]
    .map(
      ([a, i, t]) =>
        `<button class="icon ghost" title="${t}" aria-label="${t}" data-action="${a}" ${!selected.size || locked ? "disabled" : ""}>${icon(i)}</button>`,
    )
    .join(
      "",
    )}</div><div class="toolbar-end"><div class="search">${icon("search")}<input id="rule-search" aria-label="Поиск правил" placeholder="Найти правило…" value="${e(search)}"></div><select id="chain-filter" aria-label="Фильтр цепочки">${[
    ["", "Все цепочки"],
    ["srcnat", "srcnat"],
    ["dstnat", "dstnat"],
    ["output", "output"],
  ]
    .map(
      ([v, l]) =>
        `<option value="${v}" ${chainFilter === v ? "selected" : ""}>${l}</option>`,
    )
    .join(
      "",
    )}</select><select id="protocol-filter" aria-label="Фильтр протокола">${[
    ["", "Протокол"],
    ["tcp", "TCP"],
    ["udp", "UDP"],
    ["any", "Any"],
    ["icmp", "ICMP"],
    ["gre", "GRE"],
    ["esp", "ESP"],
    ["ah", "AH"],
  ]
    .map(
      ([v, l]) =>
        `<option value="${v}" ${protocolFilter === v ? "selected" : ""}>${l}</option>`,
    )
    .join(
      "",
    )}</select><button class="icon ghost" data-action="columns" title="Настроить колонки" aria-label="Настроить колонки">${icon("list")}</button><button class="icon ghost" data-action="refresh" title="Обновить" aria-label="Обновить">${icon("refresh")}</button></div></div>
    <div class="table-scroll"><table class="rules-table"><thead><tr><th><input type="checkbox" id="select-all" aria-label="Выбрать все показанные правила" ${rows.length && rows.every((r) => selected.has(r.id)) ? "checked" : ""}></th><th class="drag-column" aria-label="Перетаскивание"></th><th>#</th>${ruleColumns.map(([key, label]) => `<th data-column="${key}" ${visibleColumns.has(key) ? "" : "hidden"}>${label}</th>`).join("")}<th></th></tr></thead><tbody id="rules-body">${renderRuleRows(rows)}</tbody></table>${!rows.length ? empty("shield", search || chainFilter || protocolFilter ? "Ничего не найдено" : "Пока нет правил NAT", search || chainFilter || protocolFilter ? "Измените поисковый запрос или фильтры." : "Добавьте первое правило или выберите готовый шаблон в редакторе.") : ""}</div>
    ${selected.size === 1 ? renderDetail(state.config.rules.find((r) => selected.has(r.id))) : ""}
    <div class="panel-footer"><span>${rows.length} из ${state.config.rules.length} правил${selected.size ? ` · выбрано ${selected.size}` : ""}</span><div class="footer-legend"><span><i class="dot"></i>Включено</span><span><i class="dot off"></i>Отключено</span><span>${isDemo() ? "Счётчики недоступны в демо" : "Счётчики первых пакетов соединений"}</span></div></div>`;
}
function renderRuleRows(rows) {
  return rows
    .map((rule) => {
      const values = {
        name: `<div class="rule-name"><span class="dot ${rule.enabled ? "" : "off"}"></span>${e(rule.name)}</div>${rule.comment ? `<div class="rule-comment" title="${e(rule.comment)}">${e(rule.comment)}</div>` : ""}`,
        action: actionBadge(rule.action),
        chain: `<span class="mono">${e(rule.chain)}</span>`,
        protocol: `<span class="protocol-badge">${e(rule.protocol)}</span>`,
        src: addr(rule, "src"),
        dst: addr(rule, "dst"),
        src_ports: `<span class="mono">${e(rule.src_ports || "—")}</span>`,
        dst_ports: `<span class="mono">${e(rule.dst_ports || "—")}</span>`,
        in_interface: `<span class="mono">${e(rule.in_interface || "—")}</span>`,
        out_interface: `<span class="mono">${e(rule.out_interface || "—")}</span>`,
        target: `<span class="mono">${e(target(rule))}</span>`,
        bytes: isDemo() ? "—" : fmtBytes(statistics[rule.id]?.bytes || 0),
        packets: isDemo()
          ? "—"
          : (statistics[rule.id]?.packets || 0).toLocaleString("ru-RU"),
      };
      return `<tr data-rule="${e(rule.id)}" class="${selected.has(rule.id) ? "selected " : ""}${rule.enabled ? "" : "disabled"}" tabindex="0" aria-label="${e(rule.name)}">
      <td><input type="checkbox" data-select="${e(rule.id)}" aria-label="Выбрать ${e(rule.name)}" ${selected.has(rule.id) ? "checked" : ""}></td>
      <td class="drag-column"><button class="drag-handle" draggable="${canWrite() && !state.pending && !offline}" data-drag-id="${e(rule.id)}" title="Перетащить правило" aria-label="Перетащить ${e(rule.name)}" ${!canWrite() || state.pending || offline ? "disabled" : ""}>${icon("grip")}</button></td>
      <td class="row-number">${state.config.rules.indexOf(rule)}</td>
      ${ruleColumns.map(([key]) => `<td data-column="${key}" ${visibleColumns.has(key) ? "" : "hidden"} class="${["bytes", "packets"].includes(key) ? "counter-cell" : ""}">${values[key]}</td>`).join("")}
      <td><button class="icon ghost" data-action="edit" data-id="${e(rule.id)}" title="Редактировать правило" aria-label="Редактировать ${e(rule.name)}" ${state.pending ? "disabled" : ""}>${icon("edit")}</button></td></tr>`;
    })
    .join("");
}
function renderDetail(r) {
  if (!r) return "";
  return `<div class="detail"><div class="detail-title"><b>${e(r.name)} <span>· предпросмотр потока</span></b><button class="small ghost" data-action="edit" data-id="${e(r.id)}" ${state.pending ? "disabled" : ""}>${icon("edit")}Редактировать</button></div><div class="flow"><div class="flow-item"><div class="flow-label">Source</div><div class="flow-value">${e(r.src_list || r.src_address || "any")}${r.src_ports ? " : " + e(r.src_ports) : ""}</div></div>${icon("arrow")}<div class="flow-item"><div class="flow-label">Match · ${e(r.chain)}</div><div class="flow-value">${e(r.protocol.toUpperCase())} → ${e(r.dst_list || r.dst_address || "any")}${r.dst_ports ? " : " + e(r.dst_ports) : ""}</div></div>${icon("arrow")}<div class="flow-item"><div class="flow-label">${e(r.action)}</div><div class="flow-value">${e(target(r))}</div></div></div></div>`;
}
function empty(ico, title, description) {
  return `<div class="empty">${icon(ico)}<p>${e(title)}</p><small>${e(description)}</small></div>`;
}
function renderLists() {
  return `<div class="toolbar"><button class="primary add" data-action="add-list" ${state.pending || offline ? "disabled" : ""}>${icon("plus")}Создать список</button><span class="muted">${state.config.address_lists.length} списков</span></div><div class="view-panel"><div class="list-grid">${state.config.address_lists
    .map((l) => {
      const refs = [
        ...state.config.rules,
        ...(state.config.filter_rules || []),
      ].filter((r) => r.src_list === l.name || r.dst_list === l.name).length;
      return `<article class="address-card"><div class="address-card-head"><h3>${e(l.name)}</h3><button class="icon ghost" data-action="edit-list" data-id="${e(l.id)}" title="Редактировать список" aria-label="Редактировать ${e(l.name)}" ${state.pending ? "disabled" : ""}>${icon("edit")}</button></div>${l.comment ? `<p>${e(l.comment)}</p>` : ""}<div class="addresses">${l.addresses.map((a) => `<span class="address-chip">${e(a)}</span>`).join("")}</div><div class="address-card-foot"><span>${l.addresses.length} адресов · ${refs} правил</span><button class="small ghost" data-action="delete-list" data-id="${e(l.id)}" ${refs || state.pending ? "disabled" : ""} title="${refs ? "Сначала уберите список из правил" : "Удалить список"}">${icon("minus")}Удалить</button></div></article>`;
    })
    .join(
      "",
    )}</div>${!state.config.address_lists.length ? empty("list", "Пока нет списков адресов", "Добавьте IP-адреса или подсети и используйте список в правилах.") : ""}</div>`;
}
function renderInterfaces() {
  return `<div class="toolbar"><span class="muted">${isDemo() ? "Пример сетевой конфигурации" : "Обнаруженные интерфейсы Linux-хоста"}</span><button class="small" data-action="refresh">${icon("refresh")}Обновить</button></div><div class="view-panel"><div class="interface-grid">${interfaces.map((i) => `<article class="interface-card">${icon("network")}<h3>${e(i.name)}</h3><p>${e(i.address || "IPv4 не назначен")}</p><div class="interface-status"><span class="badge">${e(i.state)}</span><span>${e(i.role)}</span></div></article>`).join("")}</div>${!interfaces.length ? empty("network", "Нет данных об интерфейсах", "Нажмите «Обновить», чтобы повторить запрос.") : ""}<p class="interface-note">${isDemo() ? "В деморежиме показаны примерные интерфейсы. В Linux здесь появятся реальные интерфейсы сервера." : `IPv4 forwarding: <b>${forwarding ? "включён" : "выключен"}</b>. IP-адреса задаются в IP Addresses, bridge и VLAN — в соответствующих разделах. Forwarding настраивается в DNS & Forwarding; разрешения транзита — в Firewall Filter.`}</p></div>`;
}
const eventNames = {
  saved: "Черновик сохранён",
  discarded: "Черновик отменён",
  applying: "Правила применяются",
  confirmed: "Применение подтверждено",
  rolled_back: "Правила восстановлены",
  rollback_failed: "Ошибка отката",
};
function renderAudit() {
  return `<div class="toolbar"><span class="muted">Последние 100 событий</span><button class="small" data-action="refresh">${icon("refresh")}Обновить</button></div><div class="view-panel">${audit.length ? audit.map((row) => `<div class="audit-row">${icon(row.event === "rollback_failed" ? "info" : "clock")}<div><b>${e(eventNames[row.event] || row.event)}</b><p>${e(row.detail)}</p></div><time>${e(new Date(row.at * 1000).toLocaleString("ru-RU"))}</time></div>`).join("") : empty("clock", "Журнал пока пуст", "Здесь появятся события сохранения, применения и восстановления правил.")}</div>`;
}
function renderStatus() {
  if (!canWrite())
    return `<footer class="bottom-status"><div class="status-left"><div>${icon("lock")}Только просмотр · группа read</div><span>${state.pending ? "Применение конфигурации выполняется администратором" : state.dirty ? "На сервере есть неприменённый черновик" : "Конфигурация доступна для просмотра"}</span></div><div class="status-right"><button class="small" data-action="preview">${icon("terminal")}Предпросмотр</button><span>Revision ${state.revision}</span></div></footer>`;
  if (state.pending)
    return `<footer class="bottom-status pending"><div class="status-left"><div class="status-message">${icon("clock")}<b>${state.pending.error ? "Ошибка отката. Требуется проверка сервера." : `Подтвердите связь: <span id="countdown">${secondsLeft()}</span> сек.`}</b></div><span>Без подтверждения — автоматический откат</span></div><div class="status-right"><button data-action="rollback">Откатить сейчас</button><button class="primary" data-action="confirm" ${state.pending.error ? "disabled" : ""}>${icon("check")}Подтвердить связь</button></div></footer>`;
  if (state.dirty)
    return `<footer class="bottom-status dirty"><div class="status-left"><div class="status-message">${icon("edit")}<b>Есть неприменённые изменения</b></div><span>Черновик сохранён на сервере</span></div><div class="status-right"><button class="ghost" data-action="discard">Отменить</button><button data-action="preview">${icon("terminal")}Предпросмотр</button><button class="primary" data-action="apply" ${offline ? "disabled" : ""}>${icon("check")}${isDemo() ? "Применить в демо" : "Применить"}</button></div></footer>`;
  return `<footer class="bottom-status"><div class="status-left"><div><span class="dot"></span>${isDemo() ? "Деморежим · изменения сети отключены" : "Подтверждённая конфигурация сохранена"}</div><span>Revision ${state.revision}</span></div><div class="status-right"><span class="muted">${selected.size ? "Двойной щелчок — редактировать" : view === "rules" ? "Выберите правило для просмотра деталей" : "IP · DHCP · VLAN · Firewall"}</span>${!isDemo() ? '<button class="small" data-action="apply">Применить повторно</button>' : ""}<span>IPv4</span></div></footer>`;
}
function secondsLeft() {
  return Math.max(0, Math.ceil(state.pending.deadline - Date.now() / 1000));
}
function dialogFrame(title, subtitle, content, footer = "", tabs = "") {
  dialog.className = "";
  dialog.innerHTML = `<div class="dialog-head"><div><h2 id="dialog-title">${e(title)}</h2>${subtitle ? `<p>${e(subtitle)}</p>` : ""}</div><button class="icon ghost" data-action="close" aria-label="Закрыть">${icon("x")}</button></div>${tabs}<div class="dialog-content">${content}</div><div class="dialog-error hidden" role="alert"></div><div class="dialog-footer">${footer || '<button data-action="close">Закрыть</button>'}</div>`;
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  if (!dialog.open) dialog.showModal();
  applyAccessControls();
}
const defaultRule = () => ({
  id: crypto.randomUUID(),
  name: "",
  enabled: true,
  chain: "dstnat",
  action: "dst-nat",
  protocol: "tcp",
  src_address: "",
  dst_address: "",
  src_list: "",
  dst_list: "",
  src_ports: "",
  dst_ports: "",
  in_interface: "",
  out_interface: "",
  in_interface_list: "",
  out_interface_list: "",
  to_address: "",
  to_ports: "",
  connection_states: [],
  comment: "",
});
function openEditor(id, duplicate = false) {
  if (!canWrite() && (!id || duplicate)) {
    toast("Группа read: новые правила и копии недоступны.", true);
    return;
  }
  if (busy) return;
  draftRevision = state.revision;
  if (state.pending)
    return toast("Сначала подтвердите применение или откатите правила.", true);
  const found = state.config.rules.find((r) => r.id === id);
  draft = found ? structuredClone(found) : defaultRule();
  if (duplicate) {
    draft.id = crypto.randomUUID();
    draft.name += " (copy)";
  }
  editorTab = "general";
  renderEditor();
}
function field(
  label,
  name,
  value,
  placeholder = "",
  type = "text",
  extra = "",
) {
  return `<label class="field ${extra}"><span>${label}</span><input name="${name}" value="${e(value)}" placeholder="${e(placeholder)}" type="${type}" ${name === "name" ? 'maxlength="80"' : ""}></label>`;
}
function selectField(label, name, value, options, note = "") {
  return `<label class="field"><span>${label}</span><select name="${name}">${options
    .map((option) => {
      const [val, text] = Array.isArray(option) ? option : [option, option];
      return `<option value="${e(val)}" ${value === val ? "selected" : ""}>${e(text)}</option>`;
    })
    .join("")}</select>${note ? `<small>${e(note)}</small>` : ""}</label>`;
}
function interfaceField(label, name, value, available) {
  const names = interfaceNames(routerContext());
  const options = [
    ["", "Любой интерфейс"],
    ...names.map((name) => [
      name,
      `${name}${interfaces.find((item) => item.name === name)?.address ? " · " + interfaces.find((item) => item.name === name).address : ""}`,
    ]),
  ];
  if (value && !names.includes(value))
    options.push([value, `${value} · не обнаружен`]);
  return `<label class="field"><span>${label}</span><select name="${name}" ${available ? "" : "disabled"}>${options.map(([key, text]) => `<option value="${e(key)}" ${value === key ? "selected" : ""}>${e(text)}</option>`).join("")}</select></label>`;
}

function renderEditor() {
  const r = draft;
  const existing = state.config.rules.some((rule) => rule.id === r.id);
  let content = "";
  if (editorTab === "general")
    content = `<div class="winbox-form">
    ${field("Name", "name", r.name, "Имя правила")}
    ${selectField("Chain", "chain", r.chain, [
      ["dstnat", "dstnat"],
      ["srcnat", "srcnat"],
      ["output", "output"],
    ])}
    <div class="form-divider"></div>
    ${field("Src. Address", "src_address", r.src_address, "0.0.0.0/0 · любой")}
    ${field("Dst. Address", "dst_address", r.dst_address, "0.0.0.0/0 · любой")}
    ${selectField("Protocol", "protocol", r.protocol, [
      ["any", "all"],
      ["tcp", "6 (tcp)"],
      ["udp", "17 (udp)"],
      ["icmp", "1 (icmp)"],
      ["gre", "47 (gre)"],
      ["esp", "50 (esp)"],
      ["ah", "51 (ah)"],
    ])}
    ${field("Src. Port", "src_ports", r.src_ports, "Любой · 1024-65535")}
    ${field("Dst. Port", "dst_ports", r.dst_ports, "Любой · 80,443,8000-8010")}
    <div class="form-divider"></div>
    ${interfaceField("In. Interface", "in_interface", r.in_interface, r.chain === "dstnat")}
    ${interfaceField("Out. Interface", "out_interface", r.out_interface, r.chain !== "dstnat")}
    <div class="field-note">${isDemo() ? "Демо: интерфейсы приведены для примера." : "Интерфейсы обнаружены автоматически на Linux-хосте."} Списки адресов — во вкладке Advanced.</div>
    <label class="field"><span>Template</span><select id="template"><option value="">Без шаблона</option><option value="forward">Port forwarding</option><option value="masquerade">Masquerade · Internet access</option><option value="dns">DNS redirect</option><option value="snat">Source NAT</option></select></label>
    <label class="field"><span>Comment</span><textarea name="comment" rows="2" maxlength="200" placeholder="Комментарий к правилу">${e(r.comment)}</textarea></label>
    </div>`;
  if (editorTab === "advanced")
    content = `<div class="winbox-form">
    ${selectField("Src. Address List", "src_list", r.src_list, [["", "Не использовать"], ...state.config.address_lists.map((item) => [item.name, item.name])])}
    ${selectField("Dst. Address List", "dst_list", r.dst_list, [["", "Не использовать"], ...state.config.address_lists.map((item) => [item.name, item.name])])}
    ${selectField("In. Interface List", "in_interface_list", r.in_interface_list || "", [["", "Не использовать"], ...(state.config.network?.interface_lists || []).map((item) => [item.name, item.name])])}${selectField("Out. Interface List", "out_interface_list", r.out_interface_list || "", [["", "Не использовать"], ...(state.config.network?.interface_lists || []).map((item) => [item.name, item.name])])}<div class="field-note">Для source и destination укажите адрес в General или список здесь. Если список ещё не создан, добавьте его в Address Lists.</div>
    <div class="form-divider"></div><div class="field"><span>Connection State</span><div class="states">${["NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"].map((value) => `<label class="checkbox-label"><input type="checkbox" name="state" value="${value}" ${r.connection_states.includes(value) ? "checked" : ""}>${value.toLowerCase()}</label>`).join("")}</div><small>Без отметок — любое состояние.</small></div></div>`;
  if (editorTab === "action")
    content = `<div class="winbox-form">
    ${selectField("Action", "action", r.action, r.chain === "srcnat" ? ["masquerade", "src-nat", "accept"] : ["dst-nat", "redirect", "accept"])}
    ${["dst-nat", "src-nat"].includes(r.action) ? field("To Addresses", "to_address", r.to_address, "192.168.10.10") : ""}
    ${r.action !== "accept" ? field("To Ports", "to_ports", r.to_ports, "Не менять") : ""}
    <div class="field-note">${r.action === "masquerade" ? "Подставляет IP исходящего интерфейса. Выберите Out. Interface в General." : r.action === "redirect" ? "Перенаправляет на сервис этого Linux-хоста. Укажите локальный порт." : r.action === "accept" ? "Завершает обработку NAT. Разрешения FORWARD настраиваются отдельно." : "Укажите один IPv4-адрес. To Ports — один порт или диапазон; пустое поле сохраняет порт."}</div></div>`;
  if (editorTab === "statistics")
    content = `<div class="rule-statistics"><div class="statistics-caption">${isDemo() ? "В деморежиме реальных счётчиков нет" : "Счётчики работающей версии правила"}</div>
    <dl><div><dt>Bytes</dt><dd data-counter="bytes">${isDemo() ? "—" : fmtBytes(statistics[r.id]?.bytes || 0)}</dd></div><div><dt>Packets</dt><dd data-counter="packets">${isDemo() ? "—" : (statistics[r.id]?.packets || 0).toLocaleString("ru-RU")}</dd></div><div><dt>Chain</dt><dd>${e(r.chain)}</dd></div><div><dt>Action</dt><dd>${e(r.action)}</dd></div></dl><div class="field-note">NAT учитывает первые пакеты соединений. После применения счётчики управляемых цепочек сбрасываются. Изменения черновика ещё не меняют работающие правила.</div></div>`;
  const buttons = `<aside class="rule-actions"><button class="primary" data-action="save-rule">OK</button><button data-action="close">Cancel</button><button data-action="save-rule-open">Apply</button><div class="form-divider"></div><button data-action="editor-toggle">${icon(r.enabled ? "x" : "check")}${r.enabled ? "Disable" : "Enable"}</button><button data-action="editor-comment">${icon("edit")}Comment</button><button data-action="editor-copy">${icon("copy")}Copy</button>${existing ? `<button class="danger" data-action="editor-remove">${icon("minus")}Remove</button>` : ""}</aside>`;
  dialogFrame(
    existing ? `NAT Rule · ${r.name}` : "New NAT Rule",
    "OK / Apply сохраняют правило в черновик. Применение к сети — отдельно.",
    `<div class="rule-editor-layout"><form id="rule-form">${content}</form>${buttons}</div>`,
    `<label class="checkbox-label left"><input type="checkbox" id="rule-enabled" ${r.enabled ? "checked" : ""}>Enabled</label><span class="muted">${e(r.chain)} → ${e(r.action)}</span>`,
    `<div class="dialog-tabs">${[
      ["general", "General"],
      ["advanced", "Advanced"],
      ["action", "Action"],
      ["statistics", "Statistics"],
    ]
      .map(
        ([id, label]) =>
          `<button class="dialog-tab ${editorTab === id ? "active" : ""}" data-action="editor-tab" data-tab="${id}">${label}</button>`,
      )
      .join("")}</div>`,
  );
  dialog.classList.add("winbox-editor");
}
function collectRule() {
  const form = dialog.querySelector("#rule-form");
  if (!form) return;
  for (const [key, val] of new FormData(form)) {
    if (key !== "state") draft[key] = String(val).trim();
  }
  if (editorTab === "advanced")
    draft.connection_states = [
      ...form.querySelectorAll('[name="state"]:checked'),
    ].map((x) => x.value);
  draft.enabled = dialog.querySelector("#rule-enabled").checked;
}
function openList(id) {
  if (!canWrite() && !id) {
    toast("Группа read: новые списки недоступны.", true);
    return;
  }
  draftRevision = state.revision;
  const list = state.config.address_lists.find((l) => l.id === id) || {
    id: crypto.randomUUID(),
    name: "",
    addresses: [],
    comment: "",
  };
  draft = structuredClone(list);
  dialogFrame(
    list.name ? "Редактировать Address List" : "Новый Address List",
    "Один адрес или подсеть в каждой строке.",
    `<form id="list-form"><div class="form-grid">${field("Имя списка", "name", list.name, "Например, trusted-hosts", "text", "wide")}<label class="field wide"><span>IPv4-адреса и подсети</span><textarea name="addresses" rows="7" placeholder="192.168.10.0/24&#10;10.8.0.5">${e(list.addresses.join("\n"))}</textarea><small>До 256 адресов. Повторяющиеся записи будут объединены.</small></label>${field("Комментарий", "comment", list.comment, "Назначение списка", "text", "wide")}</div></form>`,
    `<button data-action="close">Отмена</button><button class="primary" data-action="save-list">${icon("check")}Сохранить список</button>`,
  );
}
function confirmDialog(
  title,
  message,
  action,
  label = "Подтвердить",
  danger = false,
  revision = state.revision,
) {
  confirmationRevision = revision;
  dialogFrame(
    title,
    "",
    `<p class="preview-note">${e(message)}</p>`,
    `<button data-action="close">Отмена</button><button class="${danger ? "danger" : "primary"}" data-action="${action}">${e(label)}</button>`,
  );
}
function showHelp() {
  dialogFrame(
    "OpenMikroRout · справка",
    "Лёгкий Linux-роутер с привычной логикой WinBox.",
    `<div class="help-content"><h3>Настройка локальной сети</h3><p>Создайте bridge и выберите LAN-порты. Для отдельных сетей создайте VLAN на нужном parent-интерфейсе. Затем назначьте IPv4-адрес в IP Addresses, создайте IP Pool и DHCP Server на этом интерфейсе.</p><h3>Интернет и защита</h3><p>Задайте default route 0.0.0.0/0, включите forwarding в DNS & Forwarding и создайте srcnat / masquerade для WAN. В Firewall Filter настройте разрешения input и forward. Списки адресов и интерфейсов позволяют применять правила сразу к группам.</p><h3>Работа с правилами</h3><p>Двойной щелчок открывает свойства. В NAT перетаскивайте правила за ⋮⋮; стрелки тоже меняют порядок. Show Columns выбирает колонки и сохраняет выбор в браузере. OK сохраняет и закрывает редактор, Apply сохраняет без закрытия. Ctrl/Cmd+F — поиск; Insert — добавить; Delete — удалить; Ctrl/Cmd+E / D — включить / отключить; Ctrl/Cmd+M — комментарий.</p><h3>Сохранение и применение</h3><p>Все разделы используют общий черновик. Сохранение не меняет работающую сеть. Предпросмотр показывает команды и настройки служб. После применения подтвердите связь в течение 60 секунд. Без подтверждения сервер попытается восстановить предыдущую конфигурацию. Ошибка восстановления отображается явно и требует проверки.</p><h3>Что сохраняется отдельно</h3><p>Приложение управляет собственными ресурсами. Чужие интерфейсы, адреса, маршруты и DHCP / DNS-службы не должны захватываться. Bridge и VLAN используют Linux networking, DHCP / DNS — отдельный dnsmasq, NAT / Filter — iptables. IPv4. Dummy — программный интерфейс, а не VPN. Это самостоятельный Linux-роутер, не полная реализация RouterOS.</p><h3>Деморежим</h3><p>Настройки и примеры сохраняются в отдельной базе. Сеть этого компьютера не изменяется; реальные службы, leases и счётчики доступны только в Linux-режиме.</p></div>`,
  );
}

function renderLogin(error = "") {
  root.innerHTML = `<div class="login"><form class="login-card" id="login-form">${brandMarkup()}<h2>Вход в OpenMikroRout</h2><p>Войдите в учётную запись. Группа read разрешает просмотр, full — управление роутером.</p><label class="field"><span>Имя пользователя</span><input type="text" name="username" autocomplete="username" maxlength="64" value="${e(loginUsername)}" required autofocus></label><label class="field"><span>Пароль</span><input type="password" name="password" autocomplete="current-password" maxlength="512" required></label><label class="field"><span>Код 2FA или резервный код</span><input name="code" type="text" autocomplete="one-time-code" maxlength="64"><small>Оставьте пустым, если 2FA выключена.</small></label><button class="primary" type="submit">Войти ${icon("arrow")}</button><small role="alert">${e(error)}</small></form></div>`;
}
function updateRuleCounters() {
  if (
    !dialog.open ||
    editorTab !== "statistics" ||
    !dialog.querySelector("#rule-form")
  )
    return;
  const counts = statistics[draft.id] || { bytes: 0, packets: 0 };
  dialog.querySelector('[data-counter="bytes"]').textContent = isDemo()
    ? "—"
    : fmtBytes(counts.bytes);
  dialog.querySelector('[data-counter="packets"]').textContent = isDemo()
    ? "—"
    : counts.packets.toLocaleString("ru-RU");
}
function updateTelemetry() {
  const container = document.querySelector("#telemetry-overview");
  if (!container || view !== "overview" || dialog.open) return;
  updateTelemetryView(container, routerContext());
}
function closeTelemetryChart() {
  const kind = telemetryExpanded?.kind;
  telemetryExpanded = null;
  document.body.classList.remove("telemetry-expanded-open");
  updateTelemetry();
  if (kind)
    document
      .querySelector(`[data-action="telemetry-expand"][data-kind="${kind}"]`)
      ?.focus({ preventScroll: true });
}
async function refreshTelemetryHistory(replace = false) {
  if (!alive || !state || view !== "overview" || document.hidden) return;
  const seconds = telemetryExpanded?.period || 60;
  replace ||= historyPeriod !== seconds || historyCursor === null;
  if (historyController && !replace) return;
  historyController?.abort();
  const controller = new AbortController();
  historyController = controller;
  const generation = authGeneration;
  const query = new URLSearchParams({ seconds: String(seconds) });
  if (telemetrySelection !== "all") query.set("interface", telemetrySelection);
  if (!replace && historyCursor !== null)
    query.set("after", String(historyCursor));
  try {
    const result = await api(`telemetry/history?${query}`, {
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]),
    });
    if (
      controller.signal.aborted ||
      generation !== authGeneration ||
      view !== "overview"
    )
      return;
    if (!result.available)
      throw new Error(result.error || "История недоступна");
    if (historyCursor !== null && result.timestamp < historyCursor) {
      // The server clock moved backwards; restart the cursor on the next poll.
      historyCursor = null;
      telemetryHistory = [];
      telemetry = null;
      return;
    }
    telemetryHistory = mergeStoredTelemetryHistory(
      telemetryHistory,
      result.points,
      { replace },
    );
    if (
      telemetry &&
      telemetry.timestamp >= (telemetryHistory.at(-1)?.timestamp || 0)
    )
      telemetryHistory = appendTelemetryHistory(telemetryHistory, telemetry);
    if (result.points.length) historyCursor = result.points.at(-1).timestamp;
    historyPeriod = seconds;
    telemetryHistoryError = "";
  } catch (failure) {
    if (!controller.signal.aborted && generation === authGeneration)
      telemetryHistoryError = failure.message || "Не удалось загрузить историю";
  } finally {
    if (historyController === controller) historyController = null;
    if (!controller.signal.aborted && generation === authGeneration)
      updateTelemetry();
  }
}
async function refreshTelemetry(fast = false) {
  const inFlight = fast ? fastTelemetryRequest : telemetryRequest;
  if (inFlight) return inFlight;
  if (!alive || !state || view !== "overview" || dialog.open || document.hidden)
    return;
  const controller = new AbortController();
  if (fast) fastTelemetryController = controller;
  else telemetryController = controller;
  const request = (async () => {
    try {
      const snapshot = await api(fast ? "telemetry?fast=true" : "telemetry", {
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]),
      });
      if (!alive || !state || controller.signal.aborted) return;
      telemetry = mergeTelemetrySnapshot(telemetry, snapshot);
      // A stored-history response may be newer than this in-flight live request.
      if (telemetry.timestamp >= (telemetryHistory.at(-1)?.timestamp || 0))
        telemetryHistory = appendTelemetryHistory(telemetryHistory, telemetry);
      telemetryError = "";
      if (
        telemetrySelection !== "all" &&
        !telemetry.interfaces?.some((item) => item.name === telemetrySelection)
      )
        telemetrySelection = "all";
    } catch (error) {
      if (!alive || controller.signal.aborted || !state) return;
      telemetryError = error.message || "Не удалось получить сетевые метрики.";
    } finally {
      if (fast && fastTelemetryController === controller) {
        fastTelemetryController = null;
        fastTelemetryRequest = null;
      } else if (!fast && telemetryController === controller) {
        telemetryController = null;
        telemetryRequest = null;
      }
      if (alive && state) updateTelemetry();
    }
  })();
  if (fast) fastTelemetryRequest = request;
  else telemetryRequest = request;
  return request;
}
async function refresh(manual = false) {
  if (draggingId || document.body.classList.contains("router-drag-active"))
    return;
  if (dialog.open && !state) return;
  const generation = authGeneration;
  const next = await api("state");
  if (generation !== authGeneration) return;
  if (draggingId || document.body.classList.contains("router-drag-active"))
    return;
  const changed =
    !state ||
    next.revision !== state.revision ||
    JSON.stringify(next.pending) !== JSON.stringify(state.pending) ||
    next.dirty !== state.dirty ||
    next.auth_enabled !== state.auth_enabled ||
    JSON.stringify(next.current_user) !== JSON.stringify(state.current_user) ||
    offline;
  state = next;
  if (!canWrite()) users = [];
  const ids = new Set(next.config.rules.map((rule) => rule.id));
  selected = new Set([...selected].filter((id) => ids.has(id)));
  const dnsForm = document.querySelector("#router-dns-form");
  if (view === "dns" && dnsForm?.dataset.dirty === "true") {
    const statusbar = document.querySelector("#statusbar");
    if (statusbar) statusbar.innerHTML = renderStatus();
    applyAccessControls();
    return;
  }
  if (manual || changed) {
    const results = await Promise.allSettled([
      api("interfaces"),
      api("audit"),
      api("statistics"),
      api("network/status"),
    ]);
    if (generation !== authGeneration || !state) return;
    if (results[0].status === "fulfilled") {
      interfaces = results[0].value.interfaces;
      forwarding = results[0].value.forwarding;
    }
    if (results[1].status === "fulfilled") audit = results[1].value;
    if (results[2].status === "fulfilled")
      statistics = results[2].value.counters;
    if (results[3].status === "fulfilled") networkStatus = results[3].value;
    const failure = results.find((result) => result.status === "rejected");
    if (failure) throw failure.reason;
    offline = false;
    if (draggingId || document.body.classList.contains("router-drag-active"))
      return;
    if (view === "users") await refreshUsers();
    render();
  } else if (
    !isDemo() &&
    ((view === "rules" && !dialog.open) ||
      (dialog.open &&
        editorTab === "statistics" &&
        dialog.querySelector("#rule-form")))
  ) {
    statistics = (await api("statistics")).counters;
    if (generation !== authGeneration || !state) return;
    if (draggingId || document.body.classList.contains("router-drag-active"))
      return;
    if (dialog.open) updateRuleCounters();
    else {
      document.querySelector("#rules-body").innerHTML =
        renderRuleRows(filteredRules());
      applyAccessControls();
    }
  } else if (view === "users") {
    await refreshUsers();
    render();
  }
  await Promise.all([refreshTelemetry(), refreshTelemetryHistory()]);
  if (view === "connections" && !dialog.open)
    await refreshConnections(routerContext());
  if (view === "updates") await refreshUpdates(routerContext());
}

async function handleAction(button) {
  const action = button.dataset.action,
    id = button.dataset.id;
  if (button.disabled || busy) return;
  if (state && !canWrite() && !isReadAction(action)) {
    toast("Группа read: доступен только просмотр.", true);
    return;
  }
  if (await handleUsersAction(button, routerContext())) return;
  if (await handleSecurityAction(button, routerContext())) return;
  if (await handleConnectionsAction(button, routerContext())) return;
  if (await handleUpdatesAction(button, routerContext())) return;
  if (await handleRouterAction(button, routerContext())) return;
  if (action === "close") {
    dialog.close();
    return;
  }
  if (action === "menu") {
    setNavigationOpen(
      !document.querySelector("#sidebar")?.classList.contains("open"),
      true,
    );
    return;
  }
  if (action === "nav-group") {
    const group = button.dataset.group;
    if (!["ip", "system"].includes(group)) return;
    if (expandedGroups.has(group)) expandedGroups.delete(group);
    else expandedGroups.add(group);
    render();
    document
      .querySelector(`[data-action="nav-group"][data-group="${group}"]`)
      ?.focus({ preventScroll: true });
    return;
  }
  if (action === "help") {
    showHelp();
    return;
  }
  if (action === "telemetry-refresh") {
    await Promise.all([refreshTelemetry(), refreshTelemetryHistory(true)]);
    return;
  }
  if (action === "telemetry-expand") {
    const kind = button.dataset.kind;
    if (!["speed", "packets"].includes(kind) || view !== "overview") return;
    telemetryExpanded = { kind, period: 60 };
    document.body.classList.add("telemetry-expanded-open");
    updateTelemetry();
    document
      .querySelector('[data-action="telemetry-collapse"]')
      ?.focus({ preventScroll: true });
    void refreshTelemetryHistory(true);
    return;
  }
  if (action === "telemetry-collapse") {
    closeTelemetryChart();
    return;
  }
  if (action === "columns") {
    dialogFrame(
      "Show Columns",
      "Выберите нужные поля. Порядок выполнения правил не меняется.",
      `<div class="column-options">${ruleColumns.map(([key, label]) => `<label class="checkbox-label"><input type="checkbox" name="column" value="${key}" ${visibleColumns.has(key) ? "checked" : ""} ${key === "name" ? "disabled" : ""}>${label}</label>`).join("")}</div>`,
      '<button data-action="columns-reset">По умолчанию</button><button data-action="close">Cancel</button><button class="primary" data-action="columns-save">OK</button>',
    );
    return;
  }
  if (action === "columns-reset") {
    dialog.querySelectorAll('[name="column"]').forEach((input) => {
      input.checked = defaultColumns.includes(input.value);
    });
    return;
  }
  if (action === "columns-save") {
    visibleColumns = new Set([
      "name",
      ...[...dialog.querySelectorAll('[name="column"]:checked')].map(
        (input) => input.value,
      ),
    ]);
    try {
      localStorage.setItem(
        "nat-panel.columns",
        JSON.stringify([...visibleColumns]),
      );
    } catch {
      toast("Выбор колонок сохранён только до закрытия вкладки.", true);
    }
    dialog.close();
    render();
    return;
  }
  if (action === "view") {
    const nextView = button.dataset.view;
    if (["users", "updates"].includes(nextView) && !canWrite()) return;
    closeTelemetryChart();
    historyController?.abort();
    view = nextView;
    if (view === "security") await refreshSecurity();
    if (window.matchMedia("(max-width: 680px)").matches)
      setNavigationOpen(false);
    selected.clear();
    render();
    if (
      [
        "audit",
        "interfaces",
        "overview",
        "leases",
        "routes",
        "dns",
        "dhcp_servers",
        "users",
        "connections",
        "updates",
      ].includes(view)
    )
      await run(() => refresh(true));
    return;
  }
  if (action === "add") {
    openEditor();
    return;
  }
  if (action === "edit") {
    openEditor(id);
    return;
  }
  if (action === "comment") {
    if (selected.size !== 1) {
      toast("Для комментария выберите одно правило.", true);
      return;
    }
    openEditor([...selected][0]);
    dialog.querySelector('[name="comment"]').focus();
    return;
  }
  if (action === "editor-tab") {
    if (canWrite()) collectRule();
    editorTab = button.dataset.tab;
    renderEditor();
    if (editorTab === "statistics" && !isDemo())
      await run(async () => {
        statistics = (await api("statistics")).counters;
        updateRuleCounters();
      });
    return;
  }
  if (action === "editor-toggle") {
    collectRule();
    draft.enabled = !draft.enabled;
    renderEditor();
    return;
  }
  if (action === "editor-comment") {
    collectRule();
    editorTab = "general";
    renderEditor();
    dialog.querySelector('[name="comment"]').focus();
    return;
  }
  if (action === "editor-copy") {
    collectRule();
    draft.id = crypto.randomUUID();
    draft.name += " (copy)";
    editorTab = "general";
    renderEditor();
    return;
  }
  if (action === "editor-remove") {
    selected = new Set([draft.id]);
    confirmDialog(
      "Удалить правило?",
      "Правило будет удалено из черновика. Применение к сети — отдельно.",
      "delete-confirm",
      "Удалить",
      true,
      draftRevision,
    );
    return;
  }
  if (action === "add-list" || action === "edit-list") {
    openList(id);
    return;
  }
  if (action === "duplicate") {
    if (selected.size !== 1) {
      toast("Для копирования выберите одно правило.", true);
      return;
    }
    openEditor([...selected][0], true);
    return;
  }
  if (action === "export") {
    const blob = new Blob(
      [JSON.stringify({ version: 1, config: state.config }, null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob),
      a = document.createElement("a");
    a.href = url;
    a.download = `openmikrorout-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Конфигурация экспортирована");
    return;
  }
  if (action === "import") {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.addEventListener("change", () =>
      run(async () => {
        const file = input.files[0];
        if (!file) return;
        if (file.size > 1048576) throw new Error("Файл превышает 1 MiB");
        const parsed = JSON.parse(await file.text());
        if (parsed.version !== 1 || !parsed.config)
          throw new Error("Ожидается экспорт OpenMikroRout версии 1");
        const legacyNat = !Object.hasOwn(parsed.config, "network");
        draft = prepareImportedConfig(parsed.config, state.config);
        confirmDialog(
          "Импорт конфигурации",
          `Будет загружен черновик: ${draft.rules?.length ?? 0} NAT, ${draft.filter_rules?.length ?? 0} Filter, ${draft.network?.addresses?.length ?? 0} IP, ${draft.network?.dhcp_servers?.length ?? 0} DHCP. ${legacyNat ? "В старом NAT-экспорте нет сетевых разделов — текущие настройки IP, DHCP, Bridge, VLAN и Filter сохраняются. " : ""}Работающая сеть изменится после применения.`,
          "import-confirm",
          "Импортировать",
        );
      }),
    );
    input.click();
    return;
  }
  if (action === "delete") {
    confirmDialog(
      "Удалить выбранные правила?",
      `Из черновика будут удалены ${selected.size} правил. Для изменения работающей сети потребуется применить конфигурацию.`,
      "delete-confirm",
      "Удалить",
      true,
    );
    return;
  }
  if (action === "delete-list") {
    draft = { id };
    confirmDialog(
      "Удалить список адресов?",
      "Список будет удалён из черновика. Используемые в правилах списки удалить нельзя.",
      "delete-list-confirm",
      "Удалить",
      true,
    );
    return;
  }
  if (action === "discard") {
    confirmDialog(
      "Отменить изменения?",
      "Черновик будет заменён последней подтверждённой конфигурацией.",
      "discard-confirm",
      "Отменить изменения",
      true,
    );
    return;
  }
  if (action === "apply") {
    confirmDialog(
      isDemo() ? "Применить в деморежиме?" : "Применить настройки роутера?",
      isDemo()
        ? "Будет запущена симуляция применения. Подтвердите её в течение 60 секунд. Настройки сети не изменятся."
        : "Будут применены интерфейсы, IP, DHCP / DNS, маршруты и Firewall из черновика. После применения подтвердите доступ за 60 секунд. Без подтверждения сервер попытается восстановить предыдущие настройки.",
      "apply-confirm",
      "Применить",
    );
    return;
  }
  await run(async () => {
    if (action === "refresh") {
      await refresh(true);
      toast("Данные обновлены");
      return;
    }
    if (action === "logout") {
      await api("logout", { method: "POST" });
      clearSession();
      renderLogin();
      return;
    }
    if (action === "preview") {
      const result = await api("preview", { method: "POST" });
      dialogFrame(
        "Предпросмотр конфигурации",
        "Проверка не изменяет правила хоста.",
        `<p class="preview-note">${isDemo() ? "Синтаксис конфигурации проверен приложением. Проверка ядром доступна только в Linux." : "Проверка iptables-restore --test успешно пройдена."} Ниже — NAT, Firewall Filter, виртуальные интерфейсы и настройки IP / DHCP / DNS из общего черновика.</p><pre class="code-preview">${e(result.script)}</pre>${result.router ? `<h3 class="preview-section-title">Firewall Filter</h3><pre class="code-preview">${e(result.router.filter_script || "")}</pre><h3 class="preview-section-title">Links · Bridge / VLAN / Virtual</h3><pre class="code-preview">${e(JSON.stringify(result.router.links || {}, null, 2))}</pre><h3 class="preview-section-title">IP · DHCP · DNS · Routes</h3><pre class="code-preview">${e(JSON.stringify(result.router.network || {}, null, 2))}</pre>` : result.network ? `<h3 class="preview-section-title">Network configuration</h3><pre class="code-preview">${e(JSON.stringify(result.network, null, 2))}</pre>` : ""}`,
      );
      return;
    }
    if (action === "save-rule" || action === "save-rule-open") {
      collectRule();
      if (!draft.name) throw new Error("Укажите имя правила.");
      const cfg = configCopy(),
        index = cfg.rules.findIndex((r) => r.id === draft.id);
      if (index >= 0) cfg.rules[index] = draft;
      else cfg.rules.push(draft);
      const saved = await saveConfig(cfg, draftRevision);
      draftRevision = saved.revision;
      draft = structuredClone(
        saved.config.rules.find((rule) => rule.id === draft.id) || draft,
      );
      if (action === "save-rule") dialog.close();
      else if (dialog.open) renderEditor();
      toast("Правило сохранено в черновик");
      return;
    }
    if (action === "save-list") {
      const values = Object.fromEntries(
        new FormData(dialog.querySelector("#list-form")),
      );
      const item = {
        id: draft.id,
        name: String(values.name).trim(),
        comment: String(values.comment).trim(),
        addresses: String(values.addresses)
          .split(/[\n,]+/)
          .map((x) => x.trim())
          .filter(Boolean),
      };
      const cfg = configCopy(),
        index = cfg.address_lists.findIndex((l) => l.id === draft.id);
      if (index >= 0) {
        const old = cfg.address_lists[index].name;
        cfg.address_lists[index] = item;
        for (const r of [...cfg.rules, ...(cfg.filter_rules || [])]) {
          if (r.src_list === old) r.src_list = item.name;
          if (r.dst_list === old) r.dst_list = item.name;
        }
      } else cfg.address_lists.push(item);
      await saveConfig(cfg, draftRevision);
      dialog.close();
      toast("Список адресов сохранён");
      return;
    }
    if (
      action === "delete-confirm" ||
      action === "enable" ||
      action === "disable"
    ) {
      const cfg = configCopy();
      cfg.rules =
        action === "delete-confirm"
          ? cfg.rules.filter((r) => !selected.has(r.id))
          : cfg.rules.map((r) =>
              selected.has(r.id) ? { ...r, enabled: action === "enable" } : r,
            );
      await saveConfig(
        cfg,
        action === "delete-confirm" ? confirmationRevision : state.revision,
      );
      dialog.close();
      toast(
        action === "delete-confirm"
          ? "Правила удалены из черновика"
          : "Состояние правил сохранено",
      );
      return;
    }
    if (action === "move-up" || action === "move-down") {
      if (selected.size !== 1)
        throw new Error("Для перемещения выберите одно правило.");
      const cfg = configCopy(),
        i = cfg.rules.findIndex((r) => selected.has(r.id)),
        j = i + (action === "move-up" ? -1 : 1);
      if (j < 0 || j >= cfg.rules.length) return;
      [cfg.rules[i], cfg.rules[j]] = [cfg.rules[j], cfg.rules[i]];
      await saveConfig(cfg);
      return;
    }
    if (action === "delete-list-confirm") {
      const cfg = configCopy();
      cfg.address_lists = cfg.address_lists.filter((l) => l.id !== draft.id);
      await saveConfig(cfg, confirmationRevision);
      dialog.close();
      toast("Список удалён");
      return;
    }
    if (action === "import-confirm") {
      await saveConfig(draft, confirmationRevision);
      dialog.close();
      toast("Конфигурация импортирована в черновик");
      return;
    }
    if (action === "discard-confirm") {
      assertDraftRevision(confirmationRevision, state.revision);
      acceptState(
        await api("discard", {
          method: "POST",
          body: JSON.stringify({ revision: confirmationRevision }),
        }),
      );
      dialog.close();
      toast("Черновик отменён");
      return;
    }
    if (action === "apply-confirm") {
      assertDraftRevision(confirmationRevision, state.revision);
      acceptState(
        await api("apply", {
          method: "POST",
          body: JSON.stringify({ revision: confirmationRevision }),
        }),
      );
      dialog.close();
      toast("Подтвердите связь до истечения таймера");
      return;
    }
    if (action === "confirm") {
      acceptState(
        await api("confirm", {
          method: "POST",
          body: JSON.stringify({ token: state.pending.token }),
        }),
      );
      toast("Применение подтверждено");
      return;
    }
    if (action === "rollback") {
      acceptState(await api("rollback", { method: "POST" }));
      toast("Предыдущие правила восстановлены. Черновик сохранён.");
      return;
    }
  });
}

function updateSelection() {
  for (const row of document.querySelectorAll("[data-rule]")) {
    row.classList.toggle("selected", selected.has(row.dataset.rule));
    row.querySelector("input").checked = selected.has(row.dataset.rule);
  }
  for (const button of document.querySelectorAll(".toolbar-start .icon"))
    button.disabled = !selected.size || !!state.pending || offline;
  const all = document.querySelector("#select-all");
  if (all)
    all.checked =
      filteredRules().length > 0 &&
      filteredRules().every((r) => selected.has(r.id));
  document.querySelector(".detail")?.remove();
  const footer = document.querySelector(".panel-footer");
  if (footer) {
    footer.querySelector("span").textContent =
      `${filteredRules().length} из ${state.config.rules.length} правил${selected.size ? ` · выбрано ${selected.size}` : ""}`;
    if (selected.size === 1)
      footer.insertAdjacentHTML(
        "beforebegin",
        renderDetail(state.config.rules.find((r) => selected.has(r.id))),
      );
  }
  document.querySelector("#statusbar").innerHTML = renderStatus();
  applyAccessControls();
}

function clearDragIndicators() {
  document.querySelectorAll(".drop-before, .drop-after").forEach((row) => {
    row.classList.remove("drop-before", "drop-after");
  });
}
function endDrag() {
  draggingId = null;
  clearDragIndicators();
  document
    .querySelectorAll(".dragging")
    .forEach((row) => row.classList.remove("dragging"));
}
document.addEventListener(
  "dragstart",
  (event) => {
    if (
      !canWrite() &&
      event.target.closest("[data-drag-id],[data-filter-drag]")
    ) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  },
  true,
);
document.addEventListener("dragstart", (event) => {
  const handle = event.target.closest("[data-drag-id]");
  if (
    !handle ||
    handle.disabled ||
    !canWrite() ||
    busy ||
    state.pending ||
    offline
  ) {
    if (handle) event.preventDefault();
    return;
  }
  draggingId = handle.dataset.dragId;
  event.dataTransfer.effectAllowed = "move";
  event.dataTransfer.setData("text/plain", draggingId);
  const row = handle.closest("[data-rule]");
  event.dataTransfer.setDragImage(row, 30, row.offsetHeight / 2);
  row.classList.add("dragging");
});
document.addEventListener("dragover", (event) => {
  const row = event.target.closest("[data-rule]");
  if (
    !draggingId ||
    !row ||
    row.dataset.rule === draggingId ||
    busy ||
    state.pending
  )
    return;
  event.preventDefault();
  event.dataTransfer.dropEffect = "move";
  const rect = row.getBoundingClientRect();
  clearDragIndicators();
  row.classList.add(
    event.clientY < rect.top + rect.height / 2 ? "drop-before" : "drop-after",
  );
});
document.addEventListener("dragleave", (event) => {
  const row = event.target.closest("[data-rule]");
  if (row && !row.contains(event.relatedTarget)) {
    row.classList.remove("drop-before", "drop-after");
  }
});
document.addEventListener("drop", (event) => {
  const row = event.target.closest("[data-rule]");
  if (!draggingId || !row || !canWrite() || busy || state.pending || offline)
    return;
  event.preventDefault();
  const sourceId = draggingId;
  const targetId = row.dataset.rule;
  const rect = row.getBoundingClientRect();
  const placement =
    event.clientY < rect.top + rect.height / 2 ? "before" : "after";
  endDrag();
  void run(async () => {
    const config = configCopy();
    const reordered = reorderRules(config.rules, sourceId, targetId, placement);
    if (reordered.every((rule, index) => rule.id === config.rules[index].id))
      return;
    config.rules = reordered;
    selected = new Set([sourceId]);
    await saveConfig(config);
    toast("Порядок правил сохранён в черновик");
  });
});
document.addEventListener("dragend", endDrag);
document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (button) {
    void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  const row = event.target.closest("[data-rule]");
  if (row && !event.target.closest("input")) {
    selected = new Set([row.dataset.rule]);
    updateSelection();
  }
});
document.addEventListener("dblclick", (event) => {
  const row = event.target.closest("[data-rule]");
  if (row && !event.target.closest("button,input"))
    openEditor(row.dataset.rule);
});
document.addEventListener("keydown", (event) => {
  if (
    event.key === "Escape" &&
    !dialog.open &&
    document.querySelector("#sidebar.open")
  ) {
    event.preventDefault();
    setNavigationOpen(false, true);
    return;
  }
  if (telemetryExpanded) {
    if (event.key === "Escape") {
      event.preventDefault();
      closeTelemetryChart();
    } else if (event.key === "Tab") {
      const controls = [
        ...document.querySelectorAll(
          ".telemetry-expanded button,.telemetry-expanded select",
        ),
      ];
      const first = controls[0],
        last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }
    return;
  }
  if (event.key === "Enter" && event.target.matches("[data-rule]")) {
    event.preventDefault();
    openEditor(event.target.dataset.rule);
    return;
  }
  if (dialog.open || !state || view !== "rules" || busy) return;
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
    event.preventDefault();
    document.querySelector("#rule-search").focus();
    return;
  }
  if (event.target.closest("input,textarea,select")) return;
  if (!canWrite()) return;
  let action;
  if (event.key === "Insert") action = "add";
  if (selected.size && event.key === "Delete") action = "delete";
  if (selected.size && (event.ctrlKey || event.metaKey)) {
    action =
      { d: "disable", e: "enable", m: "comment" }[event.key.toLowerCase()] ||
      action;
  }
  if (selected.size === 1 && event.altKey) {
    action =
      { ArrowUp: "move-up", ArrowDown: "move-down" }[event.key] || action;
  }
  const button =
    action && document.querySelector(`.toolbar [data-action="${action}"]`);
  if (button && !button.disabled) {
    event.preventDefault();
    void handleAction(button).catch((error) => toast(error.message, true));
  }
});
document.addEventListener("input", (event) => {
  const dnsForm = event.target.closest("#router-dns-form");
  if (dnsForm && canWrite()) dnsForm.dataset.dirty = "true";
  if (event.target.id === "rule-search") {
    search = event.target.value;
    const pos = event.target.selectionStart;
    render();
    const node = document.querySelector("#rule-search");
    node.focus();
    node.setSelectionRange(pos, pos);
  }
});
document.addEventListener("change", (event) => {
  const node = event.target;
  if (node.id === "telemetry-period" && telemetryExpanded) {
    const period = Number(node.value);
    if ([60, 300, 900, 3600].includes(period)) {
      telemetryExpanded = { ...telemetryExpanded, period };
      updateTelemetry();
      void refreshTelemetryHistory(true);
    }
    return;
  }
  if (node.id === "telemetry-interface") {
    telemetrySelection = node.value;
    historyCursor = null;
    updateTelemetry();
    void refreshTelemetryHistory(true);
    return;
  }
  if (
    !canWrite() &&
    node.closest(
      "#rule-form,#list-form,#router-form,#router-port-form,#router-dns-form,#user-form",
    )
  )
    return;
  handleRouterChange(event, routerContext());
  if (node.dataset.select) {
    node.checked
      ? selected.add(node.dataset.select)
      : selected.delete(node.dataset.select);
    updateSelection();
  }
  if (node.id === "select-all") {
    selected = node.checked
      ? new Set(filteredRules().map((r) => r.id))
      : new Set();
    updateSelection();
  }
  if (node.id === "chain-filter") {
    chainFilter = node.value;
    render();
  }
  if (node.id === "protocol-filter") {
    protocolFilter = node.value;
    render();
  }
  if (node.id === "rule-enabled" && draft && canWrite())
    draft.enabled = node.checked;
  if (node.name === "chain" && dialog.querySelector("#rule-form")) {
    collectRule();
    draft.action = draft.chain === "srcnat" ? "masquerade" : "dst-nat";
    draft.in_interface = "";
    draft.out_interface = "";
    draft.in_interface_list = "";
    draft.out_interface_list = "";
    draft.to_address = "";
    draft.to_ports = "";
    renderEditor();
  }
  if (node.name === "protocol" && dialog.querySelector("#rule-form")) {
    collectRule();
    if (!["tcp", "udp"].includes(draft.protocol)) {
      draft.src_ports = "";
      draft.dst_ports = "";
      draft.to_ports = "";
    }
    renderEditor();
  }
  if (node.name === "action" && dialog.querySelector("#rule-form")) {
    collectRule();
    if (!["dst-nat", "src-nat"].includes(draft.action)) draft.to_address = "";
    if (draft.action === "accept") draft.to_ports = "";
    renderEditor();
  }
  if (node.id === "template") {
    collectRule();
    const name = draft.name,
      id = draft.id;
    draft = { ...defaultRule(), id, name };
    if (node.value === "masquerade")
      Object.assign(draft, {
        name: name || "Internet access",
        chain: "srcnat",
        action: "masquerade",
        protocol: "any",
      });
    if (node.value === "forward")
      Object.assign(draft, {
        name: name || "Port forwarding",
        dst_ports: "443",
        to_ports: "443",
      });
    if (node.value === "dns")
      Object.assign(draft, {
        name: name || "DNS redirect",
        action: "redirect",
        protocol: "udp",
        dst_ports: "53",
        to_ports: "53",
      });
    if (node.value === "snat")
      Object.assign(draft, {
        name: name || "Source NAT",
        chain: "srcnat",
        action: "src-nat",
        protocol: "any",
      });
    renderEditor();
  }
});
document.addEventListener("focusout", (event) => {
  if (event.target.id === "telemetry-interface")
    queueMicrotask(updateTelemetry);
});
document.addEventListener("submit", (event) => {
  event.preventDefault();
  if (event.target.id === "connections-filter") {
    void handleAction({
      dataset: { action: "connections-filter" },
      disabled: false,
    }).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "user-form") {
    void handleAction({
      dataset: { action: "user-save" },
      disabled: false,
    }).catch((error) => toast(error.message, true));
    return;
  }
  if (
    event.target.id.startsWith("security-") ||
    event.target.id === "update-proof-form"
  ) {
    const button = dialog.querySelector(
      '[data-action="security-setup"],[data-action="security-confirm"],[data-action="security-disable"],[data-action="user-totp-reset-confirm"],[data-action="updates-apply"]',
    );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "login-form")
    void run(async () => {
      try {
        const values = new FormData(event.target);
        loginUsername = String(values.get("username") || "").trim();
        const password = String(values.get("password") || "");
        await api("login", {
          method: "POST",
          body: JSON.stringify({
            username: loginUsername,
            password,
            code: String(values.get("code") || "").trim(),
          }),
        });
        event.target.querySelector('[name="password"]').value = "";
        clearSession();
        await refresh(true);
      } catch (error) {
        renderLogin(error.message);
      }
    });
});
async function boot() {
  try {
    await refresh(true);
  } catch (error) {
    if (state) {
      offline = true;
      render();
    } else if (!document.querySelector("#login-form"))
      root.innerHTML = `<div class="empty"><p>Сервер недоступен</p><small>${e(error.message)}</small><button data-action="refresh">Повторить</button></div>`;
  }
}
installRouterEvents(routerContext);
void boot();
async function poll() {
  if (!alive || !state || busy || pollInFlight || document.hidden) return;
  pollInFlight = true;
  try {
    await refresh();
  } catch (error) {
    if (state && !offline) {
      offline = true;
      render();
      toast(`Данные сервера недоступны. ${error.message}`, true);
    }
  } finally {
    pollInFlight = false;
  }
}
function updateCountdown() {
  if (state?.pending) {
    const node = document.querySelector("#countdown");
    if (node) node.textContent = secondsLeft();
  }
}
function startPolling() {
  pollTimer = setInterval(poll, 5000);
  telemetryTimer = setInterval(() => {
    if (!busy) void refreshTelemetry(true);
  }, 200);
  countdownTimer = setInterval(updateCountdown, 1000);
}
startPolling();
window
  .matchMedia("(max-width: 680px)")
  .addEventListener("change", () => setNavigationOpen(false));
window.addEventListener("pagehide", () => {
  alive = false;
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  telemetryController?.abort();
  fastTelemetryController?.abort();
  historyController?.abort();
  clearInterval(pollTimer);
  clearInterval(telemetryTimer);
  clearInterval(countdownTimer);
});
window.addEventListener("pageshow", () => {
  if (!alive) {
    alive = true;
    startPolling();
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
    telemetryController?.abort();
    fastTelemetryController?.abort();
    historyController?.abort();
  } else {
    void refreshTelemetry(true);
    void poll();
  }
});

dialog.addEventListener("close", () => {
  if (
    !dialog.open &&
    dialog.querySelector("#security-recovery-codes,#security-setup-form")
  )
    dialog.innerHTML = "";
  if (!dialog.open && state && ["security", "updates"].includes(view)) render();
});
