import { t, html, setLanguage, locale } from "./i18n.js";
import { newUuid } from "./uuid.js";
import { installCheckboxSelectEvents } from "./checkbox-select.js";
import { assertDraftRevision } from "./draft-guards.js";
import {
  renderQueryBuilder,
  applyQueryBuilder,
  getAppliedQuery,
  compileQueryExpression,
  resetAllQueryBuilders,
  handleQueryBuilderInput,
  handleQueryBuilderAction,
} from "./query-builder.js";
import { natQuerySchema } from "./config-filter-schemas.js";
import {
  withRuleNegation,
  collectRuleNegations,
  toggleRuleNegation,
  syncRuleNegationControls,
  negatedValue,
  negationSummary,
} from "./rule-match-ui.js";
import {
  renderHeaderControls,
  captureHeaderState,
  restoreHeaderState,
  closeHeaderPopovers,
} from "./header-ui.js?v=1";
import {
  navigationGroupIds,
  navigationItems,
  expandNavigationForView,
  renderSidebarNavigation,
  renderNavigationBreadcrumbs,
} from "./navigation-ui.js?v=1";
import {
  countryField,
  renderRuleFail2ban,
  renderLegacyBanMatch,
  collectRuleProtection,
  defaultRuleProtection,
} from "./rule-security-ui.js?v=3";
import {
  loginMarkup,
  bindLoginControls,
  setLoginBusy,
} from "./login-ui.js?v=1";
import {
  renderBackups,
  handleBackupAction,
  handleBackupInput,
  resetBackups,
} from "./backups-ui.js?v=1";
import {
  applicationViews,
  renderApplications,
  refreshApplications,
  resetApplications,
  handleApplicationsAction,
  handleApplicationsInput,
  installApplicationsEvents,
} from "./applications-ui.js?v=1";
import { reorderRules } from "./rule-order.js";
import {
  renderTools,
  handleToolsAction,
  handleToolsInput,
  resetTools,
} from "./tools-ui.js?v=1";
import {
  renderCapture,
  refreshCapture,
  handleCaptureAction,
  handleCaptureInput,
  resetCapture,
} from "./capture-ui.js";
import {
  renderWireGuard,
  refreshWireGuard,
  resetWireGuard,
  clearWireGuardSecrets,
  handleWireGuardAction,
  handleWireGuardChange,
} from "./wireguard-ui.js?v=2";
import {
  appendTelemetryHistory,
  mergeTelemetrySnapshot,
  mergeStoredTelemetryHistory,
  stopTelemetryAnimation,
  updateTelemetryView,
} from "./telemetry-ui.js?v=7";
import {
  hasWriteAccess,
  isReadAction,
  applyReadAccess,
} from "./access-ui.js?v=9";
import { renderUsers, handleUsersAction } from "./users-ui.js?v=2";
import { renderSecurity, handleSecurityAction } from "./security-ui.js?v=1";
import {
  renderUpdates,
  refreshUpdates,
  resetUpdates,
  handleUpdatesAction,
} from "./updates-ui.js?v=2";
import {
  renderConnections,
  setConnectionSource,
  refreshConnections,
  resetConnections,
  handleConnectionsAction,
} from "./connections-ui.js?v=6";
import {
  routerViews,
  renderRouterView,
  handleRouterAction,
  handleRouterChange,
  interfaceNames,
  installRouterEvents,
} from "./router-pages.js?v=16";

import {
  protectionViews,
  renderProtection,
  refreshProtection,
  resetProtection,
  handleProtectionAction,
  handleProtectionInput,
  renderSystemLists,
  addressListChoices,
  renderF2BRuleSummary,
} from "./protection-ui.js?v=3";
import {
  discoveryViews,
  renderDiscovery,
  refreshDiscovery,
  resetDiscovery,
  handleDiscoveryAction,
  handleDiscoveryInput,
} from "./discovery-ui.js?v=1";
import { proofForm, proof, clearProof } from "./security-ui.js?v=1";

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
  html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[name] || paths.grid}"/></svg>`;
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
dialog.addEventListener("close", () => {
  if (
    dialog.querySelector("#backup-proof") ||
    dialog.querySelector('[name="new_archive_password"]')
  ) {
    for (const input of dialog.querySelectorAll(
      'input[type="password"],input[name="code"]',
    ))
      input.value = "";
  }
});
let state,
  view = "overview",
  selected = new Set();
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
const expandedGroups = new Set(["ip", "firewall"]);
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
  applicationTimer,
  alive = true;
const isDemo = () => state?.mode === "demo";
const canWrite = () => hasWriteAccess(state);
const currentUser = () => state?.current_user || null;
function requireWrite() {
  if (!canWrite())
    throw new Error(
      t("Группа read: изменения доступны только пользователям full."),
    );
}
function applyAccessControls() {
  applyReadAccess(document, state);
}
function clearSession() {
  clearTimeout(toastTimer);
  const oldToast = document.querySelector("#toast");
  if (oldToast) {
    oldToast.textContent = "";
    oldToast.className = "";
  }
  setNavigationOpen(false);
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  resetUpdates();
  resetBackups();
  resetConnections();
  resetWireGuard();
  resetTools();
  resetCapture();
  resetProtection();
  resetDiscovery();
  resetApplications();
  resetAllQueryBuilders();
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
  ["name", t("Comment / Name")],
  ["action", t("Action")],
  ["chain", t("Chain")],
  ["protocol", t("Protocol")],
  ["src", t("Src. Address / List")],
  ["dst", t("Dst. Address / List")],
  ["src_ports", t("Src. Port")],
  ["dst_ports", t("Dst. Port")],
  ["in_interface", t("In. Interface")],
  ["out_interface", t("Out. Interface")],
  ["target", t("To Addresses / Ports")],
  ["bytes", t("Bytes")],
  ["packets", t("Packets")],
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
  const { responseType, ...fetchOptions } = options;
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
      "me/preferences",
    ].includes(path)
  )
    requireWrite();
  const generation = authGeneration;
  const response = await fetch(`/api/${path}`, {
    credentials: "same-origin",
    signal: AbortSignal.timeout(path === "apply" ? 45000 : 20000),
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      "X-NAT-Request": "1",
      ...fetchOptions.headers,
    },
  });
  const data =
    response.ok && responseType === "stream"
      ? response
      : response.ok && responseType === "blob"
        ? await response.blob()
        : await response.json();
  if (response.status === 401 && path !== "login") {
    if (generation === authGeneration) {
      clearSession();
      renderLogin();
    }
    throw new Error(t("Сессия завершена. Войдите снова."));
  }
  if (!response.ok) {
    const detail = Array.isArray(data.detail)
      ? data.detail
          .map((x) => `${x.field ? x.field + ": " : ""}${x.message}`)
          .join("\n")
      : data.detail;
    throw new Error(detail || html`Ошибка HTTP ${response.status}`);
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
  if (state.current_user) setLanguage(state.current_user.language);
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
  return html`<span class="action-badge ${e(action)}">${icon(action === "masquerade" ? "swap" : action === "accept" ? "check" : "arrow")}${e(action)}</span>`;
}
function listRef(name) {
  return html`<span class="list-ref">${icon("list")}${e(name)}</span>`;
}
function addr(rule, side) {
  const address = rule[`${side}_list`]
    ? listRef(negatedValue(rule, `${side}_list`))
    : html`<span class="mono ${rule[`${side}_address`] ? "" : "muted"}">${e(negatedValue(rule, `${side}_address`, "any"))}</span>`;
  const country = rule[`${side}_country`];
  const conditions = [
    country ? `Country: ${negatedValue(rule, `${side}_country`)}` : "",
    side === "src" && rule.f2b_profile
      ? `${rule.f2b_match === "banned" ? "∈" : "∉"} f2b_${rule.f2b_profile}`
      : "",
    side === "src" && rule.protection?.enabled ? t("Fail2ban · авто") : "",
  ].filter(Boolean);
  return (
    address +
    (conditions.length
      ? html`<small class="cell-note">${e(conditions.join(" · "))}</small>`
      : "")
  );
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
function setNavigationOpen(open, focus = false) {
  const sidebar = document.querySelector("#sidebar");
  const mobile = window.matchMedia("(max-width: 680px)").matches;
  sidebar?.classList.toggle("open", open && mobile);
  document.body.classList.toggle("mobile-navigation-open", open && mobile);
  const main = document.querySelector("main");
  if (main) main.inert = open && mobile;
  const button = document.querySelector('[data-action="menu"].mobile-menu');
  button?.setAttribute("aria-expanded", String(open && mobile));
  if (focus) {
    const active = sidebar?.querySelector(".nav-item.active");
    const destination = open
      ? active?.getClientRects().length
        ? active
        : sidebar?.querySelector(".nav-group-toggle.active-branch") ||
          sidebar?.querySelector(".nav-item")
      : button;
    destination?.focus({ preventScroll: true });
  }
}
function navigationContext() {
  return { state, interfaces, canWrite, view, expandedGroups, e, icon };
}
function renderNavigation() {
  return renderSidebarNavigation(navigationContext());
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
  return html`<div class="configuration-stat" title="${e(meta)}"><span>${e(t(title))}</span><strong>${e(number)}</strong></div>`;
}

function brandMarkup() {
  return html`<div class="brand"><img src="/logo.png?v=5" alt="OpenMikroRout"><div class="brand-word"><strong>Open<span>Mikro</span>Rout</strong><small>OPEN NETWORK ROUTER</small></div></div>`;
}
function routerContext() {
  return {
    state,
    setLanguage,
    showHostConnections: (address) => {
      setConnectionSource(address);
      return handleAction({
        dataset: { action: "view", view: "connections" },
        disabled: false,
      });
    },
    navigate: (name) =>
      handleAction({
        dataset: { action: "view", view: name },
        disabled: false,
      }),
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
    acceptState,
    render,
  };
}
function render() {
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  if (!state) return;
  const headerState = captureHeaderState(root);
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
    applicationViews[view] ||
    protectionViews[view] ||
    discoveryViews[view] ||
    routerViews[view] ||
    {
      rules: [
        t("NAT Rules"),
        t(
          "Трансляция адресов, проброс портов и управление доступом в интернет.",
        ),
      ],
      lists: [
        t("Address Lists"),
        t("Списки адресов и подсетей для NAT и Firewall."),
      ],
      interfaces: [
        t("Interfaces"),
        t("Обнаруженные физические и виртуальные интерфейсы Linux."),
      ],
      audit: [
        t("Журнал изменений"),
        t("История сохранения, применения и восстановления конфигурации."),
      ],
      users: [t("Users"), t("Учётные записи и группы доступа read / full.")],
      security: [
        t("Мой профиль"),
        t("Личная двухфакторная аутентификация и резервные коды."),
      ],
      connections: [
        t("Connections"),
        t("Входящие соединения IPv4 и наблюдение попыток подключения."),
      ],
      backups: [
        t("Backup / Restore"),
        t("Экспорт .rsc, импорт и зашифрованные резервные копии."),
      ],
      updates: [
        t("Updates"),
        t("Подписанные обновления из GitHub с резервной копией и откатом."),
      ],
      wireguard: [
        t("WireGuard"),
        t("VPN-сервер, клиент и site-to-site · IPv4 · ключи и peers."),
      ],
      wireguard_peers: [
        t("WireGuard Peers"),
        t("Устройства и удалённые сети, handshake и счётчики туннелей."),
      ],
      tools: [
        t("Tools"),
        t("Ping, traceroute, DNS, маршруты и проверка TCP-соединений."),
      ],
      capture: [
        t("Packet Sniffer"),
        t("Просмотр заголовков IPv4-пакетов на выбранном интерфейсе."),
      ],
    }[view] ||
    routerViews.overview;
  document.title = `OpenMikroRout · ${t(title)}`;
  let tabs;
  if (["rules", "filter", "lists", "connections"].includes(view))
    tabs = [
      ["filter", t("Filter Rules"), "shield", (cfg.filter_rules || []).length],
      ["rules", "NAT", "swap", rules.length],
      ["lists", t("Address Lists"), "list", cfg.address_lists.length],
      ["connections", t("Connections"), "activity", ""],
    ];
  else if (
    ["interfaces", "vlans", "virtual_interfaces", "interface_lists"].includes(
      view,
    )
  )
    tabs = [
      ["interfaces", t("Interfaces"), "network", interfaces.length],
      ["vlans", t("VLAN"), "swap", count("vlans")],
      ["virtual_interfaces", t("Virtual"), "grid", count("virtual_interfaces")],
      [
        "interface_lists",
        t("Interface Lists"),
        "network",
        count("interface_lists"),
      ],
    ];
  else if (["bridges", "bridge_ports"].includes(view))
    tabs = [
      ["bridges", t("Bridge"), "network", count("bridges")],
      [
        "bridge_ports",
        t("Ports"),
        "network",
        (network.bridges || []).reduce(
          (total, bridge) => total + bridge.members.length,
          0,
        ),
      ],
    ];
  else if (["dhcp_servers", "dhcp_networks", "leases"].includes(view))
    tabs = [
      ["dhcp_servers", t("DHCP Server"), "server", count("dhcp_servers")],
      ["dhcp_networks", t("Networks"), "network", count("dhcp_servers")],
      ["leases", t("Leases"), "clock", (networkStatus.leases || []).length],
    ];
  else if (["wireguard", "wireguard_peers"].includes(view))
    tabs = [
      ["wireguard", t("Interfaces"), "network", count("wireguard_interfaces")],
      ["wireguard_peers", t("Peers"), "user", count("wireguard_peers")],
    ];
  else if (["dns", "dns_static"].includes(view))
    tabs = [
      ["dns", t("Settings"), "activity", ""],
      ["dns_static", t("Static"), "list", count("dns_static")],
    ];
  else tabs = [];
  const body = applicationViews[view]
    ? renderApplications(routerContext(), view)
    : protectionViews[view]
      ? renderProtection(view, routerContext())
      : discoveryViews[view]
        ? renderDiscovery(view, routerContext())
        : view === "backups"
          ? renderBackups(routerContext())
          : view === "tools"
            ? renderTools(routerContext())
            : view === "capture"
              ? renderCapture(routerContext())
              : ["wireguard", "wireguard_peers"].includes(view)
                ? renderWireGuard(routerContext(), view === "wireguard_peers")
                : view === "updates"
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
                                : (view === "filter"
                                    ? renderF2BRuleSummary(routerContext())
                                    : "") +
                                  renderRouterView(view, routerContext());
  root.innerHTML = html`<div class="app-shell">
    <aside class="sidebar ${sidebarOpen ? "open" : ""}" id="sidebar">${brandMarkup()}
      <nav class="sidebar-navigation" aria-label="Настройки роутера">${renderNavigation()}</nav>
      <div class="sidebar-bottom"><button class="nav-item" data-action="help">${icon("help")}Справка</button></div>
    </aside><button class="sidebar-scrim" data-action="menu" aria-label="Закрыть меню" tabindex="-1"></button>
    <main class="main"><header class="topbar"><div class="breadcrumbs"><button class="icon ghost mobile-menu" aria-label="Открыть меню" aria-controls="sidebar" aria-expanded="false" data-action="menu">${icon("menu")}</button>${icon("network")}${renderNavigationBreadcrumbs(navigationContext(), title)}</div>${renderHeaderControls(routerContext())}</header>
    <div class="content">${state.runtime_error ? html`<div class="connection-error" role="alert">${icon("info")} Восстановление конфигурации требует внимания: ${e(state.runtime_error)}</div>` : ""}${offline ? html`<div class="connection-error">Данные сервера недоступны. Изменения заблокированы до восстановления соединения.</div>` : ""}
      ${!canWrite() ? html`<div class="read-only-banner">${icon("lock")}Группа read: настройки доступны для просмотра. Изменения выполняют пользователи full.</div>` : ""}
      <div class="page-heading"><div><h1>${e(t(title))}</h1><p>${e(t(description))}</p></div><div class="heading-buttons"><button data-action="preview" title="Предпросмотр конфигурации">${icon("terminal")}<span class="btn-label">Preview</span></button><button data-action="import" title="Импорт конфигурации">${icon("upload")}<span class="btn-label">Импорт</span></button><button data-action="export" title="Экспорт конфигурации">${icon("download")}<span class="btn-label">Export</span></button></div></div>
      ${["overview", "users", "security", "updates", "connections", "backups", ...Object.keys(applicationViews), ...Object.keys(protectionViews), ...Object.keys(discoveryViews)].includes(view) ? "" : html`<div class="configuration-summary" aria-label="Сводка конфигурации">${stat(t("Интерфейсы"), interfaces.length, `${count("bridges")} bridge · ${count("vlans")} VLAN`)}${stat(t("IP-адреса"), count("addresses"), t("Назначены в конфигурации"))}${stat(t("DHCP Servers"), count("dhcp_servers"), html`${count("pools")} пулов · ${(networkStatus.leases || []).length} аренд`)}${stat(t("Firewall Rules"), rules.length + (cfg.filter_rules || []).length, `${rules.length} NAT · ${(cfg.filter_rules || []).length} Filter`)}</div>`}
      <section class="panel ${view === "overview" ? "overview-panel" : ""}">${tabs.length ? html`<div class="panel-tabs">${tabs.map(([id, label, ico, total]) => html`<button class="panel-tab ${view === id ? "active" : ""}" data-action="view" data-view="${id}">${icon(ico)}${t(label)}<span class="tab-count">${total}</span></button>`).join("")}</div>` : ""}${body}</section>
      ${["overview", "users", "security", "updates", "connections", "backups", ...Object.keys(applicationViews), ...Object.keys(protectionViews), ...Object.keys(discoveryViews)].includes(view) ? "" : html`<details class="configuration-help"><summary>Работа с черновиком и применением</summary><div class="info-row"><div class="tip-card">${icon("info")}<div><h3>Один черновик для всего роутера</h3><p>Bridge → VLAN → IP-адрес → DHCP → маршруты и Firewall. Сначала сохраните настройки, затем проверьте общий предпросмотр.</p><button class="text-link" data-action="help">Как это работает ${icon("arrow")}</button></div></div><div class="tip-card">${icon("lock")}<div><h3>${isDemo() ? t("Можно спокойно экспериментировать") : t("Применение с контролем связи")}</h3><p>${isDemo() ? t("Деморежим использует отдельную базу и симуляцию. Сетевые настройки компьютера не меняются.") : t("После применения подтвердите связь в течение 60 секунд. Без подтверждения сервер попытается восстановить предыдущую конфигурацию.")}</p></div></div></div></details>`}
      <div class="page-footer"><span>${icon("shield")}OpenMikroRout · Your network. Your rules.</span><span>Lightweight Linux router · IPv4</span></div>
    </div><div id="statusbar">${renderStatus()}</div></main></div>`;
  const navigation = document.querySelector(".sidebar-navigation");
  if (navigation) navigation.scrollTop = sidebarScroll;
  setNavigationOpen(sidebarOpen);
  applyAccessControls();
  restoreHeaderState(root, headerState);
}

function filteredRules() {
  const matches = compileQueryExpression(
    getAppliedQuery("nat"),
    natQuerySchema(),
  );
  return state.config.rules.filter(matches);
}
function renderRules() {
  const rows = filteredRules(),
    locked = !!state.pending || offline || !canWrite();
  return html`<div class="toolbar"><div class="toolbar-start"><button class="primary add" data-action="add" ${locked ? "disabled" : ""}>${icon("plus")}Добавить правило</button><span class="separator"></span>${[
    ["delete", "minus", t("Удалить выбранные")],
    ["enable", "check", t("Включить")],
    ["disable", "x", t("Отключить")],
    ["comment", "edit", t("Комментарий")],
    ["duplicate", "copy", t("Создать копию")],
    ["move-up", "up", t("Переместить выше")],
    ["move-down", "arrowdown", t("Переместить ниже")],
  ]
    .map(
      ([a, i, t]) =>
        html`<button class="icon ghost" title="${t}" aria-label="${t}" data-action="${a}" ${!selected.size || locked ? "disabled" : ""}>${icon(i)}</button>`,
    )
    .join(
      "",
    )}</div><div class="toolbar-end"><button class="icon ghost" data-action="columns" title="Настроить колонки" aria-label="Настроить колонки">${icon("list")}</button><button class="icon ghost" data-action="refresh" title="Обновить" aria-label="Обновить">${icon("refresh")}</button></div></div>
    ${renderQueryBuilder("nat", natQuerySchema(), { applyAction: "nat-query-apply" })}
    <div class="table-scroll"><table class="rules-table"><thead><tr><th><input type="checkbox" id="select-all" aria-label="Выбрать все показанные правила" ${rows.length && rows.every((r) => selected.has(r.id)) ? "checked" : ""}></th><th class="drag-column" aria-label="Перетаскивание"></th><th>#</th>${ruleColumns.map(([key, label]) => html`<th data-column="${key}" ${visibleColumns.has(key) ? "" : "hidden"}>${t(label)}</th>`).join("")}<th></th></tr></thead><tbody id="rules-body">${renderRuleRows(rows)}</tbody></table>${!rows.length ? empty("shield", getAppliedQuery("nat") ? t("Ничего не найдено") : t("Пока нет правил NAT"), getAppliedQuery("nat") ? t("Измените поисковый запрос или фильтры.") : t("Добавьте первое правило или выберите готовый шаблон в редакторе.")) : ""}</div>
    ${selected.size === 1 ? renderDetail(state.config.rules.find((r) => selected.has(r.id))) : ""}
    <div class="panel-footer"><span>${rows.length} из ${state.config.rules.length} правил${selected.size ? html` · выбрано ${selected.size}` : ""}</span><div class="footer-legend"><span><i class="dot"></i>Включено</span><span><i class="dot off"></i>Отключено</span><span>${isDemo() ? t("Счётчики недоступны в демо") : t("Счётчики первых пакетов соединений")}</span></div></div>`;
}
function updateRuleTable() {
  const body = document.querySelector("#rules-body");
  if (!body) return;
  const rows = filteredRules();
  body.innerHTML = renderRuleRows(rows);
  const scroll = body.closest(".table-scroll");
  scroll.querySelector(".empty")?.remove();
  if (!rows.length)
    scroll.insertAdjacentHTML(
      "beforeend",
      empty(
        "shield",
        t("Ничего не найдено"),
        t("Измените поисковый запрос или фильтры."),
      ),
    );
  updateSelection();
}
function renderRuleRows(rows) {
  return rows
    .map((rule) => {
      const values = {
        name: html`<div class="rule-name"><span class="dot ${rule.enabled ? "" : "off"}"></span>${negationSummary(rule) ? html`<span class="rule-negation-badge" title="${e(t("Отрицание условий: {fields}", { fields: negationSummary(rule) }))}">!</span>` : ""}${e(rule.name)}</div>${rule.comment ? html`<div class="rule-comment" title="${e(rule.comment)}">${e(rule.comment)}</div>` : ""}`,
        action: actionBadge(rule.action),
        chain: html`<span class="mono">${e(rule.chain)}</span>`,
        protocol: html`<span class="protocol-badge">${e(negatedValue(rule, "protocol"))}</span>`,
        src: addr(rule, "src"),
        dst: addr(rule, "dst"),
        src_ports: html`<span class="mono">${e(negatedValue(rule, "src_ports"))}</span>`,
        dst_ports: html`<span class="mono">${e(negatedValue(rule, "dst_ports"))}</span>`,
        in_interface: html`<span class="mono">${e(negatedValue(rule, "in_interface"))}</span>`,
        out_interface: html`<span class="mono">${e(negatedValue(rule, "out_interface"))}</span>`,
        target: html`<span class="mono">${e(target(rule))}</span>`,
        bytes: isDemo() ? "—" : fmtBytes(statistics[rule.id]?.bytes || 0),
        packets: isDemo()
          ? "—"
          : (statistics[rule.id]?.packets || 0).toLocaleString(locale()),
      };
      return html`<tr data-rule="${e(rule.id)}" class="${selected.has(rule.id) ? "selected " : ""}${rule.enabled ? "" : "disabled"}" tabindex="0" aria-label="${e(rule.name)}">
      <td><input type="checkbox" data-select="${e(rule.id)}" aria-label="Выбрать ${e(rule.name)}" ${selected.has(rule.id) ? "checked" : ""}></td>
      <td class="drag-column"><button class="drag-handle" draggable="${canWrite() && !state.pending && !offline}" data-drag-id="${e(rule.id)}" title="Перетащить правило" aria-label="Перетащить ${e(rule.name)}" ${!canWrite() || state.pending || offline ? "disabled" : ""}>${icon("grip")}</button></td>
      <td class="row-number">${state.config.rules.indexOf(rule)}</td>
      ${ruleColumns.map(([key]) => html`<td data-column="${key}" ${visibleColumns.has(key) ? "" : "hidden"} class="${["bytes", "packets"].includes(key) ? "counter-cell" : ""}">${values[key]}</td>`).join("")}
      <td><button class="icon ghost" data-action="edit" data-id="${e(rule.id)}" title="Редактировать правило" aria-label="Редактировать ${e(rule.name)}" ${state.pending ? "disabled" : ""}>${icon("edit")}</button></td></tr>`;
    })
    .join("");
}
function renderDetail(r) {
  if (!r) return "";
  return html`<div class="detail"><div class="detail-title"><b>${e(r.name)} <span>· предпросмотр потока</span></b><button class="small ghost" data-action="edit" data-id="${e(r.id)}" ${state.pending ? "disabled" : ""}>${icon("edit")}Редактировать</button></div><div class="flow"><div class="flow-item"><div class="flow-label">Source</div><div class="flow-value">${addr(r, "src")}${r.src_ports ? " : " + e(negatedValue(r, "src_ports")) : ""}</div></div>${icon("arrow")}<div class="flow-item"><div class="flow-label">Match · ${e(r.chain)}</div><div class="flow-value">${e(negatedValue(r, "protocol").toUpperCase())} → ${addr(r, "dst")}${r.dst_ports ? " : " + e(negatedValue(r, "dst_ports")) : ""}</div></div>${icon("arrow")}<div class="flow-item"><div class="flow-label">${e(r.action)}</div><div class="flow-value">${e(target(r))}</div></div></div></div>`;
}
function empty(ico, title, description) {
  return html`<div class="empty">${icon(ico)}<p>${e(t(title))}</p><small>${e(t(description))}</small></div>`;
}
function renderLists() {
  return html`<div class="toolbar"><button class="primary add" data-action="add-list" ${state.pending || offline ? "disabled" : ""}>${icon("plus")}Создать список</button><span class="muted">${state.config.address_lists.length} списков</span></div><div class="view-panel"><div class="list-grid">${state.config.address_lists
    .map((l) => {
      const refs = [
        ...state.config.rules,
        ...(state.config.filter_rules || []),
      ].filter((r) => r.src_list === l.name || r.dst_list === l.name).length;
      return html`<article class="address-card"><div class="address-card-head"><h3>${e(l.name)}</h3><button class="icon ghost" data-action="edit-list" data-id="${e(l.id)}" title="Редактировать список" aria-label="Редактировать ${e(l.name)}" ${state.pending ? "disabled" : ""}>${icon("edit")}</button></div>${l.comment ? html`<p>${e(l.comment)}</p>` : ""}<div class="addresses">${l.addresses.map((a) => html`<span class="address-chip">${e(a)}</span>`).join("")}</div><div class="address-card-foot"><span>${l.addresses.length} адресов · ${refs} правил</span><button class="small ghost" data-action="delete-list" data-id="${e(l.id)}" ${refs || state.pending ? "disabled" : ""} title="${refs ? t("Сначала уберите список из правил") : t("Удалить список")}">${icon("minus")}Удалить</button></div></article>`;
    })
    .join(
      "",
    )}</div>${!state.config.address_lists.length ? empty("list", t("Пока нет списков адресов"), t("Добавьте IP-адреса или подсети и используйте список в правилах.")) : ""}</div>${renderSystemLists(routerContext())}`;
}
function renderInterfaces() {
  return html`<div class="toolbar"><span class="muted">${isDemo() ? t("Пример сетевой конфигурации") : t("Обнаруженные интерфейсы Linux-хоста")}</span><button class="small" data-action="refresh">${icon("refresh")}Обновить</button></div><div class="view-panel"><div class="interface-grid">${interfaces.map((i) => html`<article class="interface-card">${icon("network")}<h3>${e(i.name)}</h3><p>${e(i.address || t("IPv4 не назначен"))}</p><div class="interface-status"><span class="badge">${e(i.state)}</span><span>${e(i.role)}</span></div></article>`).join("")}</div>${!interfaces.length ? empty("network", t("Нет данных об интерфейсах"), t("Нажмите «Обновить», чтобы повторить запрос.")) : ""}<p class="interface-note">${isDemo() ? t("В деморежиме показаны примерные интерфейсы. В Linux здесь появятся реальные интерфейсы сервера.") : html`IPv4 forwarding: <b>${forwarding ? t("включён") : t("выключен")}</b>. IP-адреса задаются в IP Addresses, bridge и VLAN — в соответствующих разделах. Forwarding настраивается в DNS & Forwarding; разрешения транзита — в Firewall Filter.`}</p></div>`;
}
const eventNames = {
  saved: t("Черновик сохранён"),
  discarded: t("Черновик отменён"),
  applying: t("Правила применяются"),
  confirmed: t("Применение подтверждено"),
  rolled_back: t("Правила восстановлены"),
  rollback_failed: t("Ошибка отката"),
};
function renderAudit() {
  return html`<div class="toolbar"><span class="muted">Последние 100 событий</span><button class="small" data-action="refresh">${icon("refresh")}Обновить</button></div><div class="view-panel">${audit.length ? audit.map((row) => html`<div class="audit-row">${icon(row.event === "rollback_failed" ? "info" : "clock")}<div><b>${e(t(eventNames[row.event] || row.event))}</b><p>${e(row.detail)}</p></div><time>${e(new Date(row.at * 1000).toLocaleString(locale()))}</time></div>`).join("") : empty("clock", t("Журнал пока пуст"), t("Здесь появятся события сохранения, применения и восстановления правил."))}</div>`;
}
function renderStatus() {
  if (!canWrite())
    return html`<footer class="bottom-status"><div class="status-left"><div>${icon("lock")}Только просмотр · группа read</div><span>${state.pending ? t("Применение конфигурации выполняется администратором") : state.dirty ? t("На сервере есть неприменённый черновик") : t("Конфигурация доступна для просмотра")}</span></div><div class="status-right"><button class="small" data-action="preview">${icon("terminal")}Предпросмотр</button><span>Revision ${state.revision}</span></div></footer>`;
  if (state.pending)
    return html`<footer class="bottom-status pending"><div class="status-left"><div class="status-message">${icon("clock")}<b>${state.pending.error ? t("Ошибка отката. Требуется проверка сервера.") : html`Подтвердите связь: <span id="countdown">${secondsLeft()}</span> сек.`}</b></div><span>Без подтверждения — автоматический откат${state.restore_accounts ? t(" · После подтверждения войдите с учётными данными из копии") : ""}</span></div><div class="status-right"><button data-action="rollback">Откатить сейчас</button><button class="primary" data-action="confirm" ${state.pending.error ? "disabled" : ""}>${icon("check")}Подтвердить связь</button></div></footer>`;
  if (state.dirty)
    return html`<footer class="bottom-status dirty"><div class="status-left"><div class="status-message">${icon("edit")}<b>Есть неприменённые изменения</b></div><span>${state.restore_accounts ? t("Восстановление включает пользователей и 2FA; учётки заменятся после подтверждения") : t("Черновик сохранён на сервере")}</span></div><div class="status-right"><button class="ghost" data-action="discard">Отменить</button><button data-action="preview">${icon("terminal")}Предпросмотр</button><button class="primary" data-action="apply" ${offline ? "disabled" : ""}>${icon("check")}${isDemo() ? t("Применить в демо") : t("Применить")}</button></div></footer>`;
  return html`<footer class="bottom-status"><div class="status-left"><div><span class="dot"></span>${isDemo() ? t("Деморежим · изменения сети отключены") : t("Подтверждённая конфигурация сохранена")}</div><span>Revision ${state.revision}</span></div><div class="status-right"><span class="muted">${selected.size ? t("Двойной щелчок — редактировать") : view === "rules" ? t("Выберите правило для просмотра деталей") : t("IP · DHCP · VLAN · Firewall")}</span>${!isDemo() ? html`<button class="small" data-action="apply">Применить повторно</button>` : ""}<span>IPv4</span></div></footer>`;
}
function secondsLeft() {
  return Math.max(0, Math.ceil(state.pending.deadline - Date.now() / 1000));
}
function dialogFrame(
  title,
  subtitle,
  content,
  footer = "",
  tabs = "",
  { rawTitle = false } = {},
) {
  dialog.className = "";
  dialog.innerHTML = html`<div class="dialog-head"><div><h2 id="dialog-title">${e(rawTitle ? title : t(title))}</h2>${subtitle ? html`<p>${e(subtitle)}</p>` : ""}</div><button class="icon ghost" data-action="close" aria-label="Закрыть">${icon("x")}</button></div>${tabs}<div class="dialog-content">${content}</div><div class="dialog-error hidden" role="alert"></div><div class="dialog-footer">${footer || html`<button data-action="close">Закрыть</button>`}</div>`;
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  if (!dialog.open) dialog.showModal();
  applyAccessControls();
}
const defaultRule = () => ({
  id: newUuid(),
  name: "",
  enabled: true,
  chain: "dstnat",
  action: "dst-nat",
  protocol: "tcp",
  negate: [],
  src_address: "",
  dst_address: "",
  src_list: "",
  dst_list: "",
  src_country: "",
  dst_country: "",
  f2b_profile: "",
  f2b_match: "not_banned",
  protection: defaultRuleProtection(),
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
    toast(t("Группа read: новые правила и копии недоступны."), true);
    return;
  }
  if (busy) return;
  draftRevision = state.revision;
  if (state.pending)
    return toast(
      t("Сначала подтвердите применение или откатите правила."),
      true,
    );
  const found = state.config.rules.find((r) => r.id === id);
  draft = found ? structuredClone(found) : defaultRule();
  if (duplicate) {
    draft.id = newUuid();
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
  return withRuleNegation(
    html`<label class="field ${extra}"><span>${t(label)}</span><input name="${name}" value="${e(value)}" placeholder="${e(placeholder)}" type="${type}" ${name === "name" ? 'maxlength="80"' : ""}></label>`,
    name,
    draft,
    { disabled: !canWrite() },
  );
}
function selectField(label, name, value, options, note = "") {
  return withRuleNegation(
    html`<label class="field"><span>${t(label)}</span><select name="${name}">${options
      .map((option) => {
        const [val, text] = Array.isArray(option) ? option : [option, option];
        return html`<option value="${e(val)}" ${value === val ? "selected" : ""}>${e(text)}</option>`;
      })
      .join(
        "",
      )}</select>${note ? html`<small>${e(note)}</small>` : ""}</label>`,
    name,
    draft,
    { disabled: !canWrite() },
  );
}
function interfaceField(label, name, value, available) {
  const names = interfaceNames(routerContext());
  const options = [
    ["", t("Любой интерфейс")],
    ...names.map((name) => [
      name,
      `${name}${interfaces.find((item) => item.name === name)?.address ? " · " + interfaces.find((item) => item.name === name).address : ""}`,
    ]),
  ];
  if (value && !names.includes(value))
    options.push([value, html`${value} · не обнаружен`]);
  return withRuleNegation(
    html`<label class="field"><span>${t(label)}</span><select name="${name}" ${available ? "" : "disabled"}>${options.map(([key, text]) => html`<option value="${e(key)}" ${value === key ? "selected" : ""}>${e(text)}</option>`).join("")}</select></label>`,
    name,
    draft,
    { disabled: !available || !canWrite() },
  );
}

function renderEditor() {
  const r = draft;
  const existing = state.config.rules.some((rule) => rule.id === r.id);
  let content = "";
  if (editorTab === "general")
    content = html`<div class="winbox-form">
    ${field(t("Name"), "name", r.name, t("Имя правила"))}
    ${selectField(t("Chain"), "chain", r.chain, [
      ["dstnat", "dstnat"],
      ["srcnat", "srcnat"],
      ["output", "output"],
    ])}
    <div class="form-divider"></div>
    ${field(t("Src. Address"), "src_address", r.src_address, t("0.0.0.0/0 · любой"))}
    ${field(t("Dst. Address"), "dst_address", r.dst_address, t("0.0.0.0/0 · любой"))}
    ${selectField(t("Protocol"), "protocol", r.protocol, [
      ["any", "all"],
      ["tcp", "6 (tcp)"],
      ["udp", "17 (udp)"],
      ["icmp", "1 (icmp)"],
      ["gre", "47 (gre)"],
      ["esp", "50 (esp)"],
      ["ah", "51 (ah)"],
    ])}
    ${field(t("Src. Port"), "src_ports", r.src_ports, t("Любой · 1024-65535"))}
    ${field(t("Dst. Port"), "dst_ports", r.dst_ports, t("Любой · 80,443,8000-8010"))}
    <div class="form-divider"></div>
    ${interfaceField(t("In. Interface"), "in_interface", r.in_interface, r.chain === "dstnat")}
    ${interfaceField(t("Out. Interface"), "out_interface", r.out_interface, r.chain !== "dstnat")}
    <div class="field-note">${isDemo() ? t("Демо: интерфейсы приведены для примера.") : t("Интерфейсы обнаружены автоматически на Linux-хосте.")} Списки адресов — во вкладке Advanced.</div>
    <div class="field-note">Кнопка ! исключает указанное значение. Для списка исключаются все его адреса.</div>
    <label class="field"><span>Template</span><select id="template"><option value="">Без шаблона</option><option value="forward">Port forwarding</option><option value="masquerade">Masquerade · Internet access</option><option value="dns">DNS redirect</option><option value="snat">Source NAT</option></select></label>
    <label class="field"><span>Comment</span><textarea name="comment" rows="2" maxlength="200" placeholder="Комментарий к правилу">${e(r.comment)}</textarea></label>
    </div>`;
  if (editorTab === "advanced")
    content = html`<div class="winbox-form">
    ${selectField(t("Src. Address List"), "src_list", r.src_list, [["", t("Не использовать")], ...addressListChoices(state.config)])}
    ${selectField(t("Dst. Address List"), "dst_list", r.dst_list, [["", t("Не использовать")], ...addressListChoices(state.config)])}
    ${withRuleNegation(countryField(routerContext(), "src_country", r.src_country), "src_country", r, { disabled: !canWrite() })}
    ${withRuleNegation(countryField(routerContext(), "dst_country", r.dst_country), "dst_country", r, { disabled: !canWrite() })}
    <div class="field-note">Страна дополняет адрес и список: должны совпасть все условия. Dst. Country в dstnat проверяется до подмены назначения. База стран и обновления — Security → GeoIP.</div>
    ${selectField(t("In. Interface List"), "in_interface_list", r.in_interface_list || "", [["", t("Не использовать")], ...(state.config.network?.interface_lists || []).map((item) => [item.name, item.name])])}${selectField(t("Out. Interface List"), "out_interface_list", r.out_interface_list || "", [["", t("Не использовать")], ...(state.config.network?.interface_lists || []).map((item) => [item.name, item.name])])}<div class="field-note">Для source и destination укажите адрес в General или список здесь. Если список ещё не создан, добавьте его в Address Lists.</div>
    <div class="form-divider"></div>${withRuleNegation(html`<div class="field"><span>Connection State</span><div class="states">${["NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"].map((value) => html`<label class="checkbox-label"><input type="checkbox" name="state" value="${value}" ${r.connection_states.includes(value) ? "checked" : ""}>${value.toLowerCase()}</label>`).join("")}</div><small>Без отметок — любое состояние.</small></div>`, "connection_states", r, { disabled: !canWrite() })}</div>`;
  if (editorTab === "fail2ban")
    content = renderRuleFail2ban(routerContext(), r);
  if (editorTab === "advanced")
    content += html`<details class="rule-condition-help" ${r.f2b_profile ? "open" : ""}><summary>Дополнительное условие по списку Fail2ban</summary>${renderLegacyBanMatch(routerContext(), r)}</details>`;
  if (editorTab === "action")
    content = html`<div class="winbox-form">
    ${selectField(t("Action"), "action", r.action, r.chain === "srcnat" ? ["masquerade", "src-nat", "accept"] : ["dst-nat", "redirect", "accept"])}
    ${["dst-nat", "src-nat"].includes(r.action) ? field(t("To Addresses"), "to_address", r.to_address, "192.168.10.10") : ""}
    ${r.action !== "accept" ? field(t("To Ports"), "to_ports", r.to_ports, t("Не менять")) : ""}
    <div class="field-note">${r.action === "masquerade" ? t("Подставляет IP исходящего интерфейса. Выберите Out. Interface в General.") : r.action === "redirect" ? t("Перенаправляет на сервис этого Linux-хоста. Укажите локальный порт.") : r.action === "accept" ? t("Завершает обработку NAT. Разрешения FORWARD настраиваются отдельно.") : t("Укажите один IPv4-адрес. To Ports — один порт или диапазон; пустое поле сохраняет порт.")}</div></div>`;
  if (editorTab === "statistics")
    content = html`<div class="rule-statistics"><div class="statistics-caption">${isDemo() ? t("В деморежиме реальных счётчиков нет") : t("Счётчики работающей версии правила")}</div>
    <dl><div><dt>Bytes</dt><dd data-counter="bytes">${isDemo() ? "—" : fmtBytes(statistics[r.id]?.bytes || 0)}</dd></div><div><dt>Packets</dt><dd data-counter="packets">${isDemo() ? "—" : (statistics[r.id]?.packets || 0).toLocaleString(locale())}</dd></div><div><dt>Chain</dt><dd>${e(r.chain)}</dd></div><div><dt>Action</dt><dd>${e(r.action)}</dd></div></dl><div class="field-note">NAT учитывает первые пакеты соединений. После применения счётчики управляемых цепочек сбрасываются. Изменения черновика ещё не меняют работающие правила.</div></div>`;
  const buttons = html`<aside class="rule-actions"><button class="primary" data-action="save-rule">OK</button><button data-action="close">Cancel</button><button data-action="save-rule-open">Apply</button><div class="form-divider"></div><button data-action="editor-toggle">${icon(r.enabled ? "x" : "check")}${r.enabled ? t("Disable") : t("Enable")}</button><button data-action="editor-comment">${icon("edit")}Comment</button><button data-action="editor-copy">${icon("copy")}Copy</button>${existing ? html`<button class="danger" data-action="editor-remove">${icon("minus")}Remove</button>` : ""}</aside>`;
  dialogFrame(
    existing ? `NAT Rule · ${r.name}` : t("New NAT Rule"),
    t("OK / Apply сохраняют правило в черновик. Применение к сети — отдельно."),
    html`<div class="rule-editor-layout"><form id="rule-form">${content}</form>${buttons}</div>`,
    html`<label class="checkbox-label left"><input type="checkbox" id="rule-enabled" ${r.enabled ? "checked" : ""}>Enabled</label><span class="muted">${e(r.chain)} → ${e(r.action)}</span>`,
    html`<div class="dialog-tabs">${[
      ["general", t("General")],
      ["advanced", t("Advanced")],
      ["fail2ban", "Fail2ban"],
      ["action", t("Action")],
      ["statistics", t("Statistics")],
    ]
      .map(
        ([id, label]) =>
          html`<button class="dialog-tab ${editorTab === id ? "active" : ""}" data-action="editor-tab" data-tab="${id}">${t(label)}</button>`,
      )
      .join("")}</div>`,
  );
  dialog.classList.add("winbox-editor");
}
function collectRule() {
  if (!canWrite()) return;
  const form = dialog.querySelector("#rule-form");
  if (!form) return;
  for (const [key, val] of new FormData(form)) {
    if (key !== "state" && !key.startsWith("protection_"))
      draft[key] = String(val).trim();
  }
  if (editorTab === "advanced")
    draft.connection_states = [
      ...form.querySelectorAll('[name="state"]:checked'),
    ].map((x) => x.value);
  draft.enabled = dialog.querySelector("#rule-enabled").checked;
  const protection = collectRuleProtection(form, draft.protection);
  if (protection) draft.protection = protection;
  draft.negate = collectRuleNegations(form, draft);
}
function openList(id) {
  if (!canWrite() && !id) {
    toast(t("Группа read: новые списки недоступны."), true);
    return;
  }
  draftRevision = state.revision;
  const list = state.config.address_lists.find((l) => l.id === id) || {
    id: newUuid(),
    name: "",
    addresses: [],
    comment: "",
  };
  draft = structuredClone(list);
  dialogFrame(
    list.name ? t("Редактировать Address List") : t("Новый Address List"),
    t("Один адрес или подсеть в каждой строке."),
    html`<form id="list-form"><div class="form-grid">${field(t("Имя списка"), "name", list.name, t("Например, trusted-hosts"), "text", "wide")}<label class="field wide"><span>IPv4-адреса и подсети</span><textarea name="addresses" rows="7" placeholder="192.168.10.0/24&#10;10.8.0.5">${e(list.addresses.join("\n"))}</textarea><small>До 256 адресов. Повторяющиеся записи будут объединены.</small></label>${field(t("Комментарий"), "comment", list.comment, t("Назначение списка"), "text", "wide")}</div></form>`,
    html`<button data-action="close">Отмена</button><button class="primary" data-action="save-list">${icon("check")}Сохранить список</button>`,
  );
}
function confirmDialog(
  title,
  message,
  action,
  label = t("Подтвердить"),
  danger = false,
  revision = state.revision,
) {
  confirmationRevision = revision;
  dialogFrame(
    title,
    "",
    html`<p class="preview-note">${e(message)}</p>`,
    html`<button data-action="close">Отмена</button><button class="${danger ? "danger" : "primary"}" data-action="${action}">${e(t(label))}</button>`,
  );
}
function showHelp() {
  dialogFrame(
    t("OpenMikroRout · справка"),
    t("Лёгкий Linux-роутер с привычной логикой WinBox."),
    html`<div class="help-content"><h3>Настройка локальной сети</h3><p>Создайте bridge и выберите LAN-порты. Для отдельных сетей создайте VLAN на нужном parent-интерфейсе. Затем назначьте IPv4-адрес в IP Addresses, создайте IP Pool и DHCP Server на этом интерфейсе.</p><h3>Интернет и защита</h3><p>Задайте default route 0.0.0.0/0, включите forwarding в DNS & Forwarding и создайте srcnat / masquerade для WAN. В Firewall Filter настройте разрешения input и forward. Списки адресов и интерфейсов позволяют применять правила сразу к группам.</p><h3>Работа с правилами</h3><p>Двойной щелчок открывает свойства. В NAT перетаскивайте правила за ⋮⋮; стрелки тоже меняют порядок. Show Columns выбирает колонки и сохраняет выбор в браузере. OK сохраняет и закрывает редактор, Apply сохраняет без закрытия. Ctrl/Cmd+F — поиск; Insert — добавить; Delete — удалить; Ctrl/Cmd+E / D — включить / отключить; Ctrl/Cmd+M — комментарий.</p><h3>Сохранение и применение</h3><p>Все разделы используют общий черновик. Сохранение не меняет работающую сеть. Предпросмотр показывает команды и настройки служб. После применения подтвердите связь в течение 60 секунд. Без подтверждения сервер попытается восстановить предыдущую конфигурацию. Ошибка восстановления отображается явно и требует проверки.</p><h3>Что сохраняется отдельно</h3><p>Приложение управляет собственными ресурсами. Чужие интерфейсы, адреса, маршруты и DHCP / DNS-службы не должны захватываться. Bridge и VLAN используют Linux networking, DHCP / DNS — отдельный dnsmasq, NAT / Filter — iptables. IPv4. Dummy — программный интерфейс, а не VPN. Это самостоятельный Linux-роутер, не полная реализация RouterOS.</p><h3>Деморежим</h3><p>Настройки и примеры сохраняются в отдельной базе. Сеть этого компьютера не изменяется; реальные службы, leases и счётчики доступны только в Linux-режиме.</p></div>`,
  );
}

function renderLogin(error = "") {
  document.title = t("OpenMikroRout · Вход");
  root.innerHTML = loginMarkup({
    brand: brandMarkup(),
    icon,
    e,
    username: loginUsername,
    error,
  });
  bindLoginControls(document.querySelector("#login-form"), Boolean(error));
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
    : counts.packets.toLocaleString(locale());
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
      throw new Error(result.error || t("История недоступна"));
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
      telemetryHistoryError =
        failure.message || t("Не удалось загрузить историю");
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
      telemetryError =
        error.message || t("Не удалось получить сетевые метрики.");
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
  const languageChanged =
    state.current_user && setLanguage(state.current_user.language);
  if (!canWrite()) users = [];
  const ids = new Set(next.config.rules.map((rule) => rule.id));
  selected = new Set([...selected].filter((id) => ids.has(id)));
  const settingsForm = document.querySelector(
    "#router-dns-form,#router-domain-form,#backup-import-form,#f2b-settings,#geo-settings,#discovery-settings,#scan-settings,#application-settings-form",
  );
  if (
    [
      "dns",
      "web_settings",
      "backups",
      ...Object.keys(applicationViews),
      ...Object.keys(protectionViews),
      ...Object.keys(discoveryViews),
    ].includes(view) &&
    settingsForm?.dataset.dirty === "true"
  ) {
    const statusbar = document.querySelector("#statusbar");
    if (statusbar) statusbar.innerHTML = renderStatus();
    applyAccessControls();
    return;
  }
  if (manual || changed || languageChanged) {
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
    const before = JSON.stringify(users);
    await refreshUsers();
    if (before !== JSON.stringify(users) && !dialog.open) render();
  }
  await Promise.all([refreshTelemetry(), refreshTelemetryHistory()]);
  await refreshProtection(routerContext());
  await refreshDiscovery(routerContext());
  if (applicationViews[view]) await refreshApplications(routerContext());
  if (view === "capture") await refreshCapture(routerContext());
  if (view === "connections" && !dialog.open)
    await refreshConnections(routerContext());
  if (view === "updates") await refreshUpdates(routerContext());
  if (["wireguard", "wireguard_peers"].includes(view))
    await refreshWireGuard(routerContext());
}

async function handleAction(button) {
  const action = button.dataset.action,
    id = button.dataset.id;
  if (button.disabled || busy) return;
  if (state && !canWrite() && !isReadAction(action)) {
    toast(t("Группа read: доступен только просмотр."), true);
    return;
  }
  if (handleQueryBuilderAction(button)) return;
  if (action === "nat-query-apply") {
    applyQueryBuilder("nat");
    updateRuleTable();
    return;
  }
  if (action === "rule-negate") {
    const field = button.dataset.ruleNegate;
    if (!dialog.querySelector("#rule-form")) return;
    collectRule();
    if (toggleRuleNegation(draft, field)) {
      renderEditor();
      dialog
        .querySelector(`[data-rule-negate="${field}"]`)
        ?.focus({ preventScroll: true });
    }
    return;
  }
  if (action === "rule-protection-open") {
    if (
      button.dataset.table === "nat" &&
      state.config.rules.some((rule) => rule.id === id)
    ) {
      openEditor(id);
      if (dialog.querySelector("#rule-form")) {
        editorTab = "fail2ban";
        renderEditor();
      }
    } else if (
      button.dataset.table === "filter" &&
      state.config.filter_rules.some((rule) => rule.id === id)
    ) {
      await handleRouterAction(
        { dataset: { action: "router-edit", kind: "filter", id } },
        routerContext(),
      );
      if (dialog.querySelector("#router-form"))
        await handleRouterAction(
          { dataset: { action: "router-editor-tab", tab: "fail2ban" } },
          routerContext(),
        );
    }
    return;
  }
  if (await handleApplicationsAction(button, routerContext())) return;
  if (await handleProtectionAction(button, routerContext())) return;
  if (await handleDiscoveryAction(button, routerContext())) return;
  if (await handleUsersAction(button, routerContext())) return;
  if (await handleSecurityAction(button, routerContext())) return;
  if (await handleConnectionsAction(button, routerContext())) return;
  if (await handleUpdatesAction(button, routerContext())) return;
  if (await handleBackupAction(button, routerContext())) return;
  if (await handleWireGuardAction(button, routerContext())) return;
  if (await handleToolsAction(button, routerContext())) return;
  if (await handleCaptureAction(button, routerContext())) return;
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
    if (!navigationGroupIds.has(group)) return;
    if (expandedGroups.has(group)) expandedGroups.delete(group);
    else expandedGroups.add(group);
    const navigation = document.querySelector(".sidebar-navigation");
    if (navigation) {
      const scroll = navigation.scrollTop;
      navigation.innerHTML = renderNavigation();
      navigation.scrollTop = scroll;
    }
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
      t("Show Columns"),
      t("Выберите нужные поля. Порядок выполнения правил не меняется."),
      html`<div class="column-options">${ruleColumns.map(([key, label]) => html`<label class="checkbox-label"><input type="checkbox" name="column" value="${key}" ${visibleColumns.has(key) ? "checked" : ""} ${key === "name" ? "disabled" : ""}>${t(label)}</label>`).join("")}</div>`,
      html`<button data-action="columns-reset">По умолчанию</button><button data-action="close">Cancel</button><button class="primary" data-action="columns-save">OK</button>`,
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
      toast(t("Выбор колонок сохранён только до закрытия вкладки."), true);
    }
    dialog.close();
    render();
    return;
  }
  if (action === "view") {
    const nextView = button.dataset.view;
    if (["users", "updates"].includes(nextView) && !canWrite()) return;
    if (view === "tools" && nextView !== "tools") resetTools();
    if (view === "capture" && nextView !== "capture") resetCapture();
    closeTelemetryChart();
    historyController?.abort();
    view = nextView;
    expandNavigationForView(
      navigationItems(navigationContext()),
      view,
      expandedGroups,
    );
    if (view === "security") await refreshSecurity();
    if (window.matchMedia("(max-width: 680px)").matches)
      setNavigationOpen(false);
    selected.clear();
    render();
    window.scrollTo(0, 0);
    await refreshProtection(routerContext());
    await refreshDiscovery(routerContext());
    if (applicationViews[view])
      await refreshApplications(routerContext(), { force: true });
    if (view === "capture") await refreshCapture(routerContext());
    if (["wireguard", "wireguard_peers"].includes(view))
      await refreshWireGuard(routerContext());
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
      toast(t("Для комментария выберите одно правило."), true);
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
    draft.id = newUuid();
    draft.name += " (copy)";
    editorTab = "general";
    renderEditor();
    return;
  }
  if (action === "editor-remove") {
    selected = new Set([draft.id]);
    confirmDialog(
      t("Удалить правило?"),
      t("Правило будет удалено из черновика. Применение к сети — отдельно."),
      "delete-confirm",
      t("Удалить"),
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
      toast(t("Для копирования выберите одно правило."), true);
      return;
    }
    openEditor([...selected][0], true);
    return;
  }
  if (action === "export" || action === "import") {
    resetTools();
    resetCapture();
    view = "backups";
    expandNavigationForView(
      navigationItems(navigationContext()),
      view,
      expandedGroups,
    );
    render();
    return;
  }
  if (action === "delete") {
    confirmDialog(
      t("Удалить выбранные правила?"),
      html`Из черновика будут удалены ${selected.size} правил. Для изменения работающей сети потребуется применить конфигурацию.`,
      "delete-confirm",
      t("Удалить"),
      true,
    );
    return;
  }
  if (action === "delete-list") {
    draft = { id };
    confirmDialog(
      t("Удалить список адресов?"),
      t(
        "Список будет удалён из черновика. Используемые в правилах списки удалить нельзя.",
      ),
      "delete-list-confirm",
      t("Удалить"),
      true,
    );
    return;
  }
  if (action === "discard") {
    confirmDialog(
      t("Отменить изменения?"),
      t("Черновик будет заменён последней подтверждённой конфигурацией."),
      "discard-confirm",
      t("Отменить изменения"),
      true,
    );
    return;
  }
  if (action === "apply") {
    confirmDialog(
      isDemo()
        ? t("Применить в деморежиме?")
        : t("Применить настройки роутера?"),
      isDemo()
        ? t(
            "Будет запущена симуляция применения. Подтвердите её в течение 60 секунд. Настройки сети не изменятся.",
          )
        : t(
            "Будут применены интерфейсы, IP, DHCP / DNS, маршруты и Firewall из черновика. После применения подтвердите доступ за 60 секунд. Без подтверждения сервер попытается восстановить предыдущие настройки.",
          ),
      "apply-confirm",
      t("Применить"),
    );
    if (state.security_dirty && state.auth_enabled) {
      dialog
        .querySelector(".dialog-content")
        .insertAdjacentHTML(
          "beforeend",
          proofForm(
            routerContext(),
            "apply-security-proof",
            t("Изменяется защита роутера. Подтвердите учётные данные."),
          ),
        );
    }
    return;
  }
  await run(async () => {
    if (action === "refresh") {
      await refresh(true);
      toast(t("Данные обновлены"));
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
        t("Предпросмотр конфигурации"),
        t("Проверка не изменяет правила хоста."),
        html`<p class="preview-note">${isDemo() ? t("Синтаксис конфигурации проверен приложением. Проверка ядром доступна только в Linux.") : t("Проверка iptables-restore --test успешно пройдена.")} Ниже — NAT, Firewall Filter, виртуальные интерфейсы и настройки IP / DHCP / DNS из общего черновика.</p><pre class="code-preview">${e(result.script)}</pre>${result.router ? html`<h3 class="preview-section-title">Firewall Filter</h3><pre class="code-preview">${e(result.router.filter_script || "")}</pre><h3 class="preview-section-title">Links · Bridge / VLAN / Virtual</h3><pre class="code-preview">${e(JSON.stringify(result.router.links || {}, null, 2))}</pre><h3 class="preview-section-title">IP · DHCP · DNS · Routes</h3><pre class="code-preview">${e(JSON.stringify(result.router.network || {}, null, 2))}</pre>${result.router.wireguard ? html`<h3 class="preview-section-title">WireGuard · interfaces / peers</h3><pre class="code-preview">${e(JSON.stringify(result.router.wireguard, null, 2))}</pre>` : ""}${result.router.system_lists ? html`<h3 class="preview-section-title">System address lists · GeoIP / Fail2ban</h3><pre class="code-preview">${e(JSON.stringify(result.router.system_lists, null, 2))}</pre>` : ""}${result.router.fail2ban ? html`<h3 class="preview-section-title">Fail2ban</h3><pre class="code-preview">${e(JSON.stringify(result.router.fail2ban, null, 2))}</pre>` : ""}${result.router.vpn_routes ? html`<h3 class="preview-section-title">WireGuard · source routing</h3><pre class="code-preview">${e(JSON.stringify(result.router.vpn_routes, null, 2))}</pre>` : ""}` : result.network ? html`<h3 class="preview-section-title">Network configuration</h3><pre class="code-preview">${e(JSON.stringify(result.network, null, 2))}</pre>` : ""}`,
      );
      return;
    }
    if (action === "save-rule" || action === "save-rule-open") {
      if (!dialog.querySelector("#rule-form").reportValidity()) return;
      collectRule();
      if (!draft.name) throw new Error(t("Укажите имя правила."));
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
      toast(t("Правило сохранено в черновик"));
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
      toast(t("Список адресов сохранён"));
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
          ? t("Правила удалены из черновика")
          : t("Состояние правил сохранено"),
      );
      return;
    }
    if (action === "move-up" || action === "move-down") {
      if (selected.size !== 1)
        throw new Error(t("Для перемещения выберите одно правило."));
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
      toast(t("Список удалён"));
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
      toast(t("Черновик отменён"));
      return;
    }
    if (action === "apply-confirm") {
      assertDraftRevision(confirmationRevision, state.revision);
      const credentials =
        state.security_dirty && state.auth_enabled
          ? proof(routerContext(), "apply-security-proof")
          : null;
      if (state.security_dirty && state.auth_enabled && !credentials) return;
      acceptState(
        await api("apply", {
          method: "POST",
          body: JSON.stringify({
            revision: confirmationRevision,
            proof: credentials,
          }),
        }),
      );
      clearProof(routerContext());
      dialog.close();
      toast(t("Подтвердите связь до истечения таймера"));
      return;
    }
    if (action === "confirm") {
      const result = await api("confirm", {
        method: "POST",
        body: JSON.stringify({ token: state.pending.token }),
      });
      if (result.reauthenticate) {
        clearSession();
        renderLogin();
        toast(
          t(
            "Восстановление подтверждено. Войдите с учётными данными из копии.",
          ),
        );
        return;
      }
      acceptState(result);
      toast(t("Применение подтверждено"));
      return;
    }
    if (action === "rollback") {
      acceptState(await api("rollback", { method: "POST" }));
      toast(t("Предыдущие правила восстановлены. Черновик сохранён."));
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
      html`${filteredRules().length} из ${state.config.rules.length} правил${selected.size ? html` · выбрано ${selected.size}` : ""}`;
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
    toast(t("Порядок правил сохранён в черновик"));
  });
});
document.addEventListener("dragend", endDrag);
document.addEventListener("click", (event) => {
  const popover = event.target.closest("details[data-header-popover]");
  if (!popover || event.target.closest("summary,button[data-action]"))
    closeHeaderPopovers(root, {
      except: event.target.closest("summary") ? popover : null,
    });
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
    event.key === "Enter" &&
    event.target.matches(
      'input:not([type="checkbox"]):not([data-checkbox-search])',
    )
  ) {
    const region = event.target.closest("[data-query-builder]");
    const apply = region?.querySelector("[data-query-apply]");
    if (apply && !apply.disabled) {
      event.preventDefault();
      void handleAction(apply).catch((error) => toast(error.message, true));
      return;
    }
  }
  if (
    event.key === "Escape" &&
    !dialog.open &&
    closeHeaderPopovers(root, { restoreFocus: true })
  ) {
    event.preventDefault();
    return;
  }
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
    const builder = document.querySelector('[data-query-builder="nat"]');
    if (builder) builder.open = true;
    builder
      ?.querySelector(
        '[data-query-part="value"], [data-action="query-builder-add"]',
      )
      ?.focus();
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
  syncRuleNegationControls(
    event.target.closest("#rule-form,#router-form[data-kind=filter]"),
    canWrite(),
  );
  if (event.target.matches("[data-checkbox-search]")) return;
  if (handleQueryBuilderInput(event)) return;
  if (handleToolsInput(event, routerContext())) return;
  if (handleCaptureInput(event, routerContext())) return;
  if (handleApplicationsInput(event, routerContext())) return;
  if (handleProtectionInput(event, routerContext())) return;
  if (handleDiscoveryInput(event, routerContext())) return;
  const settingsForm = event.target.closest(
    "#router-dns-form,#router-domain-form,#backup-import-form,#f2b-settings,#geo-settings,#discovery-settings,#scan-settings,#application-settings-form",
  );
  if (settingsForm && canWrite()) settingsForm.dataset.dirty = "true";
});
document.addEventListener("change", (event) => {
  syncRuleNegationControls(
    event.target.closest("#rule-form,#router-form[data-kind=filter]"),
    canWrite(),
  );
  if (handleQueryBuilderInput(event)) return;
  if (event.target.id === "login-language") {
    const form =
      event.target.closest("form") || document.querySelector("#login-form");
    const fields = form ? new FormData(form) : null;
    setLanguage(event.target.value);
    renderLogin();
    for (const name of ["username", "password", "code"])
      if (fields)
        document.querySelector(`#login-form [name="${name}"]`).value = String(
          fields.get(name) || "",
        );
    document.querySelector("#login-language")?.focus({ preventScroll: true });
    return;
  }
  handleBackupInput(event);
  const backupForm = event.target.closest("#backup-import-form");
  if (backupForm && canWrite()) backupForm.dataset.dirty = "true";
  if (handleToolsInput(event, routerContext())) return;
  if (handleCaptureInput(event, routerContext())) return;
  if (handleApplicationsInput(event, routerContext())) return;
  if (handleProtectionInput(event, routerContext())) return;
  if (handleDiscoveryInput(event, routerContext())) return;
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
  void handleWireGuardChange(event, routerContext()).catch((error) =>
    toast(error.message, true),
  );
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
  if (node.id === "rule-enabled" && draft && canWrite())
    draft.enabled = node.checked;
  if (node.name === "f2b_profile" && dialog.querySelector("#rule-form")) {
    collectRule();
    renderEditor();
  }
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
        name: name || t("Internet access"),
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
        name: name || t("Source NAT"),
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
installCheckboxSelectEvents(document);
function formSubmitAction(event) {
  if (
    event.submitter?.matches?.("button[data-action]:not([data-display-negate])")
  )
    return event.submitter;
  return (
    event.target.querySelector(
      'button[data-action]:not([type="button"]):not([type="reset"])',
    ) ||
    event.target.querySelector("button[data-action]:not([data-display-negate])")
  );
}
document.addEventListener("submit", (event) => {
  event.preventDefault();
  if (
    ["application-rule-form", "application-settings-form"].includes(
      event.target.id,
    )
  ) {
    const action =
      event.target.id === "application-rule-form"
        ? "apps-rule-save"
        : "apps-settings-save";
    const button =
      event.target.querySelector(`[data-action="${action}"]`) ||
      dialog.querySelector(`[data-action="${action}"]`);
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "preferences-form") {
    const button = event.target.querySelector(
      '[data-action="preferences-save"]',
    );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (
    event.target.matches(
      "#f2b-settings,#geo-settings,#f2b-profile-form,#geo-lookup,#protection-proof,#apply-security-proof,[data-discovery-form]",
    )
  ) {
    const button =
      formSubmitAction(event) ||
      dialog.querySelector(
        '[data-action="f2b-profile-save"],[data-action="protection-confirm"],[data-action="apply-confirm"]',
      );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (
    event.target.id === "backup-import-form" ||
    event.target.id === "backup-proof"
  ) {
    const button =
      event.target.id === "backup-import-form"
        ? event.target.querySelector('[data-action="backup-inspect"]')
        : dialog.querySelector(
            '[data-action="backup-create"],[data-action="backup-stage"]',
          );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "router-domain-form") {
    const button = event.target.querySelector(
      '[data-action="router-save-domain"]',
    );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "user-proof") {
    const button = dialog.querySelector(
      '[data-action="user-save"],[data-action="user-toggle-confirm"],[data-action="user-delete-confirm"]',
    );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "user-form") {
    void handleAction({
      dataset: { action: "user-save" },
      disabled: false,
    }).catch((error) => toast(error.message, true));
    return;
  }
  if (event.target.id === "capture-form") {
    const button = document.querySelector('[data-action="capture-start"]');
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
    return;
  }
  if (["wg-form", "wg-export-proof", "tools-form"].includes(event.target.id)) {
    const button =
      event.target.id === "tools-form"
        ? document.querySelector('[data-action="tools-run"]')
        : dialog.querySelector(
            '[data-action="wg-server-save"],[data-action="wg-import-save"],[data-action="wg-interface-save"],[data-action="wg-peer-save"],[data-action="wg-export-confirm"]',
          );
    if (button)
      void handleAction(button).catch((error) => toast(error.message, true));
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
      const form = event.target;
      setLoginBusy(form, true);
      try {
        const values = new FormData(form);
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
        form.querySelector('[name="password"]').value = "";
        form.querySelector('[name="code"]').value = "";
        clearSession();
        await refresh(true);
      } catch (error) {
        renderLogin(error.message);
      } finally {
        if (form.isConnected) setLoginBusy(form, false);
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
      root.innerHTML = html`<div class="empty"><p>Сервер недоступен</p><small>${e(error.message)}</small><button data-action="refresh">Повторить</button></div>`;
  }
}
installRouterEvents(routerContext);
installApplicationsEvents(routerContext);
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
      toast(html`Данные сервера недоступны. ${error.message}`, true);
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
  applicationTimer = setInterval(() => {
    if (
      alive &&
      state &&
      !busy &&
      !offline &&
      !document.hidden &&
      applicationViews[view] &&
      !dialog.open
    )
      void refreshApplications(routerContext()).catch((error) =>
        toast(error.message, true),
      );
  }, 1000);
}
startPolling();
window
  .matchMedia("(max-width: 680px)")
  .addEventListener("change", () => setNavigationOpen(false));
window.addEventListener("pagehide", () => {
  alive = false;
  resetTools();
  resetCapture();
  resetApplications();
  stopTelemetryAnimation(document.querySelector("#telemetry-overview"));
  telemetryController?.abort();
  fastTelemetryController?.abort();
  historyController?.abort();
  clearInterval(pollTimer);
  clearInterval(telemetryTimer);
  clearInterval(countdownTimer);
  clearInterval(applicationTimer);
});
window.addEventListener("pageshow", () => {
  if (!alive) {
    alive = true;
    startPolling();
    if (state && ["tools", "capture"].includes(view)) render();
    if (state && view === "capture")
      void refreshCapture(routerContext()).catch((error) =>
        toast(error.message, true),
      );
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
  clearWireGuardSecrets();
  clearProof(routerContext());
  if (
    !dialog.open &&
    dialog.querySelector(
      "#security-recovery-codes,#security-setup-form,#wg-form,#wg-export-proof,#wg-private-profile,#protection-proof,#apply-security-proof,#user-proof",
    )
  )
    dialog.innerHTML = "";
  if (!dialog.open && state && ["security", "updates"].includes(view)) render();
});
