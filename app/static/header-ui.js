import { t, html } from "./i18n.js";
const popoverSelector = "details[data-header-popover]";
const controlIds = new Set([
  "header-instance-trigger",
  "header-account-trigger",
  "header-account-settings",
  "header-account-logout",
]);

/** Preserve only header UI state when the surrounding application rerenders. */
export function captureHeaderState(scope) {
  const active = scope.ownerDocument?.activeElement || scope.activeElement;
  return {
    open: [...scope.querySelectorAll(`${popoverSelector}[open]`)].map(
      (popover) => popover.dataset.headerPopover,
    ),
    focus: controlIds.has(active?.id) ? active.id : null,
  };
}

export function restoreHeaderState(scope, snapshot) {
  for (const popover of scope.querySelectorAll(popoverSelector))
    popover.open = snapshot.open.includes(popover.dataset.headerPopover);
  const control = snapshot.focus
    ? scope.querySelector(`#${snapshot.focus}`)
    : null;
  if (control && !control.disabled && !control.closest("[inert]"))
    control.focus({ preventScroll: true });
}

/** Native details retain keyboard semantics; Escape can return focus to the trigger. */
export function closeHeaderPopovers(
  scope,
  { except = null, restoreFocus = false } = {},
) {
  const active = scope.ownerDocument?.activeElement || scope.activeElement;
  const open = [...scope.querySelectorAll(`${popoverSelector}[open]`)].filter(
    (popover) => popover !== except,
  );
  const focused = open.find((popover) => popover.contains(active)) || open[0];
  for (const popover of open) popover.open = false;
  if (restoreFocus)
    focused?.querySelector("summary")?.focus({ preventScroll: true });
  return open.length > 0;
}

/** Compact instance and account controls; existing actions retain their authorization. */
export function renderHeaderControls(ctx) {
  const { state, e, icon } = ctx;
  const demo = ctx.isDemo();
  const user = ctx.currentUser || state.current_user;
  const authenticated = state.auth_enabled === true && !!user?.username;
  const local = state.auth_enabled === false;
  const hostname = demo ? t("Demo Router") : state.hostname || t("Router");
  const name = authenticated
    ? user.username
    : local
      ? t("Локальный администратор")
      : t("Учётная запись");
  const role = ctx.canWrite() ? "full" : "read";
  const roleLabel = role === "full" ? t("Полный доступ") : t("Только просмотр");
  const connection = ctx.offline ? t("Нет соединения") : t("Сервер подключён");
  const accountLabel = html`Учётная запись: ${name}`;

  return html`<div class="header-controls"><span class="header-connection ${ctx.offline ? "offline" : ""}" title="${connection}"><span class="dot ${ctx.offline ? "off" : ""}" aria-hidden="true"></span><span class="header-connection-label">${ctx.offline ? t("Нет связи") : t("Подключён")}</span></span>
    <details class="header-popover header-instance" data-header-popover="instance">
      <summary class="header-trigger header-instance-trigger" id="header-instance-trigger" aria-label="${e(html`Инстанс: ${hostname}`)}" title="${e(html`Инстанс: ${hostname}`)}">${icon("server")}<span class="header-hostname">${e(hostname)}</span>${icon("chevron")}</summary>
      <div class="header-popover-panel" role="group" aria-labelledby="header-instance-title">
        <div class="header-popover-heading"><strong id="header-instance-title">${e(hostname)}</strong><span class="mode-chip ${demo ? "" : "live"}">${demo ? "DEMO" : t("LINUX · LIVE")}</span></div>
        <dl class="header-instance-meta"><div><dt>Версия</dt><dd>${state.version ? `v${e(state.version)}` : "—"}</dd></div><div><dt>Движок</dt><dd>${demo ? t("Demo engine") : t("IPv4 · iptables · dnsmasq")}</dd></div><div><dt>Соединение</dt><dd>${connection}</dd></div></dl>
        ${demo ? html`<p class="header-popover-note">Сеть хоста не изменяется</p>` : ""}
      </div>
    </details>
    <details class="header-popover header-account" data-header-popover="account">
      <summary class="header-trigger header-account-trigger" id="header-account-trigger" aria-label="${e(accountLabel)}" title="${e(accountLabel)}"><span class="header-avatar" aria-hidden="true">${icon("user")}</span></summary>
      <div class="header-popover-panel header-account-panel" role="group" aria-labelledby="header-account-title">
        <div class="header-popover-heading"><strong id="header-account-title">${e(name)}</strong></div>
        <p class="header-account-role">${authenticated || local ? html`<span class="role-badge role-${role}">${role}</span> ${roleLabel}` : t("Сессия не подтверждена")}</p>
        ${authenticated ? html`<div class="header-account-actions"><button type="button" id="header-account-settings" data-action="view" data-view="security">${icon("lock")}Мой профиль</button><button type="button" id="header-account-logout" data-action="logout">${icon("logout")}Выйти</button></div>` : local ? html`<p class="header-popover-note">Авторизация отключена</p>` : ""}
      </div>
    </details></div>`;
}
