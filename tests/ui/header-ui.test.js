import test from "node:test";
import assert from "node:assert/strict";
import {
  renderHeaderControls,
  captureHeaderState,
  restoreHeaderState,
  closeHeaderPopovers,
} from "../../app/static/header-ui.js";
import { hasWriteAccess, isReadAction } from "../../app/static/access-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );

function context(overrides = {}) {
  const state = {
    hostname: "pve1",
    version: "0.6.3",
    auth_enabled: true,
    current_user: { username: "gadmin", role: "full" },
    ...overrides,
  };
  return {
    state,
    e,
    icon: (name) => `<svg data-icon="${name}" aria-hidden="true"></svg>`,
    isDemo: () => false,
    canWrite: () => hasWriteAccess(state),
    offline: false,
  };
}

test("compact header uses native expandable controls and an icon-only account trigger", () => {
  const html = renderHeaderControls(context());
  assert.match(html, /^<div class="header-controls">/);
  assert.match(html, /<details[^>]+data-header-popover="instance"/);
  assert.match(html, /<details[^>]+data-header-popover="account"/);
  assert.match(html, /aria-label="Инстанс: pve1"/);
  assert.match(html, /aria-label="Учётная запись: gadmin"/);
  const accountTrigger = html.match(
    /<summary[^>]+id="header-account-trigger"[\s\S]*?<\/summary>/,
  )[0];
  assert.match(accountTrigger, /data-icon="user"/);
  assert.ok(!accountTrigger.includes(">gadmin<"));
  assert.match(html, /id="header-account-title">gadmin<\/strong>/);
  assert.match(html, /v0\.6\.3/);
  assert.match(html, /IPv4 · iptables · dnsmasq/);
  assert.match(html, /Сервер подключён/);
});

test("instance and user metadata cannot inject markup or summary attributes", () => {
  const html = renderHeaderControls(
    context({
      hostname: '"><img src=x onerror=bad>',
      version: "<script>bad()</script>",
      current_user: { username: '"><svg onload=bad>', role: "read" },
    }),
  );
  assert.ok(!html.includes("<img") && !html.includes("<script>"));
  assert.ok(!html.includes("<svg onload="));
  assert.match(html, /aria-label="Инстанс: &quot;&gt;&lt;img/);
  assert.match(html, /aria-label="Учётная запись: &quot;&gt;&lt;svg/);
  assert.match(html, /v&lt;script&gt;/);
});

test("authenticated read and full users keep self-account and logout actions without extra permissions", () => {
  for (const role of ["read", "full"]) {
    const html = renderHeaderControls(
      context({ current_user: { username: "operator", role } }),
    );
    assert.match(html, new RegExp(`role-${role}`));
    assert.match(html, /data-action="view" data-view="security"/);
    assert.match(html, /data-action="logout"/);
    assert.match(html, /id="header-account-settings"/);
    assert.match(html, /id="header-account-logout"/);
    assert.match(html, role === "read" ? /Только просмотр/ : /Полный доступ/);
    assert.ok(!html.includes('data-view="users"'));
    for (const [, action] of html.matchAll(/data-action="([^"]+)"/g))
      assert.equal(isReadAction(action), true);
  }
});

test("anonymous demo identifies the local administrator but offers no session or 2FA actions", () => {
  const ctx = context({ auth_enabled: false, current_user: null });
  ctx.isDemo = () => true;
  const html = renderHeaderControls(ctx);
  assert.match(html, /Инстанс: Demo Router/);
  assert.match(html, /Demo engine/);
  assert.match(html, /Сеть хоста не изменяется/);
  assert.match(html, /Локальный администратор/);
  assert.match(html, /Авторизация отключена/);
  assert.match(html, /role-full/);
  assert.ok(!html.includes('data-action="logout"'));
  assert.ok(!html.includes('data-view="security"'));
  assert.ok(!html.includes("LINUX · LIVE"));
});

test("missing authenticated identity never presents an administrator or a usable session", () => {
  const html = renderHeaderControls(context({ current_user: null }));
  assert.match(html, /Сессия не подтверждена/);
  assert.ok(!html.includes("Локальный администратор"));
  assert.ok(!html.includes('data-action="logout"'));
  assert.ok(!html.includes('data-view="security"'));
});

test("offline state remains explicit and absent version is not replaced with a fabricated release", () => {
  const ctx = context({ version: "", hostname: "" });
  ctx.offline = true;
  const html = renderHeaderControls(ctx);
  assert.match(html, /class="header-connection offline"/);
  assert.match(html, /Нет связи/);
  assert.match(html, /Нет соединения/);
  assert.ok(!html.includes("Сервер подключён"));
  assert.match(html, /<dt>Версия<\/dt><dd>—<\/dd>/);
  assert.match(html, /Инстанс: Router/);
});

function headerFixture() {
  const document = { activeElement: null };
  const controls = new Map();
  const popovers = ["instance", "account"].map((name) => {
    const control = {
      id: `header-${name}-trigger`,
      focus(options) {
        assert.deepEqual(options, { preventScroll: true });
        document.activeElement = this;
      },
      closest: () => null,
    };
    controls.set(control.id, control);
    return {
      open: false,
      dataset: { headerPopover: name },
      contains: (element) => element === control,
      querySelector: () => control,
    };
  });
  return {
    ownerDocument: document,
    popovers,
    controls,
    querySelectorAll: (selector) =>
      selector.endsWith("[open]")
        ? popovers.filter((popover) => popover.open)
        : popovers,
    querySelector: (selector) => controls.get(selector.slice(1)),
  };
}

test("rerender restores expanded header and keyboard focus without scrolling", () => {
  const before = headerFixture();
  before.popovers[1].open = true;
  before.ownerDocument.activeElement = before.controls.get(
    "header-account-trigger",
  );
  const snapshot = captureHeaderState(before);
  const after = headerFixture();
  restoreHeaderState(after, snapshot);
  assert.deepEqual(
    after.popovers.map((popover) => popover.open),
    [false, true],
  );
  assert.equal(after.ownerDocument.activeElement.id, "header-account-trigger");
  before.ownerDocument.activeElement = { id: "rule-search" };
  assert.equal(captureHeaderState(before).focus, null);
});

test("header does not steal focus from mobile navigation or restore removed session controls", () => {
  const scope = headerFixture();
  scope.controls.get("header-account-trigger").closest = () => ({
    inert: true,
  });
  restoreHeaderState(scope, {
    open: ["account"],
    focus: "header-account-trigger",
  });
  assert.equal(scope.ownerDocument.activeElement, null);
  restoreHeaderState(scope, {
    open: ["account"],
    focus: "header-account-logout",
  });
  assert.equal(scope.ownerDocument.activeElement, null);
});

test("outside click closes popovers without moving focus; Escape restores the opened trigger", () => {
  const scope = headerFixture();
  scope.popovers.forEach((popover) => (popover.open = true));
  const external = { id: "rule-search" };
  scope.ownerDocument.activeElement = external;
  assert.equal(closeHeaderPopovers(scope, { except: scope.popovers[1] }), true);
  assert.deepEqual(
    scope.popovers.map((popover) => popover.open),
    [false, true],
  );
  assert.equal(scope.ownerDocument.activeElement, external);
  assert.equal(closeHeaderPopovers(scope, { restoreFocus: true }), true);
  assert.equal(scope.ownerDocument.activeElement.id, "header-account-trigger");
  assert.equal(closeHeaderPopovers(scope, { restoreFocus: true }), false);
});
