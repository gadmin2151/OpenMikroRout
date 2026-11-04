import test from "node:test";
import assert from "node:assert/strict";
import { renderSecurity } from "../../app/static/security-ui.js";
import {
  renderUpdates,
  handleUpdatesAction,
} from "../../app/static/updates-ui.js";
import { isReadAction } from "../../app/static/access-ui.js";
import {
  refreshConnections,
  resetConnections,
} from "../../app/static/connections-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const ctx = {
  e,
  icon: () => "",
  currentUser: {
    id: "one",
    username: "<admin>",
    role: "read",
    totp_enabled: false,
  },
  canWrite: () => false,
  state: { version: "0.3.0" },
};

test("read accounts can manage their own factor but cannot reset others or start updates", () => {
  for (const action of [
    "security-enroll",
    "security-setup",
    "security-confirm",
    "security-disable",
    "connections-filter",
    "connections-reset",
  ])
    assert.equal(isReadAction(action), true, action);
  for (const action of [
    "user-totp-reset",
    "user-totp-reset-confirm",
    "updates-check",
    "updates-open",
    "updates-apply",
  ])
    assert.equal(isReadAction(action), false, action);
});

test("security page defaults to disabled and never interpolates account markup or private fields", () => {
  const html = renderSecurity({
    ...ctx,
    securityStatus: {
      enabled: false,
      secret: "MUST-NOT-APPEAR",
      recovery_codes: ["MUST-NOT-APPEAR"],
    },
  });
  assert.match(html, /2FA выключена/);
  assert.match(html, /Включить 2FA/);
  assert.match(html, /&lt;admin&gt;/);
  assert.ok(!html.includes("<admin>") && !html.includes("MUST-NOT-APPEAR"));
  const active = renderSecurity({
    ...ctx,
    securityStatus: { enabled: true, recovery_codes_remaining: 7 },
  });
  assert.match(active, /2FA включена/);
  assert.match(active, /<b>7<\/b>/);
});

test("forged update actions are rejected before any request or dialog", async () => {
  let calls = 0;
  assert.match(renderUpdates(ctx), /доступны пользователям full/);
  await assert.rejects(
    handleUpdatesAction(
      { dataset: { action: "updates-apply" } },
      { ...ctx, api: () => calls++ },
    ),
    /full/,
  );
  assert.equal(calls, 0);
});

test("incoming monitor escapes packet-derived content and drops data when the session changes", async () => {
  const original = globalThis.document;
  const target = { innerHTML: "" };
  globalThis.document = { querySelector: () => target };
  let generation = 1;
  const monitor = {
    ...ctx,
    generation: 1,
    getGeneration: () => generation,
    isCurrentView: () => true,
    api: async () => ({
      available: true,
      demo: false,
      timestamp: 1700000000,
      total: 1,
      matched: 1,
      partial: false,
      items: [
        {
          protocol: "tcp",
          source: '<img src=x onerror="bad">',
          destination: "203.0.113.1",
          source_port: 10000,
          destination_port: 3389,
          state: "SYN_SENT",
          interface: "eth0",
          packets: null,
          bytes: null,
          expires_in: 30,
        },
      ],
    }),
  };
  try {
    await refreshConnections(monitor);
    assert.match(target.innerHTML, /&lt;img/);
    assert.ok(!target.innerHTML.includes("<img"));
    resetConnections();
    target.innerHTML = "";
    generation++;
    await refreshConnections(monitor);
    assert.equal(target.innerHTML, "");
  } finally {
    resetConnections();
    globalThis.document = original;
  }
});
