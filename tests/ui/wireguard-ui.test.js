import test from "node:test";
import assert from "node:assert/strict";
import { URL } from "node:url";
import {
  renderWireGuard,
  handleWireGuardAction,
  resetWireGuard,
  clearWireGuardSecrets,
  handshakeText,
  splitNetworks,
} from "../../app/static/wireguard-ui.js";
import { renderTools, handleToolsAction } from "../../app/static/tools-ui.js";
import { isReadAction } from "../../app/static/access-ui.js";
import { assertLinkRemoval } from "../../app/static/draft-guards.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
function context(write = true) {
  return {
    state: { revision: 1, auth_enabled: false, config: { network: {} } },
    canWrite: () => write,
    generation: 0,
    getGeneration: () => 0,
    e,
    icon: () => "",
    offline: false,
    networkStatus: {},
    interfaces: [],
    empty: (_icon, title, body) => `<p>${e(title)} ${e(body)}</p>`,
  };
}

test("VPN pages explain useful empty states and the draft/application boundary", () => {
  resetWireGuard();
  assert.match(renderWireGuard(context()), /Настроить сервер/);
  assert.match(renderWireGuard(context()), /Импорт клиента/);
  assert.match(
    renderWireGuard(context(), true),
    /Подключите первое устройство/,
  );
  assert.match(renderWireGuard(context()), /откат/);
});

test("WireGuard names, keys and remote endpoints are escaped; private fields never render in a table", () => {
  resetWireGuard();
  const unsafe = '<img src=x onerror="alert(1)">';
  const ctx = context();
  ctx.state.config.network = {
    wireguard_interfaces: [
      {
        id: "one",
        name: unsafe,
        public_key: unsafe,
        role: "server",
        enabled: true,
        mtu: 1420,
        listen_port: 51820,
        private_key: "MUST-NOT-APPEAR",
      },
    ],
    wireguard_peers: [
      {
        id: "two",
        name: unsafe,
        interface: unsafe,
        allowed_ips: [unsafe],
        endpoint_host: unsafe,
        endpoint_port: 51820,
        enabled: true,
        private_key: "MUST-NOT-APPEAR",
      },
    ],
  };
  for (const peers of [false, true]) {
    const html = renderWireGuard(ctx, peers);
    assert.ok(!html.includes(unsafe) && !html.includes("MUST-NOT-APPEAR"));
    assert.match(html, /&lt;img/);
  }
});

test("read users inspect VPN properties but cannot generate keys, mutate, export or run diagnostics", async () => {
  const ctx = context(false);
  for (const action of ["wg-refresh", "wg-interface-edit", "wg-peer-edit"])
    assert.equal(isReadAction(action), true);
  for (const action of [
    "wg-server",
    "wg-import",
    "wg-export",
    "wg-export-confirm",
    "wg-download",
    "wg-interface-save",
    "wg-peer-save",
    "wg-remove-confirm",
    "tools-run",
  ]) {
    assert.equal(isReadAction(action), false);
    await assert.rejects(
      action.startsWith("tools-")
        ? handleToolsAction({ dataset: { action } }, ctx)
        : handleWireGuardAction({ dataset: { action } }, ctx),
      /full/,
    );
  }
  assert.match(renderTools(ctx), /data-action="tools-run" disabled/);
});

test("handshake age never claims connectivity before a handshake; list input is predictable", () => {
  assert.equal(handshakeText(null), "Ожидание handshake");
  assert.equal(
    handshakeText({ latest_handshake: 0, handshake_age_seconds: 0 }),
    "Ожидание handshake",
  );
  assert.equal(
    handshakeText({ latest_handshake: 100, handshake_age_seconds: 22 }),
    "22 с назад",
  );
  assert.equal(
    handshakeText({ latest_handshake: 100, handshake_age_seconds: 130 }),
    "2 мин назад",
  );
  assert.equal(
    handshakeText({ latest_handshake: 100, handshake_age_seconds: 7400 }),
    "2 ч назад",
  );
  assert.deepEqual(splitNetworks(" 10.0.0.0/24,\n192.168.1.0/24; 1.1.1.1 "), [
    "10.0.0.0/24",
    "192.168.1.0/24",
    "1.1.1.1",
  ]);
});

test("private profiles are escaped and clearing them prevents a later stale download", async () => {
  resetWireGuard();
  let html = "";
  let downloads = 0;
  const originalDocument = globalThis.document;
  const create = URL.createObjectURL;
  globalThis.document = { createElement: () => ({ click: () => downloads++ }) };
  URL.createObjectURL = () => "blob:test-only";
  try {
    const ctx = {
      ...context(),
      run: (fn) => fn(),
      dialog: { querySelectorAll: () => [] },
      dialogFrame: (_title, _subtitle, content) => {
        html = content;
      },
      api: async () => ({
        configuration: "PrivateKey = <private-test-value>\n",
        qr_data_url: "",
        filename: "test.conf",
      }),
    };
    await handleWireGuardAction(
      { dataset: { action: "wg-export", id: "one", client: "true" } },
      ctx,
    );
    await handleWireGuardAction(
      { dataset: { action: "wg-export-confirm" } },
      ctx,
    );
    assert.match(html, /&lt;private-test-value&gt;/);
    assert.ok(!html.includes("<private-test-value>"));
    clearWireGuardSecrets();
    await handleWireGuardAction({ dataset: { action: "wg-download" } }, ctx);
    assert.equal(downloads, 0);
  } finally {
    globalThis.document = originalDocument;
    URL.createObjectURL = create;
    resetWireGuard();
  }
});

test("deleting a VPN interface requires removing its peers and IP references first", () => {
  const config = {
    network: {
      wireguard_interfaces: [{ id: "one", name: "wg0" }],
      wireguard_peers: [{ name: "Phone", interface: "wg0" }],
    },
  };
  assert.throws(
    () => assertLinkRemoval(config, "wireguard_interfaces", "one"),
    /WireGuard Peer: Phone/,
  );
});
