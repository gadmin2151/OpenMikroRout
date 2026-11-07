import test from "node:test";
import assert from "node:assert/strict";
import {
  networkFromAddress,
  interfaceNames,
  renderRouterView,
  handleRouterAction,
  routerViews,
} from "../../app/static/router-pages.js";

test("DHCP network suggestions retain the router address and calculate CIDR boundaries", () => {
  assert.deepEqual(networkFromAddress("192.168.10.129/25"), {
    network: "192.168.10.128/25",
    gateway: "192.168.10.129",
  });
  assert.deepEqual(networkFromAddress("255.255.255.255/0"), {
    network: "0.0.0.0/0",
    gateway: "255.255.255.255",
  });
  assert.deepEqual(networkFromAddress("10.0.0.5/32"), {
    network: "10.0.0.5/32",
    gateway: "10.0.0.5",
  });
  assert.deepEqual(networkFromAddress("10.0.0.5/31"), {
    network: "10.0.0.4/31",
    gateway: "10.0.0.5",
  });
});

test("malformed IPv4 / prefixes never turn into seemingly valid DHCP defaults", () => {
  for (const value of [
    "192.168.1.1",
    "192.168.1.1/",
    "1..2.3/24",
    "01.2.3.4/24",
    "256.1.1.1/24",
    "1.2.3.4/33",
    "1.2.3.4/-1",
    "1.2.3.4/24/1",
    "x/24",
    "::1/64",
  ])
    assert.equal(networkFromAddress(value), null, value);
});

test("interface choices include unapplied bridge, VLAN and dummy names without duplicates", () => {
  const ctx = {
    interfaces: [{ name: "eth0" }, { name: "br-lan" }],
    state: {
      config: {
        network: {
          bridges: [{ name: "br-lan" }],
          vlans: [{ name: "vlan20" }],
          virtual_interfaces: [{ name: "lo-mgmt" }],
        },
      },
    },
  };
  assert.deepEqual(interfaceNames(ctx), [
    "eth0",
    "br-lan",
    "vlan20",
    "lo-mgmt",
  ]);
  assert.deepEqual(ctx.interfaces, [{ name: "eth0" }, { name: "br-lan" }]);
});

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function context(config = {}) {
  return {
    state: {
      config: { rules: [], filter_rules: [], address_lists: [], ...config },
    },
    interfaces: [],
    networkStatus: {},
    offline: false,
    e: escape,
    icon: () => "<svg></svg>",
    isDemo: () => true,
    actionBadge: escape,
    empty: (_icon, title, body) => `<p>${escape(title)} ${escape(body)}</p>`,
  };
}

test("all router pages have usable empty states before network configuration exists", () => {
  for (const view of Object.keys(routerViews))
    assert.ok(renderRouterView(view, context()).length > 0, view);
});

test("web settings escape the domain and expose the existing revisioned draft flow", () => {
  const html = renderRouterView(
    "web_settings",
    context({ web_domain: '<img src=x onerror="bad">' }),
  );
  assert.match(html, /router-domain-form/);
  assert.match(html, /router-save-domain/);
  assert.match(html, /&lt;img/);
  assert.ok(!html.includes("<img"));
  assert.match(html, /DNS A-запись/);
});

test("read accounts cannot forge a domain save action", async () => {
  await assert.rejects(
    handleRouterAction(
      { dataset: { action: "router-save-domain" } },
      {
        ...context(),
        canWrite: () => false,
      },
    ),
    /full/,
  );
});

test("configuration and lease values are escaped rather than inserted as markup", () => {
  const unsafe = '<img src=x onerror="alert(1)">';
  const ctx = context({
    network: {
      addresses: [
        {
          id: "ip-1",
          address: unsafe,
          interface: unsafe,
          enabled: true,
          comment: unsafe,
        },
      ],
    },
  });
  const html = renderRouterView("addresses", ctx);
  assert.ok(!html.includes(unsafe));
  assert.ok(html.includes("&lt;img"));
  ctx.networkStatus.leases = [
    {
      address: "192.168.1.10",
      mac: "00:11:22:33:44:55",
      hostname: unsafe,
      expires: 0,
    },
  ];
  assert.ok(!renderRouterView("leases", ctx).includes(unsafe));
});

test("DNS forwarding defaults to preserve and opening settings never modifies configuration", () => {
  const ctx = context({
    network: {
      forwarding: null,
      dns: {
        enabled: false,
        listen_interfaces: [],
        servers: [],
        cache_size: 1000,
        local_domain: "",
      },
    },
  });
  const before = JSON.parse(JSON.stringify(ctx.state.config));
  const html = renderRouterView("dns", ctx);
  assert.ok(html.includes('value="preserve" selected'));
  assert.deepEqual(ctx.state.config, before);
});

function editorContext(item, writable = true) {
  const ctx = context({
    filter_rules: [item],
    fail2ban: { enabled: false, profiles: [] },
  });
  ctx.state.revision = 7;
  ctx.canWrite = () => writable;
  ctx.currentForm = null;
  ctx.dialog = {
    classList: { add() {} },
    close() {},
    querySelector: () => ctx.currentForm,
  };
  ctx.dialogFrame = (_title, _description, body, _footer, tabs) => {
    ctx.body = body;
    ctx.tabs = tabs;
  };
  ctx.run = async (fn) => fn();
  ctx.toast = () => {};
  ctx.saveConfig = async (config, revision) => {
    assert.equal(revision, 7);
    ctx.saved = config;
    return { config, revision: 8 };
  };
  return ctx;
}
function form(values) {
  return {
    values,
    dataset: {},
    reportValidity: () => true,
    querySelector(selector) {
      const key = /name="([^"]+)"/.exec(selector)?.[1];
      return Object.hasOwn(values, key) ? {} : null;
    },
  };
}
class TestFormData {
  constructor(form) {
    this.values = form.values;
  }
  has(key) {
    return this.values[key] !== null && Object.hasOwn(this.values, key);
  }
  get(key) {
    return this.values[key] ?? null;
  }
  getAll(key) {
    return this.values[key] == null ? [] : [this.values[key]].flat();
  }
}

test("Filter tabs preserve hidden conditions, clear visible checks, and save all tabs atomically", async (t) => {
  const originalFormData = globalThis.FormData;
  globalThis.FormData = TestFormData;
  t.after(() => {
    globalThis.FormData = originalFormData;
  });
  const original = {
    id: "filter-1",
    name: "Initial",
    chain: "forward",
    action: "accept",
    protocol: "tcp",
    enabled: true,
    src_address: "10.0.0.0/24",
    dst_address: "",
    src_list: "",
    dst_list: "",
    src_country: "MD",
    dst_country: "RO",
    f2b_profile: "web",
    f2b_match: "not_banned",
    protection: {
      enabled: false,
      event_source: "connections",
      max_retry: 8,
      find_time: 300,
      ban_time: 1800,
    },
    connection_states: ["NEW"],
    dst_ports: "443",
    comment: "preserve",
  };
  const ctx = editorContext(original);
  const action = (name, data = {}) =>
    handleRouterAction({ dataset: { action: name, ...data } }, ctx);
  await action("router-edit", { kind: "filter", id: original.id });
  assert.match(ctx.tabs, /General.*Advanced.*Fail2ban.*Action/);
  assert.ok(!ctx.body.includes('name="action"'));
  ctx.currentForm = form({ name: "Edited", enabled: null, dst_ports: "8443" });
  await action("router-editor-tab", { tab: "advanced" });
  assert.match(ctx.body, /Src\. Country/);
  assert.match(ctx.body, /value="RO" selected/);
  assert.match(ctx.body, /Дополнительное условие по списку Fail2ban/);
  assert.match(ctx.body, /name="f2b_profile"/);
  assert.match(ctx.body, /value="web" selected/);
  assert.ok(!ctx.body.includes('name="protection_enabled"'));
  ctx.currentForm = form({
    src_country: "US",
    dst_country: "",
    connection_states: null,
    f2b_profile: "ssh",
    f2b_match: "banned",
  });
  await action("router-editor-tab", { tab: "fail2ban" });
  assert.match(ctx.body, /name="protection_enabled"/);
  assert.match(ctx.body, /name="protection_max_retry"[^>]*value="8"/);
  assert.match(ctx.body, /Любой адрес : 8443 · TCP/);
  assert.ok(!ctx.body.includes('name="f2b_profile"'));
  ctx.currentForm = form({
    protection_enabled: "on",
    protection_event_source: "connections",
    protection_max_retry: "12",
    protection_find_time: "120",
    protection_ban_time: "7200",
  });
  await action("router-editor-tab", { tab: "action" });
  assert.match(ctx.body, /name="action"/);
  ctx.currentForm = form({ action: "drop" });
  await action("router-save");
  assert.deepEqual(ctx.saved.filter_rules[0], {
    ...original,
    name: "Edited",
    enabled: false,
    dst_ports: "8443",
    src_country: "US",
    dst_country: "",
    connection_states: [],
    f2b_profile: "ssh",
    f2b_match: "banned",
    protection: {
      enabled: true,
      event_source: "connections",
      max_retry: 12,
      find_time: 120,
      ban_time: 7200,
    },
    action: "drop",
  });
  assert.equal(original.name, "Initial");
  assert.equal(original.protection.enabled, false);
});

test("copying a Filter rule carries inline protection and legacy conditions into a separate draft", async (t) => {
  t.mock.method(globalThis, "FormData", function (form) {
    return new TestFormData(form);
  });
  const original = {
    id: "filter-source",
    name: "Protected service",
    chain: "forward",
    action: "accept",
    protocol: "tcp",
    dst_address: "10.0.0.7",
    dst_ports: "443",
    enabled: true,
    src_country: "MD",
    dst_country: "RO",
    f2b_profile: "old-service",
    f2b_match: "not_banned",
    protection: {
      enabled: true,
      event_source: "connections",
      max_retry: 8,
      find_time: 300,
      ban_time: 1800,
    },
  };
  const before = globalThis.structuredClone(original);
  const ctx = editorContext(original);
  const action = (name, data = {}) =>
    handleRouterAction({ dataset: { action: name, ...data } }, ctx);
  await action("router-edit", { kind: "filter", id: original.id });
  ctx.currentForm = form({});
  await action("router-editor-tab", { tab: "fail2ban" });
  ctx.currentForm = form({
    protection_enabled: null,
    protection_event_source: "connections",
    protection_max_retry: "10",
    protection_find_time: "600",
    protection_ban_time: "3600",
  });
  await action("router-editor-copy");
  assert.match(ctx.body, /name="protection_max_retry"[^>]*value="10"/);
  assert.ok(!ctx.body.includes('name="protection_enabled" checked'));
  ctx.currentForm = form({});
  await action("router-editor-tab", { tab: "advanced" });
  assert.match(ctx.body, /value="old-service" selected/);
  assert.match(ctx.body, /value="MD" selected/);
  assert.match(ctx.body, /value="RO" selected/);
  await action("router-save");
  assert.equal(ctx.saved.filter_rules.length, 2);
  const copy = ctx.saved.filter_rules[1];
  assert.notEqual(copy.id, original.id);
  assert.deepEqual(copy, {
    ...original,
    id: copy.id,
    name: "Protected service-copy",
    protection: {
      enabled: false,
      event_source: "connections",
      max_retry: 10,
      find_time: 600,
      ban_time: 3600,
    },
  });
  assert.deepEqual(original, before);
  assert.deepEqual(ctx.saved.filter_rules[0], before);
});

test("read users can navigate all Filter tabs without disabled controls altering values", async (t) => {
  t.mock.method(globalThis, "FormData", function () {
    throw new Error("Read controls must not be collected");
  });
  const item = {
    id: "readonly",
    name: "Inspect",
    chain: "forward",
    action: "drop",
    src_country: "MD",
    f2b_profile: "web",
    f2b_match: "banned",
    protocol: "tcp",
    protection: {
      enabled: true,
      event_source: "connections",
      max_retry: 5,
      find_time: 600,
      ban_time: 900,
    },
  };
  const before = globalThis.structuredClone(item);
  const ctx = editorContext(item, false);
  await handleRouterAction(
    { dataset: { action: "router-edit", kind: "filter", id: item.id } },
    ctx,
  );
  for (const tab of ["advanced", "fail2ban", "action", "general", "advanced"]) {
    await handleRouterAction(
      { dataset: { action: "router-editor-tab", tab } },
      ctx,
    );
    if (tab === "fail2ban") {
      assert.match(ctx.body, /name="protection_enabled" checked/);
      assert.ok(!ctx.body.includes('name="f2b_profile"'));
    }
  }
  assert.match(ctx.body, /value="MD" selected/);
  assert.equal(ctx.saved, undefined);
  assert.equal(item.f2b_match, "banned");
  assert.deepEqual(item, before);
});

test("Filter table makes country and Fail2ban conditions visible without opening rules", () => {
  const html = renderRouterView(
    "filter",
    context({
      filter_rules: [
        {
          id: "rule",
          name: "Country",
          chain: "forward",
          action: "drop",
          protocol: "tcp",
          enabled: true,
          src_country: "MD",
          dst_country: "RO",
          f2b_profile: "ssh",
          f2b_match: "banned",
        },
      ],
    }),
  );
  assert.match(html, /Country: MD/);
  assert.match(html, /Country: RO/);
  assert.match(html, /∈ f2b_ssh/);
});
