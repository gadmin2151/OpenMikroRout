import test from "node:test";
import assert from "node:assert/strict";
import {
  assertDraftRevision,
  assertLinkRemoval,
  linkReferences,
} from "../../app/static/draft-guards.js";
import { handleRouterAction } from "../../app/static/router-pages.js";

const clone = (value) => JSON.parse(JSON.stringify(value));

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function config() {
  return {
    rules: [],
    filter_rules: [],
    address_lists: [],
    network: {
      addresses: [
        {
          id: "ip",
          interface: "eth0",
          address: "192.168.1.1/24",
          enabled: true,
          comment: "base",
        },
      ],
      bridges: [
        {
          id: "bridge",
          name: "br-lan",
          members: ["eth1"],
          enabled: true,
          stp: true,
          mtu: 1500,
          comment: "",
        },
      ],
      vlans: [],
      virtual_interfaces: [],
      routes: [],
      dhcp_servers: [],
      dhcp_reservations: [],
      pools: [],
      interface_lists: [],
      dns: {
        enabled: false,
        servers: [],
        listen_interfaces: [],
        cache_size: 1000,
        local_domain: "",
      },
    },
  };
}
function context(revision = 4) {
  const calls = [];
  const form = {
    reportValidity: () => true,
    dataset: {},
    entries: [
      ["interface", "eth0"],
      ["address", "192.168.1.1/24"],
      ["enabled", "on"],
      ["comment", "form-change"],
    ],
  };
  const ctx = {
    state: { revision, config: config() },
    interfaces: [{ name: "eth0" }, { name: "eth1" }],
    offline: false,
    busy: false,
    e: escape,
    icon: () => "<svg></svg>",
    dialogFrame: () => {},
    dialog: {
      classList: { add: () => {} },
      querySelector: () => form,
      close: () => {},
    },
    toast: () => {},
    run: async (task) => task(),
    saveConfig: async (value, expected) => {
      calls.push({ expected, config: clone(value) });
      assert.equal(expected, ctx.state.revision);
      ctx.state = {
        ...ctx.state,
        revision: expected + 1,
        config: clone(value),
      };
      return clone(ctx.state);
    },
  };
  return { ctx, calls, form };
}
const button = (action, kind, id) => ({ dataset: { action, kind, id } });

test("revision guard rejects stale, malformed and polled-forward editor baselines", () => {
  assert.equal(assertDraftRevision(4, 4), 4);
  for (const value of [3, 5, -1, null, undefined, "4", Number.NaN])
    assert.throws(() => assertDraftRevision(value, 4), /другой сессии/);
});

test("router IP editor cannot overwrite an object updated by a concurrent session after polling", async () => {
  const { ctx, calls } = context();
  await handleRouterAction(button("router-edit", "addresses", "ip"), ctx);
  ctx.state.revision = 5;
  ctx.state.config.network.addresses[0].comment = "concurrent edit";
  await assert.rejects(
    handleRouterAction(button("router-save"), ctx),
    /другой сессии/,
  );
  assert.equal(calls.length, 0);
  assert.equal(
    ctx.state.config.network.addresses[0].comment,
    "concurrent edit",
  );
});

test("Filter and bridge-port editors retain opening revisions even after current state advances", async () => {
  const { ctx, calls } = context();
  ctx.state.config.filter_rules = [
    {
      id: "filter",
      name: "Allow LAN",
      enabled: true,
      chain: "forward",
      action: "accept",
      protocol: "any",
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
      connection_states: [],
      comment: "",
    },
  ];
  await handleRouterAction(button("router-edit", "filter", "filter"), ctx);
  ctx.state.revision = 5;
  await assert.rejects(
    handleRouterAction(button("router-apply"), ctx),
    /другой сессии/,
  );
  await handleRouterAction(
    {
      ...button("router-port-edit", undefined, "bridge"),
      dataset: { action: "router-port-edit", id: "bridge", member: "eth1" },
    },
    ctx,
  );
  ctx.state.revision = 6;
  await assert.rejects(
    handleRouterAction(button("router-port-save"), ctx),
    /другой сессии/,
  );
  assert.equal(calls.length, 0);
});

test("successful Apply advances the editor baseline; a later external edit is still rejected", async () => {
  const { ctx, calls, form } = context();
  const NativeFormData = globalThis.FormData;
  globalThis.FormData = class {
    constructor(value) {
      this.values = new Map(value.entries);
    }
    has(key) {
      return this.values.has(key);
    }
    get(key) {
      return this.values.get(key) ?? null;
    }
    getAll(key) {
      const value = this.get(key);
      return value === null ? [] : Array.isArray(value) ? value : [value];
    }
  };
  try {
    await handleRouterAction(button("router-edit", "addresses", "ip"), ctx);
    await handleRouterAction(button("router-apply"), ctx);
    assert.equal(form.dataset.revision, "5");
    await handleRouterAction(button("router-apply"), ctx);
    assert.deepEqual(
      calls.map((call) => call.expected),
      [4, 5],
    );
    ctx.state.revision = 7;
    await assert.rejects(
      handleRouterAction(button("router-apply"), ctx),
      /другой сессии/,
    );
    assert.equal(calls.length, 2);
  } finally {
    globalThis.FormData = NativeFormData;
  }
});

test("DNS saves use page opening revision, not the latest polled revision", async () => {
  const { ctx, calls } = context(5),
    previousDocument = globalThis.document;
  globalThis.document = {
    querySelector: () => ({ dataset: { revision: "4" } }),
  };
  try {
    await assert.rejects(
      handleRouterAction(button("router-save-dns"), ctx),
      /другой сессии/,
    );
    assert.equal(calls.length, 0);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  }
});

test("link deletion reports all dependent resources, including disabled objects", () => {
  const cfg = config();
  cfg.network.addresses = [
    { interface: "br-lan", address: "192.168.10.1/24", enabled: false },
  ];
  cfg.network.routes = [{ interface: "br-lan", destination: "10.0.0.0/8" }];
  cfg.network.dhcp_servers = [{ interface: "br-lan", name: "dhcp-lan" }];
  cfg.network.dns.listen_interfaces = ["br-lan"];
  cfg.network.vlans = [{ id: "vlan", name: "vlan20", parent: "br-lan" }];
  cfg.network.interface_lists = [{ name: "LAN", members: ["br-lan"] }];
  cfg.rules = [{ name: "Internet", out_interface: "br-lan" }];
  cfg.filter_rules = [{ name: "LAN policy", in_interface: "br-lan" }];
  const refs = linkReferences(cfg, "br-lan");
  assert.equal(refs.length, 8);
  assert.throws(
    () => assertLinkRemoval(cfg, "bridges", "bridge"),
    /IP Address.*DHCP Server.*VLAN Parent.*Interface List.*NAT.*Filter.*переназначьте/,
  );
  assert.doesNotThrow(() => assertLinkRemoval(config(), "bridges", "bridge"));
});

test("remove action is blocked before showing destructive confirmation when link is referenced", async () => {
  const { ctx, calls } = context();
  ctx.state.config.network.addresses[0].interface = "br-lan";
  await assert.rejects(
    handleRouterAction(button("router-remove", "bridges", "bridge"), ctx),
    /Нельзя удалить br-lan/,
  );
  assert.equal(calls.length, 0);
  assert.equal(ctx.state.config.network.bridges.length, 1);
});
