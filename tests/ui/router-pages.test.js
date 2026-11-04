import test from "node:test";
import assert from "node:assert/strict";
import {
  networkFromAddress,
  interfaceNames,
  renderRouterView,
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
