import test from "node:test";
import assert from "node:assert/strict";
import {
  navigationItems,
  navigationPath,
  navigationGroupIds,
  expandNavigationForView,
  renderSidebarNavigation,
  renderNavigationBreadcrumbs,
} from "../../app/static/navigation-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char],
  );
function context(write = true) {
  return {
    state: {
      auth_enabled: true,
      config: {
        rules: [{ src_country: "MD" }],
        filter_rules: [{}, {}],
        address_lists: [{ name: "office" }],
        system_lists: [{ name: "geo_MD" }],
        fail2ban: { profiles: [{ id: "web" }] },
        network: { addresses: [{}, {}], bridges: [{}], dhcp_servers: [{}] },
      },
    },
    interfaces: [{ name: "eth0" }],
    canWrite: () => write,
    view: "rules",
    expandedGroups: new Set(["ip", "firewall"]),
    e,
    icon: () => "<svg></svg>",
  };
}
const flatten = (items) =>
  items.flatMap((item) => [item, ...flatten(item.children || [])]);

test("menu has one logical destination per view and Firewall is grouped under IP", () => {
  const items = navigationItems(context());
  const nodes = flatten(items);
  const views = nodes.flatMap((item) => item.views || []);
  assert.equal(new Set(views).size, views.length);
  assert.deepEqual(
    navigationPath(items, "rules").map((item) => item.id || item.view),
    ["ip", "firewall", "rules"],
  );
  assert.deepEqual(
    navigationPath(items, "connections").map((item) => item.id || item.view),
    ["ip", "firewall", "connections"],
  );
  assert.deepEqual(
    navigationPath(items, "fail2ban").map((item) => item.id || item.view),
    ["protection", "fail2ban"],
  );
  assert.deepEqual(
    navigationPath(items, "security").map((item) => item.id || item.view),
    ["system", "security"],
  );
  assert.equal(navigationPath(items, "audit").length, 1);
  assert.deepEqual(
    new Set(nodes.filter((item) => item.children).map((item) => item.id)),
    navigationGroupIds,
  );
});

test("all existing subpages retain their selected parent and expand only the requested branch", () => {
  const items = navigationItems(context());
  for (const [view, parent] of [
    ["vlans", "interfaces"],
    ["interface_lists", "interfaces"],
    ["virtual_interfaces", "interfaces"],
    ["bridge_ports", "bridges"],
    ["wireguard_peers", "wireguard"],
    ["dhcp_networks", "dhcp_servers"],
    ["dhcp_reservations", "dhcp_servers"],
    ["leases", "dhcp_servers"],
    ["dns_static", "dns"],
  ])
    assert.equal(navigationPath(items, view).at(-1).view, parent);
  const expanded = new Set(["system"]);
  expandNavigationForView(items, "rules", expanded);
  assert.deepEqual([...expanded], ["system", "ip", "firewall"]);
  expandNavigationForView(items, "missing", expanded);
  assert.deepEqual([...expanded], ["system", "ip", "firewall"]);
});

test("read users retain protection, backup, diagnostics and account access without admin-only destinations", () => {
  const nodes = flatten(navigationItems(context(false)));
  const views = nodes.map((item) => item.view);
  assert.ok(!views.includes("users"));
  assert.ok(!views.includes("updates"));
  for (const view of [
    "fail2ban",
    "geoip",
    "security",
    "backups",
    "tools",
    "network_scan",
    "port_scan",
  ])
    assert.ok(views.includes(view), view);
  const demo = context();
  demo.state.auth_enabled = false;
  assert.equal(navigationPath(navigationItems(demo), "security").length, 0);
});

test("counts include deduplicated country and ban lists but do not claim live security status", () => {
  const nodes = flatten(navigationItems(context()));
  assert.equal(nodes.find((item) => item.view === "lists").total, 3);
  assert.equal(nodes.find((item) => item.view === "interfaces").total, 1);
  assert.equal(nodes.find((item) => item.view === "fail2ban").total, undefined);
  const html = renderSidebarNavigation(context());
  assert.match(html, /Обнаружено интерфейсов/);
  assert.match(html, /Записей в черновике/);
  assert.ok(!html.includes('data-action="preview"'));
});

test("nested current location and breadcrumbs are accessible while closed groups stay closed", () => {
  const ctx = context();
  ctx.expandedGroups = new Set();
  const html = renderSidebarNavigation(ctx);
  assert.match(
    html,
    /active-branch[^>]*data-group="firewall" aria-expanded="false"/,
  );
  assert.match(html, /id="nav-group-firewall" hidden/);
  assert.match(html, /data-view="rules" aria-current="page"/);
  assert.equal((html.match(/aria-current="page"/g) || []).length, 1);
  assert.match(
    renderNavigationBreadcrumbs(ctx, "Правила NAT"),
    /IP.*Межсетевой экран.*Правила NAT/,
  );
  ctx.view = "vlans";
  assert.match(renderNavigationBreadcrumbs(ctx, "VLAN"), /Интерфейсы.*VLAN/);
  assert.ok(
    !renderNavigationBreadcrumbs(ctx, '<img src=x onerror="bad">').includes(
      "<img",
    ),
  );
});
