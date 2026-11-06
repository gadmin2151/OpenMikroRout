import test from "node:test";
import assert from "node:assert/strict";
import {
  addressListChoices,
  renderF2BRuleSummary,
  renderProtection,
  renderSystemLists,
  handleProtectionAction,
  resetProtection,
  refreshProtection,
} from "../../app/static/protection-ui.js";
import { isReadAction } from "../../app/static/access-ui.js";
const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function context(write = true) {
  return {
    e,
    icon: () => "",
    canWrite: () => write,
    offline: false,
    state: {
      revision: 2,
      config: {
        address_lists: [{ name: "office" }],
        system_lists: [{ name: "geo_MD", kind: "country", country: "MD" }],
        geoip: { auto_update: false, check_hours: 24 },
        fail2ban: {
          enabled: true,
          access_mode: "direct",
          trusted_proxies: [],
          profiles: [
            {
              id: "web",
              name: "<img src=x onerror=evil()>",
              enabled: true,
              service: "web",
              chain: "input",
              ports: [8088],
              max_retry: 5,
              find_time: 600,
              ban_time: 900,
              in_interface: "eth0",
              destination: "",
              include_countries: ["MD"],
              exclude_countries: [],
            },
          ],
        },
      },
    },
    run: async (fn) => fn(),
  };
}
test("all editors resolve static, country and profile lists once including empty temporary lists", () => {
  assert.deepEqual(addressListChoices(context().state.config), [
    ["office", "office"],
    ["geo_MD", "geo_MD"],
    ["f2b_web", "f2b_web"],
  ]);
  assert.deepEqual(addressListChoices({}), []);
});
test("protection pages escape profile content and explain IPv4 and NAT boundaries", () => {
  resetProtection();
  const ctx = context();
  const f2b = renderProtection("fail2ban", ctx);
  assert.ok(f2b.includes("&lt;img"));
  assert.ok(!f2b.includes("<img"));
  assert.ok(f2b.includes("loopback"));
  assert.ok(f2b.includes("IPv6"));
  const geo = renderProtection("geoip", ctx);
  assert.ok(geo.includes("само по себе оно не блокирует доступ"));
  assert.ok(geo.includes('href="https://db-ip.com"'));
  assert.ok(renderSystemLists(ctx).includes("geo_MD"));
  const rules = renderF2BRuleSummary(ctx);
  assert.ok(rules.includes("OMR_F2B"));
  assert.ok(rules.includes("Управляется Fail2ban"));
  assert.ok(!rules.includes("data-filter-drag"));
});
test("read users can inspect but cannot mutate or unban via a direct action", async () => {
  resetProtection();
  const ctx = context(false);
  assert.ok(renderProtection("fail2ban", ctx).includes("<fieldset disabled>"));
  for (const action of [
    "f2b-save",
    "f2b-remove",
    "geo-update",
    "geo-register",
    "f2b-unban",
  ]) {
    await assert.rejects(
      handleProtectionAction({ dataset: { action } }, ctx),
      /full/,
    );
    assert.equal(isReadAction(action), false);
  }
  for (const action of [
    "f2b-edit",
    "geo-lookup",
    "system-list-open",
    "protection-page",
  ])
    assert.equal(isReadAction(action), true);
});

test("changing security pages aborts stale requests and force refresh replaces pending data", async () => {
  resetProtection();
  const originalDocument = globalThis.document;
  globalThis.document = { querySelector: () => null };
  const ctx = context();
  ctx.generation = 0;
  ctx.getGeneration = () => 0;
  let view = "fail2ban";
  ctx.isCurrentView = (name) => name === view;
  const deferred = [];
  ctx.api = (path, { signal }) =>
    new Promise((resolve) => deferred.push({ path, signal, resolve }));
  try {
    const first = refreshProtection(ctx);
    view = "geoip";
    const second = refreshProtection(ctx);
    assert.ok(deferred.slice(0, 2).every((item) => item.signal.aborted));
    const third = refreshProtection(ctx, { force: true });
    assert.ok(deferred.slice(2, 4).every((item) => item.signal.aborted));
    deferred.forEach((item, index) =>
      item.resolve(
        item.path.includes("countries") || item.path.includes("bans")
          ? { items: [], total: 0 }
          : { version: index >= 4 ? "fresh" : "stale", warnings: [] },
      ),
    );
    await Promise.all([first, second, third]);
    assert.match(renderProtection("geoip", ctx), /fresh/);
    assert.doesNotMatch(renderProtection("geoip", ctx), /stale/);
  } finally {
    globalThis.document = originalDocument;
    resetProtection();
  }
});
