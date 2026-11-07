import test from "node:test";
import assert from "node:assert/strict";
import {
  addressListChoices,
  renderF2BRuleSummary,
  renderInlineProtection,
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
function inlineRule(overrides = {}) {
  return {
    id: "b77eb0fc-86e6-4108-9451-e245b3dd7d27",
    name: "Remote desktop",
    chain: "dstnat",
    action: "dst-nat",
    protocol: "tcp",
    enabled: true,
    dst_address: "198.51.100.20",
    dst_ports: "13389",
    to_address: "10.0.0.5",
    to_ports: "3389",
    in_interface: "eth0",
    protection: {
      enabled: true,
      event_source: "connections",
      max_retry: 8,
      find_time: 120,
      ban_time: 3600,
    },
    ...overrides,
  };
}

test("Security lists rule-owned protection by translated service and draft state without duplicating editors", () => {
  const ctx = context();
  ctx.state.config.rules = [
    inlineRule(),
    inlineRule({
      id: "disabled-policy",
      name: "Hidden disabled policy",
      protection: { enabled: false },
    }),
    inlineRule({
      id: "legacy-rule",
      name: "Legacy without policy",
      protection: undefined,
    }),
  ];
  ctx.state.config.filter_rules = [
    inlineRule({
      id: 'filter"<bad>',
      name: "<script>unsafe</script>",
      chain: "input",
      action: "accept",
      to_address: undefined,
      to_ports: "",
      dst_address: "10.0.0.1",
      dst_ports: "22",
      enabled: false,
      protection: {
        enabled: true,
        event_source: "ssh",
        max_retry: 5,
        find_time: 600,
        ban_time: 900,
      },
    }),
  ];
  delete ctx.state.config.filter_rules[0].to_address;
  const before = globalThis.structuredClone(ctx.state.config);
  const html = renderInlineProtection(ctx);
  assert.match(html, /Правил: 2/);
  assert.match(html, /10\.0\.0\.5/);
  assert.match(html, /TCP 3389 · eth0/);
  assert.match(html, /NAT · input \/ forward/);
  assert.match(html, /Правила фильтрации · input/);
  assert.match(html, /TCP-подключения/);
  assert.match(html, /Ошибки SSH/);
  assert.match(html, /8 за 120 с/);
  assert.match(html, /3600 с/);
  assert.match(html, /Включено в черновике/);
  assert.match(html, /Правило выключено/);
  assert.ok(!html.includes("Hidden disabled policy"));
  assert.ok(!html.includes("Legacy without policy"));
  assert.ok(!html.includes("<script>"));
  assert.match(html, /&lt;script&gt;unsafe/);
  assert.match(html, /data-id="filter&quot;&lt;bad&gt;"/);
  assert.match(html, /data-action="rule-protection-open" data-table="nat"/);
  assert.match(html, /data-action="rule-protection-open" data-table="filter"/);
  assert.ok(!html.includes('data-action="f2b-edit"'));
  assert.ok(!html.includes("<input"));
  assert.deepEqual(ctx.state.config, before);
});

test("rule-owned protection remains visible when manual profiles are off and empty states point to the rule", () => {
  const ctx = context();
  assert.match(
    renderInlineProtection(ctx),
    /Откройте NAT или Filter Rule → Fail2ban/,
  );
  ctx.state.config.fail2ban.enabled = false;
  ctx.state.config.rules = [inlineRule()];
  const html = renderProtection("fail2ban", ctx);
  assert.match(html, /Включить ручные профили/);
  assert.match(html, /Их выключатель не отключает защиту/);
  assert.match(html, /Remote desktop/);
  assert.ok(!html.includes('name="enabled" checked'));
  const summary = renderF2BRuleSummary(ctx);
  assert.match(summary, /Remote desktop/);
  assert.match(summary, /Включено в черновике/);
  assert.ok(!summary.includes("&lt;img"));
});

test("read users can open the source rule while pending apply or an offline server blocks the shortcut", () => {
  const ctx = context(false);
  ctx.state.config.rules = [inlineRule()];
  const shortcut = (html) =>
    html.match(/<button\s+data-action="rule-protection-open"[^>]*>/)?.[0];
  assert.equal(isReadAction("rule-protection-open"), true);
  assert.ok(!shortcut(renderInlineProtection(ctx)).includes("disabled"));
  ctx.state.pending = { revision: 2 };
  assert.match(shortcut(renderInlineProtection(ctx)), /disabled/);
  ctx.state.pending = null;
  ctx.offline = true;
  assert.match(shortcut(renderInlineProtection(ctx)), /disabled/);
});

test("saving the manual profile toggle preserves rule-owned policies and the opening draft revision", async (t) => {
  const ctx = context();
  ctx.state.config.rules = [inlineRule()];
  const before = globalThis.structuredClone(ctx.state.config);
  const values = new Map([
    ["access_mode", "direct"],
    ["trusted_proxies", ""],
  ]);
  const settings = { dataset: { revision: "2" }, reportValidity: () => true };
  const originalDocument = globalThis.document;
  globalThis.document = {
    querySelector(selector) {
      assert.equal(selector, "#f2b-settings");
      return settings;
    },
  };
  t.after(() => {
    globalThis.document = originalDocument;
  });
  t.mock.method(globalThis, "FormData", function (form) {
    assert.equal(form, settings);
    return values;
  });
  ctx.toast = () => {};
  let saved;
  ctx.saveConfig = async (config, revision) => {
    assert.equal(revision, 2);
    saved = config;
  };
  await handleProtectionAction({ dataset: { action: "f2b-save" } }, ctx);
  assert.equal(saved.fail2ban.enabled, false);
  assert.deepEqual(saved.rules, before.rules);
  assert.deepEqual(saved.fail2ban.profiles, before.fail2ban.profiles);
  assert.deepEqual(ctx.state.config, before);
});
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
    "rule-protection-open",
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
