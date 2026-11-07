import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import {
  countryField,
  countryOptions,
  collectRuleProtection,
  defaultRuleProtection,
  renderLegacyBanMatch,
  renderRuleFail2ban,
  ruleServiceSummary,
} from "../../app/static/rule-security-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );
const config = {
  enabled: false,
  profiles: [
    {
      id: "ssh",
      name: "<script>bad</script>",
      service: "ssh",
      enabled: true,
      max_retry: 5,
      find_time: 600,
      ban_time: 900,
    },
  ],
};
const ctx = { e, state: { config: { fail2ban: config } } };

test("country selector is independent of downloaded GeoIP data and matches backend country contract", () => {
  const backend = readFileSync(
    new URL("../../app/system_lists.py", import.meta.url),
    "utf8",
  );
  const backendCodes = [
    ...backend.split("def country_code")[0].matchAll(/"([A-Z]{2})"/g),
  ]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(
    countryOptions()
      .map(([code]) => code)
      .sort(),
    backendCodes,
  );
  const html = countryField(ctx, "src_country", "MD");
  assert.match(html, /Src\. Country/);
  assert.match(html, /value="MD" selected/);
  assert.match(html, /Любая страна/);
  assert.ok(!countryField(ctx, "dst_country", "<img src=x>").includes("<img"));
});

test("inline Fail2ban derives its service from the rule without asking for a profile or duplicate port", () => {
  const item = {
    chain: "dstnat",
    action: "dst-nat",
    protocol: "tcp",
    in_interface: "eth0",
    dst_address: "198.51.100.20",
    dst_ports: "8443",
    to_address: "10.0.0.5",
    to_ports: "443",
  };
  const before = globalThis.structuredClone(item);
  const html = renderRuleFail2ban(ctx, item);
  assert.match(html, /10\.0\.0\.5 : 443 · TCP/);
  assert.match(html, /input \/ forward · eth0/);
  assert.match(html, /name="protection_enabled"/);
  assert.match(html, /name="protection_event_source"/);
  assert.match(html, /name="protection_max_retry"[^>]*value="5"/);
  assert.match(html, /name="protection_find_time"[^>]*value="600"/);
  assert.match(html, /name="protection_ban_time"[^>]*value="900"/);
  assert.match(html, /value="connections" selected/);
  assert.match(html, /создаются автоматически при применении/);
  assert.match(html, /Security → Fail2ban/);
  assert.match(html, /TCP-подключение — не ошибка пароля/);
  assert.match(html, /завершённым двусторонним TCP-рукопожатием/);
  assert.match(html, /наблюдённым ответом на обратном пути/);
  assert.match(html, /hairpin через один интерфейс не создаёт событий/);
  assert.match(html, /ошибки паролей на серверах за NAT требуют их журналов/);
  for (const field of ["f2b_profile", "f2b_match", "dst_ports", "to_ports"])
    assert.ok(!html.includes(`name="${field}"`), field);
  assert.deepEqual(item, before);
});

test("service summaries use translated NAT endpoints, redirect input and Filter destination scope", () => {
  const nat = {
    chain: "dstnat",
    action: "dst-nat",
    protocol: "tcp",
    to_address: "10.0.0.8",
    dst_ports: "2222",
    in_interface_list: "WAN",
  };
  assert.deepEqual(ruleServiceSummary(nat), {
    chain: "input / forward",
    destination: "10.0.0.8",
    ports: "2222",
    incoming: "WAN",
    supported: true,
  });
  assert.equal(ruleServiceSummary({ ...nat, to_ports: "22" }).ports, "22");
  assert.deepEqual(
    ruleServiceSummary({ ...nat, action: "redirect", to_ports: "8088" }),
    {
      chain: "input",
      destination: "Этот роутер",
      ports: "8088",
      incoming: "WAN",
      supported: true,
    },
  );
  assert.deepEqual(
    ruleServiceSummary({
      chain: "input",
      action: "accept",
      protocol: "tcp",
      dst_list: "management",
      dst_ports: "22,443",
      in_interface: "wg0",
    }),
    {
      chain: "input",
      destination: "management",
      ports: "22,443",
      incoming: "wg0",
      supported: true,
    },
  );
  for (const rule of [
    { ...nat, protocol: "udp" },
    { ...nat, action: "accept" },
    { ...nat, chain: "srcnat", action: "masquerade" },
    { chain: "output", protocol: "tcp" },
  ])
    assert.equal(ruleServiceSummary(rule).supported, false);
});

test("inline protection shows saved settings, escapes service labels and warns about inactive rules", () => {
  const html = renderRuleFail2ban(ctx, {
    chain: "input",
    protocol: "tcp",
    enabled: false,
    dst_address: '<img src=x onerror="bad">',
    in_interface: 'wan"<script>bad</script>',
    protection: {
      enabled: true,
      event_source: "ssh",
      max_retry: 8,
      find_time: 300,
      ban_time: 3600,
    },
  });
  assert.match(html, /name="protection_enabled" checked/);
  assert.match(html, /value="ssh" selected/);
  assert.match(html, /name="protection_max_retry"[^>]*value="8"/);
  assert.match(html, /Само правило выключено/);
  assert.match(html, /&lt;img/);
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img"));
  const unsupported = renderRuleFail2ban(ctx, {
    chain: "forward",
    protocol: "udp",
  });
  assert.match(unsupported, /name="protection_enabled"[^>]*disabled/);
  assert.match(unsupported, /Доступно для TCP/);
});

test("router authentication sources are selectable only for input while an existing invalid choice stays visible", () => {
  const forwarded = {
    chain: "dstnat",
    action: "dst-nat",
    protocol: "tcp",
    to_address: "127.0.0.1",
    to_ports: "8088",
  };
  for (const rule of [forwarded, { chain: "forward", protocol: "tcp" }]) {
    const html = renderRuleFail2ban(ctx, rule);
    assert.match(html, /<option value="web"[^>]*disabled/);
    assert.match(html, /<option value="ssh"[^>]*disabled/);
    assert.ok(!html.match(/<option value="connections"[^>]*disabled/));
  }
  for (const rule of [
    { ...forwarded, action: "redirect" },
    { chain: "input", protocol: "tcp" },
  ]) {
    const html = renderRuleFail2ban(ctx, rule);
    assert.ok(!html.match(/<option value="(?:web|ssh)"[^>]*disabled/));
  }
  const invalid = renderRuleFail2ban(ctx, {
    ...forwarded,
    protection: { enabled: true, event_source: "ssh" },
  });
  assert.match(invalid, /<option value="ssh" selected/);
  assert.match(invalid, /role="alert"/);
  assert.match(invalid, /выберите новые TCP-подключения/);
});

class ProtectionFormData {
  constructor(form) {
    this.values = form.values;
  }
  has(key) {
    return this.values[key] !== null && Object.hasOwn(this.values, key);
  }
  get(key) {
    return this.values[key] ?? null;
  }
}
const protectionForm = (values) => ({
  values,
  querySelector(selector) {
    const key = /name="([^"]+)"/.exec(selector)?.[1];
    return Object.hasOwn(values, key) ? {} : null;
  },
});

test("protection form collects numeric settings and an unchecked enable control without mutating the original", (t) => {
  t.mock.method(globalThis, "FormData", function (form) {
    return new ProtectionFormData(form);
  });
  const original = { ...defaultRuleProtection(), enabled: true };
  const before = globalThis.structuredClone(original);
  const collected = collectRuleProtection(
    protectionForm({
      protection_enabled: null,
      protection_event_source: "web",
      protection_max_retry: "12",
      protection_find_time: "120",
      protection_ban_time: "7200",
    }),
    original,
  );
  assert.deepEqual(collected, {
    enabled: false,
    event_source: "web",
    max_retry: 12,
    find_time: 120,
    ban_time: 7200,
  });
  assert.deepEqual(original, before);
  assert.equal(
    collectRuleProtection(
      protectionForm({
        protection_enabled: "on",
        protection_event_source: "connections",
        protection_max_retry: "5",
        protection_find_time: "600",
        protection_ban_time: "900",
      }),
      undefined,
    ).enabled,
    true,
  );
});

test("opening another tab preserves protection and legacy rules remain disabled by default", (t) => {
  t.mock.method(globalThis, "FormData", function () {
    throw new Error("Hidden protection fields must not be collected");
  });
  const original = { ...defaultRuleProtection(), enabled: true };
  assert.equal(collectRuleProtection(protectionForm({}), original), original);
  assert.equal(collectRuleProtection(protectionForm({}), undefined), undefined);
  const defaults = defaultRuleProtection();
  assert.equal(defaults.enabled, false);
  defaults.enabled = true;
  assert.equal(defaultRuleProtection().enabled, false);
  assert.ok(
    !renderRuleFail2ban(ctx, { chain: "input", protocol: "tcp" }).includes(
      'name="protection_enabled" checked',
    ),
  );
});

test("legacy Fail2ban condition explains actual matching semantics and preserves Security", () => {
  const before = globalThis.structuredClone(config);
  const html = renderLegacyBanMatch(ctx, {
    chain: "dstnat",
    f2b_profile: "ssh",
    f2b_match: "banned",
  });
  assert.match(html, /value="banned" selected/);
  assert.match(html, /SSH этого роутера/);
  assert.match(html, /NAT не блокирует пакеты/);
  assert.match(html, /Security → Fail2ban/);
  assert.match(html, /действуют до истечения/);
  assert.match(html, /RDP/);
  assert.ok(!html.includes("<script>"));
  assert.deepEqual(config, before);
  const filter = renderLegacyBanMatch(ctx, { chain: "forward" });
  assert.match(filter, /расположите правило до разрешающих/);
  assert.match(filter, /value="not_banned" selected/);
  assert.ok(!filter.includes("NAT не блокирует пакеты"));
});

test("missing profiles and old configurations do not silently erase saved conditions", () => {
  const html = renderLegacyBanMatch(ctx, {
    chain: "input",
    f2b_profile: 'missing"bad',
  });
  assert.match(html, /профиль не найден/);
  assert.match(html, /value="missing&quot;bad" selected/);
  assert.match(
    renderLegacyBanMatch({ e, state: { config: {} } }, {}),
    /Не использовать/,
  );
});
