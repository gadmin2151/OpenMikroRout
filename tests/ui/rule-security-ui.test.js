import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import {
  countryField,
  countryOptions,
  renderRuleFail2ban,
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

test("Fail2ban condition explains actual matching semantics and preserves Security", () => {
  const before = globalThis.structuredClone(config);
  const html = renderRuleFail2ban(ctx, {
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
  const filter = renderRuleFail2ban(ctx, { chain: "forward" });
  assert.match(filter, /расположите правило до разрешающих/);
  assert.match(filter, /value="not_banned" selected/);
  assert.ok(!filter.includes("NAT не блокирует пакеты"));
});

test("missing profiles and old configurations do not silently erase saved conditions", () => {
  const html = renderRuleFail2ban(ctx, {
    chain: "input",
    f2b_profile: 'missing"bad',
  });
  assert.match(html, /профиль не найден/);
  assert.match(html, /value="missing&quot;bad" selected/);
  assert.match(
    renderRuleFail2ban({ e, state: { config: {} } }, {}),
    /Не использовать/,
  );
});
