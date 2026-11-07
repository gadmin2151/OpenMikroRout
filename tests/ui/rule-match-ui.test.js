import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import vm from "node:vm";
import { setLanguage } from "../../app/static/i18n.js";
import {
  collectRuleNegations,
  negatedValue,
  negationSummary,
  ruleNegations,
  syncRuleNegationControls,
  toggleRuleNegation,
  withRuleNegation,
} from "../../app/static/rule-match-ui.js";

test.afterEach(() => setLanguage("ru"));

function button(field, pressed = false) {
  const attrs = new Map([["aria-pressed", String(pressed)]]);
  return {
    dataset: { ruleNegate: field },
    disabled: false,
    getAttribute: (name) => attrs.get(name),
    setAttribute: (name, value) => attrs.set(name, value),
  };
}
function form(buttons, controls = {}, id = "router-form") {
  return {
    id,
    querySelectorAll(selector) {
      if (selector === "[data-rule-negate]") return buttons;
      const key = /name="([^"]+)"/.exec(selector)?.[1];
      return controls[key] || [];
    },
  };
}

test("old rules default to normal matching; only populated supported conditions can be negated", () => {
  assert.deepEqual(ruleNegations({ src_address: "10.0.0.1" }), []);
  const rule = {
    src_address: "10.0.0.1",
    src_list: " ",
    protocol: "any",
    connection_states: [],
    in_interface_list: "WAN",
    to_address: "10.0.0.2",
    negate: [
      "src_address",
      "src_address",
      "src_list",
      "protocol",
      "connection_states",
      "in_interface_list",
      "to_address",
      "__proto__",
    ],
  };
  assert.deepEqual(ruleNegations(rule), ["src_address"]);
  assert.equal(negatedValue(rule, "src_address"), "! 10.0.0.1");
  assert.equal(negatedValue({ mtu: 0 }, "mtu"), "0");
  assert.equal(toggleRuleNegation(rule, "protocol"), false);
  assert.equal(toggleRuleNegation(rule, "to_address"), false);
  assert.equal(toggleRuleNegation(rule, "src_address"), true);
  assert.deepEqual(rule.negate, []);
  assert.equal(toggleRuleNegation(rule, "src_address"), true);
  assert.deepEqual(rule.negate, ["src_address"]);
});

test("! fields expose pressed state and a separate accessible control in both profile languages", () => {
  const markup =
    '<label class="field"><span>Src. Address</span><input name="src_address" value="10.0.0.1"></label>';
  const rule = { src_address: "10.0.0.1", negate: ["src_address"] };
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const html = withRuleNegation(markup, "src_address", rule);
    assert.match(html, /^<div class="field rule-match-field">/);
    assert.ok(html.endsWith("</div>"));
    assert.match(html, /data-action="rule-negate"/);
    assert.match(html, /aria-pressed="true"/);
    assert.match(html, /<input aria-labelledby="rule-match-label-src_address"/);
    assert.match(html, /<label[^>]*for="rule-match-input-src_address"/);
    assert.match(html, /<input[^>]*id="rule-match-input-src_address"/);
    assert.match(html, /<button[^>]*aria-label="[^"]+"/);
    assert.doesNotMatch(html, /\bdisabled\b/);
    assert.match(
      html,
      language === "en"
        ? /Everything except the specified value/
        : /Все, кроме указанного/,
    );
    if (language === "en") assert.doesNotMatch(html, /[А-Яа-яЁё]/u);
  }
  assert.match(
    withRuleNegation(markup, "src_address", rule, { disabled: true }),
    /aria-pressed="true"[^>]*disabled/,
  );
  assert.match(
    withRuleNegation(markup, "src_address", { src_address: "" }),
    /aria-pressed="false"[^>]*disabled/,
  );
  assert.equal(withRuleNegation(markup, "to_address", rule), markup);
  assert.equal(withRuleNegation(markup, "in_interface_list", rule), markup);
});

test("negation of a selected state group is independent from its individual checkboxes", () => {
  const markup =
    '<div class="field"><span>Connection State</span><div class="states"><label><input type="checkbox" name="state" value="NEW" checked>new</label></div></div>';
  const html = withRuleNegation(markup, "connection_states", {
    connection_states: ["NEW"],
    negate: ["connection_states"],
  });
  assert.match(html, /aria-pressed="true"/);
  assert.match(
    html,
    /class="states" role="group" aria-labelledby="rule-match-label-connection_states"/,
  );
  assert.match(html, /name="state" value="NEW" checked/);
  assert.equal(
    negatedValue(
      { connection_states: ["NEW", "INVALID"], negate: ["connection_states"] },
      "connection_states",
    ),
    "! NEW, INVALID",
  );
});

test("collecting one editor tab preserves other exclusions and clears only empty or unchecked criteria", () => {
  const rule = {
    src_address: "10.0.0.1",
    src_country: "MD",
    dst_ports: "",
    negate: ["src_country", "dst_ports"],
  };
  const mounted = form([
    button("src_address", true),
    button("dst_ports", true),
    button("to_address", true),
  ]);
  assert.deepEqual(collectRuleNegations(mounted, rule), [
    "src_country",
    "src_address",
  ]);
  rule.negate = ["src_country", "src_address"];
  assert.deepEqual(collectRuleNegations(form([button("src_address")]), rule), [
    "src_country",
  ]);
  setLanguage("en");
  assert.match(negationSummary(rule), /Country|country/);
});

test("typing enables ! without rerendering controls, clearing resets it, and read mode blocks changes", () => {
  const invert = button("src_address", true);
  const input = { value: "10.0.0.1", selectionStart: 4, disabled: false };
  const mounted = form([invert], { src_address: [input] });
  syncRuleNegationControls(mounted, true);
  assert.equal(invert.disabled, false);
  assert.equal(input.value, "10.0.0.1");
  assert.equal(input.selectionStart, 4);
  input.value = "";
  syncRuleNegationControls(mounted, true);
  assert.equal(invert.disabled, true);
  assert.equal(invert.getAttribute("aria-pressed"), "false");
  input.value = "10.0.0.2";
  syncRuleNegationControls(mounted, true);
  assert.equal(invert.disabled, false);
  syncRuleNegationControls(mounted, false);
  assert.equal(invert.disabled, true);
  input.disabled = true;
  syncRuleNegationControls(mounted, true);
  assert.equal(invert.disabled, true);
  const states = button("connection_states", true);
  const state = { checked: true, disabled: false };
  const nat = form([states], { state: [state] }, "rule-form");
  syncRuleNegationControls(nat, true);
  assert.equal(states.disabled, false);
  state.checked = false;
  syncRuleNegationControls(nat, true);
  assert.equal(states.disabled, true);
  assert.equal(states.getAttribute("aria-pressed"), "false");
});

test("the NAT collector preserves exclusions across mounted tabs, clears empty matches, and respects read access", () => {
  const source = readFileSync(
    new URL("../../app/static/app.js", import.meta.url),
    "utf8",
  );
  const collector = source.slice(
    source.indexOf("function collectRule() {"),
    source.indexOf("function openList("),
  );
  const draft = {
    src_address: "10.0.0.1",
    src_country: "MD",
    dst_ports: "443",
    connection_states: ["NEW"],
    negate: ["src_country", "dst_ports", "connection_states"],
    protection: { enabled: false },
  };
  let writable = true;
  let values = [
    ["src_address", "10.0.0.2"],
    ["dst_ports", ""],
  ];
  let mounted = form([button("src_address", true), button("dst_ports", true)]);
  const context = vm.createContext({
    draft,
    canWrite: () => writable,
    collectRuleNegations,
    collectRuleProtection: (_form, original) => original,
    dialog: {
      querySelector: (selector) =>
        selector === "#rule-form" ? mounted : { checked: true },
    },
    FormData: class {
      constructor() {
        return values;
      }
    },
    editorTab: "general",
  });
  vm.runInContext(`${collector}\ncollectRule();`, context);
  assert.equal(draft.src_address, "10.0.0.2");
  assert.deepEqual(draft.negate, [
    "src_country",
    "connection_states",
    "src_address",
  ]);
  context.editorTab = "advanced";
  values = [["src_country", "RO"]];
  mounted = form([
    button("src_country", true),
    button("connection_states", false),
  ]);
  vm.runInContext("collectRule();", context);
  assert.deepEqual(draft.negate, ["src_country", "src_address"]);
  assert.equal(draft.connection_states.length, 0);
  const before = globalThis.structuredClone(draft);
  writable = false;
  values = [["src_address", "forged"]];
  vm.runInContext("collectRule();", context);
  assert.deepEqual(JSON.parse(JSON.stringify(draft)), before);
});
