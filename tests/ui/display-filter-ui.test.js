import test from "node:test";
import assert from "node:assert/strict";
import { setLanguage } from "../../app/static/i18n.js";
import {
  displayFilterField,
  displayFilterToggle,
  displayNegations,
  displayNegationQuery,
  syncDisplayFilterControl,
} from "../../app/static/display-filter-ui.js";

test.afterEach(() => setLanguage("ru"));

test("display exclusions serialize only populated whitelisted criteria in canonical order", () => {
  const values = {
    source: "192.0.2.1",
    protocol: "tcp",
    search: " ",
    limit: "200",
  };
  const allowed = ["source", "protocol", "search"];
  for (const flags of [
    ["protocol", "search", "source", "source", "limit", "__proto__"],
    new Set(["protocol", "search", "source", "limit"]),
    "protocol,search,source,limit",
  ]) {
    assert.deepEqual(displayNegations(flags, values, allowed), [
      "source",
      "protocol",
    ]);
    assert.equal(
      displayNegationQuery(flags, values, allowed),
      "source,protocol",
    );
  }
  assert.equal(displayNegationQuery(undefined, values, allowed), "");
  assert.equal(displayNegationQuery({ source: true }, values, allowed), "");
  assert.equal(
    displayNegationQuery(["protocol"], { protocol: "" }, allowed),
    "",
  );
});

test("shared ! controls have translated labels, pressed state, empty and permission-disabled states", () => {
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const button = displayFilterToggle({
      name: "source",
      label: "Источник",
      value: "192.0.2.1",
      negated: true,
      action: "connections-negate",
    });
    assert.match(button, /type="button"/);
    assert.match(
      button,
      /data-action="connections-negate" data-display-negate="source"/,
    );
    assert.match(button, /aria-pressed="true"/);
    assert.match(button, /aria-label="[^"]+"/);
    assert.doesNotMatch(button, /\bdisabled\b/);
    if (language === "en") assert.doesNotMatch(button, /[А-Яа-яЁё]/u);
  }
  const args = {
    name: "source",
    label: "Source",
    value: "192.0.2.1",
    negated: true,
    action: "capture-negate",
  };
  assert.match(
    displayFilterToggle({ ...args, disabled: true }),
    /aria-pressed="true"[^>]*disabled/,
  );
  assert.match(
    displayFilterToggle({ ...args, value: "" }),
    /aria-pressed="false"[^>]*disabled/,
  );
  assert.equal(
    displayFilterToggle({ ...args, name: 'source" onclick="bad' }),
    "",
  );
  assert.equal(displayFilterToggle({ ...args, action: 'bad"' }), "");
  assert.doesNotMatch(
    displayFilterToggle({ ...args, label: "<img src=x>" }),
    /<img/,
  );
});

test("field decoration preserves submitted names, constraints, values and a clickable native label", () => {
  const markup =
    '<label class="field"><span>Источник</span><input name="source" value="&lt;host&gt;" maxlength="32" required></label>';
  const options = {
    value: "<host>",
    negated: true,
    action: "connections-negate",
    idPrefix: "connections",
  };
  const result = displayFilterField(markup, "source", options);
  assert.match(result, /^<div class="field">/);
  assert.ok(result.endsWith("</div>"));
  assert.match(result, /<label for="connections-source">Источник<\/label>/);
  assert.match(
    result,
    /<input id="connections-source" name="source" value="&lt;host&gt;" maxlength="32" required>/,
  );
  assert.doesNotMatch(result, /<label[^>]*>[\s\S]*<button[\s\S]*<\/label>/);
  const existing = displayFilterField(
    markup.replace("<input ", '<input id="existing" '),
    "source",
    options,
  );
  assert.match(existing, /for="existing"/);
  assert.equal((existing.match(/\bid="existing"/g) || []).length, 1);
  assert.equal(displayFilterField(markup, 'invalid"', options), markup);
});

test("sync changes only the ! button and retains an explicit permission lock", () => {
  const attrs = {};
  const button = {
    disabled: true,
    setAttribute: (key, value) => {
      attrs[key] = value;
    },
  };
  const input = { value: "192.0.2.1", selectionStart: 5 };
  const form = {
    querySelector: (selector) =>
      selector.includes("data-display-negate") ? button : input,
  };
  syncDisplayFilterControl(form, "source", input.value, true);
  assert.equal(button.disabled, false);
  assert.equal(attrs["aria-pressed"], "true");
  assert.deepEqual(input, { value: "192.0.2.1", selectionStart: 5 });
  syncDisplayFilterControl(form, "source", input.value, true, true);
  assert.equal(button.disabled, true);
  assert.equal(attrs["aria-pressed"], "true");
  syncDisplayFilterControl(form, "source", "", true);
  assert.equal(button.disabled, true);
  assert.equal(attrs["aria-pressed"], "false");
});
