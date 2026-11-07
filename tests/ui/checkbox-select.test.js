import test from "node:test";
import assert from "node:assert/strict";
import {
  checkboxSelect,
  handleCheckboxSelectEvent,
  installCheckboxSelectEvents,
} from "../../app/static/checkbox-select.js";

const choices = [
  ["eth0", "WAN"],
  ["br-lan", "LAN"],
  ["eth0", "WAN"],
];

test("multi-selection renders named native checkboxes and selected values, without modifier keys", () => {
  const html = checkboxSelect({
    name: "listen_interfaces",
    label: "Listen interfaces",
    options: choices,
    selected: ["br-lan"],
  });
  assert.equal((html.match(/type="checkbox"/g) || []).length, 2);
  assert.match(html, /name="listen_interfaces" value="br-lan" checked/);
  assert.match(html, /name="listen_interfaces" value="eth0"/);
  assert.match(html, /role="group" aria-label="Listen interfaces"/);
  assert.match(html, /<output[^>]*>1 \/ 2<\/output>/);
  assert.doesNotMatch(html, /<select|multiple|Ctrl|Cmd/);
});

test("choice names, captions and values are escaped as data", () => {
  const html = checkboxSelect({
    name: 'interface" autofocus onfocus="bad()',
    label: '<img src=x onerror="bad()">',
    options: [['"><script>bad()</script>', "<img src=x>"]],
    selected: [],
  });
  assert.doesNotMatch(html, /<img|<script|name="interface"/);
  assert.match(html, /&lt;img/);
  assert.match(html, /&quot;/);
});

test("empty required groups mark the first choice, and selected groups do not force a specific value", () => {
  const first = checkboxSelect({
    name: "members",
    label: "Members",
    options: choices,
    required: true,
  });
  assert.equal((first.match(/\srequired/g) || []).length, 1);
  const selected = checkboxSelect({
    name: "members",
    label: "Members",
    options: choices,
    selected: ["br-lan"],
    required: true,
  });
  assert.doesNotMatch(selected, /\srequired(?:\s|>)/);
});

test("disabled lists expose disabled native controls, while search does not submit any extra value", () => {
  const html = checkboxSelect({
    name: "members",
    label: "Members",
    options: choices,
    searchable: true,
    disabled: true,
  });
  assert.match(html, /data-checkbox-command="all" disabled/);
  assert.match(html, /value="eth0"[^>]* disabled/);
  assert.match(html, /type="search" data-checkbox-search/);
  assert.doesNotMatch(html, /type="search"[^>]*\sname=/);
});

function groupFixture() {
  const counter = {};
  const empty = {};
  const options = [
    { textContent: "WAN eth0", hidden: false },
    { textContent: "LAN br-lan", hidden: false },
  ];
  let changes = 0;
  const checkboxes = [false, false].map((checked) => ({
    checked,
    required: false,
    matches: () => false,
    dispatchEvent: () => changes++,
  }));
  const group = {
    querySelectorAll: (selector) =>
      selector === 'input[type="checkbox"]' ? checkboxes : options,
    querySelector: (selector) =>
      selector === "output"
        ? counter
        : selector === ".checkbox-select-no-results"
          ? empty
          : checkboxes[0],
    hasAttribute: () => true,
  };
  return { group, counter, empty, options, checkboxes, changes: () => changes };
}

test("select-all and clear operate only enabled checkboxes, emit one change and update required state", () => {
  const f = groupFixture();
  f.checkboxes[1].matches = () => true;
  const command = {
    dataset: { checkboxCommand: "all" },
    matches: () => false,
  };
  const event = {
    type: "click",
    target: {
      closest: (selector) =>
        selector === "[data-checkbox-select]" ? f.group : command,
    },
    preventDefault() {},
  };
  assert.equal(handleCheckboxSelectEvent(event), true);
  assert.deepEqual(
    f.checkboxes.map((box) => box.checked),
    [true, false],
  );
  assert.equal(f.counter.textContent, "1 / 2");
  assert.equal(f.checkboxes[0].required, false);
  assert.equal(f.changes(), 1);
  command.dataset.checkboxCommand = "clear";
  handleCheckboxSelectEvent(event);
  assert.equal(f.counter.textContent, "0 / 2");
  assert.equal(f.checkboxes[0].required, true);
  assert.equal(f.changes(), 2);
});

test("search filters visible choices without clearing checked values", () => {
  const f = groupFixture();
  f.checkboxes[0].checked = true;
  const input = {
    value: "  LAN ",
    matches: () => true,
    closest: () => f.group,
  };
  assert.equal(
    handleCheckboxSelectEvent({ type: "input", target: input }),
    true,
  );
  assert.deepEqual(
    f.options.map((option) => option.hidden),
    [true, false],
  );
  assert.equal(f.empty.hidden, true);
  assert.equal(f.checkboxes[0].checked, true);
  input.value = "missing";
  handleCheckboxSelectEvent({ type: "input", target: input });
  assert.equal(f.empty.hidden, false);
});

test("delegated listeners install once and ignore unrelated form input", () => {
  const events = [];
  const scope = { addEventListener: (name) => events.push(name) };
  installCheckboxSelectEvents(scope);
  installCheckboxSelectEvents(scope);
  assert.deepEqual(events, ["click", "change", "input"]);
  assert.equal(
    handleCheckboxSelectEvent({
      type: "change",
      target: { closest: () => null },
    }),
    false,
  );
});
