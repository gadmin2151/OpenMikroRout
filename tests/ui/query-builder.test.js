import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { setLanguage } from "../../app/static/i18n.js";
import { isReadAction } from "../../app/static/access-ui.js";
import { casefold } from "../../app/static/casefold.js";
import {
  renderQueryBuilder,
  applyQueryBuilder,
  getAppliedExpression,
  getAppliedQuery,
  resetQueryBuilder,
  resetAllQueryBuilders,
  handleQueryBuilderInput,
  handleQueryBuilderAction,
  compileQueryExpression,
  validateQueryExpression,
} from "../../app/static/query-builder.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("../fixtures/query-expressions.json", import.meta.url),
    "utf8",
  ),
);
const schema = Object.entries(fixture.schema).map(([field, spec]) => ({
  field,
  label: field,
  type: spec.kind,
  options: spec.options,
}));
const condition = (field, op, value = "") => ({
  kind: "condition",
  field,
  op,
  value,
});
const group = (...children) => ({ kind: "group", join: "and", children });
const originalDocument = globalThis.document;
test.afterEach(() => {
  resetAllQueryBuilders();
  globalThis.document = originalDocument;
  setLanguage("ru");
});

for (const example of fixture.cases)
  test(`shared Python/JS predicate fixture: ${example.name}`, () => {
    const ast = validateQueryExpression(example.expression, schema);
    if (example.canonical) assert.deepEqual(ast, example.canonical);
    const predicate = compileQueryExpression(example.expression, schema);
    for (const item of example.rows)
      assert.equal(predicate(item.row), item.matches, JSON.stringify(item.row));
  });
for (const example of fixture.invalid)
  test(`shared Python/JS rejection fixture: ${example.name}`, () => {
    assert.throws(() => validateQueryExpression(example.expression, schema));
  });

function create(scope = "test") {
  globalThis.document = { querySelector: () => null, documentElement: {} };
  const element = {
    dataset: { queryBuilder: scope },
    querySelector: () => null,
  };
  const render = () =>
    renderQueryBuilder(scope, schema, { applyAction: "connections-filter" });
  render();
  return {
    scope,
    render,
    action(name, path = "", kind = "condition") {
      return handleQueryBuilderAction({
        dataset: {
          action: `query-builder-${name}`,
          scope,
          queryPath: path,
          kind,
        },
      });
    },
    input(part, path, value) {
      const input = {
        value,
        selectionStart: 2,
        dataset: { queryPart: part, queryPath: path },
        closest: () => element,
      };
      assert.equal(handleQueryBuilderInput({ target: input }), true);
      assert.equal(input.value, value);
      assert.equal(input.selectionStart, 2);
    },
    leaf(path, field, op, value) {
      this.input("field", path, field);
      this.input("op", path, op);
      this.input("value", path, value);
    },
  };
}
test("builder composes visible nested AND/OR groups, applies atomically and keeps unfinished draft edits away from active filters", () => {
  const ui = create();
  ui.action("add");
  assert.match(ui.render(), /Не применён/);
  ui.leaf("0", "name", "contains", "Router");
  ui.action("add", "", "group");
  ui.input("join", "1", "or");
  ui.action("add", "1");
  ui.leaf("1.0", "protocol", "eq", "tcp");
  ui.action("add", "1");
  ui.leaf("1.1", "address", "in", "192.0.2.19/24");
  const applied = applyQueryBuilder("test");
  const ast = getAppliedQuery("test");
  assert.equal(ast.children[1].join, "or");
  assert.equal(ast.children[1].children[1].value, "192.0.2.0/24");
  assert.equal(
    (ui.render().match(/query-builder-parenthesis/g) || []).length,
    4,
  );
  assert.match(ui.render(), /data-query-apply="test"/);
  ui.action("add");
  assert.throws(() => applyQueryBuilder("test"), /Завершите/);
  assert.equal(getAppliedExpression("test"), applied);
  assert.match(ui.render(), /Завершите все условия/);
  ui.action("remove", "2");
  assert.equal(applyQueryBuilder("test"), applied);
  const copy = getAppliedQuery("test");
  copy.children.length = 0;
  assert.equal(getAppliedQuery("test").children.length, 2);
  ui.action("clear");
  assert.equal(
    getAppliedExpression("test"),
    applied,
    "clear is a draft operation until Apply",
  );
  assert.equal(applyQueryBuilder("test"), "");
});
test("builder enforces leaf/depth limits before growing the draft and rejects incomplete subgroups", () => {
  const ui = create();
  for (let index = 0; index < 17; index++) {
    ui.action("add");
    if (index < 16) ui.leaf(String(index), "name", "eq", "a");
  }
  assert.equal(getAppliedQuery("test"), null);
  applyQueryBuilder("test");
  assert.equal(getAppliedQuery("test").children.length, 16);
  resetQueryBuilder("test");
  ui.render();
  ui.action("add", "", "group");
  ui.action("add", "0", "group");
  ui.action("add", "0.0", "group");
  assert.throws(() => applyQueryBuilder("test"));
  ui.action("add", "0.0");
  ui.leaf("0.0.0", "name", "eq", "a");
  const ast = JSON.parse(applyQueryBuilder("test"));
  assert.equal(ast.children[0].children[0].children.length, 1);
});
test("builder respects per-field operators, does not require values for empty, and escapes user values", () => {
  const ui = create();
  ui.action("add");
  ui.leaf("0", "name", "contains", '<img src=x onerror="bad">');
  const markup = ui.render();
  assert.doesNotMatch(markup, /<img/);
  assert.match(markup, /&lt;img/);
  ui.input("op", "0", "empty");
  assert.equal(JSON.parse(applyQueryBuilder("test")).children[0].value, "");
  const restricted = [
    {
      field: "protocol",
      label: "Protocol",
      type: "enum",
      options: ["tcp", "udp"],
      operators: ["eq", "neq"],
    },
  ];
  assert.throws(() =>
    validateQueryExpression(condition("protocol", "in", "tcp"), restricted),
  );
  for (const action of [
    "query-builder-add",
    "query-builder-remove",
    "query-builder-clear",
  ])
    assert.equal(isReadAction(action), true);
});
test("builder and errors follow RU/EN and widgets keep independent drafts and applied state", () => {
  const first = create("first"),
    second = create("second");
  first.action("add");
  first.leaf("0", "name", "eq", "router");
  applyQueryBuilder("first");
  second.action("add");
  setLanguage("en");
  assert.throws(() => applyQueryBuilder("second"), /Complete every/);
  assert.doesNotMatch(second.render(), /[А-Яа-яЁё]/u);
  assert.equal(getAppliedQuery("first").children[0].value, "router");
  resetQueryBuilder("second");
  assert.equal(getAppliedExpression("second"), "");
  assert.notEqual(getAppliedExpression("first"), "");
  assert.equal(
    handleQueryBuilderAction({ dataset: { action: "other" } }),
    false,
  );
  assert.equal(
    handleQueryBuilderInput({ target: { closest: () => null } }),
    false,
  );
});
test("canonical byte/value bounds cannot be bypassed with Unicode, oversized objects or duplicate JSON keys", () => {
  assert.doesNotThrow(() =>
    validateQueryExpression(condition("name", "eq", "é".repeat(128)), schema),
  );
  assert.throws(() =>
    validateQueryExpression(condition("name", "eq", "é".repeat(129)), schema),
  );
  assert.throws(() =>
    validateQueryExpression(
      group(
        ...Array.from({ length: 16 }, () =>
          condition("name", "eq", "🙂".repeat(128)),
        ),
      ),
      schema,
    ),
  );
  const circle = group();
  circle.children.push(circle);
  assert.throws(() => validateQueryExpression(circle, schema));
  assert.throws(() => validateQueryExpression(" ".repeat(4097), schema));
});
test("safe configured accessors are read once per row and matching never resolves property paths or evaluates strings", () => {
  let reads = 0;
  const fields = [
    {
      field: "name",
      label: "Name",
      type: "text",
      get: (row) => {
        reads++;
        return row.alias;
      },
    },
  ];
  const predicate = compileQueryExpression(
    group(
      condition("name", "contains", "alpha"),
      condition("name", "neq", "beta"),
    ),
    fields,
  );
  assert.equal(predicate({ alias: "Alpha" }), true);
  assert.equal(reads, 1);
  assert.throws(() =>
    compileQueryExpression(
      condition("constructor.prototype", "eq", "x"),
      fields,
    ),
  );
  assert.equal(casefold("Straße ΣΟΣ ﬃ"), "strasse σοσ ffi");
});
