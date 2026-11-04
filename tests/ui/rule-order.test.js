import test from "node:test";
import assert from "node:assert/strict";
import { reorderRules } from "../../app/static/rule-order.js";

const original = Object.freeze(
  ["a", "b", "c", "d", "e"].map((id) => Object.freeze({ id })),
);
const ids = (rules) => rules.map((rule) => rule.id).join("");

test("moves downward before and after the target without mutating the input", () => {
  assert.equal(ids(reorderRules(original, "a", "d", "before")), "bcade");
  assert.equal(ids(reorderRules(original, "a", "d", "after")), "bcdae");
  assert.equal(ids(original), "abcde");
});
test("moves upward to the first position", () => {
  assert.equal(ids(reorderRules(original, "e", "a", "before")), "eabcd");
  assert.equal(ids(reorderRules(original, "e", "a", "after")), "aebcd");
});
test("dropping on self, in the current position or outside the list is harmless", () => {
  assert.equal(reorderRules(original, "c", "c", "before"), original);
  assert.equal(ids(reorderRules(original, "b", "c", "before")), "abcde");
  assert.equal(ids(reorderRules(original, "b", "a", "after")), "abcde");
  assert.equal(reorderRules(original, "unknown", "a", "before"), original);
  assert.equal(reorderRules(original, "a", "unknown", "after"), original);
  assert.deepEqual(reorderRules([], "a", "b", "before"), []);
});
test("a filtered view still reorders the full list and preserves hidden rules", () => {
  // The visible rows are a/c/e, while b/d are hidden by a filter.
  const result = reorderRules(original, "a", "e", "after");
  assert.equal(ids(result), "bcdea");
  assert.ok(result.indexOf(original[1]) < result.indexOf(original[3]));
});
test("unknown placement is rejected", () => {
  assert.throws(() => reorderRules(original, "a", "b", "invalid"), RangeError);
});
