/**
 * Move one rule relative to another in the complete execution order.
 * Hidden / filtered rules retain their relative order. The input is never mutated.
 * @template {{ id: string }} T
 * @param {T[]} rules
 * @param {string} sourceId
 * @param {string} targetId
 * @param {'before' | 'after'} placement
 * @returns {T[]}
 */
export function reorderRules(rules, sourceId, targetId, placement) {
  if (!["before", "after"].includes(placement)) {
    throw new RangeError("Unknown rule placement");
  }
  const sourceIndex = rules.findIndex((rule) => rule.id === sourceId);
  if (
    sourceId === targetId ||
    sourceIndex < 0 ||
    !rules.some((rule) => rule.id === targetId)
  ) {
    return rules;
  }
  const result = rules.slice();
  const [source] = result.splice(sourceIndex, 1);
  const targetIndex = result.findIndex((rule) => rule.id === targetId);
  result.splice(targetIndex + (placement === "after" ? 1 : 0), 0, source);
  return result;
}
