import { html, t } from "./i18n.js";
import {
  operatorsForField,
  queryLimits,
  validateQueryExpression,
} from "./query-expression.js";
export {
  compileQueryExpression,
  matchesQueryExpression,
  validateQueryExpression,
  queryLimits,
} from "./query-expression.js";

const scopes = new Map();
const identifier = /^[a-z][a-z0-9_-]{0,63}$/;
const emptyGroup = () => ({ kind: "group", join: "and", children: [] });
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const labels = {
  eq: "равно",
  neq: "не равно",
  contains: "содержит",
  not_contains: "не содержит",
  in: "входит в",
  not_in: "не входит в",
  gt: "больше",
  gte: "не меньше",
  lt: "меньше",
  lte: "не больше",
  empty: "пусто",
  not_empty: "не пусто",
};
const needsValue = (op) => !["empty", "not_empty"].includes(op);
function counts(node, depth = 1) {
  if (node.kind !== "group") return { leaves: 1, nodes: 1, depth };
  return node.children.reduce(
    (sum, child) => {
      const value = counts(child, depth + 1);
      return {
        leaves: sum.leaves + value.leaves,
        nodes: sum.nodes + value.nodes,
        depth: Math.max(sum.depth, value.depth),
      };
    },
    { leaves: 0, nodes: 1, depth },
  );
}
function nodeAt(state, path) {
  if (!path) return state.draft;
  if (!/^\d{1,2}(?:\.\d{1,2}){0,2}$/.test(path)) return null;
  return path
    .split(".")
    .reduce(
      (node, index) =>
        node?.kind === "group" ? node.children[Number(index)] : null,
      state.draft,
    );
}
const pathDepth = (path) => (path ? path.split(".").length + 1 : 1);
function mounted(scope) {
  return typeof document === "undefined"
    ? null
    : document.querySelector(`[data-query-builder="${scope}"]`);
}
function conditionMarkup(state, node, path) {
  const field = state.schema.find((item) => item.field === node.field);
  const operators = field ? operatorsForField(field) : [];
  const options = field?.options || [];
  const values =
    field?.type === "enum" && options.length && ["eq", "neq"].includes(node.op)
      ? html`<select data-query-part="value" data-query-path="${path}" aria-label="Значение"><option value="">Значение…</option>${options
          .map((option) => {
            const [value, label] = Array.isArray(option)
              ? option
              : [option, option];
            return html`<option value="${escape(value)}" ${value === node.value ? "selected" : ""}>${escape(t(label))}</option>`;
          })
          .join("")}</select>`
      : html`<input type="text" data-query-part="value" data-query-path="${path}" aria-label="Значение" maxlength="128" value="${escape(node.value)}" ${!field || !needsValue(node.op) ? "disabled" : ""} ${field?.type === "number" ? 'inputmode="decimal"' : ""} placeholder="${escape(!needsValue(node.op) ? t("Значение не требуется") : ["in", "not_in"].includes(node.op) ? t("Значения через запятую") : field?.type === "ipv4" ? t("IPv4 / CIDR") : field?.type === "ports" ? "80,443,8000-8010" : t("Значение…"))}">`;
  return html`<div class="query-builder-row" data-query-row="${path}"><select data-query-part="field" data-query-path="${path}" aria-label="Поле"><option value="">Поле…</option>${state.schema.map((item) => html`<option value="${escape(item.field)}" ${item.field === node.field ? "selected" : ""}>${escape(t(item.label))}</option>`).join("")}</select><select data-query-part="op" data-query-path="${path}" aria-label="Оператор" ${field ? "" : "disabled"}>${operators.map((op) => html`<option value="${op}" ${op === node.op ? "selected" : ""}>${escape(t(labels[op]))}</option>`).join("")}</select>${values}<button type="button" class="query-builder-remove" data-action="query-builder-remove" data-scope="${state.scope}" data-query-path="${path}" aria-label="Удалить условие" title="Удалить условие">×</button></div>`;
}
function groupMarkup(state, group, path = "") {
  const count = counts(state.draft),
    depth = pathDepth(path);
  const addCondition =
    count.leaves < queryLimits.leaves &&
    count.nodes < queryLimits.nodes &&
    depth < queryLimits.depth;
  const addGroup =
    count.nodes < queryLimits.nodes && depth < queryLimits.depth - 1;
  return html`<section class="query-builder-group" data-query-group="${path}"><div class="query-builder-group-head"><span class="query-builder-parenthesis" aria-hidden="true">(</span><label><span class="sr-only">Объединение условий</span><select data-query-part="join" data-query-path="${path}" aria-label="Объединение условий"><option value="and" ${group.join === "and" ? "selected" : ""}>${t("И (AND)")}</option><option value="or" ${group.join === "or" ? "selected" : ""}>${t("ИЛИ (OR)")}</option></select></label><button type="button" data-action="query-builder-add" data-kind="condition" data-scope="${state.scope}" data-query-path="${path}" ${addCondition ? "" : "disabled"}>+ Условие</button><button type="button" data-action="query-builder-add" data-kind="group" data-scope="${state.scope}" data-query-path="${path}" ${addGroup ? "" : "disabled"}>+ Группа</button>${path ? html`<button type="button" class="query-builder-remove" data-action="query-builder-remove" data-scope="${state.scope}" data-query-path="${path}" aria-label="Удалить группу" title="Удалить группу">×</button>` : ""}</div><div class="query-builder-children">${
    group.children
      .map((child, index) => {
        const next = path ? `${path}.${index}` : String(index);
        return child.kind === "group"
          ? groupMarkup(state, child, next)
          : conditionMarkup(state, child, next);
      })
      .join("") ||
    html`<p class="query-builder-empty">Добавьте условие или группу условий.</p>`
  }</div><span class="query-builder-parenthesis" aria-hidden="true">)</span></section>`;
}
function bodyMarkup(state) {
  const attrs = Object.entries(state.options.applyData || {})
    .filter(([key]) => /^[a-z][a-z0-9-]*$/.test(key))
    .map(([key, value]) => `data-${key}="${escape(value)}"`)
    .join(" ");
  return html`${groupMarkup(state, state.draft)}<p class="query-builder-hint">Расширенный фильтр объединяется с быстрыми условиями через И. До 16 условий и 4 уровней.</p><div class="query-builder-error" role="alert" ${state.error ? "" : "hidden"}>${escape(state.error)}</div><div class="query-builder-actions"><button type="button" data-action="query-builder-clear" data-scope="${state.scope}">Очистить конструктор</button><button type="button" class="primary" data-action="${state.options.applyAction}" data-query-apply="${state.scope}" ${attrs}>Применить фильтр</button></div>`;
}
function summaryMarkup(state) {
  const count = counts(state.draft).leaves;
  const dirty = state.appliedDraft !== JSON.stringify(state.draft);
  return html`<span>Расширенный фильтр</span><span class="query-builder-count">${count} / 16</span>${dirty ? html`<span class="query-builder-pending">Не применён</span>` : state.applied ? html`<span class="query-builder-active">Применён</span>` : ""}`;
}
function updateWidget(state, focus) {
  const element = mounted(state.scope);
  if (!element) return;
  state.open = element.open;
  const body = element.querySelector(".query-builder-body");
  if (body) body.innerHTML = bodyMarkup(state);
  const summary = element.querySelector("summary");
  if (summary) summary.innerHTML = summaryMarkup(state);
  if (focus) element.querySelector(focus)?.focus({ preventScroll: true });
}
function showError(state, message = "") {
  state.error = message;
  const element = mounted(state.scope),
    region = element?.querySelector(".query-builder-error");
  if (message) {
    state.open = true;
    if (element) element.open = true;
  }
  if (region) {
    region.textContent = message;
    region.hidden = !message;
  }
  const summary = element?.querySelector?.("summary");
  if (summary) summary.innerHTML = summaryMarkup(state);
}

export function renderQueryBuilder(scope, schema, options) {
  if (!identifier.test(scope) || !identifier.test(options?.applyAction || ""))
    throw new Error("Invalid query builder scope");
  let state = scopes.get(scope);
  if (!state) {
    state = {
      scope,
      schema,
      options,
      draft: emptyGroup(),
      applied: null,
      appliedDraft: JSON.stringify(emptyGroup()),
      error: "",
      open: false,
    };
    scopes.set(scope, state);
  }
  state.schema = schema;
  state.options = options;
  const previous = mounted(scope);
  if (typeof previous?.open === "boolean") state.open = previous.open;
  return html`<details class="query-builder" data-query-builder="${scope}" ${state.open ? "open" : ""}><summary>${summaryMarkup(state)}</summary><div class="query-builder-body">${bodyMarkup(state)}</div></details>`;
}
export function applyQueryBuilder(scope) {
  const state = scopes.get(scope);
  if (!state) return "";
  try {
    const expression = validateQueryExpression(state.draft, state.schema);
    state.applied = expression;
    state.appliedDraft = JSON.stringify(state.draft);
    showError(state);
    const summary = mounted(scope)?.querySelector("summary");
    if (summary) summary.innerHTML = summaryMarkup(state);
    return expression ? JSON.stringify(expression) : "";
  } catch (error) {
    showError(state, error.message);
    throw error;
  }
}
export const getAppliedExpression = (scope) =>
  scopes.get(scope)?.applied ? JSON.stringify(scopes.get(scope).applied) : "";
export const getAppliedQuery = (scope) =>
  scopes.get(scope)?.applied
    ? structuredClone(scopes.get(scope).applied)
    : null;
export function resetQueryBuilder(scope) {
  scopes.delete(scope);
}
export function resetAllQueryBuilders() {
  scopes.clear();
}

export function handleQueryBuilderInput(event) {
  const input = event.target,
    element = input?.closest?.("[data-query-builder]");
  const state = scopes.get(element?.dataset.queryBuilder),
    part = input?.dataset?.queryPart;
  if (!state || !["field", "op", "value", "join"].includes(part)) return false;
  const node = nodeAt(state, input.dataset.queryPath || "");
  if (!node) return true;
  if (part === "join") {
    if (node.kind === "group" && ["and", "or"].includes(input.value))
      node.join = input.value;
    showError(state);
    return true;
  }
  if (node.kind !== "condition") return true;
  if (part === "value") {
    node.value = String(input.value);
    showError(state);
    return true;
  }
  if (part === "field") {
    const field = state.schema.find((item) => item.field === input.value);
    node.field = field?.field || "";
    node.op = field ? operatorsForField(field)[0] : "eq";
    node.value = "";
  } else {
    const field = state.schema.find((item) => item.field === node.field);
    if (!field || !operatorsForField(field).includes(input.value)) return true;
    node.op = input.value;
    if (!needsValue(node.op)) node.value = "";
  }
  showError(state);
  const row = element.querySelector(
    `[data-query-row="${input.dataset.queryPath}"]`,
  );
  if (row)
    row.outerHTML = conditionMarkup(state, node, input.dataset.queryPath);
  element
    .querySelector(
      `[data-query-path="${input.dataset.queryPath}"][data-query-part="${part === "field" ? "op" : needsValue(node.op) ? "value" : "op"}"]`,
    )
    ?.focus({ preventScroll: true });
  return true;
}
export function handleQueryBuilderAction(button) {
  const action = button.dataset.action;
  if (
    ![
      "query-builder-add",
      "query-builder-remove",
      "query-builder-clear",
    ].includes(action)
  )
    return false;
  const state = scopes.get(button.dataset.scope);
  if (!state || button.disabled) return true;
  const path = button.dataset.queryPath || "";
  if (action === "query-builder-clear") state.draft = emptyGroup();
  else if (action === "query-builder-add") {
    const group = nodeAt(state, path),
      count = counts(state.draft),
      depth = pathDepth(path);
    if (group?.kind !== "group" || count.nodes >= queryLimits.nodes)
      return true;
    if (button.dataset.kind === "group") {
      if (depth >= queryLimits.depth - 1) return true;
      group.children.push(emptyGroup());
    } else {
      if (
        button.dataset.kind !== "condition" ||
        count.leaves >= queryLimits.leaves ||
        depth >= queryLimits.depth
      )
        return true;
      group.children.push({
        kind: "condition",
        field: "",
        op: "eq",
        value: "",
      });
    }
  } else {
    if (!path || !nodeAt(state, path)) return true;
    const parts = path.split("."),
      index = Number(parts.pop()),
      parent = nodeAt(state, parts.join("."));
    if (parent?.kind !== "group") return true;
    parent.children.splice(index, 1);
  }
  showError(state);
  updateWidget(state);
  return true;
}
