import { html, t } from "./i18n.js";

const identifier = /^[a-z][a-z0-9_-]*$/;
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const populated = (value) =>
  Array.isArray(value)
    ? value.length > 0
    : value != null && String(value).trim() !== "";

/** A display scope supplies its own whitelist, independently of router rules. */
export function displayNegations(negate, values, allowed) {
  const selected = new Set(
    typeof negate === "string"
      ? negate.split(",")
      : Array.isArray(negate) || negate instanceof Set
        ? negate
        : [],
  );
  return allowed.filter(
    (name) =>
      identifier.test(name) && selected.has(name) && populated(values[name]),
  );
}

export function displayNegationQuery(negate, values, allowed) {
  return displayNegations(negate, values, allowed).join(",");
}

export function displayFilterToggle({
  name,
  label,
  value,
  negated = false,
  action,
  disabled = false,
}) {
  if (!identifier.test(name) || !identifier.test(action)) return "";
  const active = populated(value);
  return html`<button type="button" class="rule-negate display-filter-negate" data-action="${action}" data-display-negate="${name}" aria-pressed="${active && negated}" aria-label="${escape(t("Отрицание условия: {field}", { field: t(label) }))}" title="Все, кроме указанного" ${active && !disabled ? "" : "disabled"}>!</button>`;
}

/** Decorate existing native fields without putting an interactive button inside
 * their label. Input names, validation and user-entered values stay unchanged. */
export function displayFilterField(
  markup,
  name,
  {
    value,
    negated = false,
    action,
    idPrefix = "display-filter",
    disabled = false,
  } = {},
) {
  if (!identifier.test(name) || !identifier.test(idPrefix)) return markup;
  const heading = /<span>([\s\S]*?)<\/span>/.exec(markup);
  const control = /<(?:input|select)\b([^>]*)>/.exec(markup);
  if (!heading || !control) return markup;
  const existingId = /\bid="([^"]+)"/.exec(control[1])?.[1];
  const controlId = existingId || `${idPrefix}-${name}`;
  const toggle = displayFilterToggle({
    name,
    label: heading[1],
    value,
    negated,
    action,
    disabled,
  });
  if (!toggle) return markup;
  let result = markup.replace(
    heading[0],
    html`<span class="display-filter-heading"><label for="${controlId}">${heading[1]}</label>${toggle}</span>`,
  );
  if (!existingId)
    result = result.replace(/<(input|select)\b/, `<$1 id="${controlId}"`);
  if (result.startsWith("<label"))
    result = result
      .replace(/^<label\b/, "<div")
      .replace(/<\/label>$/, "</div>");
  return result;
}

/** Keep editable filters stable while typing and polling; only their ! changes. */
export function syncDisplayFilterControl(
  form,
  name,
  value,
  negated,
  disabled = false,
) {
  if (!identifier.test(name)) return;
  const button = form?.querySelector?.(`[data-display-negate="${name}"]`);
  if (!button) return;
  const active = populated(value);
  button.disabled = !active || disabled;
  button.setAttribute("aria-pressed", String(active && negated));
}
