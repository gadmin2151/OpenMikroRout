import { html, t } from "./i18n.js";

const fields = new Set([
  "protocol",
  "src_address",
  "dst_address",
  "src_list",
  "dst_list",
  "src_country",
  "dst_country",
  "src_ports",
  "dst_ports",
  "in_interface",
  "out_interface",
  "connection_states",
]);
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );

function hasValue(item, field) {
  if (!fields.has(field)) return false;
  const value = item[field];
  return field === "connection_states"
    ? Array.isArray(value) && value.length > 0
    : typeof value === "string" &&
        !!value.trim() &&
        !(field === "protocol" && value === "any");
}

export function ruleNegations(item) {
  return [...new Set(Array.isArray(item.negate) ? item.negate : [])].filter(
    (field) => fields.has(field) && hasValue(item, field),
  );
}

export function negatedValue(item, field, fallback = "—") {
  const value = item[field];
  const display = Array.isArray(value) ? value.join(", ") : value;
  return `${ruleNegations(item).includes(field) ? "! " : ""}${display == null || display === "" ? fallback : display}`;
}

export function negationSummary(item) {
  const labels = {
    protocol: "Protocol",
    src_address: "Src. Address",
    dst_address: "Dst. Address",
    src_list: "Src. Address List",
    dst_list: "Dst. Address List",
    src_country: "Src. Country",
    dst_country: "Dst. Country",
    src_ports: "Src. Port",
    dst_ports: "Dst. Port",
    in_interface: "In. Interface",
    out_interface: "Out. Interface",
    connection_states: "Connection State",
  };
  return ruleNegations(item)
    .map((field) => t(labels[field]))
    .join(", ");
}

/** Decorate our existing field templates, preserving their native controls and
 * names. The control's label remains separate from the interactive ! button. */
export function withRuleNegation(
  markup,
  field,
  item,
  { action = "rule-negate", disabled = false } = {},
) {
  if (!fields.has(field)) return markup;
  const heading = /<span>([\s\S]*?)<\/span>/.exec(markup);
  if (!heading) return markup;
  const labelId = `rule-match-label-${field}`;
  const control = /<(?:input|select)\b([^>]*)>/.exec(markup);
  const existingId = /\bid="([^"]+)"/.exec(control?.[1] || "")?.[1];
  const controlId = existingId || `rule-match-input-${field}`;
  const label =
    field === "connection_states"
      ? html`<span id="${labelId}">${heading[1]}</span>`
      : html`<label id="${labelId}" for="${controlId}">${heading[1]}</label>`;
  const pressed = ruleNegations(item).includes(field);
  const caption = html`<span class="rule-match-heading">${label}<button type="button" class="rule-negate" data-action="${action}" data-rule-negate="${field}" aria-pressed="${pressed}" aria-label="${escape(t("Отрицание условия: {field}", { field: t(heading[1]) }))}" title="Все, кроме указанного" ${disabled || !hasValue(item, field) ? "disabled" : ""}>!</button></span>`;
  let result = markup
    .replace(heading[0], caption)
    .replace(
      /class="([^"]*)"/,
      (_match, value) => `class="${value} rule-match-field"`,
    );
  if (result.startsWith("<label"))
    result = result
      .replace(/^<label\b/, "<div")
      .replace(/<\/label>$/, "</div>");
  if (field !== "connection_states")
    result = result.replace(
      /<(input|select)\b/,
      `<$1 aria-labelledby="${labelId}"${existingId ? "" : ` id="${controlId}"`}`,
    );
  else
    result = result.replace(
      'class="states"',
      `class="states" role="group" aria-labelledby="${labelId}"`,
    );
  return result;
}

export function collectRuleNegations(form, item) {
  const selected = new Set(ruleNegations(item));
  for (const button of form.querySelectorAll?.("[data-rule-negate]") || []) {
    const field = button.dataset.ruleNegate;
    if (!fields.has(field)) continue;
    if (button.getAttribute("aria-pressed") === "true" && hasValue(item, field))
      selected.add(field);
    else selected.delete(field);
  }
  return [...selected];
}

export function toggleRuleNegation(item, field) {
  if (!hasValue(item, field)) return false;
  const selected = new Set(ruleNegations(item));
  if (selected.has(field)) selected.delete(field);
  else selected.add(field);
  item.negate = [...selected];
  return true;
}

/** Editing an empty field must enable its ! control without replacing the form
 * or caret. Clearing a field resets only its visible negation state. */
export function syncRuleNegationControls(form, canWrite) {
  for (const button of form?.querySelectorAll?.("[data-rule-negate]") || []) {
    const field = button.dataset.ruleNegate;
    if (!fields.has(field)) continue;
    const name =
      field === "connection_states" && form.id === "rule-form"
        ? "state"
        : field;
    const inputs = [...form.querySelectorAll(`[name="${name}"]`)];
    const usable = inputs.filter((input) => !input.disabled);
    const present =
      field === "connection_states"
        ? usable.some((input) => input.checked)
        : usable.some(
            (input) =>
              typeof input.value === "string" &&
              input.value.trim() &&
              !(field === "protocol" && input.value === "any"),
          );
    button.disabled = !canWrite || !present;
    if (!present) button.setAttribute("aria-pressed", "false");
  }
}
