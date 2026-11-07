import { html, t } from "./i18n.js";

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const installedScopes = new WeakSet();

/** Real checkboxes preserve native keyboard navigation and FormData.getAll(name). */
export function checkboxSelect({
  name,
  label,
  options,
  selected = [],
  required = false,
  disabled = false,
  searchable = options.length > 6,
}) {
  const values = new Set(selected);
  const choices = [
    ...new Map(options.map(([value, text]) => [String(value), text])),
  ];
  const count = choices.filter(([value]) => values.has(value)).length;
  return html`<div class="field checkbox-field"><span>${escape(t(label))}</span><div class="checkbox-select" role="group" aria-label="${escape(t(label))}" data-checkbox-select ${required ? 'data-checkbox-required="true"' : ""}><div class="checkbox-select-toolbar"><output class="checkbox-select-count" aria-live="polite">${count} / ${choices.length}</output><button type="button" data-checkbox-command="all" ${disabled || !choices.length ? "disabled" : ""}>${escape(t("Выбрать все"))}</button><button type="button" data-checkbox-command="clear" ${disabled || !choices.length ? "disabled" : ""}>${escape(t("Очистить"))}</button></div>${searchable && choices.length ? html`<input class="checkbox-select-search" type="search" data-checkbox-search aria-label="${escape(t("Поиск в списке"))}" placeholder="${escape(t("Поиск в списке"))}" autocomplete="off" ${disabled ? "disabled" : ""}>` : ""}<div class="checkbox-select-options">${choices.map(([value, text], index) => html`<label class="checkbox-select-option"><input type="checkbox" name="${escape(name)}" value="${escape(value)}" ${values.has(value) ? "checked" : ""} ${required && count === 0 && index === 0 ? "required" : ""} ${disabled ? "disabled" : ""}><span>${escape(text)}</span></label>`).join("") || html`<span class="checkbox-select-empty">${escape(t("Нет доступных вариантов"))}</span>`}</div><span class="checkbox-select-empty checkbox-select-no-results" hidden>${escape(t("Ничего не найдено"))}</span></div></div>`;
}

function updateGroup(group) {
  const checkboxes = [...group.querySelectorAll('input[type="checkbox"]')];
  const count = checkboxes.filter((input) => input.checked).length;
  const counter = group.querySelector("output");
  if (counter) counter.textContent = `${count} / ${checkboxes.length}`;
  // An initially empty required group fails reportValidity immediately. Any checked
  // member satisfies the group, without forcing a particular interface to be selected.
  for (const [index, input] of checkboxes.entries())
    input.required =
      group.hasAttribute("data-checkbox-required") &&
      count === 0 &&
      index === 0;
}

export function handleCheckboxSelectEvent(event) {
  const group = event.target?.closest?.("[data-checkbox-select]");
  if (!group) return false;
  if (event.type === "click") {
    const button = event.target.closest("[data-checkbox-command]");
    if (!button) return false;
    event.preventDefault();
    if (button.matches(":disabled")) return true;
    const checked = button.dataset.checkboxCommand === "all";
    for (const input of group.querySelectorAll('input[type="checkbox"]'))
      if (!input.matches(":disabled")) input.checked = checked;
    updateGroup(group);
    // Consumers observing form changes (draft guards, live previews) see one event.
    group
      .querySelector('input[type="checkbox"]')
      ?.dispatchEvent(new globalThis.Event("change", { bubbles: true }));
    return true;
  }
  if (
    event.type === "input" &&
    event.target.matches("[data-checkbox-search]")
  ) {
    const query = event.target.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const option of group.querySelectorAll(".checkbox-select-option")) {
      option.hidden = !option.textContent.toLocaleLowerCase().includes(query);
      if (!option.hidden) visible++;
    }
    const empty = group.querySelector(".checkbox-select-no-results");
    if (empty) empty.hidden = visible > 0;
    return true;
  }
  if (event.type === "change") {
    updateGroup(group);
    return true;
  }
  return false;
}

export function installCheckboxSelectEvents(scope = document) {
  if (installedScopes.has(scope)) return;
  installedScopes.add(scope);
  for (const event of ["click", "change", "input"])
    scope.addEventListener(event, handleCheckboxSelectEvent);
}
