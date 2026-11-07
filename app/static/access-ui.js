import { t } from "./i18n.js";
/** UI permissions complement server authorization; unknown actions require full access. */
const readActions = new Set([
  "preferences-save",
  "close",
  "menu",
  "nav-group",
  "help",
  "view",
  "refresh",
  "logout",
  "preview",
  "export",
  "backup-export-rsc",
  "backup-export-json",
  "backup-reset",
  "telemetry-refresh",
  "telemetry-expand",
  "telemetry-collapse",
  "columns",
  "columns-reset",
  "columns-save",
  "edit",
  "edit-list",
  "editor-tab",
  "router-edit",
  "router-editor-tab",
  "router-port-edit",
  "router-reload-dns",
  "security-enroll",
  "security-setup",
  "security-confirm",
  "security-disable-open",
  "security-disable",
  "security-download",
  "connections-kind",
  "connections-filter",
  "connections-reset",
  "connections-refresh",
  "protection-refresh",
  "protection-search",
  "protection-page",
  "geo-lookup",
  "f2b-edit",
  "rule-protection-open",
  "system-list-open",
  "system-list-page",
  "system-list-search",
  "discovery-refresh",
  "discovery-search",
  "discovery-page",
  "discovery-host",
  "discovery-connections",
  "scan-refresh",
  "scan-settings-open",
  "scan-job",
  "scan-page",
  "wg-refresh",
  "wg-interface-edit",
  "wg-peer-edit",
]);
export function hasWriteAccess(state) {
  return (
    !!state &&
    (state.auth_enabled === false ||
      (state.auth_enabled === true && state.current_user?.role === "full"))
  );
}
export function isReadAction(action) {
  return readActions.has(action);
}
export function applyReadAccess(scope, state) {
  if (!state || hasWriteAccess(state)) return;
  for (const button of scope.querySelectorAll("button[data-action]")) {
    if (!isReadAction(button.dataset.action)) {
      button.disabled = true;
      button.title = t("Группа read: доступен только просмотр");
    }
  }
  for (const handle of scope.querySelectorAll(
    "[data-drag-id],[data-filter-drag]",
  )) {
    handle.disabled = true;
    handle.draggable = false;
  }
  const forms =
    "#rule-form,#list-form,#router-form,#router-port-form,#router-dns-form,#router-domain-form,#backup-import-form,#user-form,#wg-form,#f2b-profile-form,#f2b-settings,#geo-settings,#discovery-settings,#scan-settings";
  for (const form of scope.querySelectorAll(forms)) {
    for (const field of form.querySelectorAll("input,select,textarea,button")) {
      if (
        field.tagName === "SELECT" ||
        field.tagName === "BUTTON" ||
        [
          "checkbox",
          "radio",
          "file",
          "range",
          "color",
          "submit",
          "button",
        ].includes(field.type)
      )
        field.disabled = true;
      else field.readOnly = true;
    }
  }
  const enabled = scope.querySelector("#rule-enabled");
  if (enabled) enabled.disabled = true;
}
