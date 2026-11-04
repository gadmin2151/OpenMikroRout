import test from "node:test";
import assert from "node:assert/strict";
import {
  hasWriteAccess,
  isReadAction,
  applyReadAccess,
} from "../../app/static/access-ui.js";
const read = { auth_enabled: true, current_user: { role: "read" } };

test("only a known full session or explicitly unauthenticated demo has write access", () => {
  assert.equal(
    hasWriteAccess({ auth_enabled: true, current_user: { role: "full" } }),
    true,
  );
  assert.equal(
    hasWriteAccess({ auth_enabled: false, current_user: null }),
    true,
  );
  for (const state of [
    null,
    undefined,
    {},
    read,
    { auth_enabled: true },
    { auth_enabled: true, current_user: { role: "superadmin" } },
  ])
    assert.equal(hasWriteAccess(state), false);
});
test("read access permits inspection and local preferences but defaults to denying mutations and unknown actions", () => {
  for (const action of [
    "view",
    "nav-group",
    "preview",
    "export",
    "columns-save",
    "editor-tab",
    "edit",
    "router-edit",
    "router-port-edit",
    "telemetry-refresh",
    "logout",
  ])
    assert.equal(isReadAction(action), true, action);
  for (const action of [
    "apply",
    "apply-confirm",
    "rollback",
    "confirm",
    "save-rule",
    "import",
    "router-new",
    "router-toggle",
    "router-save",
    "user-new",
    "user-save",
    "new-future-action",
    "",
    undefined,
  ])
    assert.equal(isReadAction(action), false, action);
});
test("read controls stay locked after selection updates while property tabs remain available", () => {
  const write = { dataset: { action: "delete" }, disabled: false },
    view = { dataset: { action: "editor-tab" }, disabled: false },
    unknown = { dataset: { action: "future-save" }, disabled: false },
    drag = { disabled: false, draggable: true },
    enabled = { disabled: false },
    text = { tagName: "INPUT", type: "text", readOnly: false },
    select = { tagName: "SELECT", disabled: false },
    checkbox = { tagName: "INPUT", type: "checkbox", disabled: false };
  const form = { querySelectorAll: () => [text, select, checkbox] };
  const scope = {
    querySelectorAll: (selector) =>
      selector === "button[data-action]"
        ? [write, view, unknown]
        : selector === "[data-drag-id],[data-filter-drag]"
          ? [drag]
          : [form],
    querySelector: () => enabled,
  };
  applyReadAccess(scope, read);
  assert.equal(write.disabled, true);
  assert.equal(unknown.disabled, true);
  assert.equal(view.disabled, false);
  assert.equal(drag.disabled, true);
  assert.equal(drag.draggable, false);
  assert.equal(text.readOnly, true);
  assert.equal(select.disabled, true);
  assert.equal(checkbox.disabled, true);
  assert.equal(enabled.disabled, true);
  write.disabled = false;
  applyReadAccess(scope, read);
  assert.equal(write.disabled, true);
});
test("login and full-access controls keep their existing validation and busy state", () => {
  const scope = {
    querySelectorAll: () => {
      throw new Error("must not alter controls");
    },
  };
  applyReadAccess(scope, null);
  applyReadAccess(scope, { auth_enabled: false });
  applyReadAccess(scope, {
    auth_enabled: true,
    current_user: { role: "full" },
  });
});
