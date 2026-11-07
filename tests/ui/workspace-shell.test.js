import test from "node:test";
import assert from "node:assert/strict";
import {
  hasUnsavedWorkspaceForm,
  markWorkspaceFormDirty,
  workspaceStorageKey,
} from "../../app/static/workspace-shell.js";

const origin = "https://router.example:8443";
const state = {
  hostname: "pve1",
  mode: "linux",
  auth_enabled: true,
  current_user: { id: "account-1", username: "operator", language: "ru" },
};

function forbidPrivateReads(object, names) {
  for (const name of names)
    Object.defineProperty(object, name, {
      get() {
        return assert.fail(`Workspace metadata must not read ${name}`);
      },
    });
  return object;
}

function form({ id = "router-form", connected = true, dialog = null } = {}) {
  return forbidPrivateReads(
    {
      id,
      dataset: {},
      isConnected: connected,
      closest(selector) {
        assert.equal(selector, "dialog");
        return dialog;
      },
    },
    ["elements", "innerHTML", "textContent", "password", "value"],
  );
}

function changed(fieldForm) {
  const target = forbidPrivateReads(
    {
      closest(selector) {
        assert.equal(selector, "form");
        return fieldForm;
      },
    },
    ["value", "checked", "files", "textContent"],
  );
  return markWorkspaceFormDirty({ target });
}

function documentWith(...forms) {
  return {
    querySelectorAll(selector) {
      assert.equal(selector, 'form[data-workspace-dirty="true"]');
      return forms.filter((item) => item.dataset.workspaceDirty === "true");
    },
  };
}

test("workspace layouts are isolated by origin, account, router and execution mode", () => {
  const initial = workspaceStorageKey(state, origin);
  assert.equal(workspaceStorageKey({ ...state }, origin), initial);
  const isolated = [
    workspaceStorageKey(state, "https://router.example"),
    workspaceStorageKey(state, "http://router.example:8443"),
    workspaceStorageKey(state, "https://other-router.example:8443"),
    workspaceStorageKey({ ...state, hostname: "pve2" }, origin),
    workspaceStorageKey({ ...state, mode: "demo" }, origin),
    workspaceStorageKey(
      { ...state, current_user: { id: "account-2" } },
      origin,
    ),
  ];
  assert.equal(new Set([initial, ...isolated]).size, isolated.length + 1);
});

test("renames and language preferences preserve the same account's desktop", () => {
  const initial = workspaceStorageKey(state, origin);
  assert.equal(
    workspaceStorageKey(
      {
        ...state,
        current_user: {
          ...state.current_user,
          username: "renamed-operator",
          language: "en",
        },
      },
      origin,
    ),
    initial,
  );
});

test("signed-out, local-auth-disabled and identified accounts cannot share layout keys", () => {
  const signedOut = workspaceStorageKey(
    { ...state, current_user: null },
    origin,
  );
  const local = workspaceStorageKey(
    { ...state, current_user: null, auth_enabled: false },
    origin,
  );
  assert.notEqual(signedOut, local);
  assert.notEqual(signedOut, workspaceStorageKey(state, origin));
  assert.notEqual(local, workspaceStorageKey(state, origin));
  assert.equal(
    workspaceStorageKey({ mode: "demo", auth_enabled: false }, origin),
    workspaceStorageKey(
      { mode: "demo", auth_enabled: false, hostname: "router" },
      origin,
    ),
  );
});

test("layout keys serialize only identity fields and retain unambiguous separators", () => {
  const account = forbidPrivateReads({ id: 'account/with,"separators' }, [
    "username",
    "password",
    "totp_secret",
    "recovery_codes",
  ]);
  const identity = forbidPrivateReads(
    { ...state, current_user: account, hostname: "Сеть,router/1" },
    ["config", "password", "token", "csrf_token", "session", "cookie"],
  );
  const key = workspaceStorageKey(identity, origin);
  const prefix = "openmikrorout.workspace.v1.";
  assert.ok(key.startsWith(prefix));
  assert.deepEqual(JSON.parse(decodeURIComponent(key.slice(prefix.length))), [
    origin,
    "linux",
    "Сеть,router/1",
    'account/with,"separators',
  ]);
});

test("configuration, account and import editor changes set only an unsaved flag", () => {
  for (const id of [
    "rule-form",
    "list-form",
    "router-form",
    "router-port-form",
    "wg-form",
    "router-dns-form",
    "router-domain-form",
    "backup-import-form",
    "f2b-profile-form",
    "f2b-settings",
    "geo-settings",
    "discovery-settings",
    "scan-settings",
    "user-form",
    "preferences-form",
  ]) {
    const editor = form({ id });
    assert.equal(changed(editor), true, id);
    assert.deepEqual(editor.dataset, { workspaceDirty: "true" }, id);
    assert.equal(changed(editor), true, `${id} remains dirty`);
  }
});

test("tool targets, searches, login and credential proofs are not editor changes", () => {
  for (const id of [
    "tools-form",
    "capture-form",
    "scan-start",
    "monitor-filters",
    "login-form",
    "user-proof",
    "security-proof",
    "unknown-form",
    "",
  ]) {
    const control = form({ id });
    assert.equal(changed(control), undefined, id);
    assert.deepEqual(control.dataset, {}, id);
  }
  assert.equal(changed(null), undefined);
  assert.equal(markWorkspaceFormDirty({}), undefined);
  assert.equal(markWorkspaceFormDirty({ target: {} }), undefined);
});

test("searching a checkbox list does not dirty its surrounding settings form", () => {
  const editor = form({ id: "scan-settings" });
  const target = forbidPrivateReads(
    {
      matches(selector) {
        assert.equal(selector, "[data-checkbox-search]");
        return true;
      },
      closest(selector) {
        assert.equal(selector, "form");
        return editor;
      },
    },
    ["value", "checked", "files"],
  );
  assert.equal(markWorkspaceFormDirty({ target }), undefined);
  assert.deepEqual(editor.dataset, {});
  assert.equal(hasUnsavedWorkspaceForm(documentWith(editor)), false);
  // A subsequent real checkbox change must still protect the edited form.
  assert.equal(changed(editor), true);
  assert.equal(hasUnsavedWorkspaceForm(documentWith(editor)), true);
});

test("unsaved detection considers connected page forms and open editor dialogs", () => {
  const page = form();
  const editor = form({ id: "user-form", dialog: { open: true } });
  const pageDocument = documentWith(page);
  assert.equal(hasUnsavedWorkspaceForm(pageDocument), false);
  changed(page);
  assert.equal(hasUnsavedWorkspaceForm(pageDocument), true);
  changed(editor);
  assert.equal(hasUnsavedWorkspaceForm(documentWith(editor)), true);
  assert.equal(hasUnsavedWorkspaceForm(documentWith()), false);
});

test("closed and unmounted editor forms do not block closing or navigation", () => {
  const closed = form({ dialog: { open: false } });
  const unmounted = form({ connected: false });
  const unmountedDialog = form({ connected: false, dialog: { open: true } });
  for (const editor of [closed, unmounted, unmountedDialog]) changed(editor);
  const detached = documentWith(closed, unmounted, unmountedDialog);
  assert.equal(hasUnsavedWorkspaceForm(detached), false);
  closed.closest("dialog").open = true;
  assert.equal(hasUnsavedWorkspaceForm(detached), true);
  closed.closest("dialog").open = false;
  unmounted.isConnected = true;
  assert.equal(hasUnsavedWorkspaceForm(detached), true);
});
