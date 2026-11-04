import test from "node:test";
import assert from "node:assert/strict";
import { handleUsersAction, renderUsers } from "../../app/static/users-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const admin = {
  id: "admin-id",
  username: "admin",
  role: "full",
  enabled: true,
  created_at: 1700000000,
};
const reader = {
  id: "reader-id",
  username: "viewer",
  role: "read",
  enabled: true,
  created_at: 1700000100,
};
function context(overrides = {}) {
  const calls = {
    api: [],
    frames: [],
    closed: 0,
    refreshed: 0,
    rendered: 0,
    toasts: [],
  };
  const ctx = {
    state: { auth_enabled: true },
    users: [{ ...admin }, { ...reader }],
    currentUser: admin,
    busy: false,
    offline: false,
    canWrite: () => true,
    e,
    icon: () => "<svg></svg>",
    api: async (path, options) => {
      calls.api.push({ path, options });
      return {};
    },
    refreshUsers: async () => {
      calls.refreshed++;
    },
    render: () => {
      calls.rendered++;
    },
    toast: (...args) => calls.toasts.push(args),
    run: async (task) => task(),
    dialogFrame: (...args) => calls.frames.push(args),
    dialog: {
      close: () => {
        calls.closed++;
      },
      classList: { add: () => {} },
      querySelector: () => null,
    },
    ...overrides,
  };
  return { ctx, calls };
}
function button(action, id, disabled = false) {
  return { dataset: { action, id }, disabled };
}

test("read users and anonymous demo do not receive account-management controls or other account names", () => {
  const { ctx } = context({ canWrite: () => false, currentUser: reader });
  const readHtml = renderUsers(ctx);
  assert.ok(readHtml.includes("Ваша группа: read"));
  assert.ok(!readHtml.includes('data-action="user-'));
  assert.ok(!readHtml.includes("admin"));
  const demo = renderUsers({
    ...ctx,
    state: { auth_enabled: false },
    canWrite: () => true,
  });
  assert.ok(demo.includes("Включите авторизацию"));
  assert.ok(!demo.includes('data-action="user-'));
});

test("table renders only public account fields and escapes API-controlled attributes and names", () => {
  const unsafe = '<img src=x onerror="alert(1)">';
  const { ctx } = context({
    users: [
      {
        ...admin,
        id: unsafe,
        username: unsafe,
        password: "secret-not-a-public-field",
        password_hash: "hash-not-a-public-field",
      },
    ],
  });
  const html = renderUsers(ctx);
  assert.ok(!html.includes(unsafe));
  assert.ok(html.includes("&lt;img"));
  assert.ok(!html.includes("secret-not-a-public-field"));
  assert.ok(!html.includes("hash-not-a-public-field"));
  assert.ok(html.includes("read"));
  assert.ok(html.includes("full"));
});

test("edit form never pre-fills a password and protects the only enabled full user", async () => {
  const { ctx, calls } = context({
    users: [{ ...admin, password: "sensitive-existing-password" }],
  });
  await handleUsersAction(button("user-edit", admin.id), ctx);
  const form = calls.frames[0][2];
  assert.ok(form.includes('id="user-form"'));
  assert.ok(form.includes('autocomplete="new-password"'));
  assert.ok(form.includes('minlength="12" maxlength="512"'));
  assert.ok(!form.includes("sensitive-existing-password"));
  assert.ok(!/name="password"[^>]*value=/.test(form));
  assert.ok(form.includes('value="read"  disabled'));
  assert.ok(form.includes('type="hidden" name="enabled"'));
  assert.ok(form.includes("последний включённый пользователь full"));
});

test("direct mutation actions cannot bypass read access or the last enabled full guard", async () => {
  for (const action of ["user-remove", "user-toggle", "user-delete-confirm"]) {
    const { ctx, calls } = context();
    await assert.rejects(
      handleUsersAction(button(action, admin.id), ctx),
      /последнего включённого/,
    );
    assert.equal(calls.api.length, 0);
  }
  const { ctx, calls } = context({
    canWrite: () => false,
    currentUser: reader,
  });
  await assert.rejects(
    handleUsersAction(button("user-new"), ctx),
    /только группе full/,
  );
  assert.equal(calls.frames.length, 0);
  assert.equal(calls.api.length, 0);
});

test("toggle updates the selected account then refreshes the user view", async () => {
  const { ctx, calls } = context();
  assert.equal(
    await handleUsersAction(button("user-toggle", reader.id), ctx),
    true,
  );
  assert.deepEqual(calls.api, [
    {
      path: "users/reader-id",
      options: { method: "PUT", body: JSON.stringify({ enabled: false }) },
    },
  ]);
  assert.equal(calls.refreshed, 1);
  assert.equal(calls.rendered, 1);
  assert.equal(calls.closed, 1);
});

test("deletion requires its confirmation action and uses an encoded account id", async () => {
  const id = "reader / unsafe";
  const { ctx, calls } = context({
    users: [admin, { ...reader, id, username: "<viewer>" }],
  });
  await handleUsersAction(button("user-remove", id), ctx);
  assert.equal(calls.api.length, 0);
  assert.ok(calls.frames[0][2].includes("&lt;viewer&gt;"));
  await handleUsersAction(button("user-delete-confirm", id), ctx);
  assert.equal(calls.api[0].path, "users/reader%20%2F%20unsafe");
  assert.equal(calls.api[0].options.method, "DELETE");
});

test("blank edit password preserves the existing secret and submitted passwords are never echoed", async (t) => {
  t.mock.method(globalThis, "FormData", function (form) {
    return form.fields;
  });
  const passwordInput = { value: "" };
  const form = {
    dataset: { id: reader.id },
    reportValidity: () => true,
    fields: new Map([
      ["username", " VIEWER "],
      ["role", "read"],
      ["password", ""],
      ["enabled", "on"],
    ]),
    querySelector: () => passwordInput,
  };
  const { ctx, calls } = context();
  ctx.dialog.querySelector = () => form;
  await handleUsersAction(button("user-save"), ctx);
  assert.deepEqual(JSON.parse(calls.api[0].options.body), {
    username: "viewer",
    role: "read",
    enabled: true,
  });
  form.dataset.id = "";
  form.fields.set("password", "valid-new-password");
  passwordInput.value = "valid-new-password";
  await handleUsersAction(button("user-save"), ctx);
  assert.equal(calls.api[1].options.method, "POST");
  assert.equal(
    JSON.parse(calls.api[1].options.body).password,
    "valid-new-password",
  );
  assert.equal(passwordInput.value, "");
  assert.ok(!JSON.stringify(calls.toasts).includes("valid-new-password"));
});

test("forged save cannot demote or disable the final full account", async (t) => {
  t.mock.method(globalThis, "FormData", function (form) {
    return form.fields;
  });
  const form = {
    dataset: { id: admin.id },
    reportValidity: () => true,
    fields: new Map([
      ["username", "admin"],
      ["role", "read"],
      ["password", ""],
    ]),
  };
  const { ctx, calls } = context();
  ctx.dialog.querySelector = () => form;
  await assert.rejects(
    handleUsersAction(button("user-save"), ctx),
    /хотя бы один включённый/,
  );
  assert.equal(calls.api.length, 0);
});

test("API failures reach the shared error handler without clearing the form or refreshing", async () => {
  const { ctx, calls } = context({
    api: async () => {
      throw new Error("Conflict");
    },
  });
  await assert.rejects(
    handleUsersAction(button("user-toggle", reader.id), ctx),
    /Conflict/,
  );
  assert.equal(calls.closed, 0);
  assert.equal(calls.refreshed, 0);
  assert.equal(await handleUsersAction(button("unrelated"), ctx), false);
});
