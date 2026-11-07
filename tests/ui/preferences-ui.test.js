import test from "node:test";
import assert from "node:assert/strict";
import {
  renderSecurity,
  handleSecurityAction,
} from "../../app/static/security-ui.js";
import { applyReadAccess, isReadAction } from "../../app/static/access-ui.js";
import { getLanguage, setLanguage } from "../../app/static/i18n.js";

test.afterEach(() => setLanguage("ru"));

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );

function context() {
  const calls = [];
  const ctx = {
    e: escape,
    icon: () => "",
    currentUser: { id: "reader", username: "<reader>", role: "read" },
    state: { auth_enabled: true, current_user: { role: "read" } },
    canWrite: () => false,
    generation: 1,
    getGeneration: () => 1,
    run: (task) => task(),
    api: async (path, options) => {
      calls.push([path, options]);
      return { language: "en" };
    },
    setLanguage: (value) => {
      calls.push(["setLanguage", value]);
      setLanguage(value);
    },
    render: () => calls.push(["render"]),
    toast: (message) => calls.push(["toast", message]),
  };
  return { ctx, calls };
}

async function withForm(value, task, { valid = true } = {}) {
  const originalDocument = globalThis.document;
  const OriginalFormData = globalThis.FormData;
  const form = { reportValidity: () => valid };
  globalThis.document = {
    documentElement: {},
    querySelector: (selector) => {
      assert.equal(selector, "#preferences-form");
      return form;
    },
  };
  globalThis.FormData = class {
    constructor(selected) {
      assert.equal(selected, form);
    }
    get(name) {
      assert.equal(name, "language");
      return value;
    }
  };
  try {
    return await task();
  } finally {
    globalThis.document = originalDocument;
    globalThis.FormData = OriginalFormData;
  }
}

const save = { dataset: { action: "preferences-save" } };

test("profile language defaults to RU and restores an EN account selection", () => {
  const { ctx } = context();
  setLanguage("ru");
  const russian = renderSecurity(ctx);
  assert.match(russian, /name="language"/);
  assert.match(russian, /value="ru" selected/);
  assert.match(russian, /value="en" >English · EN/);
  assert.match(russian, /&lt;reader&gt;/);
  assert.doesNotMatch(russian, /<reader>/);
  setLanguage("en");
  const english = renderSecurity({
    ...ctx,
    currentUser: { ...ctx.currentUser, language: "en" },
  });
  assert.match(english, /<h3>Interface language<\/h3>/);
  assert.match(english, /value="ru" >Русский · RU/);
  assert.match(english, /value="en" selected/);
});

test("read access preserves the preference save control while denying router writes", () => {
  const { ctx } = context();
  const preference = {
    dataset: { action: "preferences-save" },
    disabled: false,
  };
  const write = { dataset: { action: "apply" }, disabled: false };
  const scope = {
    querySelectorAll: (selector) =>
      selector === "button[data-action]" ? [preference, write] : [],
    querySelector: () => null,
  };
  assert.equal(isReadAction("preferences-save"), true);
  applyReadAccess(scope, ctx.state);
  assert.equal(preference.disabled, false);
  assert.equal(write.disabled, true);
});

test("read user saves only its own language without full-access proof", async () => {
  const { ctx, calls } = context();
  await withForm("en", async () => {
    assert.equal(await handleSecurityAction(save, ctx), true);
  });
  assert.equal(calls[0][0], "me/preferences");
  assert.equal(calls[0][1].method, "PUT");
  assert.deepEqual(JSON.parse(calls[0][1].body), { language: "en" });
  assert.deepEqual(calls.slice(1), [
    ["setLanguage", "en"],
    ["render"],
    ["toast", "Language saved"],
  ]);
  assert.equal(ctx.currentUser.language, "en");
  assert.equal(getLanguage(), "en");
});

test("language changes are applied only after the server confirms the save", async () => {
  const { ctx, calls } = context();
  let resolve;
  ctx.api = () =>
    new Promise((done) => {
      resolve = done;
    });
  await withForm("en", async () => {
    const pending = handleSecurityAction(save, ctx);
    assert.equal(getLanguage(), "ru");
    assert.equal(ctx.currentUser.language, undefined);
    assert.deepEqual(calls, []);
    resolve({ language: "en" });
    await pending;
  });
  assert.equal(getLanguage(), "en");
  assert.equal(ctx.currentUser.language, "en");
});

test("a response from a previous login cannot change the new user's language", async () => {
  const { ctx, calls } = context();
  let resolve;
  let generation = 1;
  ctx.api = () =>
    new Promise((done) => {
      resolve = done;
    });
  ctx.getGeneration = () => generation;
  await withForm("en", async () => {
    const pending = handleSecurityAction(save, ctx);
    generation = 2;
    ctx.currentUser = {
      id: "new-reader",
      username: "new-user",
      role: "read",
      language: "ru",
    };
    resolve({ language: "en" });
    await pending;
  });
  assert.equal(ctx.currentUser.language, "ru");
  assert.equal(getLanguage(), "ru");
  assert.deepEqual(calls, []);
});

test("failed saves leave the language and profile unchanged without a success message", async () => {
  const { ctx, calls } = context();
  ctx.currentUser.language = "ru";
  ctx.api = async () => {
    throw new Error("backend unavailable");
  };
  await withForm("en", async () => {
    await assert.rejects(
      handleSecurityAction(save, ctx),
      /backend unavailable/,
    );
  });
  assert.equal(ctx.currentUser.language, "ru");
  assert.equal(getLanguage(), "ru");
  assert.deepEqual(calls, []);
});

test("invalid forms and signed-out users do not send preference mutations", async () => {
  const { ctx, calls } = context();
  await withForm(
    "en",
    async () => {
      assert.equal(await handleSecurityAction(save, ctx), true);
    },
    { valid: false },
  );
  assert.deepEqual(calls, []);
  ctx.currentUser = null;
  await assert.rejects(handleSecurityAction(save, ctx), /Войдите/);
  assert.deepEqual(calls, []);
});
