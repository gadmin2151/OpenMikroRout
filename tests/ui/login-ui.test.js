import test from "node:test";
import assert from "node:assert/strict";
import {
  loginMarkup,
  bindLoginControls,
  setLoginBusy,
} from "../../app/static/login-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );

test("login keeps the credential contract and escapes untrusted names and errors", () => {
  const html = loginMarkup({
    brand: "<div>OpenMikroRout</div>",
    icon: () => "",
    e,
    username: '"><img src=x onerror=bad>',
    error: "<script>bad()</script>",
  });
  assert.ok(!html.includes("<script>") && !html.includes("<img src=x"));
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /value="&quot;&gt;&lt;img/);
  assert.match(html, /id="login-form" aria-busy="false"/);
  assert.match(
    html,
    /type="password" name="password" autocomplete="current-password"/,
  );
  assert.match(html, /name="username" autocomplete="username"/);
  const code = html.match(/<input[^>]+name="code"[^>]*>/)[0];
  assert.match(code, /autocomplete="one-time-code"/);
  assert.ok(!code.includes("required"));
  assert.match(html, /class="login-password-toggle" type="button"/);
  assert.match(html, /role="alert"/);
  assert.match(
    loginMarkup({
      brand: "",
      icon: () => "",
      e,
      username: "admin",
      error: "Incorrect username or password",
    }),
    /Неверное имя пользователя или пароль\./,
  );
});

function fixture() {
  let click, focused;
  const password = {
    type: "password",
    value: "test-only-password",
    focus: () => (focused = "password"),
  };
  const username = { focus: () => (focused = "username") };
  const toggle = {
    disabled: false,
    attributes: {},
    addEventListener: (_, listener) => (click = listener),
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
  };
  const submit = { disabled: false },
    label = { textContent: "Войти" };
  const form = {
    attributes: {},
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    querySelector: (selector) =>
      ({
        '[name="password"]': password,
        '[name="username"]': username,
        ".login-password-toggle": toggle,
        '[type="submit"]': submit,
        "[data-login-submit-label]": label,
      })[selector],
  };
  return {
    form,
    password,
    toggle,
    submit,
    label,
    click: () => click(),
    focused: () => focused,
  };
}

test("show password preserves the credential and announces its state without submitting", () => {
  const view = fixture();
  bindLoginControls(view.form);
  assert.equal(view.focused(), "username");
  view.click();
  assert.equal(view.password.type, "text");
  assert.equal(view.toggle.attributes["aria-pressed"], "true");
  assert.equal(view.toggle.attributes["aria-label"], "Скрыть пароль");
  assert.equal(view.password.value, "test-only-password");
  view.click();
  assert.equal(view.password.type, "password");
  assert.equal(view.toggle.attributes["aria-pressed"], "false");
  bindLoginControls(view.form, true);
  assert.equal(view.focused(), "password");
});

test("pending login prevents another submit while preserving credentials", () => {
  const view = fixture();
  setLoginBusy(view.form, true);
  assert.equal(view.submit.disabled, true);
  assert.equal(view.form.attributes["aria-busy"], "true");
  assert.equal(view.label.textContent, "Входим…");
  assert.equal(view.password.value, "test-only-password");
  setLoginBusy(view.form, false);
  assert.equal(view.submit.disabled, false);
  assert.equal(view.toggle.disabled, false);
  assert.equal(view.label.textContent, "Войти");
});
