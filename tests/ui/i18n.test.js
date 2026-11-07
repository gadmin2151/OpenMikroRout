import test from "node:test";
import assert from "node:assert/strict";
import {
  getLanguage,
  html,
  locale,
  setLanguage,
  t,
} from "../../app/static/i18n.js";
import { messages } from "../../app/static/messages.js";

test.afterEach(() => setLanguage("ru"));

test("profile language selects Russian or English and a matching number/date locale", () => {
  setLanguage("ru");
  assert.equal(getLanguage(), "ru");
  assert.equal(locale(), "ru-RU");
  assert.equal(setLanguage("ru"), false);
  assert.equal(setLanguage("en"), true);
  assert.equal(getLanguage(), "en");
  assert.equal(locale(), "en-US");
  assert.equal(t("Address"), "Address");
  assert.equal(setLanguage("en"), false);
  assert.equal(setLanguage("unsupported"), true);
  assert.equal(getLanguage(), "ru");
  assert.equal(locale(), "ru-RU");
  assert.equal(t("Address"), "Адрес");
});

test("templates translate developer text and accessible attributes in both languages", () => {
  const render = () =>
    html`<button title="Address" aria-label="Interface">Сохранить</button><input placeholder="Имя пользователя"><img alt="QR-код для приложения-аутентификатора">`;
  setLanguage("en");
  const english = render();
  assert.match(
    english,
    /title="Address" aria-label="Interface">Save<\/button>/,
  );
  assert.match(english, /placeholder="Username"/);
  assert.match(english, /alt="Authenticator app QR code"/);
  setLanguage("ru");
  const russian = render();
  assert.match(
    russian,
    /title="Адрес" aria-label="Интерфейс">Сохранить<\/button>/,
  );
  assert.match(russian, /placeholder="Имя пользователя"/);
});

test("configuration and user values are opaque even when they match a catalog entry", () => {
  setLanguage("en");
  const username = "Сохранить";
  const interfaceName = "Имя пользователя";
  const escapedComment =
    "&lt;img src=x onerror=&#39;bad()&#39;&gt; Address {0}";
  const result = html`<h2>${username}</h2><p title="${interfaceName}">${escapedComment}</p><span>Интерфейс ${interfaceName}</span>`;
  assert.match(result, /<h2>Сохранить<\/h2>/);
  assert.match(result, /title="Имя пользователя"/);
  assert.match(
    result,
    /&lt;img src=x onerror=&#39;bad\(\)&#39;&gt; Address \{0\}/,
  );
  assert.match(result, /<span>Interface Имя пользователя<\/span>/);
  assert.doesNotMatch(result, /<img/);
  setLanguage("ru");
  assert.equal(html`<span>${"Address"}</span>`, "<span>Address</span>");
});

test("translation leaves form values, identifiers, URLs and CSS classes unchanged", () => {
  setLanguage("ru");
  const result = html`<a href="/Action?Name=Address" id="Address" class="Interface" data-action="Apply">Address</a><input name="Name" value="Apply"><option value="enabled">Enabled</option>`;
  assert.match(
    result,
    /href="\/Action\?Name=Address" id="Address" class="Interface" data-action="Apply">Адрес<\/a>/,
  );
  assert.match(result, /<input name="Name" value="Apply">/);
  assert.match(result, /<option value="enabled">Включено<\/option>/);
});

test("cached templates follow language changes and always insert the latest values", () => {
  const render = (value) => html`<label>Интерфейс ${value}</label>`;
  setLanguage("ru");
  assert.equal(render("eth0"), "<label>Интерфейс eth0</label>");
  setLanguage("en");
  assert.equal(render("eth1"), "<label>Interface eth1</label>");
  assert.equal(render("vmbr0"), "<label>Interface vmbr0</label>");
  setLanguage("ru");
  assert.equal(render("wg0"), "<label>Интерфейс wg0</label>");
});

test("HTML formatting whitespace does not prevent translation and edge substitutions stay opaque", () => {
  setLanguage("en");
  assert.equal(html`<p>  Сохранить  </p>`, "<p>  Save  </p>");
  assert.match(
    html`<p>Наблюдаемые соседи IPv4 и действующие аренды DHCP.\n  Устройства без обмена с роутером могут ещё не отображаться.</p>`,
    /Observed IPv4 neighbors/,
  );
  assert.equal(html`<span>${4} из ${8}</span>`, "<span>4 of 8</span>");
  assert.equal(
    html`<span>${"\uE0000\uE001Сохранить"}</span>`,
    "<span>\uE0000\uE001Сохранить</span>",
  );
});

test("named substitutions and nested templates never recursively translate dynamic values", () => {
  setLanguage("en");
  assert.equal(
    t("Изменить порт {0}", { 0: "Сохранить {1}" }),
    "Edit port Сохранить {1}",
  );
  const inner = html`<strong>Сохранить</strong>`;
  assert.equal(
    html`<section>${inner}<span>${"Сохранить"}</span></section>`,
    "<section><strong>Save</strong><span>Сохранить</span></section>",
  );
  assert.equal(
    t("no catalog entry {value}", { value: "Address" }),
    "no catalog entry Address",
  );
});

test("catalog pairs are complete and preserve all interpolation placeholders", () => {
  assert.ok(Object.keys(messages).length > 1000);
  const placeholders = (value) =>
    [...value.matchAll(/\{\w+\}/g)].map(([token]) => token).sort();
  for (const [source, pair] of Object.entries(messages)) {
    assert.equal(pair.length, 2, source);
    for (const value of pair) {
      assert.equal(typeof value, "string", source);
      assert.notEqual(value.trim(), "", source);
      assert.deepEqual(placeholders(value), placeholders(source), source);
    }
  }
});
