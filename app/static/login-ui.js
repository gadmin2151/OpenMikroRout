import { t, html, getLanguage } from "./i18n.js";
/** Login presentation shares the application brand and keeps credential handling in app.js. */
const loginErrors = new Map([
  ["Incorrect username or password", "Неверное имя пользователя или пароль."],
  ["Incorrect password or authenticator code", "Неверный пароль или код 2FA."],
  [
    "Too many attempts. Try again in a minute.",
    "Слишком много попыток. Повторите вход через минуту.",
  ],
  [
    "Authentication is busy. Try again shortly.",
    "Сервис входа занят. Попробуйте немного позже.",
  ],
]);

export function loginMarkup({ brand, icon, e, username, error = "" }) {
  return html`<main class="login">
    <section class="login-identity" aria-label="OpenMikroRout">
      ${brand}
      <svg class="login-network-art" viewBox="0 0 480 340" aria-hidden="true">
        <rect x="163" y="102" width="154" height="138" rx="30"/>
        <path d="M240 102V54h106M317 171h82M163 171H79M240 240v49H132"/>
        <rect x="346" y="33" width="48" height="42" rx="12"/>
        <rect x="399" y="150" width="48" height="42" rx="12"/>
        <rect x="31" y="150" width="48" height="42" rx="12"/>
        <rect x="84" y="268" width="48" height="42" rx="12"/>
        <path class="login-router-arrows" d="M206 157h68m-10-10 10 10-10 10M274 187h-68m10-10-10 10 10 10"/>
        <circle cx="240" cy="78" r="4"/><circle cx="354" cy="171" r="4"/>
        <circle cx="117" cy="171" r="4"/><circle cx="188" cy="289" r="4"/>
      </svg>
      <div class="login-intro">
        <p class="login-eyebrow">ВАША СЕТЬ ПОД КОНТРОЛЕМ</p>
        <p class="login-headline">Ваша сеть.<br><span>Ваши правила.</span></p>
        <p class="login-description">Маршрутизация, VPN и защита сети<br>в одном рабочем пространстве.</p>
      </div>
      <div class="login-identity-footer"><span>WireGuard VPN</span><span>Firewall &amp; NAT</span><span>Мониторинг</span></div>
    </section>
    <section class="login-workspace" aria-labelledby="login-title">
      <div class="login-card">
        <div class="login-heading">
          <label class="login-language"><span>Язык интерфейса</span><select id="login-language" aria-label="Язык интерфейса"><option value="ru" ${getLanguage() === "ru" ? "selected" : ""}>RU</option><option value="en" ${getLanguage() === "en" ? "selected" : ""}>EN</option></select></label>
          <span class="login-access-label">${icon("lock")}ПАНЕЛЬ УПРАВЛЕНИЯ</span>
          <h1 id="login-title">Вход в панель</h1>
          <p>Войдите в рабочее пространство вашего роутера.</p>
        </div>
        <form id="login-form" aria-busy="false">
          <label class="field login-username-field" for="login-username"><span>Имя пользователя</span>
            <input id="login-username" type="text" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" value="${e(username)}" required>
          </label>
          <label class="field login-password-label" for="login-password"><span>Пароль</span></label>
          <div class="login-password-field">
            <input id="login-password" type="password" name="password" autocomplete="current-password" maxlength="512" required>
            <button class="login-password-toggle" type="button" aria-label="Показать пароль" aria-controls="login-password" aria-pressed="false">${eyeMarkup()}</button>
          </div>
          <label class="field login-code-field" for="login-code"><span>Код 2FA <span class="login-optional">Если включена</span></span>
            <input id="login-code" name="code" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" maxlength="64" placeholder="Код из приложения или резервный код" aria-describedby="login-code-note">
          </label>
          <p class="login-field-note" id="login-code-note">Оставьте пустым, если двухфакторная аутентификация выключена.</p>
          <button class="primary login-submit" type="submit"><span data-login-submit-label>Войти</span><span class="login-submit-arrow">${icon("arrow")}</span><span class="login-spinner" aria-hidden="true"></span></button>
          <div class="login-feedback"><div class="login-alert" role="alert" ${error ? "" : "hidden"}>${icon("info")}<p>${e(t(loginErrors.get(error) || error))}</p></div></div>
        </form>
        <p class="login-access-note">${icon("shield")}Используйте учётную запись, выданную администратором.</p>
      </div>
      <footer class="login-workspace-footer">OpenMikroRout <span>·</span> Open Network Router</footer>
    </section>
  </main>`;
}

function eyeMarkup(visible = false) {
  return html`<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>${visible ? html`<path d="m3 3 18 18"/>` : ""}</svg>`;
}

export function bindLoginControls(form, hasError = false) {
  const password = form.querySelector('[name="password"]');
  const toggle = form.querySelector(".login-password-toggle");
  toggle.addEventListener("click", () => {
    const visible = password.type === "password";
    password.type = visible ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(visible));
    toggle.setAttribute(
      "aria-label",
      visible ? t("Скрыть пароль") : t("Показать пароль"),
    );
    toggle.innerHTML = eyeMarkup(visible);
  });
  form
    .querySelector(hasError ? '[name="password"]' : '[name="username"]')
    .focus({
      preventScroll: true,
    });
}

export function setLoginBusy(form, busy) {
  form.setAttribute("aria-busy", String(busy));
  form.querySelector('[type="submit"]').disabled = busy;
  form.querySelector("[data-login-submit-label]").textContent = busy
    ? t("Входим…")
    : t("Войти");
  form.querySelector(".login-password-toggle").disabled = busy;
}
