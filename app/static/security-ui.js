import { html, t } from "./i18n.js";
/** Self-service authenticator settings are available to both read and full accounts. */
const actions = new Set([
  "preferences-save",
  "security-enroll",
  "security-setup",
  "security-confirm",
  "security-disable-open",
  "security-disable",
  "security-download",
  "user-totp-reset",
  "user-totp-reset-confirm",
]);

export function renderSecurity(ctx) {
  if (!ctx.currentUser)
    return html`<div class="empty">Войдите в учётную запись для настройки 2FA.</div>`;
  const enabled = ctx.securityStatus?.enabled ?? ctx.currentUser.totp_enabled;
  return html`<div class="feature-page"><div class="feature-heading"><div><h2>Мой профиль</h2><p>${ctx.e(ctx.currentUser.username)} · ${ctx.e(ctx.currentUser.role)}</p></div><span class="user-status ${enabled ? "active" : "disabled"}">2FA ${enabled ? t("включена") : t("выключена")}</span></div><form id="preferences-form" class="security-card"><div><h3>Язык интерфейса</h3><p>Сохраняется в вашем профиле и действует на всех устройствах после входа.</p></div><label class="field"><span>Язык</span><select name="language" aria-label="Язык интерфейса"><option value="ru" ${ctx.currentUser.language !== "en" ? "selected" : ""}>Русский · RU</option><option value="en" ${ctx.currentUser.language === "en" ? "selected" : ""}>English · EN</option></select></label><button type="submit" class="primary" data-action="preferences-save" ${ctx.offline || ctx.busy ? "disabled" : ""}>Сохранить</button></form><div class="security-card"><div>${ctx.icon("lock")}<h3>Приложение-аутентификатор</h3><p>Одноразовые коды TOTP: Google Authenticator, Microsoft Authenticator, Aegis и другие совместимые приложения. По умолчанию 2FA выключена.</p>${enabled ? html`<p>Резервных кодов осталось: <b>${ctx.e(ctx.securityStatus?.recovery_codes_remaining ?? "—")}</b>.</p>` : ""}</div><button class="${enabled ? "danger" : "primary"}" data-action="${enabled ? "security-disable-open" : "security-enroll"}" ${ctx.offline || ctx.busy ? "disabled" : ""}>${enabled ? t("Отключить 2FA") : t("Включить 2FA")}</button></div><p class="feature-note">Настройка относится только к вашей учётной записи и не меняет сетевую конфигурацию. После включения сохраните резервные коды в безопасном месте.</p></div>`;
}

export function proofForm(ctx, id, text) {
  return html`<form id="${id}" class="winbox-form"><p>${ctx.e(text)}</p><label class="field"><span>Текущий пароль</span><input name="password" type="password" autocomplete="current-password" maxlength="512" required></label><label class="field"><span>Код 2FA или резервный код</span><input name="code" autocomplete="one-time-code" maxlength="64" ${ctx.currentUser?.totp_enabled ? "required" : ""}><small>${ctx.currentUser?.totp_enabled ? t("Используйте новый код, который ещё не применялся.") : t("Оставьте пустым, если 2FA выключена.")}</small></label></form>`;
}

export function proof(ctx, id) {
  const form = ctx.dialog.querySelector(`#${id}`);
  if (!form || !form.reportValidity()) return null;
  const values = new FormData(form);
  return {
    password: String(values.get("password") || ""),
    code: String(values.get("code") || "").trim(),
  };
}

export function clearProof(ctx) {
  for (const input of ctx.dialog.querySelectorAll(
    'input[name="password"],input[name="code"]',
  ))
    input.value = "";
}

export async function handleSecurityAction(button, ctx) {
  const action = button.dataset.action;
  if (!actions.has(action)) return false;
  if (!ctx.currentUser) throw new Error(t("Войдите в учётную запись."));
  await ctx.run(async () => {
    if (action === "preferences-save") {
      const form = document.querySelector("#preferences-form");
      if (!form?.reportValidity()) return;
      const language = new FormData(form).get("language");
      const generation = ctx.generation;
      const result = await ctx.api("me/preferences", {
        method: "PUT",
        body: JSON.stringify({ language }),
      });
      if (generation !== ctx.getGeneration()) return;
      ctx.currentUser.language = result.language;
      ctx.setLanguage(result.language);
      ctx.render();
      ctx.toast(t("Язык сохранён"));
      return;
    }
    if (action === "security-enroll") {
      ctx.dialogFrame(
        t("Включить 2FA"),
        t("Сначала добавьте ключ в приложение, затем подтвердите кодом."),
        html`<form id="security-setup-form" class="winbox-form"><label class="field"><span>Текущий пароль</span><input name="password" type="password" autocomplete="current-password" maxlength="512" required></label><div id="security-enrollment"></div></form>`,
        html`<button data-action="close">Отмена</button><button class="primary" data-action="security-setup">Показать QR-код</button>`,
      );
      return;
    }
    if (action === "security-setup") {
      const body = proof(ctx, "security-setup-form");
      if (!body) return;
      const setup = await ctx.api("me/totp/setup", {
        method: "POST",
        body: JSON.stringify(body),
      });
      ctx.dialog.querySelector("#security-enrollment").innerHTML =
        html`<div class="totp-enrollment"><img class="totp-qr" src="${ctx.e(setup.qr_data_url)}" alt="QR-код для приложения-аутентификатора"><label class="field"><span>Ключ для ручного добавления</span><input class="mono" value="${ctx.e(setup.secret)}" readonly></label><label class="field"><span>Код из приложения</span><input name="code" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><small>Ключ действует 10 минут. 2FA включится только после подтверждения.</small></div>`;
      button.dataset.action = "security-confirm";
      button.textContent = t("Подтвердить и включить");
      ctx.dialog.querySelector('[name="code"]').focus();
      return;
    }
    if (action === "security-confirm") {
      const body = proof(ctx, "security-setup-form");
      if (!body) return;
      const result = await ctx.api("me/totp/confirm", {
        method: "POST",
        body: JSON.stringify(body),
      });
      clearProof(ctx);
      ctx.dialogFrame(
        t("2FA включена"),
        t(
          "Сохраните резервные коды. Каждый код можно использовать один раз вместо кода из приложения.",
        ),
        html`<div class="recovery-codes"><pre id="security-recovery-codes" tabindex="0">${result.recovery_codes.map(ctx.e).join("\n")}</pre><p>Эти коды показаны один раз. Старые сессии учётной записи завершены.</p></div>`,
        html`<button data-action="security-download">Скачать коды</button><button class="primary" data-action="close">Коды сохранены</button>`,
      );
      await ctx.refreshSecurity();
      await ctx.refreshCurrentUser();
      return;
    }
    if (action === "security-download") {
      const text = ctx.dialog.querySelector(
        "#security-recovery-codes",
      )?.textContent;
      if (!text) throw new Error(t("Резервные коды уже закрыты."));
      const link = document.createElement("a");
      const url = URL.createObjectURL(
        new Blob([text + "\n"], { type: "text/plain;charset=utf-8" }),
      );
      link.href = url;
      link.download = "OpenMikroRout-recovery-codes.txt";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      return;
    }
    if (action === "security-disable-open") {
      ctx.dialogFrame(
        t("Отключить 2FA"),
        t("Подтвердите пароль и текущий одноразовый или резервный код."),
        proofForm(
          ctx,
          "security-disable-form",
          t("Приложение-аутентификатор перестанет требоваться для входа."),
        ),
        html`<button data-action="close">Отмена</button><button class="danger" data-action="security-disable">Отключить 2FA</button>`,
      );
      return;
    }
    if (action === "security-disable") {
      const body = proof(ctx, "security-disable-form");
      if (!body) return;
      await ctx.api("me/totp/disable", {
        method: "POST",
        body: JSON.stringify(body),
      });
      clearProof(ctx);
      ctx.dialog.close();
      await ctx.refreshSecurity();
      await ctx.refreshCurrentUser();
      ctx.toast(t("2FA отключена для вашей учётной записи"));
      return;
    }
    if (!ctx.canWrite()) throw new Error(t("Нужна группа full."));
    const user = ctx.users.find((item) => item.id === button.dataset.id);
    if (!user || user.id === ctx.currentUser.id)
      throw new Error(t("Для своей учётной записи используйте Security."));
    if (action === "user-totp-reset") {
      ctx.dialogFrame(
        t("Сбросить 2FA пользователя"),
        t("Подтвердите свои учётные данные администратора."),
        proofForm(
          ctx,
          "security-reset-form",
          html`Отключить аутентификатор пользователя ${user.username}? Его сессии будут завершены.`,
        ),
        html`<button data-action="close">Отмена</button><button class="danger" data-action="user-totp-reset-confirm" data-id="${ctx.e(user.id)}">Сбросить 2FA</button>`,
      );
    } else {
      const body = proof(ctx, "security-reset-form");
      if (!body) return;
      await ctx.api(`users/${encodeURIComponent(user.id)}/totp/reset`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      clearProof(ctx);
      ctx.dialog.close();
      await ctx.refreshUsers();
      ctx.render();
      ctx.toast(t("2FA пользователя сброшена"));
    }
  });
  return true;
}
