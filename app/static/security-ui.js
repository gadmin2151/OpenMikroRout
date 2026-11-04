/** Self-service authenticator settings are available to both read and full accounts. */
const actions = new Set([
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
    return '<div class="empty">Войдите в учётную запись для настройки 2FA.</div>';
  const enabled = ctx.securityStatus?.enabled ?? ctx.currentUser.totp_enabled;
  return `<div class="feature-page"><div class="feature-heading"><div><h2>Безопасность учётной записи</h2><p>${ctx.e(ctx.currentUser.username)} · ${ctx.e(ctx.currentUser.role)}</p></div><span class="user-status ${enabled ? "active" : "disabled"}">2FA ${enabled ? "включена" : "выключена"}</span></div><div class="security-card"><div>${ctx.icon("lock")}<h3>Приложение-аутентификатор</h3><p>Одноразовые коды TOTP: Google Authenticator, Microsoft Authenticator, Aegis и другие совместимые приложения. По умолчанию 2FA выключена.</p>${enabled ? `<p>Резервных кодов осталось: <b>${ctx.e(ctx.securityStatus?.recovery_codes_remaining ?? "—")}</b>.</p>` : ""}</div><button class="${enabled ? "danger" : "primary"}" data-action="${enabled ? "security-disable-open" : "security-enroll"}" ${ctx.offline || ctx.busy ? "disabled" : ""}>${enabled ? "Отключить 2FA" : "Включить 2FA"}</button></div><p class="feature-note">Настройка относится только к вашей учётной записи и не меняет сетевую конфигурацию. После включения сохраните резервные коды в безопасном месте.</p></div>`;
}

export function proofForm(ctx, id, text) {
  return `<form id="${id}" class="winbox-form"><p>${ctx.e(text)}</p><label class="field"><span>Текущий пароль</span><input name="password" type="password" autocomplete="current-password" maxlength="512" required></label><label class="field"><span>Код 2FA или резервный код</span><input name="code" autocomplete="one-time-code" maxlength="64" ${ctx.currentUser?.totp_enabled ? "required" : ""}><small>${ctx.currentUser?.totp_enabled ? "Используйте новый код, который ещё не применялся." : "Оставьте пустым, если 2FA выключена."}</small></label></form>`;
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
  if (!ctx.currentUser) throw new Error("Войдите в учётную запись.");
  await ctx.run(async () => {
    if (action === "security-enroll") {
      ctx.dialogFrame(
        "Включить 2FA",
        "Сначала добавьте ключ в приложение, затем подтвердите кодом.",
        `<form id="security-setup-form" class="winbox-form"><label class="field"><span>Текущий пароль</span><input name="password" type="password" autocomplete="current-password" maxlength="512" required></label><div id="security-enrollment"></div></form>`,
        '<button data-action="close">Отмена</button><button class="primary" data-action="security-setup">Показать QR-код</button>',
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
        `<div class="totp-enrollment"><img class="totp-qr" src="${ctx.e(setup.qr_data_url)}" alt="QR-код для приложения-аутентификатора"><label class="field"><span>Ключ для ручного добавления</span><input class="mono" value="${ctx.e(setup.secret)}" readonly></label><label class="field"><span>Код из приложения</span><input name="code" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required></label><small>Ключ действует 10 минут. 2FA включится только после подтверждения.</small></div>`;
      button.dataset.action = "security-confirm";
      button.textContent = "Подтвердить и включить";
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
        "2FA включена",
        "Сохраните резервные коды. Каждый код можно использовать один раз вместо кода из приложения.",
        `<div class="recovery-codes"><pre id="security-recovery-codes" tabindex="0">${result.recovery_codes.map(ctx.e).join("\n")}</pre><p>Эти коды показаны один раз. Старые сессии учётной записи завершены.</p></div>`,
        '<button data-action="security-download">Скачать коды</button><button class="primary" data-action="close">Коды сохранены</button>',
      );
      await ctx.refreshSecurity();
      await ctx.refreshCurrentUser();
      return;
    }
    if (action === "security-download") {
      const text = ctx.dialog.querySelector(
        "#security-recovery-codes",
      )?.textContent;
      if (!text) throw new Error("Резервные коды уже закрыты.");
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
        "Отключить 2FA",
        "Подтвердите пароль и текущий одноразовый или резервный код.",
        proofForm(
          ctx,
          "security-disable-form",
          "Приложение-аутентификатор перестанет требоваться для входа.",
        ),
        '<button data-action="close">Отмена</button><button class="danger" data-action="security-disable">Отключить 2FA</button>',
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
      ctx.toast("2FA отключена для вашей учётной записи");
      return;
    }
    if (!ctx.canWrite()) throw new Error("Нужна группа full.");
    const user = ctx.users.find((item) => item.id === button.dataset.id);
    if (!user || user.id === ctx.currentUser.id)
      throw new Error("Для своей учётной записи используйте Security.");
    if (action === "user-totp-reset") {
      ctx.dialogFrame(
        "Сбросить 2FA пользователя",
        "Подтвердите свои учётные данные администратора.",
        proofForm(
          ctx,
          "security-reset-form",
          `Отключить аутентификатор пользователя ${user.username}? Его сессии будут завершены.`,
        ),
        `<button data-action="close">Отмена</button><button class="danger" data-action="user-totp-reset-confirm" data-id="${ctx.e(user.id)}">Сбросить 2FA</button>`,
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
      ctx.toast("2FA пользователя сброшена");
    }
  });
  return true;
}
