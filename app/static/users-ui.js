import { html, t, locale } from "./i18n.js";
import { proofForm, proof, clearProof } from "./security-ui.js?v=1";

/** Account management uses the authenticated users API, independently of router drafts. */
const actions = new Set([
  "user-new",
  "user-edit",
  "user-save",
  "user-remove",
  "user-delete-confirm",
  "user-toggle",
  "user-toggle-confirm",
]);
const usernamePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function users(ctx) {
  return Array.isArray(ctx.users) ? ctx.users : [];
}
function authEnabled(ctx) {
  return ctx.state?.auth_enabled === true;
}
function mayManage(ctx) {
  return authEnabled(ctx) && ctx.canWrite();
}
function lastFull(user, rows) {
  return (
    user?.role === "full" &&
    user.enabled === true &&
    rows.filter((row) => row.role === "full" && row.enabled === true).length <=
      1
  );
}
function roleName(role) {
  return role === "full"
    ? t("full · полный доступ")
    : role === "read"
      ? t("read · просмотр")
      : t("Неизвестная группа");
}
function createdAt(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0)
    return "—";
  const date = new Date(value * 1000);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(locale());
}
function managedUser(ctx, id) {
  const found = users(ctx).find((user) => user.id === id);
  if (!found) throw new Error(t("Пользователь не найден. Обновите список."));
  return found;
}
function roleHelp() {
  return html`<div class="users-role-help"><div><strong>read</strong><span>Просмотр настроек, состояния сети и статистики.</span></div><div><strong>full</strong><span>Полное управление роутером и учётными записями.</span></div></div>`;
}

export function renderUsers(ctx) {
  const e = ctx.e;
  if (!authEnabled(ctx))
    return html`<div class="users-access-note">Включите авторизацию, чтобы создавать пользователей и назначать группы доступа.</div>${roleHelp()}`;
  if (!ctx.canWrite())
    return html`<div class="users-access-note">Управление пользователями доступно группе full. Ваша группа: ${e(ctx.currentUser?.role || "read")}.</div>`;
  const rows = users(ctx);
  const locked = ctx.busy || ctx.offline;
  return html`<div class="toolbar"><button class="primary add" data-action="user-new" ${locked ? "disabled" : ""}>${ctx.icon("plus")}Добавить пользователя</button><span class="muted">${rows.length} учётных записей</span></div>${roleHelp()}${ctx.usersError ? html`<div class="users-access-note" role="alert">Не удалось обновить пользователей: ${e(ctx.usersError)}</div>` : ""}<div class="table-scroll"><table class="rules-table users-table"><thead><tr><th>Имя пользователя</th><th>Группа</th><th>Статус</th><th>Создан</th><th>Действия</th></tr></thead><tbody>${
    rows
      .map((user) => {
        const finalAdmin = lastFull(user, rows);
        const escapedId = e(user.id);
        const name = e(user.username);
        const roleClass = ["read", "full"].includes(user.role) ? user.role : "";
        const enabled = user.enabled === true;
        return html`<tr><td><strong class="mono">${name}</strong><small class="users-current">2FA ${user.totp_enabled ? t("включена") : t("выключена")}</small>${user.id === ctx.currentUser?.id ? html`<small class="users-current">Текущая учётная запись</small>` : ""}</td><td><span class="user-role ${roleClass}">${e(roleName(user.role))}</span></td><td><span class="user-status ${enabled ? "active" : "disabled"}">${enabled ? t("Включён") : t("Отключён")}</span></td><td>${e(createdAt(user.created_at))}</td><td><div class="row-actions"><button class="icon ghost" data-action="user-edit" data-id="${escapedId}" aria-label="Редактировать ${name}" title="Редактировать" ${locked ? "disabled" : ""}>${ctx.icon("edit")}</button>${user.totp_enabled && user.id !== ctx.currentUser?.id ? html`<button class="icon ghost" data-action="user-totp-reset" data-id="${escapedId}" title="Сбросить 2FA" aria-label="Сбросить 2FA ${name}" ${locked ? "disabled" : ""}>${ctx.icon("lock")}</button>` : ""}<button class="icon ghost" data-action="user-toggle" data-id="${escapedId}" aria-label="${enabled ? t("Отключить") : t("Включить")} ${name}" title="${finalAdmin ? t("Нужен хотя бы один включённый full") : enabled ? t("Отключить") : t("Включить")}" ${locked || finalAdmin ? "disabled" : ""}>${ctx.icon(enabled ? "x" : "check")}</button><button class="icon ghost danger" data-action="user-remove" data-id="${escapedId}" aria-label="Удалить ${name}" title="${finalAdmin ? t("Нельзя удалить последнего включённого full") : t("Удалить")}" ${locked || finalAdmin ? "disabled" : ""}>${ctx.icon("minus")}</button></div></td></tr>`;
      })
      .join("") ||
    html`<tr><td colspan="5" class="users-empty">Пользователей нет. Обновите страницу, чтобы получить актуальный список.</td></tr>`
  }</tbody></table></div><div class="users-access-note">Изменение пароля, имени, группы или статуса завершает сессии этой учётной записи. Пользователи сохраняются сразу, отдельно от черновика сети.</div>`;
}

function showEditor(ctx, user = null) {
  const e = ctx.e;
  const finalAdmin = lastFull(user, users(ctx));
  const role = user?.role || "read";
  ctx.dialogFrame(
    user ? t("Edit User") : t("New User"),
    t("Группы доступа: read — просмотр, full — полное управление."),
    html`<div class="rule-editor-layout"><div><form id="user-form" class="winbox-form" data-id="${e(user?.id || "")}"><label class="field"><span>Имя пользователя</span><input name="username" type="text" autocomplete="off" value="${e(user?.username || "")}" minlength="1" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9._\\-]{0,63}" required><small>Латинские буквы, цифры, точка, дефис и подчёркивание. До 64 символов.</small></label><label class="field"><span>Группа</span><select name="role" required><option value="read" ${role === "read" ? "selected" : ""} ${finalAdmin ? "disabled" : ""}>read · только просмотр</option><option value="full" ${role === "full" ? "selected" : ""}>full · полное управление</option></select></label><label class="field"><span>${user ? t("Новый пароль") : t("Пароль")}</span><input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="512" ${user ? "" : "required"}><small>${user ? t("Оставьте пустым, чтобы сохранить пароль. Новый пароль — от 12 символов.") : t("От 12 до 512 символов.")}</small></label>${user ? html`<div class="field"><span>Статус</span><label class="checkbox-label"><input name="enabled" type="checkbox" ${user.enabled ? "checked" : ""} ${finalAdmin ? "disabled" : ""}>Включён</label>${finalAdmin ? html`<input type="hidden" name="enabled" value="on">` : ""}</div>` : ""}${finalAdmin ? html`<div class="field-note users-last-admin-note">Это последний включённый пользователь full. Чтобы изменить его группу или отключить, сначала добавьте другого администратора.</div>` : ""}<div class="field-note">Изменения сохраняются сразу. При изменении своей учётной записи потребуется войти снова.</div></form>${proofForm(ctx, "user-proof", t("Подтвердите изменение своим текущим паролем и кодом 2FA."))}</div><aside class="rule-actions"><button class="primary" data-action="user-save">OK</button><button data-action="close">Cancel</button></aside></div>`,
    html`<span class="muted">Управление доступом · без изменения сетевого черновика</span>`,
  );
  ctx.dialog.classList.add("winbox-editor", "users-editor");
}
async function refreshAfterWrite(ctx, message) {
  ctx.dialog.close();
  await ctx.refreshUsers();
  ctx.render();
  ctx.toast(message);
}

export async function handleUsersAction(button, ctx) {
  const action = button.dataset.action;
  if (!actions.has(action)) return false;
  if (button.disabled || ctx.busy) return true;
  await ctx.run(async () => {
    if (!mayManage(ctx))
      throw new Error(
        t("Управление пользователями доступно только группе full после входа."),
      );
    if (ctx.offline)
      throw new Error(t("Нет связи с сервером. Повторите после подключения."));
    const id = button.dataset.id;
    if (action === "user-new") {
      showEditor(ctx);
      return;
    }
    if (action === "user-edit") {
      showEditor(ctx, managedUser(ctx, id));
      return;
    }
    if (action === "user-remove") {
      const user = managedUser(ctx, id);
      if (lastFull(user, users(ctx)))
        throw new Error(
          t("Нельзя удалить последнего включённого пользователя full."),
        );
      ctx.dialogFrame(
        t("Удалить пользователя?"),
        t("Учётная запись и её сессии будут удалены сразу."),
        html`<p class="preview-note">Удалить пользователя «${ctx.e(user.username)}»?</p>${proofForm(ctx, "user-proof", t("Подтвердите удаление своим текущим паролем и кодом 2FA."))}`,
        html`<button data-action="close">Cancel</button><button class="danger" data-action="user-delete-confirm" data-id="${ctx.e(user.id)}">Удалить</button>`,
      );
      return;
    }
    if (action === "user-save") {
      const form = ctx.dialog.querySelector("#user-form");
      if (!form)
        throw new Error(t("Форма пользователя закрыта. Откройте её снова."));
      if (!form.reportValidity()) return;
      const fields = new FormData(form);
      const username = String(fields.get("username") || "")
        .trim()
        .toLowerCase();
      const password = String(fields.get("password") || "");
      const role = String(fields.get("role") || "");
      const userId = form.dataset.id;
      const previous = userId ? managedUser(ctx, userId) : null;
      if (!usernamePattern.test(username))
        throw new Error(
          t(
            "Имя: от 1 до 64 латинских букв, цифр, точек, дефисов и подчёркиваний; первый символ — буква или цифра.",
          ),
        );
      if (!["read", "full"].includes(role))
        throw new Error(t("Выберите группу read или full."));
      if (
        (!previous || password) &&
        (password.length < 12 || password.length > 512)
      )
        throw new Error(t("Пароль должен содержать от 12 до 512 символов."));
      const payload = { username, role };
      if (password) payload.password = password;
      if (previous) {
        payload.enabled = fields.has("enabled");
        if (
          lastFull(previous, users(ctx)) &&
          (!payload.enabled || role !== "full")
        )
          throw new Error(
            t("Должен оставаться хотя бы один включённый пользователь full."),
          );
      }
      const credentials = proof(ctx, "user-proof");
      if (!credentials) return;
      payload.proof = credentials;
      try {
        await ctx.api(
          previous ? `users/${encodeURIComponent(userId)}` : "users",
          {
            method: previous ? "PUT" : "POST",
            body: JSON.stringify(payload),
          },
        );
      } finally {
        clearProof(ctx);
      }
      await refreshAfterWrite(
        ctx,
        previous ? t("Пользователь обновлён") : t("Пользователь создан"),
      );
      return;
    }
    const user = managedUser(ctx, id);
    if (action === "user-toggle") {
      if (lastFull(user, users(ctx)))
        throw new Error(
          t("Нельзя отключить последнего включённого пользователя full."),
        );
      ctx.dialogFrame(
        user.enabled
          ? t("Отключить пользователя?")
          : t("Включить пользователя?"),
        t(
          "Изменение применяется сразу и завершает сессии этой учётной записи.",
        ),
        proofForm(
          ctx,
          "user-proof",
          html`Подтвердите изменение пользователя «${user.username}» своим текущим паролем и кодом 2FA.`,
        ),
        html`<button data-action="close">Cancel</button><button class="primary" data-action="user-toggle-confirm" data-id="${ctx.e(user.id)}">Подтвердить</button>`,
      );
      return;
    }
    if (action === "user-toggle-confirm") {
      if (lastFull(user, users(ctx)))
        throw new Error(
          t("Нельзя отключить последнего включённого пользователя full."),
        );
      const credentials = proof(ctx, "user-proof");
      if (!credentials) return;
      try {
        await ctx.api(`users/${encodeURIComponent(user.id)}`, {
          method: "PUT",
          body: JSON.stringify({ enabled: !user.enabled, proof: credentials }),
        });
      } finally {
        clearProof(ctx);
      }
      await refreshAfterWrite(
        ctx,
        user.enabled ? t("Пользователь отключён") : t("Пользователь включён"),
      );
      return;
    }
    if (action === "user-delete-confirm") {
      if (lastFull(user, users(ctx)))
        throw new Error(
          t("Нельзя удалить последнего включённого пользователя full."),
        );
      const credentials = proof(ctx, "user-proof");
      if (!credentials) return;
      try {
        await ctx.api(`users/${encodeURIComponent(user.id)}`, {
          method: "DELETE",
          body: JSON.stringify({ proof: credentials }),
        });
      } finally {
        clearProof(ctx);
      }
      await refreshAfterWrite(ctx, t("Пользователь удалён"));
    }
  });
  return true;
}
