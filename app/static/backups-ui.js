import { html, t } from "./i18n.js";
import { proofForm, proof, clearProof } from "./security-ui.js?v=1";
import { assertDraftRevision } from "./draft-guards.js";

let preview = null;
const labels = {
  rules: "NAT",
  filter_rules: t("Firewall"),
  application_rules: "Applications",
  address_lists: t("Address Lists"),
  bridges: t("Bridge"),
  vlans: "VLAN",
  virtual_interfaces: "Virtual",
  wireguard_interfaces: "WireGuard",
  wireguard_peers: "VPN peers",
  addresses: "IP Addresses",
  routes: t("Routes"),
  interface_lists: t("Interface Lists"),
  pools: "IP Pool",
  dhcp_servers: "DHCP",
  dhcp_reservations: "DHCP reservations",
  dns_static: "DNS Static",
};

export function resetBackups() {
  preview = null;
}

export function renderBackups(ctx) {
  // The app's run() guard and .is-busy handle in-flight actions. A preview is
  // rendered inside run(), so persisting its busy flag would strand disabled buttons.
  const blocked = ctx.offline || ctx.state.pending;
  const full = ctx.canWrite();
  const rows = preview
    ? Object.keys(labels)
        .filter((k) => preview.before[k] || preview.after[k])
        .map(
          (k) =>
            html`<tr><td>${ctx.e(t(labels[k]))}</td><td class="numeric">${ctx.e(preview.before[k] || 0)}</td><td class="numeric">${ctx.e(preview.after[k] || 0)}</td></tr>`,
        )
        .join("")
    : "";
  return html`<div class="feature-page backup-page"><div class="security-card"><div><h3>Экспорт конфигурации</h3><p>Текстовый .rsc удобно читать, редактировать и переносить. JSON сохраняет совместимость с прежними экспортами.</p><label class="field"><span>Источник</span><select id="backup-export-source"><option value="applied">Подтверждённая конфигурация</option><option value="draft">Текущий черновик</option></select></label></div><div class="update-buttons"><button data-action="backup-export-rsc" ${blocked ? "disabled" : ""}>${ctx.icon("download")}Export .rsc</button><button data-action="backup-export-json" ${blocked ? "disabled" : ""}>Export JSON</button></div></div><div class="security-card"><div><h3>Зашифрованный backup</h3><p>Подтверждённые настройки, пользователи и хеши паролей, 2FA и закрытые ключи WireGuard. Пароль архива потребуется для восстановления.</p><small>История графиков, журналы и настройки самой ОС в копию не входят.</small></div><button class="primary" data-action="backup-create-open" ${blocked || !full || ctx.state.dirty ? "disabled" : ""}>${ctx.icon("download")}Создать backup</button></div><div class="security-card backup-import-card"><div><h3>Импорт / Restore</h3><p>Выберите .rsc, JSON или зашифрованный .backup. Сначала проверим файл и покажем изменения.</p></div><form id="backup-import-form" class="form-grid" data-revision="${ctx.state.revision}"><label class="field"><span>Файл конфигурации или backup</span><input type="file" name="file" accept=".rsc,.json,.backup,application/json" required ${!full ? "disabled" : ""}></label><label class="field"><span>Пароль архива .backup</span><input type="password" name="archive_password" autocomplete="off" maxlength="512" ${!full ? "disabled" : ""}><small>Для .rsc и JSON оставьте пустым.</small></label><div class="backup-import-actions"><button type="button" data-action="backup-inspect" ${blocked || !full ? "disabled" : ""}>${ctx.icon("search")}Проверить файл</button><button type="button" data-action="backup-reset">Сбросить выбор</button></div></form></div>${preview ? html`<section class="backup-preview"><h3>Предпросмотр импорта: ${ctx.e(preview.filename || "")}</h3><div class="table-scroll"><table class="rules-table"><thead><tr><th>Раздел</th><th>Сейчас</th><th>После импорта</th></tr></thead><tbody>${rows}</tbody></table></div>${preview.source_version ? html`<p>Версия источника: ${ctx.e(preview.source_version)} · VPN-ключей: ${ctx.e(preview.private_keys)}</p>` : ""}${preview.warnings.map((w) => html`<p class="feature-note">${ctx.e(w)}</p>`).join("")}${preview.accounts.length ? html`<p>Учётные записи в копии: ${preview.accounts.map((a) => `${ctx.e(a.username)} (${ctx.e(a.role)}${a.totp_enabled ? ", 2FA" : ""})`).join(", ")}</p><label class="checkbox-label"><input id="backup-restore-accounts" type="checkbox" ${ctx.state.auth_enabled ? "checked" : "disabled"}>Восстановить пользователей и 2FA</label><p class="feature-note">После подтверждения связи сессии будут завершены. Войдите с учётными данными из копии. Сняв флажок, вы сохраните текущие учётные записи.</p>` : ""}<details class="backup-script"><summary>Просмотреть конфигурацию перед импортом</summary><pre>${ctx.e(preview.script)}</pre></details><p class="feature-note">Будет заменён общий черновик. Работающая сеть изменится после «Применить»; без подтверждения связи выполнится откат.</p>${preview.revision !== ctx.state.revision ? html`<p class="connection-error">Черновик изменился; проверьте файл заново.</p>` : ""}<button class="primary" data-action="backup-stage-open" ${blocked || !full || preview.revision !== ctx.state.revision ? "disabled" : ""}>Загрузить в черновик</button></section>` : ""}<p class="feature-note">.rsc — декларативный формат OpenMikroRout. Команды RouterOS, shell и произвольные скрипты не выполняются. Текстовый экспорт не содержит паролей, секретов 2FA и закрытых VPN-ключей.</p></div>`;
}

function download(blob, extension) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `openmikrorout-${new Date().toISOString().slice(0, 10)}.${extension}`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function binaryFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new window.FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1]);
    reader.onerror = () => reject(new Error(t("Не удалось прочитать файл")));
    reader.readAsDataURL(file);
  });
}

function openProof(ctx, title, content, action) {
  ctx.dialogFrame(
    title,
    "",
    (ctx.state.auth_enabled
      ? proofForm(ctx, "backup-proof", content)
      : html`<p>${ctx.e(content)}</p>`) +
      (action === "backup-create"
        ? html`<label class="field"><span>Пароль новой резервной копии</span><input name="new_archive_password" type="password" minlength="12" maxlength="512" autocomplete="new-password" required></label><label class="field"><span>Повторите пароль архива</span><input name="repeat_archive_password" type="password" minlength="12" maxlength="512" autocomplete="new-password" required></label>`
        : ""),
    html`<button data-action="close">Отмена</button><button class="primary" data-action="${action}">${action === "backup-create" ? t("Скачать backup") : t("Загрузить черновик")}</button>`,
  );
}

export async function handleBackupAction(button, ctx) {
  const action = button.dataset.action;
  if (!action.startsWith("backup-")) return false;
  const generation = ctx.generation;
  const current = () => generation === ctx.getGeneration();
  if (action === "backup-reset") {
    resetBackups();
    ctx.render();
    return true;
  }
  if (action.startsWith("backup-export-")) {
    const kind = action.endsWith("-rsc") ? "rsc" : "json";
    const source =
      document.querySelector("#backup-export-source")?.value || "applied";
    await ctx.run(async () => {
      const blob = await ctx.api(
        `configuration/export?kind=${kind}&source=${encodeURIComponent(source)}`,
        { responseType: "blob" },
      );
      if (current()) download(blob, kind);
    });
    return true;
  }
  if (!ctx.canWrite()) throw new Error(t("Нужна учётная запись full."));
  if (action === "backup-create-open") {
    if (ctx.state.dirty || ctx.state.pending)
      throw new Error(t("Сначала примените или отмените черновик."));
    openProof(
      ctx,
      t("Создать зашифрованную копию"),
      t(
        "Копия содержит учётные записи и VPN-ключи. Сохраните пароль архива отдельно: восстановить его нельзя.",
      ),
      "backup-create",
    );
    return true;
  }
  if (action === "backup-stage-open") {
    if (!preview) throw new Error(t("Сначала проверьте файл."));
    assertDraftRevision(preview.revision, ctx.state.revision);
    preview.restore_accounts = Boolean(
      document.querySelector("#backup-restore-accounts")?.checked,
    );
    openProof(
      ctx,
      t("Загрузить конфигурацию из файла?"),
      preview.restore_accounts
        ? t(
            "Будут подготовлены настройки и учётные записи из копии. Пользователи заменятся только после подтверждения связи.",
          )
        : t(
            "Настройки будут загружены в общий черновик. Текущие пользователи сохраняются.",
          ),
      "backup-stage",
    );
    return true;
  }
  await ctx.run(async () => {
    if (action === "backup-inspect") {
      const form = document.querySelector("#backup-import-form");
      if (!form?.reportValidity()) return;
      const revision = Number(form.dataset.revision);
      assertDraftRevision(revision, ctx.state.revision);
      const file = form.querySelector('[name="file"]').files[0];
      const kind = file.name.toLowerCase().endsWith(".backup")
        ? "backup"
        : file.name.toLowerCase().endsWith(".rsc")
          ? "rsc"
          : "json";
      if (file.size > (kind === "backup" ? 8 : 1) * 1048576)
        throw new Error(t("Файл превышает допустимый размер."));
      const data =
        kind === "backup" ? await binaryFile(file) : await file.text();
      if (!current()) return;
      const pass = form.querySelector('[name="archive_password"]');
      if (kind === "backup" && !pass.value)
        throw new Error(t("Введите пароль резервной копии."));
      const body = { kind, data, revision, archive_password: pass.value };
      const result = await ctx.api("configuration/inspect", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (!current() || form.querySelector('[name="file"]').files[0] !== file)
        return;
      pass.value = "";
      preview = { ...result, revision, filename: file.name };
      ctx.render();
      return;
    }
    const credentials = ctx.state.auth_enabled
      ? proof(ctx, "backup-proof")
      : undefined;
    if (ctx.state.auth_enabled && !credentials) return;
    if (action === "backup-create") {
      const input = ctx.dialog.querySelector('[name="new_archive_password"]');
      const repeat = ctx.dialog.querySelector(
        '[name="repeat_archive_password"]',
      );
      if (!input.reportValidity() || !repeat.reportValidity()) return;
      if (input.value !== repeat.value)
        throw new Error(t("Пароли архива не совпадают."));
      const result = await ctx.api("configuration/backup", {
        method: "POST",
        body: JSON.stringify({
          archive_password: input.value,
          proof: credentials,
        }),
        responseType: "blob",
      });
      if (!current()) return;
      input.value = repeat.value = "";
      clearProof(ctx);
      ctx.dialog.close();
      download(result, "backup");
      ctx.toast(t("Зашифрованная копия скачана"));
    } else if (action === "backup-stage") {
      if (!preview) throw new Error(t("Предпросмотр недоступен."));
      assertDraftRevision(preview.revision, ctx.state.revision);
      const result = await ctx.api("configuration/stage", {
        method: "POST",
        body: JSON.stringify({
          preview_id: preview.preview_id,
          revision: preview.revision,
          restore_accounts: preview.restore_accounts,
          proof: credentials,
        }),
      });
      if (!current()) return;
      clearProof(ctx);
      ctx.dialog.close();
      preview = null;
      ctx.acceptState(result);
      ctx.toast(t("Конфигурация подготовлена. Примените и подтвердите связь."));
    }
  });
  return true;
}

export function handleBackupInput(event) {
  if (
    event.target.name === "file" &&
    event.target.closest("#backup-import-form")
  ) {
    resetBackups();
    document.querySelector(".backup-preview")?.remove();
  }
}
