import { proofForm, proof, clearProof } from "./security-ui.js?v=1";

let status = null,
  error = "",
  request = null;
const activePhases = new Set([
  "queued",
  "downloading",
  "validating",
  "installing",
  "backup",
  "restarting",
  "recovering",
]);
const phases = {
  queued: "В очереди",
  downloading: "Загрузка",
  validating: "Проверка подписи и пакета",
  installing: "Подготовка окружения",
  backup: "Резервная копия",
  restarting: "Перезапуск и проверка",
  recovering: "Восстановление",
  succeeded: "Обновлено",
  failed: "Обновление не установлено",
};

export function resetUpdates() {
  status = null;
  error = "";
  request = null;
}

export function renderUpdates(ctx) {
  if (!ctx.canWrite() || !ctx.currentUser)
    return '<div class="empty">Обновления доступны пользователям full после входа.</div>';
  const e = ctx.e;
  const latest = status?.latest;
  const job = status?.job;
  const active = activePhases.has(job?.phase);
  const blocked = ctx.busy || ctx.offline || active;
  return `<div class="feature-page"><div class="feature-heading"><div><h2>Обновление OpenMikroRout</h2><p>Установленная версия <strong>${e(status?.current_version || ctx.state.version)}</strong></p></div>${ctx.icon("download")}</div><div class="update-source"><span>Источник</span><a href="https://github.com/gadmin2151/OpenMikroRout" target="_blank" rel="noopener noreferrer">gadmin2151/OpenMikroRout</a><span>Проверка подписи Ed25519 и SHA-256</span></div>${error ? `<div class="connection-error" role="alert">${e(error)}</div>` : ""}${status?.error ? `<p class="feature-note">${e(status.error)}</p>` : ""}<div class="security-card"><div><h3>${latest ? (latest.available ? `Доступна версия ${e(latest.version)}` : "Установлена актуальная версия") : "Проверка новой версии"}</h3><p>${latest ? `GitHub: ${e(latest.version)} · commit ${e(latest.commit.slice(0, 12))}` : "Проверяется последний стабильный подписанный выпуск вашего репозитория."}</p></div><div class="update-buttons"><button data-action="updates-check" ${blocked || !status?.enabled ? "disabled" : ""}>${ctx.icon("refresh")}Проверить GitHub</button>${latest?.available ? `<button class="primary" data-action="updates-open" ${blocked || ctx.state.dirty || ctx.state.pending ? "disabled" : ""}>${ctx.icon("download")}Установить ${e(latest.version)}</button>` : ""}</div></div>${job ? `<div class="update-job" role="status"><strong>${e(phases[job.phase] || job.phase)} · ${e(job.version)}</strong><p>${e(job.message)}</p>${job.error ? `<p class="update-error">${e(job.error)}</p>` : ""}<small>${e(new Date(job.updated_at * 1000).toLocaleString("ru-RU"))}</small></div>` : ""}<p class="feature-note">Сначала примените или отмените сетевой черновик. Обновление сохраняет конфигурацию, пользователей и ключи 2FA, готовит отдельную версию и проверяет запуск. При ошибке возвращается предыдущая версия. После перезапуска панели потребуется снова войти.</p></div>`;
}

export async function refreshUpdates(ctx) {
  if (request || !ctx.isCurrentView("updates")) return request;
  const generation = ctx.generation;
  const operation = (async () => {
    try {
      const result = await ctx.api("updates");
      if (generation !== ctx.getGeneration()) return;
      const changed =
        JSON.stringify(status) !== JSON.stringify(result) || error;
      status = result;
      error = "";
      if (changed && ctx.isCurrentView("updates") && !ctx.dialog.open)
        ctx.render();
    } catch (failure) {
      if (generation === ctx.getGeneration() && ctx.isCurrentView("updates")) {
        error = failure.message;
        if (!ctx.dialog.open) ctx.render();
      }
    } finally {
      if (request === operation) request = null;
    }
  })();
  request = operation;
  return operation;
}

export async function handleUpdatesAction(button, ctx) {
  const action = button.dataset.action;
  if (!["updates-check", "updates-open", "updates-apply"].includes(action))
    return false;
  if (!ctx.canWrite() || !ctx.currentUser)
    throw new Error("Нужна учётная запись full.");
  await ctx.run(async () => {
    if (action === "updates-check") {
      try {
        status = await ctx.api("updates/check", { method: "POST" });
        error = "";
      } catch (failure) {
        error = failure.message;
      }
      ctx.render();
      return;
    }
    if (!status?.latest?.available || activePhases.has(status.job?.phase))
      throw new Error("Сначала проверьте доступную версию.");
    if (ctx.state.dirty || ctx.state.pending)
      throw new Error("Сначала примените или отмените сетевой черновик.");
    if (action === "updates-open") {
      ctx.dialogFrame(
        `Установить OpenMikroRout ${status.latest.version}?`,
        "Подтвердите свои учётные данные.",
        proofForm(
          ctx,
          "update-proof-form",
          "Панель ненадолго перезапустится. Конфигурация будет сохранена; при ошибке запуска выполнится откат.",
        ),
        '<button data-action="close">Отмена</button><button class="primary" data-action="updates-apply">Обновить сервис</button>',
      );
      return;
    }
    const body = proof(ctx, "update-proof-form");
    if (!body) return;
    body.check_id = status.latest.check_id;
    const job = await ctx.api("updates/apply", {
      method: "POST",
      body: JSON.stringify(body),
    });
    clearProof(ctx);
    ctx.dialog.close();
    status.job = job;
    ctx.render();
    ctx.toast("Обновление запущено. После перезапуска войдите снова.");
  });
  return true;
}
