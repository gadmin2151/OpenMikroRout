import { html, t, locale } from "./i18n.js";
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
  queued: t("В очереди"),
  downloading: t("Загрузка"),
  validating: t("Проверка подписи и пакета"),
  installing: t("Подготовка окружения"),
  backup: t("Резервная копия"),
  restarting: t("Перезапуск и проверка"),
  recovering: t("Восстановление"),
  succeeded: t("Обновлено"),
  failed: t("Обновление не установлено"),
};

/** Wait for the worker's completed health check, not just a listening server. */
export function createUpdateReloadWatcher({
  fetchHealth = async () => {
    const response = await fetch("/api/health", {
      cache: "no-store",
      credentials: "same-origin",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(t("Сервис перезапускается."));
    return response.json();
  },
  reload = () => window.location.reload(),
  schedule = (callback) => setTimeout(callback, 1000),
  cancel = clearTimeout,
  now = Date.now,
  onStopped = () => {},
} = {}) {
  let pending = null,
    timer = null,
    reloadedVersion = "";
  function stop() {
    pending = null;
    cancel(timer);
    timer = null;
  }
  async function poll(installation) {
    try {
      const health = await fetchHealth();
      if (pending !== installation) return;
      if (health?.update?.version === installation.version) {
        if (health.update.phase === "failed") {
          stop();
          onStopped(
            t("Обновление не установлено. Подробности — в разделе обновлений."),
          );
          return;
        }
        if (
          health.update.phase === "succeeded" &&
          health.status === "ok" &&
          health.version === installation.version
        ) {
          stop();
          reloadedVersion = installation.version;
          reload();
          return;
        }
      }
    } catch {
      // A restart temporarily interrupts requests; retry within a bounded window.
    }
    if (pending !== installation) return;
    if (now() >= installation.deadline) {
      stop();
      onStopped(
        t(
          "Не удалось дождаться обновления. Проверьте состояние сервиса и обновите страницу.",
        ),
      );
      return;
    }
    timer = schedule(() => poll(installation));
  }
  return {
    watch(version) {
      if (
        !/^\d+\.\d+\.\d+$/.test(version || "") ||
        version === pending?.version ||
        version === reloadedVersion
      )
        return;
      stop();
      pending = { version, deadline: now() + 30 * 60 * 1000 };
      void poll(pending);
    },
    stop,
  };
}

let notifyUpdate = () => {};
const updateReload = createUpdateReloadWatcher({
  onStopped: (message) => notifyUpdate(message, true),
});

function watchUpdate(job, ctx) {
  if (!activePhases.has(job?.phase)) return;
  notifyUpdate = ctx.toast;
  updateReload.watch(job.version);
}

export function resetUpdates() {
  // The public-health watcher intentionally survives logout during a restart.
  // It retains only the target version, not authenticated session data.
  status = null;
  error = "";
  request = null;
}

function licenseBlocked() {
  return (
    status?.ndpi_license?.required === true &&
    status.ndpi_license.accepted !== true
  );
}
function licenseMarkup(ctx) {
  const license = status?.ndpi_license;
  if (!license || typeof license !== "object") return "";
  const profiles = {
    "not-for-profit": t("Без прямого и косвенного дохода"),
    "commercial-license": t("Коммерческое соглашение с ntop"),
    "lgpl-only": t("Только LGPL core · ограниченное распознавание"),
  };
  let terms = "";
  try {
    const url = new URL(license.terms_url);
    if (
      url.protocol === "https:" &&
      url.hostname === "github.com" &&
      url.pathname.startsWith("/ntop/nDPI/") &&
      !url.username &&
      !url.password
    )
      terms = url.href;
  } catch {
    /* Missing/invalid metadata cannot create an unsafe outbound link. */
  }
  const profile = Object.hasOwn(profiles, license.profile)
    ? profiles[license.profile]
    : license.profile || "—";
  return html`<section class="security-card update-license ${licenseBlocked() ? "update-license-required" : ""}" aria-label="Условия nDPI"><div><h3>Лицензия nDPI ${ctx.e(license.version || "")}</h3><p>Ядро nDPI распространяется по LGPLv3. Дополнительные компоненты ntop бесплатны только при отсутствии прямого и косвенного дохода от их использования. Для использования с доходом требуется коммерческое соглашение с ntop.</p><p>Принятие условий не предоставляет коммерческую лицензию ntop. Профиль LGPL-only исключает дополнительные компоненты и уменьшает покрытие.</p>${license.accepted === true ? html`<p class="update-license-profile"><strong>Принятый профиль:</strong> ${ctx.e(profile)}</p>` : licenseBlocked() ? html`<p role="alert"><strong>Для установки требуется явное принятие условий администратором сервера.</strong></p><p>Выполните в каталоге OpenMikroRout на сервере:</p><pre><code>sudo ./deploy/accept-ndpi-license.sh</code></pre><p>Отказ отменяет установку и сохраняет существующую систему. Веб-панель не записывает согласие в /etc.</p>` : ""}${terms ? html`<a href="${ctx.e(terms)}" target="_blank" rel="noopener noreferrer">Прочитать условия nDPI</a>` : ""}${license.notice ? html`<details><summary>Оригинальное уведомление поставщика</summary><p>${ctx.e(license.notice)}</p></details>` : ""}</div></section>`;
}

export function renderUpdates(ctx) {
  if (!ctx.canWrite() || !ctx.currentUser)
    return html`<div class="empty">Обновления доступны пользователям full после входа.</div>`;
  const e = ctx.e;
  const latest = status?.latest;
  const job = status?.job;
  const active = activePhases.has(job?.phase);
  const blocked = ctx.busy || ctx.offline || active;
  return html`<div class="feature-page"><div class="feature-heading"><div><h2>Обновление OpenMikroRout</h2><p>Установленная версия <strong>${e(status?.current_version || ctx.state.version)}</strong></p></div>${ctx.icon("download")}</div><div class="update-source"><span>Источник</span><a href="https://github.com/gadmin2151/OpenMikroRout" target="_blank" rel="noopener noreferrer">gadmin2151/OpenMikroRout</a><span>Проверка подписи Ed25519 и SHA-256</span></div>${error ? html`<div class="connection-error" role="alert">${e(error)}</div>` : ""}${status?.error ? html`<p class="feature-note">${e(status.error)}</p>` : ""}${licenseMarkup(ctx)}<div class="security-card"><div><h3>${latest ? (latest.available ? html`Доступна версия ${e(latest.version)}` : t("Установлена актуальная версия")) : t("Проверка новой версии")}</h3><p>${latest ? `GitHub: ${e(latest.version)} · commit ${e(latest.commit.slice(0, 12))}` : t("Проверяется последний стабильный подписанный выпуск вашего репозитория.")}</p></div><div class="update-buttons"><button data-action="updates-check" ${blocked || !status?.enabled ? "disabled" : ""}>${ctx.icon("refresh")}Проверить GitHub</button>${latest?.available ? html`<button class="primary" data-action="updates-open" ${blocked || ctx.state.dirty || ctx.state.pending || licenseBlocked() ? "disabled" : ""}>${ctx.icon("download")}Установить ${e(latest.version)}</button>` : ""}</div></div>${job ? html`<div class="update-job" role="status"><strong>${e(t(phases[job.phase] || job.phase))} · ${e(job.version)}</strong><p>${e(job.message)}</p>${job.error ? html`<p class="update-error">${e(job.error)}</p>` : ""}<small>${e(new Date(job.updated_at * 1000).toLocaleString(locale()))}</small></div>` : ""}<p class="feature-note">Сначала примените или отмените сетевой черновик. Обновление сохраняет конфигурацию, пользователей и ключи 2FA, готовит отдельную версию и проверяет запуск. При ошибке возвращается предыдущая версия. После перезапуска панели потребуется снова войти.</p></div>`;
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
      watchUpdate(result.job, ctx);
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
    throw new Error(t("Нужна учётная запись full."));
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
    if (licenseBlocked())
      throw new Error(
        t(
          "Примите условия nDPI на сервере: sudo ./deploy/accept-ndpi-license.sh",
        ),
      );
    if (!status?.latest?.available || activePhases.has(status.job?.phase))
      throw new Error(t("Сначала проверьте доступную версию."));
    if (ctx.state.dirty || ctx.state.pending)
      throw new Error(t("Сначала примените или отмените сетевой черновик."));
    if (action === "updates-open") {
      ctx.dialogFrame(
        html`Установить OpenMikroRout ${status.latest.version}?`,
        t("Подтвердите свои учётные данные."),
        proofForm(
          ctx,
          "update-proof-form",
          t(
            "Панель ненадолго перезапустится. Конфигурация будет сохранена; при ошибке запуска выполнится откат.",
          ),
        ),
        html`<button data-action="close">Отмена</button><button class="primary" data-action="updates-apply">Обновить сервис</button>`,
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
    watchUpdate(job, ctx);
    ctx.render();
    ctx.toast(
      t(
        "Обновление запущено. После проверки запуска страница обновится автоматически.",
      ),
    );
  });
  return true;
}
