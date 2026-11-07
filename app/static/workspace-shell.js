import { t } from "./i18n.js";
import { createSharedWorkspaceApi } from "./workspace-api.js";
import { createWorkspaceHost } from "./workspace-runtime.js";
import { createWorkspaceManager } from "./workspace-manager.js";
import { getWorkspaceTools } from "./workspace-tools.js";

const editorForms = new Set([
  "rule-form",
  "list-form",
  "router-form",
  "router-port-form",
  "wg-form",
  "router-dns-form",
  "router-domain-form",
  "backup-import-form",
  "f2b-profile-form",
  "f2b-settings",
  "geo-settings",
  "discovery-settings",
  "scan-settings",
  "user-form",
  "preferences-form",
]);

/** Only a dirty flag leaves the tool document. Input values never enter layout. */
export function markWorkspaceFormDirty(event) {
  if (event.target?.matches?.("[data-checkbox-search]")) return;
  const form = event.target?.closest?.("form");
  if (!form || !editorForms.has(form.id)) return;
  form.dataset.workspaceDirty = "true";
  return true;
}

export function hasUnsavedWorkspaceForm(document) {
  return [
    ...document.querySelectorAll('form[data-workspace-dirty="true"]'),
  ].some((form) => {
    const dialog = form.closest("dialog");
    return form.isConnected && (!dialog || dialog.open);
  });
}

export function workspaceStorageKey(state, origin) {
  const account =
    state.current_user?.id ||
    (state.auth_enabled === false ? "local" : "signed-out");
  return (
    "openmikrorout.workspace.v1." +
    encodeURIComponent(
      JSON.stringify([origin, state.mode, state.hostname || "router", account]),
    )
  );
}

function choose(document, title, message, choices) {
  return new Promise((resolve) => {
    const dialog = document.createElement("dialog");
    dialog.className = "workspace-confirm";
    dialog.setAttribute("aria-labelledby", "workspace-confirm-title");
    const heading = document.createElement("h2");
    heading.id = "workspace-confirm-title";
    heading.textContent = title;
    const note = document.createElement("p");
    note.textContent = message;
    const actions = document.createElement("div");
    actions.className = "workspace-confirm-actions";
    let answer = "cancel";
    for (const choice of choices) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = choice.label;
      if (choice.primary) button.className = "primary";
      button.addEventListener("click", () => {
        answer = choice.value;
        dialog.close();
      });
      actions.append(button);
    }
    dialog.append(heading, note, actions);
    dialog.addEventListener(
      "close",
      () => {
        dialog.remove();
        resolve(answer);
      },
      { once: true },
    );
    document.body.append(dialog);
    dialog.showModal();
    actions.querySelector("button")?.focus();
  });
}

export async function confirmWorkspaceNavigation(document) {
  return (
    (await choose(
      document,
      t("Перейти в другой раздел?"),
      t("Несохранённые изменения в форме будут потеряны."),
      [
        { value: "cancel", label: t("Отмена") },
        {
          value: "continue",
          label: t("Продолжить без сохранения"),
          primary: true,
        },
      ],
    )) === "continue"
  );
}

/** The host owns shared reads and layout. Each registered document owns its
 * tools and forms; replacing chrome never replaces a tool's iframe ancestor. */
export function createDesktopWorkspace({
  container,
  getContext,
  fetcher,
  onUpdate,
  onSessionEnd,
  onError,
}) {
  const document = container.ownerDocument;
  const browser = document.defaultView;
  const shared = createSharedWorkspaceApi(fetcher);
  const visible = new Map();
  const activities = new Map();
  let manager = null;
  let destroyed = false;
  let scheduled = false;
  let refreshTimer = null;
  let signature = "";
  let stateSignature = "";
  const media = browser.matchMedia("(max-width: 680px)");
  const report = (error) => {
    if (!destroyed && error?.name !== "AbortError") onError(error);
  };
  function refreshAfterMutation() {
    shared.invalidate();
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
      if (destroyed) return;
      void getContext()
        .refreshCurrentUser()
        .then(() => host.requestRefresh())
        .catch(report);
    }, 40);
  }

  const host = createWorkspaceHost({
    window: browser,
    read: shared.read,
    onFocus: ({ id }) => manager?.focus(id),
    onNavigate: ({ view }) => manager?.open(view),
    onSessionEnd,
    onStatus: ({ id, status }) => {
      if (!manager || destroyed) return;
      activities.set(id, { active: status.active, kind: status.kind });
      manager.setActivity(id, status);
      if (status.view && manager.get(id)?.view !== status.view)
        manager.setView(id, status.view);
    },
    onMutation: refreshAfterMutation,
    onUpdate: ({ version }) => {
      if (!destroyed && getContext().canWrite())
        getContext().watchUpdate(version);
    },
  });
  browser.__omrWorkspaceHost = host;

  function synchronize() {
    if (destroyed || scheduled) return;
    scheduled = true;
    queueMicrotask(() => {
      scheduled = false;
      if (destroyed || !manager) return;
      const snapshot = manager.snapshot();
      const ids = new Set(snapshot.windows.map((item) => item.id));
      for (const id of visible.keys())
        if (!ids.has(id)) {
          host.unregister(id);
          visible.delete(id);
          activities.delete(id);
        }
      for (const item of snapshot.windows) {
        const next =
          !item.minimized && (!media.matches || item.id === snapshot.active);
        if (visible.get(item.id) !== next) {
          visible.set(item.id, next);
          host.setVisible(item.id, next);
        }
      }
      onUpdate();
    });
  }

  async function beforeClose(window) {
    const status = await host.getCloseState(window.id);
    if (destroyed) return false;
    if (status.busy) {
      report(new Error(t("Дождитесь завершения текущей операции.")));
      return false;
    }
    let scanning = status.kind === "scan" && status.active && !!status.jobId;
    if (scanning) {
      try {
        const job = await getContext().api(`scans/jobs/${status.jobId}`);
        scanning = ["queued", "running"].includes(job.state);
      } catch (error) {
        report(error);
      }
    }
    if (destroyed) return false;
    if (!status.dirty && !scanning) return true;
    const choices = [{ value: "cancel", label: t("Отмена") }];
    if (scanning) {
      choices.push({
        value: "continue",
        label: t("Продолжить в фоне"),
        primary: true,
      });
      if (getContext().canWrite())
        choices.push({ value: "stop", label: t("Остановить и закрыть") });
    } else
      choices.push({ value: "close", label: t("Закрыть окно"), primary: true });
    if (document.querySelector(".workspace-confirm[open]")) return false;
    const answer = await choose(
      document,
      t("Закрыть окно «{name}»?", { name: window.title }),
      [
        status.dirty
          ? t("Несохранённые изменения в форме будут потеряны.")
          : "",
        scanning
          ? t(
              "Сканирование выполняется на сервере. Продолжить его в фоне или остановить?",
            )
          : "",
      ]
        .filter(Boolean)
        .join(" "),
      choices,
    );
    if (destroyed || answer === "cancel") return false;
    if (answer === "stop") await host.cancelScan(window.id);
    return !destroyed;
  }

  const initial = getContext();
  const identity = workspaceStorageKey(initial.state, browser.location.origin);
  const tools = getWorkspaceTools(initial);
  manager = createWorkspaceManager({
    container,
    tools,
    storageKey: identity,
    renderIcon: initial.icon,
    onError: report,
    beforeClose,
    onFrame: (window, iframe) => {
      host.register(window.id, iframe);
      return () => host.unregister(window.id);
    },
    onNavigate: (window, _iframe, view) => host.navigate(window.id, view),
    onActive: synchronize,
    onChange: synchronize,
  });
  signature = JSON.stringify(tools);
  if (!manager.restored) manager.open("overview");
  synchronize();
  media.addEventListener("change", synchronize);

  function showWindows() {
    if (destroyed || document.querySelector(".workspace-window-list[open]"))
      return;
    const dialog = document.createElement("dialog");
    dialog.className = "workspace-confirm workspace-window-list";
    dialog.setAttribute("aria-labelledby", "workspace-windows-title");
    const heading = document.createElement("h2");
    heading.id = "workspace-windows-title";
    heading.textContent = t("Открытые окна");
    const note = document.createElement("p");
    note.textContent = t("Выберите окно, чтобы перейти к нему.");
    const list = document.createElement("ul");
    const snapshot = manager.snapshot();
    for (const item of snapshot.windows) {
      const row = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "workspace-list-entry";
      button.setAttribute("aria-pressed", String(snapshot.active === item.id));
      const name = document.createElement("strong");
      name.textContent = manager.get(item.id).title;
      const status = document.createElement("span");
      status.textContent = [
        item.minimized
          ? t("Свёрнуто")
          : snapshot.active === item.id
            ? t("Активное окно")
            : t("Открыто"),
        activities.get(item.id)?.active ? t("Выполняется") : "",
      ]
        .filter(Boolean)
        .join(" · ");
      button.append(name, status);
      button.addEventListener("click", () => {
        dialog.close();
        manager.focus(item.id);
      });
      row.append(button);
      list.append(row);
    }
    if (!snapshot.windows.length)
      note.textContent = t("Открытых окон нет. Выберите раздел в меню слева.");
    const actions = document.createElement("div");
    actions.className = "workspace-confirm-actions";
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = t("Закрыть список");
    close.addEventListener("click", () => dialog.close());
    actions.append(close);
    dialog.append(heading, note, list, actions);
    dialog.addEventListener("close", () => dialog.remove(), { once: true });
    document.body.append(dialog);
    dialog.showModal();
  }

  return {
    identity,
    open: (view) => manager.open(view),
    showWindows,
    get windowCount() {
      return manager.snapshot().windows.length;
    },
    get activeView() {
      return manager.getActive()?.view || "overview";
    },
    read: shared.read,
    notifyMutation: refreshAfterMutation,
    update() {
      if (destroyed) return;
      const tools = getWorkspaceTools(getContext());
      const next = JSON.stringify(tools);
      if (signature !== next) {
        signature = next;
        manager.setTools(tools);
      }
      const context = getContext();
      const nextState = JSON.stringify([
        context.state.revision,
        context.state.dirty,
        context.state.pending,
        context.state.current_user,
        context.offline,
      ]);
      if (stateSignature !== nextState) {
        stateSignature = nextState;
        host.requestRefresh();
      }
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      clearTimeout(refreshTimer);
      media.removeEventListener("change", synchronize);
      host.dispose();
      shared.dispose();
      manager.destroy();
      for (const dialog of document.querySelectorAll(".workspace-confirm"))
        dialog.close();
      if (browser.__omrWorkspaceHost === host)
        delete browser.__omrWorkspaceHost;
    },
  };
}
