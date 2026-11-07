import { isSharedWorkspaceRead } from "./workspace-api.js";
import {
  isWorkspaceView,
  sameWorkspaceTool,
  WORKSPACE_MAX_WINDOWS,
} from "./workspace-tools.js";

const safeId = (value) =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/.test(value);
const kinds = new Set(["idle", "tool", "capture", "scan"]);
const safeJobId = (value) =>
  typeof value === "string" &&
  /^(?:[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/i.test(value);
const emptyStatus = () => ({
  dirty: false,
  active: false,
  kind: "idle",
  jobId: null,
});

/** Keep only the latest requested subview while a tool boots or saves a form.
 * Navigation is serialized so an early menu click cannot race initialization. */
export function createWorkspaceNavigation({ ready, navigate, onError }) {
  let pending = null;
  let running = false;
  let disposed = false;
  async function flush() {
    if (disposed || running || !ready()) return;
    running = true;
    try {
      while (!disposed && pending && ready()) {
        const view = pending;
        pending = null;
        try {
          await navigate(view);
        } catch (error) {
          if (!disposed) onError(error);
        }
      }
    } finally {
      running = false;
    }
  }
  return {
    request(view) {
      if (disposed || !isWorkspaceView(view)) return false;
      pending = view;
      void flush();
      return true;
    },
    flush,
    clear() {
      pending = null;
    },
    dispose() {
      disposed = true;
      pending = null;
    },
  };
}

/** Only our two non-secret frame parameters are accepted; arbitrary URLs never
 * become workspace views, iframe targets or stored desktop entries. */
export function getWorkspaceFrame(location, browser = globalThis.window) {
  try {
    const base = browser?.location?.href || "http://localhost/";
    const url = new URL(
      typeof location === "string" ? location : location.href,
      base,
    );
    const origin = browser?.location?.origin || new URL(base).origin;
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.origin !== origin ||
      url.pathname !== "/workspace-frame" ||
      url.hash
    )
      return null;
    if (
      [...url.searchParams.keys()].some(
        (name) => !["view", "window"].includes(name),
      ) ||
      url.searchParams.getAll("view").length !== 1 ||
      url.searchParams.getAll("window").length !== 1
    )
      return null;
    const id = url.searchParams.get("window"),
      view = url.searchParams.get("view");
    return safeId(id) && isWorkspaceView(view) ? { id, view } : null;
  } catch {
    return null;
  }
}

function metadata(value, view) {
  const data = value && typeof value === "object" ? value : {};
  const result = {
    dirty: data.dirty === true,
    active:
      data.active === true ||
      data.busy === true ||
      data.streaming === true ||
      data.scanActive === true,
    kind: kinds.has(data.kind) ? data.kind : "idle",
    jobId: safeJobId(data.jobId) ? data.jobId : null,
  };
  for (const key of ["busy", "streaming", "scanActive"])
    if (typeof data[key] === "boolean") result[key] = data[key];
  if (isWorkspaceView(data.view) && sameWorkspaceTool(view, data.view))
    result.view = data.view;
  return result;
}

/** Direct same-origin bridge: no postMessage broadcast, private DOM, credentials,
 * configuration snapshots or diagnostic output enter window/layout metadata. */
export function createWorkspaceHost({
  window: browser = globalThis.window,
  read,
  onMutation = () => {},
  onSessionEnd = () => {},
  onNavigate = () => {},
  onFocus = () => {},
  onStatus = () => {},
  onUpdate = () => {},
}) {
  const records = new Map();
  let disposed = false;
  const cancelled = () =>
    new globalThis.DOMException(
      "Workspace frame is disconnected",
      "AbortError",
    );
  const warn = () => console.warn("Workspace child lifecycle hook failed");
  function invoke(record, name, ...args) {
    const hook = record.connection?.hooks[name];
    if (typeof hook !== "function") return undefined;
    try {
      const value = hook(...args);
      if (value && typeof value.then === "function") value.catch(warn);
      return value;
    } catch {
      warn();
      return undefined;
    }
  }
  function unregister(id) {
    const record = records.get(id);
    if (!record) return;
    records.delete(id);
    invoke(record, "dispose");
    record.connection = null;
  }
  function connect({ source, id, view, hooks = {} }) {
    const record = records.get(id);
    function valid() {
      try {
        if (
          disposed ||
          records.get(id) !== record ||
          !record ||
          record.iframe.contentWindow !== source ||
          source.location.origin !== browser.location.origin
        )
          return false;
        const current = getWorkspaceFrame(source.location, browser);
        const expected = getWorkspaceFrame(record.iframe.src, browser);
        return (
          current?.id === id &&
          expected?.id === id &&
          current.view === expected.view &&
          sameWorkspaceTool(view, current.view)
        );
      } catch {
        return false;
      }
    }
    if (!safeId(id) || !isWorkspaceView(view) || !valid()) return null;
    if (record.connection) invoke(record, "dispose");
    const connection = { hooks };
    record.connection = connection;
    record.view = view;
    const authorized = () => {
      if (!valid() || record.connection !== connection) throw cancelled();
    };
    const info = () => ({ id, view: record.view });
    invoke(record, "setVisible", record.visible);
    if (record.requestedView && record.requestedView !== view)
      queueMicrotask(() => {
        if (record.connection === connection && valid())
          invoke(record, "navigate", record.requestedView);
      });
    return {
      read(path, options = {}) {
        try {
          authorized();
          if (
            !isSharedWorkspaceRead(path, options) ||
            typeof read !== "function"
          )
            throw new TypeError(
              "This request cannot use the shared workspace API",
            );
          return Promise.resolve(read(path, options)).then((data) => {
            authorized();
            return structuredClone(data);
          });
        } catch (error) {
          return Promise.reject(error);
        }
      },
      notifyMutation(path) {
        authorized();
        const event = info();
        if (typeof path === "string" && /^[a-z][a-z0-9/_-]{0,255}$/.test(path))
          event.path = path;
        onMutation(event);
      },
      watchUpdate(version) {
        authorized();
        if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version))
          return false;
        onUpdate({ ...info(), version });
        return true;
      },
      notifySessionEnd() {
        authorized();
        const event = info();
        for (const name of [...records.keys()]) unregister(name);
        onSessionEnd(event);
      },
      navigate(target) {
        authorized();
        if (!isWorkspaceView(target)) return false;
        onNavigate({ id, view: target });
        return true;
      },
      focus() {
        authorized();
        onFocus(info());
      },
      publishStatus(value) {
        authorized();
        const status = metadata(value, record.view);
        if (status.view) record.view = status.view;
        onStatus({ ...info(), status });
      },
      dispose() {
        if (record.connection === connection) {
          const cleanup = connection.hooks.dispose;
          record.connection = null;
          try {
            const result = cleanup?.();
            if (result && typeof result.then === "function") result.catch(warn);
          } catch {
            warn();
          }
        }
      },
      get visible() {
        return record.visible;
      },
    };
  }
  return {
    register(id, iframe) {
      if (disposed || !safeId(id) || !iframe || typeof iframe !== "object")
        throw new TypeError("Invalid workspace frame");
      if (!records.has(id) && records.size >= WORKSPACE_MAX_WINDOWS)
        throw new Error("Workspace window limit reached");
      unregister(id);
      records.set(id, {
        iframe,
        visible: true,
        connection: null,
        view: null,
        requestedView: null,
      });
    },
    unregister,
    connect,
    setVisible(id, visible) {
      const record = records.get(id);
      if (!record) return;
      record.visible = visible === true;
      invoke(record, "setVisible", record.visible);
    },
    requestRefresh(id) {
      const selected = id
        ? [records.get(id)].filter(Boolean)
        : [...records.values()];
      for (const record of selected) invoke(record, "requestRefresh");
    },
    getCloseState(id) {
      const record = records.get(id);
      if (!record) return emptyStatus();
      const failure = () => ({ ...emptyStatus(), dirty: true, active: true });
      try {
        const value = record.connection?.hooks.getCloseState?.();
        return value && typeof value.then === "function"
          ? value.then((state) => metadata(state, record.view), failure)
          : metadata(value, record.view);
      } catch {
        warn();
        return failure();
      }
    },
    cancelScan(id) {
      const record = records.get(id);
      if (record) return invoke(record, "cancelScan");
    },
    navigate(id, view) {
      const record = records.get(id);
      if (!record || !isWorkspaceView(view)) return false;
      const initial =
        record.view || getWorkspaceFrame(record.iframe.src, browser)?.view;
      if (!sameWorkspaceTool(initial, view)) return false;
      record.requestedView = view;
      if (!record.connection) return false;
      record.view = view;
      invoke(record, "navigate", view);
      return true;
    },
    dispose() {
      for (const id of [...records.keys()]) unregister(id);
      disposed = true;
    },
  };
}

export function connectWorkspaceClient({
  window: browser = globalThis.window,
  id,
  view,
  hooks = {},
}) {
  try {
    if (
      !browser ||
      browser.parent === browser ||
      !safeId(id) ||
      !isWorkspaceView(view) ||
      browser.parent.location.origin !== browser.location.origin
    )
      return null;
    const host = browser.parent.__omrWorkspaceHost;
    if (!host || typeof host.connect !== "function") return null;
    return host.connect({ source: browser, id, view, hooks });
  } catch {
    return null;
  }
}
