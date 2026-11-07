import { t } from "./i18n.js";
import {
  WORKSPACE_VERSION,
  MAX_WORKSPACE_WINDOWS,
  MIN_WORKSPACE_ZOOM,
  MAX_WORKSPACE_ZOOM,
  workspaceViewport,
  workspaceZoom,
  workspaceTool,
  clampWindowBounds,
  defaultWindowBounds,
  displayedWindowBounds,
  readWorkspaceLayoutStatus,
  writeWorkspaceLayout,
  arrangeWindowBounds,
  retileWorkspaceWindows,
} from "./workspace-state.js";

/** Every iframe is attached once and stays attached until its window is closed.
 * Geometry, focus, arrangement and language updates touch only its outer shell. */
export function createWorkspaceManager({
  container,
  tools: initialTools,
  storageKey,
  storage,
  renderIcon,
  onActive = () => {},
  onChange = () => {},
  onNavigate = () => {},
  beforeClose = async () => true,
  onFrame = () => {},
  onError = () => {},
}) {
  const document = container.ownerDocument;
  const browser = document.defaultView;
  let tools = initialTools;
  let destroyed = false;
  let gesture = null;
  let serial = 0;
  let observer = null;
  const entries = new Map();
  const listeners = [];
  const media = browser.matchMedia("(max-width: 680px)");
  let mobile = media.matches;
  let desktopSize = { width: 1440, height: 900 };
  if (storage === undefined) {
    try {
      storage = browser.localStorage;
    } catch {
      storage = null;
    }
  }
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const listen = (node, event, callback, options) => {
    node.addEventListener(event, callback, options);
    listeners.push(() => node.removeEventListener(event, callback, options));
  };
  const shell = make("div", "workspace-shell");
  const toolbar = make("div", "workspace-toolbar");
  const desktop = make("div", "workspace-surface");
  const empty = make("div", "workspace-empty");
  const emptyTitle = make("strong");
  const emptyNote = make("p");
  empty.append(emptyTitle, emptyNote);
  desktop.append(empty);
  const taskbar = make("div", "workspace-taskbar");
  const tasks = make("div", "workspace-taskbar-items");
  taskbar.append(tasks);
  const announcement = make("div", "workspace-sr-only");
  announcement.setAttribute("role", "status");
  announcement.setAttribute("aria-live", "polite");
  shell.append(toolbar, desktop, taskbar, announcement);
  container.append(shell);

  const viewport = () =>
    workspaceViewport({
      width: desktop.clientWidth || container.clientWidth || desktopSize.width,
      height:
        desktop.clientHeight ||
        Math.max(120, (container.clientHeight || desktopSize.height) - 80),
    });
  if (!mobile) desktopSize = viewport();
  const savedLayout = readWorkspaceLayoutStatus(
    storage,
    storageKey,
    tools,
    desktopSize,
  );
  let layout = savedLayout.layout;
  const button = (action, label, text, id = null) => {
    const node = make("button", "workspace-control", text);
    node.type = "button";
    node.dataset.workspaceAction = action;
    if (id) node.dataset.window = id;
    node.title = label;
    node.setAttribute("aria-label", label);
    return node;
  };
  const controls = {
    cascade: button("cascade", t("Каскадом"), "▱"),
    tile: button("tile", t("Плиткой"), "▦"),
    gather: button("gather", t("Собрать окна"), "▣"),
    reset: button("reset", t("Сбросить раскладку"), "↺"),
    left: button("left", t("Прикрепить слева"), "◧"),
    right: button("right", t("Прикрепить справа"), "◨"),
    zoomOut: button("zoom-out", t("Уменьшить масштаб"), "−"),
    zoomReset: button("zoom-reset", t("Сбросить масштаб"), "100%"),
    zoomIn: button("zoom-in", t("Увеличить масштаб"), "+"),
  };
  const arrangeControls = make("div", "workspace-toolbar-group");
  arrangeControls.append(
    controls.cascade,
    controls.tile,
    controls.gather,
    controls.reset,
  );
  const snapControls = make("div", "workspace-toolbar-group");
  snapControls.append(controls.left, controls.right);
  const zoomControls = make("div", "workspace-toolbar-group workspace-zoom");
  zoomControls.append(controls.zoomOut, controls.zoomReset, controls.zoomIn);
  toolbar.append(arrangeControls, snapControls, zoomControls);

  function snapshot() {
    return {
      version: WORKSPACE_VERSION,
      windows: layout.windows.map((item) => ({
        id: item.id,
        toolId: item.toolId,
        view: item.view,
        bounds: { ...item.bounds },
        mode: item.mode,
        minimized: item.minimized,
        zoom: item.zoom,
      })),
      active: layout.active,
    };
  }
  function get(id) {
    const item = layout.windows.find((window) => window.id === id);
    if (!item) return null;
    const tool = workspaceTool(tools, item.view);
    return {
      ...item,
      bounds: { ...item.bounds },
      title: tool?.title || item.view,
      icon: tool?.icon,
    };
  }
  const getActive = () => get(layout.active);
  const frames = () =>
    new Map([...entries].map(([id, entry]) => [id, entry.frame]));
  const report = (error) =>
    onError(error instanceof Error ? error : new Error(String(error)));
  function changed({ active = false } = {}) {
    if (destroyed) return;
    layout.windows = retileWorkspaceWindows(layout.windows, tools, desktopSize);
    paint();
    writeWorkspaceLayout(storage, storageKey, layout, tools, desktopSize);
    onChange(snapshot());
    if (active) onActive(getActive());
  }
  function activeFallback() {
    layout.active =
      [...layout.windows].reverse().find((item) => !item.minimized)?.id || null;
  }
  function setIcon(node, name) {
    if (renderIcon && typeof name === "string")
      node.innerHTML = renderIcon(name);
    else node.textContent = "◇";
  }
  function paintEntry(item, index, size = viewport()) {
    const entry = entries.get(item.id);
    if (!entry) return;
    const tool = workspaceTool(tools, item.view);
    const active = layout.active === item.id;
    const hidden = item.minimized || (mobile && !active);
    const bounds = displayedWindowBounds(item, size, mobile);
    entry.node.hidden = hidden;
    entry.node.classList.toggle("is-active", active);
    entry.node.classList.toggle("is-maximized", item.mode === "maximized");
    entry.node.classList.toggle(
      "is-snapped",
      item.mode === "left" || item.mode === "right",
    );
    entry.node.classList.toggle("is-closing", !!entry.closing);
    entry.node.classList.toggle("is-running", entry.activity?.active === true);
    entry.activityDot.hidden = entry.activity?.active !== true;
    entry.taskActivity.hidden = entry.activity?.active !== true;
    entry.node.style.zIndex = String(index + 1);
    for (const key of ["left", "top", "width", "height"])
      entry.node.style[key] =
        `${bounds[{ left: "x", top: "y" }[key] || key]}px`;
    entry.body.style.setProperty("--workspace-scale", String(item.zoom / 100));
    const title = tool?.title || item.view;
    entry.title.textContent = title;
    entry.node.setAttribute("aria-label", title);
    entry.frame.title = title;
    entry.taskLabel.textContent = title;
    entry.task.classList.toggle("is-active", active && !item.minimized);
    entry.task.classList.toggle("is-minimized", item.minimized);
    entry.task.setAttribute("aria-pressed", String(active && !item.minimized));
    entry.task.title = entry.activity?.active
      ? `${title} · ${t("Выполняется")}`
      : title;
    entry.task.setAttribute("aria-label", entry.task.title);
    entry.maximize.textContent = item.mode === "maximized" ? "❐" : "□";
    entry.maximize.title = t(
      item.mode === "maximized" ? "Восстановить" : "Развернуть окно",
    );
    entry.maximize.setAttribute("aria-label", entry.maximize.title);
    entry.close.disabled = !!entry.closing;
  }
  function paint() {
    shell.classList.toggle("is-mobile", mobile);
    empty.hidden = layout.windows.some((item) => !item.minimized);
    const size = viewport();
    layout.windows.forEach((item, index) => paintEntry(item, index, size));
    const active = getActive();
    const noWindow = !active;
    for (const control of [controls.left, controls.right, controls.zoomReset])
      control.disabled = noWindow;
    controls.zoomOut.disabled = noWindow || active.zoom <= MIN_WORKSPACE_ZOOM;
    controls.zoomIn.disabled = noWindow || active.zoom >= MAX_WORKSPACE_ZOOM;
    controls.zoomReset.textContent = `${active?.zoom || 100}%`;
    controls.reset.disabled = !layout.windows.length;
    for (const control of [controls.cascade, controls.tile, controls.gather])
      control.disabled = !layout.windows.length || mobile;
    controls.left.disabled ||= mobile;
    controls.right.disabled ||= mobile;
  }
  function localize() {
    desktop.setAttribute("aria-label", t("Рабочий стол"));
    taskbar.setAttribute("aria-label", t("Открытые окна"));
    toolbar.setAttribute("aria-label", t("Рабочий стол"));
    zoomControls.setAttribute("aria-label", t("Масштаб окна"));
    emptyTitle.textContent = t("Нет открытых окон");
    emptyNote.textContent = t(
      "Откройте раздел в меню слева. Окна можно перемещать и менять их размер.",
    );
    for (const [key, label] of Object.entries({
      cascade: t("Каскадом"),
      tile: t("Плиткой"),
      gather: t("Собрать окна"),
      reset: t("Сбросить раскладку"),
      left: t("Прикрепить слева"),
      right: t("Прикрепить справа"),
      zoomOut: t("Уменьшить масштаб"),
      zoomReset: t("Сбросить масштаб"),
      zoomIn: t("Увеличить масштаб"),
    })) {
      controls[key].title = label;
      controls[key].setAttribute("aria-label", label);
    }
    for (const entry of entries.values()) {
      entry.title.title = t(
        "Переместить окно: Alt + стрелки. Изменить размер: Alt + Shift + стрелки.",
      );
      entry.minimize.title = t("Свернуть");
      entry.minimize.setAttribute("aria-label", t("Свернуть"));
      entry.close.title = t("Закрыть окно");
      entry.close.setAttribute("aria-label", t("Закрыть окно"));
      entry.loading.textContent = t("Загрузка окна…");
      for (const indicator of [entry.activityDot, entry.taskActivity])
        indicator.setAttribute("aria-label", t("Выполняется"));
      const tool = workspaceTool(tools, get(entry.id)?.view);
      setIcon(entry.icon, tool?.icon);
      setIcon(entry.taskIcon, tool?.icon);
    }
  }
  function attach(item) {
    const node = make("section", "workspace-window");
    node.dataset.window = item.id;
    node.setAttribute("role", "region");
    const titlebar = make("div", "workspace-titlebar");
    const icon = make("span", "workspace-window-icon");
    icon.setAttribute("aria-hidden", "true");
    const title = make("button", "workspace-window-title");
    title.type = "button";
    const activityDot = make("span", "workspace-activity-dot");
    activityDot.hidden = true;
    activityDot.setAttribute("role", "status");
    const windowControls = make("div", "workspace-window-controls");
    const minimizeButton = button("minimize", t("Свернуть"), "−", item.id);
    const maximizeButton = button(
      "maximize",
      t("Развернуть окно"),
      "□",
      item.id,
    );
    const closeButton = button("close", t("Закрыть окно"), "×", item.id);
    windowControls.append(minimizeButton, maximizeButton, closeButton);
    titlebar.append(icon, title, activityDot, windowControls);
    const body = make("div", "workspace-window-body");
    const loading = make("div", "workspace-loading", t("Загрузка окна…"));
    const frame = make("iframe", "workspace-frame");
    frame.dataset.workspaceFrame = item.id;
    frame.referrerPolicy = "same-origin";
    const params = new URLSearchParams({ view: item.view, window: item.id });
    frame.src = `/workspace-frame?${params}`;
    frame.addEventListener("load", () => {
      loading.hidden = true;
    });
    body.append(loading);
    node.append(titlebar, body);
    for (const direction of ["n", "ne", "e", "se", "s", "sw", "w", "nw"]) {
      const handle = make(
        "div",
        `workspace-resize workspace-resize-${direction}`,
      );
      handle.dataset.resizeDirection = direction;
      handle.setAttribute("aria-hidden", "true");
      node.append(handle);
    }
    const task = button("task", "", "", item.id);
    task.className = "workspace-task";
    const taskIcon = make("span", "workspace-task-icon");
    taskIcon.setAttribute("aria-hidden", "true");
    const taskLabel = make("span", "workspace-task-label");
    const taskActivity = make("span", "workspace-activity-dot");
    taskActivity.hidden = true;
    taskActivity.setAttribute("role", "status");
    task.append(taskIcon, taskLabel, taskActivity);
    const entry = {
      id: item.id,
      node,
      titlebar,
      title,
      icon,
      body,
      frame,
      loading,
      task,
      taskIcon,
      taskLabel,
      minimize: minimizeButton,
      maximize: maximizeButton,
      close: closeButton,
      activityDot,
      taskActivity,
      activity: null,
      closing: null,
      cleanup: null,
    };
    entries.set(item.id, entry);
    try {
      // Registration is synchronous and happens before the iframe can load.
      const cleanup = onFrame(get(item.id), frame);
      if (typeof cleanup === "function") entry.cleanup = cleanup;
      body.append(frame);
      desktop.append(node);
      tasks.append(task);
    } catch (error) {
      entries.delete(item.id);
      entry.cleanup?.();
      report(error);
      return false;
    }
    return true;
  }
  function focus(id) {
    const item = layout.windows.find((window) => window.id === id);
    if (!item || destroyed) return null;
    if (
      !item.minimized &&
      layout.active === id &&
      layout.windows.at(-1)?.id === id
    )
      return get(id);
    item.minimized = false;
    layout.windows = [
      ...layout.windows.filter((window) => window !== item),
      item,
    ];
    layout.active = id;
    changed({ active: true });
    // Raising a window never focuses/reloads/reparents its iframe. The existing
    // caret and selection remain owned by that frame until the user clicks it.
    return get(id);
  }
  function open(view) {
    if (destroyed) return null;
    const tool = workspaceTool(tools, view);
    if (!tool) return null;
    const existing = layout.windows.find((item) => item.toolId === tool.id);
    if (existing) {
      const result = focus(existing.id);
      if (existing.view !== view)
        onNavigate(result, entries.get(existing.id).frame, view);
      return result;
    }
    if (layout.windows.length >= MAX_WORKSPACE_WINDOWS) {
      report(new Error(t("Нельзя открыть больше 32 окон.")));
      return null;
    }
    const id =
      browser.crypto?.randomUUID?.() ||
      `w-${Date.now().toString(36)}-${++serial}`;
    const item = {
      id,
      toolId: tool.id,
      view,
      bounds: defaultWindowBounds(tool, layout.windows.length, desktopSize),
      mode: "normal",
      minimized: false,
      zoom: 100,
    };
    layout.windows.push(item);
    if (!attach(item)) {
      layout.windows = layout.windows.filter((window) => window !== item);
      return null;
    }
    localize();
    return focus(id);
  }
  async function close(id) {
    const entry = entries.get(id);
    if (!entry || destroyed) return false;
    if (entry.closing) return entry.closing;
    const closing = (async () => {
      try {
        if (
          !(await beforeClose(get(id), entry.frame)) ||
          destroyed ||
          !entries.has(id)
        )
          return false;
        try {
          entry.cleanup?.();
        } catch (error) {
          report(error);
        }
        entry.frame.remove();
        entry.node.remove();
        entry.task.remove();
        entries.delete(id);
        layout.windows = layout.windows.filter((item) => item.id !== id);
        if (layout.active === id) activeFallback();
        changed({ active: true });
        return true;
      } catch (error) {
        report(error);
        return false;
      } finally {
        entry.closing = null;
        if (!destroyed) paint();
      }
    })();
    entry.closing = closing;
    paint();
    return closing;
  }
  function minimize(id) {
    const item = layout.windows.find((window) => window.id === id);
    if (!item) return false;
    item.minimized = true;
    if (layout.active === id) activeFallback();
    changed({ active: true });
    return true;
  }
  function setMode(id, mode) {
    const item = layout.windows.find((window) => window.id === id);
    if (!item) return false;
    item.mode = mode;
    focus(id);
    return true;
  }
  function maximize(id) {
    return setMode(id, "maximized");
  }
  function restore(id) {
    return setMode(id, "normal");
  }
  function snap(id, side) {
    return ["left", "right"].includes(side) && setMode(id, side);
  }
  function setZoom(value, id = layout.active) {
    const item = layout.windows.find((window) => window.id === id);
    if (!item) return false;
    item.zoom = workspaceZoom(value);
    changed();
    return true;
  }
  function arrange(arrangement) {
    if (!["cascade", "tile", "gather"].includes(arrangement) || mobile)
      return false;
    layout.windows = arrangeWindowBounds(
      layout.windows,
      tools,
      viewport(),
      arrangement,
    );
    if (!layout.active) activeFallback();
    changed({ active: true });
    return true;
  }
  function resetLayout() {
    layout.windows = layout.windows.map((item, index) => ({
      ...item,
      bounds: defaultWindowBounds(
        workspaceTool(tools, item.view) || {},
        index,
        desktopSize,
      ),
      mode: "normal",
      minimized: false,
      zoom: 100,
    }));
    if (!layout.active) activeFallback();
    changed({ active: true });
    return true;
  }
  function setView(id, view) {
    const item = layout.windows.find((window) => window.id === id);
    const tool = workspaceTool(tools, view);
    if (!item || !tool || item.toolId !== tool.id || item.view === view)
      return false;
    item.view = view;
    changed();
    return true;
  }
  function setActivity(id, value) {
    const entry = entries.get(id);
    if (!entry) return false;
    const active = value?.active === true;
    const kind = typeof value?.kind === "string" ? value.kind.slice(0, 64) : "";
    if (entry.activity?.active === active && entry.activity?.kind === kind)
      return true;
    entry.activity = { active, kind };
    const item = layout.windows.find((window) => window.id === id);
    if (item) paintEntry(item, layout.windows.indexOf(item));
    return true;
  }
  function setTools(next) {
    tools = next;
    localize();
    changed();
  }
  function resized() {
    if (destroyed) return;
    mobile = media.matches;
    if (!mobile) {
      desktopSize = viewport();
      for (const item of layout.windows)
        item.bounds = clampWindowBounds(
          item.bounds,
          desktopSize,
          workspaceTool(tools, item.view),
          { respectMinimums: item.mode !== "tiled" },
        );
    }
    changed();
  }
  function beginGesture(event) {
    if (event.button !== 0 || mobile || gesture) return;
    const target = event.target;
    const node = target.closest(".workspace-window");
    if (!node || target.closest(".workspace-window-controls")) return;
    const resize = target.closest("[data-resize-direction]");
    const titlebar = target.closest(".workspace-titlebar");
    if (!resize && !titlebar) return;
    const item = layout.windows.find(
      (window) => window.id === node.dataset.window,
    );
    if (!item) return;
    focus(item.id);
    const surface = desktop.getBoundingClientRect();
    const bounds = displayedWindowBounds(item, viewport());
    if (item.mode !== "normal") {
      if (resize) item.bounds = bounds;
      else {
        const fraction = Math.max(
          0,
          Math.min(1, (event.clientX - surface.left - bounds.x) / bounds.width),
        );
        item.bounds.x =
          event.clientX - surface.left - item.bounds.width * fraction;
        item.bounds.y = Math.max(0, event.clientY - surface.top - 18);
      }
      item.mode = "normal";
    }
    const handle = resize || titlebar;
    gesture = {
      id: item.id,
      pointer: event.pointerId,
      handle,
      direction: resize?.dataset.resizeDirection,
      x: event.clientX,
      y: event.clientY,
      bounds: { ...item.bounds },
    };
    shell.classList.add("is-interacting");
    try {
      handle.setPointerCapture(event.pointerId);
    } catch {
      /* Pointer may have already ended. */
    }
    event.preventDefault();
    paint();
  }
  function moveGesture(event) {
    if (!gesture || gesture.pointer !== event.pointerId) return;
    const item = layout.windows.find((window) => window.id === gesture.id);
    if (!item) return;
    const dx = event.clientX - gesture.x,
      dy = event.clientY - gesture.y;
    const bounds = { ...gesture.bounds };
    if (!gesture.direction) {
      bounds.x += dx;
      bounds.y += dy;
    } else {
      const direction = gesture.direction;
      if (direction.includes("e")) bounds.width += dx;
      if (direction.includes("s")) bounds.height += dy;
      if (direction.includes("w")) {
        bounds.x += dx;
        bounds.width -= dx;
      }
      if (direction.includes("n")) {
        bounds.y += dy;
        bounds.height -= dy;
      }
    }
    item.bounds = clampWindowBounds(
      bounds,
      viewport(),
      workspaceTool(tools, item.view),
    );
    if (gesture.direction?.includes("w"))
      item.bounds.x =
        gesture.bounds.x + gesture.bounds.width - item.bounds.width;
    if (gesture.direction?.includes("n"))
      item.bounds.y =
        gesture.bounds.y + gesture.bounds.height - item.bounds.height;
    item.bounds = clampWindowBounds(
      item.bounds,
      viewport(),
      workspaceTool(tools, item.view),
    );
    paintEntry(item, layout.windows.indexOf(item));
  }
  function endGesture(event) {
    if (!gesture || (event && gesture.pointer !== event.pointerId)) return;
    const finished = gesture;
    gesture = null;
    try {
      finished.handle.releasePointerCapture(finished.pointer);
    } catch {
      /* Capture can end on cancellation. */
    }
    shell.classList.remove("is-interacting");
    changed();
  }
  listen(shell, "pointerdown", beginGesture);
  listen(shell, "pointermove", moveGesture);
  listen(shell, "pointerup", endGesture);
  listen(shell, "pointercancel", endGesture);
  listen(shell, "lostpointercapture", endGesture);
  listen(shell, "dblclick", (event) => {
    if (
      mobile ||
      !event.target.closest(".workspace-titlebar") ||
      event.target.closest(".workspace-window-controls")
    )
      return;
    const item = get(event.target.closest(".workspace-window")?.dataset.window);
    if (item)
      setMode(item.id, item.mode === "maximized" ? "normal" : "maximized");
  });
  listen(shell, "keydown", (event) => {
    if (
      !event.altKey ||
      !event.key.startsWith("Arrow") ||
      mobile ||
      !event.target.closest(".workspace-window-title")
    )
      return;
    const item = layout.windows.find(
      (window) =>
        window.id === event.target.closest(".workspace-window")?.dataset.window,
    );
    if (!item) return;
    event.preventDefault();
    const bounds = displayedWindowBounds(item, viewport());
    item.mode = "normal";
    const dx =
      event.key === "ArrowRight" ? 10 : event.key === "ArrowLeft" ? -10 : 0;
    const dy =
      event.key === "ArrowDown" ? 10 : event.key === "ArrowUp" ? -10 : 0;
    if (event.shiftKey) {
      bounds.width += dx;
      bounds.height += dy;
    } else {
      bounds.x += dx;
      bounds.y += dy;
    }
    item.bounds = clampWindowBounds(
      bounds,
      viewport(),
      workspaceTool(tools, item.view),
    );
    announcement.textContent = t(
      event.shiftKey ? "Размер окна изменён" : "Окно перемещено",
    );
    changed();
  });
  listen(shell, "click", (event) => {
    const control = event.target.closest("[data-workspace-action]");
    if (!control || control.disabled) return;
    const action = control.dataset.workspaceAction;
    const id = control.dataset.window || layout.active;
    if (action === "close") void close(id);
    else if (action === "minimize") minimize(id);
    else if (action === "maximize") {
      const item = get(id);
      if (item) setMode(id, item.mode === "maximized" ? "normal" : "maximized");
    } else if (action === "task") {
      if (id === layout.active && !mobile) minimize(id);
      else focus(id);
    } else if (["cascade", "tile", "gather"].includes(action)) arrange(action);
    else if (action === "reset") resetLayout();
    else if (action === "left" || action === "right") snap(id, action);
    else if (action === "zoom-reset") setZoom(100);
    else if (action === "zoom-out") setZoom((getActive()?.zoom || 100) - 5);
    else if (action === "zoom-in") setZoom((getActive()?.zoom || 100) + 5);
  });
  if (browser.ResizeObserver) {
    observer = new browser.ResizeObserver(resized);
    observer.observe(desktop);
  } else listen(browser, "resize", resized);
  listen(media, "change", resized);
  for (const item of [...layout.windows]) {
    if (!attach(item))
      layout.windows = layout.windows.filter((window) => window !== item);
  }
  if (
    !layout.windows.some((item) => item.id === layout.active && !item.minimized)
  )
    activeFallback();
  localize();
  changed({ active: true });

  return {
    restored: savedLayout.restored,
    resetLayout,
    open,
    focus,
    close,
    minimize,
    maximize,
    restore,
    snap,
    arrange,
    setTools,
    setView,
    setActivity,
    setZoom,
    zoomBy: (delta) => setZoom((getActive()?.zoom || 100) + delta),
    resetZoom: () => setZoom(100),
    snapshot,
    frames,
    get,
    getActive,
    destroy() {
      if (destroyed) return;
      destroyed = true;
      if (gesture) {
        try {
          gesture.handle.releasePointerCapture(gesture.pointer);
        } catch {
          /* Already released. */
        }
        gesture = null;
      }
      observer?.disconnect();
      for (const remove of listeners) remove();
      for (const entry of entries.values()) {
        try {
          entry.cleanup?.();
        } catch (error) {
          report(error);
        }
      }
      entries.clear();
      shell.remove();
    },
  };
}
