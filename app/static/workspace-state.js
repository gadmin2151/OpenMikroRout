/** Layout is the only persistent workspace state. Forms, output and credentials
 * never enter this model or the JSON written to browser storage. */
export const WORKSPACE_VERSION = 1;
export const MAX_WORKSPACE_WINDOWS = 32;
export const MAX_WORKSPACE_BYTES = 65536;
export const MIN_WORKSPACE_ZOOM = 80;
export const MAX_WORKSPACE_ZOOM = 125;
const WINDOW_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MODES = new Set(["normal", "maximized", "left", "right", "tiled"]);
const integer = (value, fallback) =>
  typeof value === "number" && Number.isFinite(value)
    ? Math.round(value)
    : fallback;
const clamp = (value, minimum, maximum) =>
  Math.max(minimum, Math.min(maximum, value));

export function workspaceViewport(value = {}) {
  return {
    width: clamp(integer(value.width, 1024), 1, 16384),
    height: clamp(integer(value.height, 720), 1, 16384),
  };
}

export function workspaceZoom(value) {
  return clamp(
    Math.round(integer(value, 100) / 5) * 5,
    MIN_WORKSPACE_ZOOM,
    MAX_WORKSPACE_ZOOM,
  );
}

export function workspaceTool(tools, view) {
  return tools.find(
    (tool) =>
      tool.view === view || tool.id === view || tool.aliases?.includes(view),
  );
}

/** Even partly off-screen windows retain a visible title on the desktop. */
export function clampWindowBounds(
  bounds,
  viewport,
  tool = {},
  { respectMinimums = true } = {},
) {
  const size = workspaceViewport(viewport);
  const minWidth = Math.min(
    size.width,
    respectMinimums ? Math.max(200, integer(tool.minWidth, 360)) : 1,
  );
  const minHeight = Math.min(
    size.height,
    respectMinimums ? Math.max(120, integer(tool.minHeight, 240)) : 1,
  );
  const width = clamp(
    integer(bounds?.width, integer(tool.width, 900)),
    minWidth,
    size.width,
  );
  const height = clamp(
    integer(bounds?.height, integer(tool.height, 620)),
    minHeight,
    size.height,
  );
  const visibleWidth = Math.min(160, width, size.width);
  return {
    x: clamp(
      integer(bounds?.x, 16),
      visibleWidth - width,
      size.width - visibleWidth,
    ),
    y: clamp(
      integer(bounds?.y, 16),
      0,
      Math.max(0, size.height - Math.min(38, height)),
    ),
    width,
    height,
  };
}

export function defaultWindowBounds(tool, index, viewport) {
  const size = workspaceViewport(viewport);
  const offset = 18 + (index % 10) * 24;
  const bounds = clampWindowBounds(
    { x: offset, y: offset, width: tool.width, height: tool.height },
    size,
    tool,
  );
  // Newly opened windows fit fully; deliberate dragging may later overlap edges.
  bounds.x = Math.max(0, Math.min(bounds.x, size.width - bounds.width));
  bounds.y = Math.max(0, Math.min(bounds.y, size.height - bounds.height));
  return bounds;
}

export function displayedWindowBounds(window, viewport, mobile = false) {
  const size = workspaceViewport(viewport);
  if (mobile || window.mode === "maximized")
    return { x: 0, y: 0, width: size.width, height: size.height };
  if (window.mode === "left" || window.mode === "right") {
    const split = Math.floor(size.width / 2);
    return {
      x: window.mode === "left" ? 0 : split,
      y: 0,
      width: window.mode === "left" ? split : size.width - split,
      height: size.height,
    };
  }
  return { ...window.bounds };
}

export function emptyWorkspaceLayout() {
  return { version: WORKSPACE_VERSION, windows: [], active: null };
}

/** All returned objects are built field by field, so unknown fields cannot leak
 * into persisted JSON. A registry-owned tool defines every allowed view. */
export function sanitizeWorkspaceLayout(value, tools, viewport) {
  if (
    !value ||
    value.version !== WORKSPACE_VERSION ||
    !Array.isArray(value.windows) ||
    value.windows.length > MAX_WORKSPACE_WINDOWS
  )
    return emptyWorkspaceLayout();
  const ids = new Set();
  const families = new Set();
  const windows = [];
  for (const item of value.windows) {
    if (
      !item ||
      typeof item.id !== "string" ||
      !WINDOW_ID.test(item.id) ||
      ids.has(item.id)
    )
      continue;
    const tool = workspaceTool(tools, item.view);
    if (!tool || families.has(tool.id)) continue;
    ids.add(item.id);
    families.add(tool.id);
    windows.push({
      id: item.id,
      toolId: tool.id,
      view: item.view,
      bounds: clampWindowBounds(item.bounds, viewport, tool, {
        respectMinimums: item.mode !== "tiled",
      }),
      mode: MODES.has(item.mode) ? item.mode : "normal",
      minimized: item.minimized === true,
      zoom: workspaceZoom(item.zoom),
    });
  }
  const active =
    windows.find((item) => item.id === value.active && !item.minimized)?.id ||
    [...windows].reverse().find((item) => !item.minimized)?.id ||
    null;
  return {
    version: WORKSPACE_VERSION,
    windows: retileWorkspaceWindows(windows, tools, viewport),
    active,
  };
}

/** A missing, unavailable, corrupt, oversized or stale layout is harmless. */
export function readWorkspaceLayoutStatus(storage, key, tools, viewport) {
  const fallback = () => ({ restored: false, layout: emptyWorkspaceLayout() });
  if (!storage || !key) return fallback();
  try {
    const text = storage.getItem(key);
    if (
      !text ||
      text.length > MAX_WORKSPACE_BYTES ||
      new globalThis.TextEncoder().encode(text).byteLength > MAX_WORKSPACE_BYTES
    )
      return fallback();
    const value = JSON.parse(text);
    if (
      !value ||
      value.version !== WORKSPACE_VERSION ||
      !Array.isArray(value.windows) ||
      value.windows.length > MAX_WORKSPACE_WINDOWS
    )
      return fallback();
    const layout = sanitizeWorkspaceLayout(value, tools, viewport);
    if (value.windows.length && !layout.windows.length) return fallback();
    return { restored: true, layout };
  } catch {
    return fallback();
  }
}

export function readWorkspaceLayout(storage, key, tools, viewport) {
  return readWorkspaceLayoutStatus(storage, key, tools, viewport).layout;
}

export function writeWorkspaceLayout(storage, key, layout, tools, viewport) {
  if (!storage || !key) return false;
  try {
    const text = JSON.stringify(
      sanitizeWorkspaceLayout(layout, tools, viewport),
    );
    if (
      new globalThis.TextEncoder().encode(text).byteLength > MAX_WORKSPACE_BYTES
    )
      return false;
    storage.setItem(key, text);
    return true;
  } catch {
    // Layout storage is optional; quota/privacy settings cannot stop routing UI.
    return false;
  }
}

export function arrangeWindowBounds(windows, tools, viewport, arrangement) {
  const size = workspaceViewport(viewport);
  const visible =
    arrangement === "gather"
      ? windows
      : windows.filter((item) => !item.minimized);
  if (!visible.length)
    return windows.map((item) => ({ ...item, bounds: { ...item.bounds } }));
  const slots =
    arrangement === "tile" ? tiledWindowSlots(visible, tools, size) : null;
  const bounds = new Map(
    visible.map((item, index) => {
      const tool = workspaceTool(tools, item.view) || {};
      let next;
      if (arrangement === "tile") {
        next = slots[index];
      } else {
        next =
          arrangement === "cascade"
            ? defaultWindowBounds(
                {
                  ...tool,
                  width: item.bounds.width,
                  height: item.bounds.height,
                },
                index,
                size,
              )
            : clampWindowBounds(item.bounds, size, tool);
        next.x = Math.max(0, Math.min(next.x, size.width - next.width));
        next.y = Math.max(0, Math.min(next.y, size.height - next.height));
      }
      return [item.id, next];
    }),
  );
  return windows.map((item) =>
    bounds.has(item.id)
      ? {
          ...item,
          mode: arrangement === "tile" ? "tiled" : "normal",
          minimized: false,
          bounds: bounds.get(item.id),
        }
      : { ...item, bounds: { ...item.bounds } },
  );
}

/** Preferred form sizes choose a useful grid; they never enlarge a tile beyond
 * its slot. Small tiles scroll inside their frame and can always be maximized. */
function tiledWindowSlots(windows, tools, viewport) {
  const size = workspaceViewport(viewport);
  const count = windows.length;
  const preferredWidth = Math.max(
    ...windows.map((item) =>
      Math.max(200, integer(workspaceTool(tools, item.view)?.minWidth, 360)),
    ),
  );
  const preferredHeight = Math.max(
    ...windows.map((item) =>
      Math.max(120, integer(workspaceTool(tools, item.view)?.minHeight, 240)),
    ),
  );
  let columns = 1;
  let bestFit = -1;
  let bestEmpty = count;
  for (let candidate = 1; candidate <= count; candidate++) {
    const rows = Math.ceil(count / candidate);
    const fit = Math.min(
      size.width / candidate / preferredWidth,
      size.height / rows / preferredHeight,
    );
    const empty = candidate * rows - count;
    if (fit > bestFit || (fit === bestFit && empty < bestEmpty)) {
      columns = candidate;
      bestFit = fit;
      bestEmpty = empty;
    }
  }
  const rows = Math.ceil(count / columns);
  return windows.map((_item, index) => {
    const row = Math.floor(index / columns);
    const rowCount = Math.min(columns, count - row * columns);
    const column = index % columns;
    const x = Math.floor((column * size.width) / rowCount);
    const y = Math.floor((row * size.height) / rows);
    return {
      x,
      y,
      width: Math.floor(((column + 1) * size.width) / rowCount) - x,
      height: Math.floor(((row + 1) * size.height) / rows) - y,
    };
  });
}

/** Reflow tiled windows after resize/restore without changing stacking order.
 * Coordinate order is stable when focusing a window changes only its z-order. */
export function retileWorkspaceWindows(windows, tools, viewport) {
  const tiled = windows
    .filter((item) => item.mode === "tiled" && !item.minimized)
    .sort(
      (a, b) =>
        a.bounds.y - b.bounds.y ||
        a.bounds.x - b.bounds.x ||
        a.id.localeCompare(b.id),
    );
  if (!tiled.length) return windows;
  const slots = tiledWindowSlots(tiled, tools, viewport);
  const bounds = new Map(tiled.map((item, index) => [item.id, slots[index]]));
  return windows.map((item) =>
    bounds.has(item.id) ? { ...item, bounds: bounds.get(item.id) } : item,
  );
}
