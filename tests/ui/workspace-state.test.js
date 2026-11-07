import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_WORKSPACE_WINDOWS,
  MAX_WORKSPACE_BYTES,
  workspaceZoom,
  workspaceTool,
  clampWindowBounds,
  defaultWindowBounds,
  displayedWindowBounds,
  emptyWorkspaceLayout,
  sanitizeWorkspaceLayout,
  readWorkspaceLayout,
  readWorkspaceLayoutStatus,
  writeWorkspaceLayout,
  arrangeWindowBounds,
  retileWorkspaceWindows,
} from "../../app/static/workspace-state.js";

const tools = [
  {
    id: "interfaces",
    view: "interfaces",
    aliases: ["vlans", "virtual_interfaces"],
    title: "Interfaces",
    minWidth: 320,
    minHeight: 180,
    width: 600,
    height: 400,
  },
  {
    id: "nat",
    view: "nat",
    title: "NAT",
    minWidth: 320,
    minHeight: 180,
    width: 600,
    height: 400,
  },
];
const viewport = { width: 1280, height: 800 };
const window = (id = "win-1", view = "interfaces") => ({
  id,
  view,
  toolId: view,
  bounds: { x: 20, y: 30, width: 600, height: 400 },
  mode: "normal",
  minimized: false,
  zoom: 100,
});
const layout = (...windows) => ({
  version: 1,
  windows,
  active: windows.at(-1)?.id || null,
});

function memoryStorage(text = null) {
  const calls = [];
  return {
    getItem: () => text,
    setItem: (key, value) => {
      text = value;
      calls.push([key, value]);
    },
    text: () => text,
    calls,
  };
}

test("registry-owned aliases resolve to one family and unknown views never become URLs", () => {
  assert.equal(workspaceTool(tools, "vlans"), tools[0]);
  assert.equal(workspaceTool(tools, "virtual_interfaces"), tools[0]);
  for (const view of [
    "https://attacker.test",
    "../../etc/passwd",
    "<script>",
    "unknown",
  ])
    assert.equal(workspaceTool(tools, view), undefined);
  assert.deepEqual(
    sanitizeWorkspaceLayout(layout(window("bad", "unknown")), tools, viewport),
    emptyWorkspaceLayout(),
  );
});

test("stored layout accepts only bounded known unique windows and never restores forms or activity", () => {
  const original = layout(
    {
      ...window(),
      form: { password: "secret" },
      output: "sensitive diagnostics",
      activity: { active: true },
    },
    window("win-2", "vlans"),
    window("win-1", "nat"),
    window("win-3", "nat"),
  );
  original.token = "credential";
  const restored = sanitizeWorkspaceLayout(original, tools, viewport);
  assert.equal(restored.windows.length, 2);
  assert.deepEqual(
    restored.windows.map((item) => item.id),
    ["win-1", "win-3"],
  );
  assert.equal(restored.active, "win-3");
  const text = JSON.stringify(restored);
  for (const forbidden of [
    "password",
    "secret",
    "output",
    "sensitive",
    "activity",
    "token",
    "credential",
    "title",
  ])
    assert.ok(!text.includes(forbidden), forbidden);
  restored.windows[0].bounds.x = 100;
  assert.equal(original.windows[0].bounds.x, 20);
});

test("corrupt, stale, oversized and blocked browser storage fall back to an empty workspace", () => {
  for (const value of [
    "{",
    "null",
    '{"version":2,"windows":[]}',
    "x".repeat(MAX_WORKSPACE_BYTES + 1),
    "я".repeat(MAX_WORKSPACE_BYTES / 2 + 1),
  ])
    assert.deepEqual(
      readWorkspaceLayout(memoryStorage(value), "user-router", tools, viewport),
      emptyWorkspaceLayout(),
    );
  const tooMany = layout(
    ...Array.from({ length: MAX_WORKSPACE_WINDOWS + 1 }, (_, index) =>
      window(`win-${index}`),
    ),
  );
  assert.deepEqual(
    sanitizeWorkspaceLayout(tooMany, tools, viewport),
    emptyWorkspaceLayout(),
  );
  assert.deepEqual(
    readWorkspaceLayout(
      {
        getItem() {
          throw new Error("denied");
        },
      },
      "key",
      tools,
      viewport,
    ),
    emptyWorkspaceLayout(),
  );
  assert.equal(
    writeWorkspaceLayout(
      {
        setItem() {
          throw new Error("quota");
        },
      },
      "key",
      layout(window()),
      tools,
      viewport,
    ),
    false,
  );
});

test("storage writes only the explicit per-user/per-router key and a canonical layout whitelist", () => {
  const storage = memoryStorage();
  const state = layout({ ...window(), csrf: "hidden", console: "output" });
  assert.equal(
    writeWorkspaceLayout(
      storage,
      "workspace:user:router",
      state,
      tools,
      viewport,
    ),
    true,
  );
  assert.equal(storage.calls.length, 1);
  assert.equal(storage.calls[0][0], "workspace:user:router");
  assert.deepEqual(
    readWorkspaceLayout(storage, "workspace:user:router", tools, viewport),
    sanitizeWorkspaceLayout(state, tools, viewport),
  );
  assert.equal(
    writeWorkspaceLayout(storage, "", state, tools, viewport),
    false,
  );
});

test("invalid geometry and zoom cannot create an invisible title, unbounded size or unsupported scale", () => {
  const bounded = clampWindowBounds(
    { x: -100000, y: 100000, width: 100000, height: 0 },
    viewport,
    tools[0],
  );
  assert.equal(bounded.width, 1280);
  assert.equal(bounded.height, 180);
  assert.ok(bounded.x + bounded.width >= 160);
  assert.ok(bounded.y + 38 <= viewport.height);
  const unknown = clampWindowBounds(
    { x: NaN, y: Infinity, width: "bad", height: null },
    viewport,
    tools[0],
  );
  assert.deepEqual(unknown, { x: 16, y: 16, width: 600, height: 400 });
  assert.deepEqual(
    [-100, 80, 81, 97, 100, 124, 1000, null, "125"].map(workspaceZoom),
    [80, 80, 80, 95, 100, 125, 125, 100, 100],
  );
  const sanitized = sanitizeWorkspaceLayout(
    layout({
      ...window(),
      mode: "arbitrary",
      minimized: "true",
      zoom: Infinity,
    }),
    tools,
    viewport,
  );
  assert.equal(sanitized.windows[0].mode, "normal");
  assert.equal(sanitized.windows[0].minimized, false);
  assert.equal(sanitized.windows[0].zoom, 100);
});

test("maximize, snap and mobile display geometry never mutate saved desktop bounds", () => {
  const item = window();
  const original = JSON.stringify(item.bounds);
  assert.deepEqual(
    displayedWindowBounds({ ...item, mode: "maximized" }, viewport),
    { x: 0, y: 0, width: 1280, height: 800 },
  );
  assert.deepEqual(displayedWindowBounds({ ...item, mode: "left" }, viewport), {
    x: 0,
    y: 0,
    width: 640,
    height: 800,
  });
  assert.deepEqual(
    displayedWindowBounds(
      { ...item, mode: "right" },
      { width: 1281, height: 800 },
    ),
    { x: 640, y: 0, width: 641, height: 800 },
  );
  assert.deepEqual(
    displayedWindowBounds(item, { width: 390, height: 600 }, true),
    { x: 0, y: 0, width: 390, height: 600 },
  );
  assert.equal(JSON.stringify(item.bounds), original);
});

test("new windows fit fully and arranging uses detached bounds while preserving minimized windows", () => {
  for (let index = 0; index < 32; index++) {
    const bounds = defaultWindowBounds(tools[0], index, viewport);
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= viewport.width);
    assert.ok(bounds.y >= 0 && bounds.y + bounds.height <= viewport.height);
  }
  const items = [
    window(),
    { ...window("win-2", "nat"), minimized: true, mode: "maximized" },
  ];
  const before = JSON.stringify(items);
  const tiled = arrangeWindowBounds(items, tools, viewport, "tile");
  assert.equal(tiled[1].minimized, true);
  assert.equal(tiled[1].mode, "maximized");
  const gathered = arrangeWindowBounds(items, tools, viewport, "gather");
  assert.ok(
    gathered.every((item) => !item.minimized && item.mode === "normal"),
  );
  assert.equal(JSON.stringify(items), before);
  assert.notEqual(gathered[0].bounds, items[0].bounds);
});

test("active restoration chooses an existing visible window rather than an unknown or minimized ID", () => {
  const first = window();
  const last = { ...window("win-2", "nat"), minimized: true };
  assert.equal(
    sanitizeWorkspaceLayout(
      { ...layout(first, last), active: "win-2" },
      tools,
      viewport,
    ).active,
    first.id,
  );
  assert.equal(
    sanitizeWorkspaceLayout(
      { ...layout(first, last), active: "unknown" },
      tools,
      viewport,
    ).active,
    first.id,
  );
  assert.equal(
    sanitizeWorkspaceLayout(
      layout({ ...first, minimized: true }, last),
      tools,
      viewport,
    ).active,
    null,
  );
});

test("an intentionally empty saved workspace is distinct from missing or invalid storage", () => {
  const empty = readWorkspaceLayoutStatus(
    memoryStorage(JSON.stringify(emptyWorkspaceLayout())),
    "key",
    tools,
    viewport,
  );
  assert.equal(empty.restored, true);
  assert.deepEqual(empty.layout, emptyWorkspaceLayout());
  for (const text of [
    null,
    "bad",
    JSON.stringify(layout(window("bad", "unknown"))),
  ])
    assert.equal(
      readWorkspaceLayoutStatus(memoryStorage(text), "key", tools, viewport)
        .restored,
      false,
    );
  const known = readWorkspaceLayoutStatus(
    memoryStorage(JSON.stringify(layout(window()))),
    "key",
    tools,
    viewport,
  );
  assert.equal(known.restored, true);
  assert.equal(known.layout.windows.length, 1);
});

function assertTiledWithoutOverlap(items, size) {
  for (const item of items) {
    const bounds = item.bounds;
    assert.ok(bounds.width > 0 && bounds.height > 0);
    assert.ok(bounds.x >= 0 && bounds.y >= 0);
    assert.ok(bounds.x + bounds.width <= size.width);
    assert.ok(bounds.y + bounds.height <= size.height);
  }
  for (let first = 0; first < items.length; first++)
    for (let last = first + 1; last < items.length; last++) {
      const a = items[first].bounds;
      const b = items[last].bounds;
      const overlapWidth =
        Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
      const overlapHeight =
        Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
      assert.ok(
        overlapWidth <= 0 || overlapHeight <= 0,
        `overlap between ${items[first].id} and ${items[last].id}`,
      );
    }
  assert.equal(
    items.reduce(
      (area, item) => area + item.bounds.width * item.bounds.height,
      0,
    ),
    size.width * size.height,
    "Integer tile edges should fill the canvas without gaps or overlaps",
  );
}

test("five large preferred forms tile without overlap at desktop and smaller sizes, including odd pixels", () => {
  const registry = Array.from({ length: 5 }, (_, index) => ({
    id: `tool${index}`,
    view: `tool${index}`,
    minWidth: 620,
    minHeight: 340,
    width: 900,
    height: 620,
  }));
  const windows = registry.map((tool, index) =>
    window(`win-${index}`, tool.view),
  );
  for (const size of [
    { width: 1216, height: 820 },
    { width: 817, height: 519 },
    { width: 390, height: 600 },
  ]) {
    const tiled = arrangeWindowBounds(windows, registry, size, "tile");
    assert.ok(tiled.every((item) => item.mode === "tiled"));
    assertTiledWithoutOverlap(tiled, size);
    assert.ok(
      tiled.some((item) => item.bounds.width < 620 || item.bounds.height < 340),
      "Tiling must relax preferred form sizes when needed",
    );
    const storage = memoryStorage();
    writeWorkspaceLayout(storage, "layout", layout(...tiled), registry, size);
    const restored = readWorkspaceLayout(storage, "layout", registry, size);
    assertTiledWithoutOverlap(restored.windows, size);
    assert.deepEqual(
      restored.windows.map((item) => item.bounds),
      tiled.map((item) => item.bounds),
    );
  }
});

test("tiled reflow preserves slot order when focus changes stacking and refits on a smaller desktop", () => {
  const registry = Array.from({ length: 5 }, (_, index) => ({
    id: `tool${index}`,
    view: `tool${index}`,
    minWidth: 620,
    minHeight: 340,
  }));
  const windows = registry.map((tool, index) =>
    window(`win-${index}`, tool.view),
  );
  const original = arrangeWindowBounds(
    windows,
    registry,
    { width: 1216, height: 820 },
    "tile",
  );
  const raised = [...original.slice(1), original[0]];
  const reflow = retileWorkspaceWindows(raised, registry, {
    width: 1216,
    height: 820,
  });
  for (const item of reflow)
    assert.deepEqual(
      item.bounds,
      original.find((before) => before.id === item.id).bounds,
    );
  const small = { width: 817, height: 519 };
  const restored = sanitizeWorkspaceLayout(layout(...raised), registry, small);
  assertTiledWithoutOverlap(restored.windows, small);
  const ordinary = clampWindowBounds(
    { width: 300, height: 200 },
    { width: 1216, height: 820 },
    registry[0],
  );
  assert.equal(
    ordinary.width,
    620,
    "Manual floating-window resizing still enforces preferred minimums",
  );
  assert.equal(ordinary.height, 340);
});
