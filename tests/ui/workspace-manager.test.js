import test from "node:test";
import assert from "node:assert/strict";
import { createWorkspaceManager } from "../../app/static/workspace-manager.js";
import { setLanguage } from "../../app/static/i18n.js";

const tools = [
  {
    id: "interfaces",
    view: "interfaces",
    aliases: ["vlans"],
    title: "Interfaces",
    width: 600,
    height: 400,
    minWidth: 320,
    minHeight: 180,
  },
  {
    id: "nat",
    view: "nat",
    title: "NAT",
    width: 600,
    height: 400,
    minWidth: 320,
    minHeight: 180,
  },
];

/** Instrument attachment/removal and geometry separately from the browser's
 * renderer. No iframe can silently detach/reload/focus without failing a test. */
function fixture(options = {}) {
  const environment = {
    width: 1280,
    height: 800,
    mobile: false,
    created: [],
    detached: [],
    focusCalls: 0,
    attributeWrites: 0,
    writes: [],
    read: null,
  };
  class Events {
    handlers = new Map();
    addEventListener(type, listener) {
      if (!this.handlers.has(type)) this.handlers.set(type, new Set());
      this.handlers.get(type).add(listener);
    }
    removeEventListener(type, listener) {
      this.handlers.get(type)?.delete(listener);
    }
    emit(type, event = {}) {
      for (const listener of this.handlers.get(type) || [])
        listener({ type, ...event });
    }
  }
  const media = new Events();
  Object.defineProperty(media, "matches", { get: () => environment.mobile });
  const browser = new Events();
  browser.matchMedia = () => media;
  browser.crypto = {
    randomUUID: () => `win-${environment.created.length + 1}`,
  };
  let document;
  class Node extends Events {
    children = [];
    parentNode = null;
    dataset = {};
    attributes = new Map();
    hidden = false;
    textContent = "";
    style = {
      setProperty(name, value) {
        this[name] = value;
      },
    };
    classList = {
      contains: (name) => this.className.split(" ").includes(name),
      toggle: (name, enabled) => {
        const values = new Set(this.className.split(" ").filter(Boolean));
        if (enabled) values.add(name);
        else values.delete(name);
        this.className = [...values].join(" ");
      },
      add: (name) => this.classList.toggle(name, true),
      remove: (name) => this.classList.toggle(name, false),
    };
    constructor(tag) {
      super();
      this.tagName = tag.toUpperCase();
      this.className = "";
      this.ownerDocument = document;
      if (tag === "iframe") {
        environment.created.push(this);
        this.contentWindow = {};
      }
    }
    get clientWidth() {
      return environment.width;
    }
    get clientHeight() {
      return this.classList.contains("workspace-surface")
        ? environment.height - 80
        : environment.height;
    }
    append(...nodes) {
      for (const node of nodes) {
        if (node.parentNode) node.remove();
        node.parentNode = this;
        this.children.push(node);
      }
    }
    remove() {
      if (!this.parentNode) return;
      const frames =
        this.tagName === "IFRAME"
          ? [this]
          : this.descendants().filter((node) => node.tagName === "IFRAME");
      environment.detached.push(...frames);
      this.parentNode.children = this.parentNode.children.filter(
        (node) => node !== this,
      );
      this.parentNode = null;
    }
    set innerHTML(value) {
      assert.equal(
        this.descendants().some((node) => node.tagName === "IFRAME"),
        false,
        "An iframe ancestor was replaced with innerHTML",
      );
      this.html = value;
    }
    setAttribute(key, value) {
      environment.attributeWrites++;
      this.attributes.set(key, String(value));
    }
    getAttribute(key) {
      return this.attributes.get(key);
    }
    descendants() {
      return this.children.flatMap((node) => [node, ...node.descendants()]);
    }
    matches(selector) {
      if (selector.startsWith("."))
        return this.classList.contains(selector.slice(1));
      const data = /^\[data-([\w-]+)\]$/.exec(selector);
      if (data)
        return Object.hasOwn(
          this.dataset,
          data[1].replace(/-([a-z])/g, (_, char) => char.toUpperCase()),
        );
      return false;
    }
    closest(selector) {
      return this.matches(selector)
        ? this
        : this.parentNode?.closest(selector) || null;
    }
    getBoundingClientRect() {
      return {
        left: 0,
        top: 40,
        width: environment.width,
        height: environment.height - 80,
      };
    }
    setPointerCapture(pointer) {
      this.pointer = pointer;
    }
    releasePointerCapture(pointer) {
      assert.equal(this.pointer, pointer);
      this.pointer = null;
    }
    focus() {
      environment.focusCalls++;
    }
  }
  document = { defaultView: browser, createElement: (tag) => new Node(tag) };
  const container = new Node("div");
  const registered = [];
  const changes = [];
  const manager = createWorkspaceManager({
    container,
    tools,
    storageKey: "workspace:user:router",
    storage: {
      getItem: () => environment.read,
      setItem: (key, text) => environment.writes.push([key, text]),
    },
    onFrame(record, frame) {
      assert.equal(
        frame.parentNode,
        null,
        "Bridge must register before initial attachment",
      );
      registered.push([record, frame]);
    },
    onChange: (state) => changes.push(state),
    ...options,
  });
  const find = (className) =>
    container.descendants().find((node) => node.classList.contains(className));
  return {
    manager,
    container,
    environment,
    registered,
    changes,
    media,
    find,
    browser,
  };
}

test("focus, move, resize, layout, zoom and locale preserve every existing iframe and its contentWindow", () => {
  const f = fixture();
  const first = f.manager.open("interfaces");
  const second = f.manager.open("nat");
  const frames = f.manager.frames();
  const sources = [...frames].map(([id, frame]) => [
    id,
    frame,
    frame.src,
    frame.contentWindow,
  ]);
  for (const action of [
    () => f.manager.focus(first.id),
    () => f.manager.minimize(first.id),
    () => f.manager.focus(first.id),
    () => f.manager.maximize(first.id),
    () => f.manager.restore(first.id),
    () => f.manager.snap(first.id, "left"),
    () => f.manager.snap(second.id, "right"),
    () => f.manager.arrange("tile"),
    () => f.manager.arrange("cascade"),
    () => f.manager.arrange("gather"),
    () => f.manager.setZoom(125, first.id),
    () =>
      f.manager.setTools(
        tools.map((tool) => ({ ...tool, title: `RU ${tool.title}` })),
      ),
  ])
    action();
  for (const [id, frame, src, contentWindow] of sources) {
    assert.equal(f.manager.frames().get(id), frame);
    assert.equal(frame.src, src);
    assert.equal(frame.contentWindow, contentWindow);
    assert.ok(frame.parentNode);
  }
  assert.equal(f.manager.get(first.id).title, "RU Interfaces");
  assert.equal(f.environment.created.length, 2);
  assert.equal(f.environment.detached.length, 0);
  assert.equal(
    f.environment.focusCalls,
    0,
    "Raising windows must not steal the frame caret",
  );
  assert.equal(f.registered.length, 2);
  f.manager.destroy();
});

test("alias navigation reuses a family and synchronizes view without modifying iframe.src", () => {
  const requests = [];
  const f = fixture({
    onNavigate: (record, frame, view) =>
      requests.push([record.id, frame, view]),
  });
  const opened = f.manager.open("interfaces");
  const frame = f.manager.frames().get(opened.id);
  const source = frame.src;
  const alias = f.manager.open("vlans");
  assert.equal(alias.id, opened.id);
  assert.deepEqual(requests, [[opened.id, frame, "vlans"]]);
  assert.equal(f.manager.setView(opened.id, "vlans"), true);
  assert.equal(f.manager.get(opened.id).view, "vlans");
  assert.equal(f.manager.setView(opened.id, "nat"), false);
  assert.equal(frame.src, source);
  assert.equal(f.environment.created.length, 1);
  assert.equal(f.manager.open("https://attacker.test"), null);
  f.manager.destroy();
});

test("close waits for one confirmation and cancels safely without detaching the frame", async () => {
  let resolve;
  let proofs = 0;
  const f = fixture({
    beforeClose: () => {
      proofs++;
      return new Promise((done) => {
        resolve = done;
      });
    },
  });
  const opened = f.manager.open("nat");
  const pending = f.manager.close(opened.id);
  const duplicate = f.manager.close(opened.id);
  assert.equal(proofs, 1);
  assert.equal(f.manager.frames().size, 1);
  resolve(false);
  assert.equal(await pending, false);
  assert.equal(await duplicate, false);
  assert.equal(f.environment.detached.length, 0);
  const allowed = f.manager.close(opened.id);
  resolve(true);
  assert.equal(await allowed, true);
  assert.equal(f.manager.frames().size, 0);
  assert.equal(f.environment.detached.length, 1);
  assert.equal(f.manager.getActive(), null);
  f.manager.destroy();
});

test("mobile switches full-screen panels while preserving desktop bounds and frame instances", () => {
  const f = fixture();
  const first = f.manager.open("interfaces");
  const second = f.manager.open("nat");
  const before = f.manager.snapshot();
  const frames = f.manager.frames();
  f.environment.mobile = true;
  f.environment.width = 390;
  f.environment.height = 700;
  f.media.emit("change");
  assert.deepEqual(f.manager.get(first.id).bounds, first.bounds);
  assert.deepEqual(f.manager.get(second.id).bounds, second.bounds);
  const firstWindow = frames.get(first.id).closest(".workspace-window");
  const secondWindow = frames.get(second.id).closest(".workspace-window");
  assert.equal(firstWindow.hidden, true);
  assert.equal(secondWindow.hidden, false);
  assert.equal(secondWindow.style.width, "390px");
  f.manager.focus(first.id);
  assert.equal(firstWindow.hidden, false);
  assert.equal(secondWindow.hidden, true);
  f.environment.mobile = false;
  f.environment.width = 1280;
  f.environment.height = 800;
  f.media.emit("change");
  assert.deepEqual(f.manager.get(first.id).bounds, before.windows[0].bounds);
  assert.equal(firstWindow.hidden, false);
  assert.equal(secondWindow.hidden, false);
  assert.equal(f.environment.detached.length, 0);
  f.manager.destroy();
});

test("keyboard move/resize and pointer gestures update bounded geometry without reparenting", () => {
  const f = fixture();
  const opened = f.manager.open("nat");
  const shell = f.find("workspace-shell");
  const title = f.find("workspace-window-title");
  const preventDefault = () => {};
  shell.emit("keydown", {
    target: title,
    altKey: true,
    key: "ArrowRight",
    preventDefault,
  });
  assert.equal(f.manager.get(opened.id).bounds.x, opened.bounds.x + 10);
  shell.emit("keydown", {
    target: title,
    altKey: true,
    shiftKey: true,
    key: "ArrowDown",
    preventDefault,
  });
  assert.equal(
    f.manager.get(opened.id).bounds.height,
    opened.bounds.height + 10,
  );
  const target = f.find("workspace-titlebar");
  shell.emit("pointerdown", {
    target,
    button: 0,
    pointerId: 1,
    clientX: 40,
    clientY: 80,
    preventDefault,
  });
  shell.emit("pointermove", {
    target,
    pointerId: 1,
    clientX: 90,
    clientY: 110,
  });
  shell.emit("pointerup", { target, pointerId: 1 });
  assert.equal(f.manager.get(opened.id).bounds.x, opened.bounds.x + 60);
  assert.equal(f.manager.get(opened.id).bounds.y, opened.bounds.y + 30);
  assert.equal(f.environment.detached.length, 0);
  f.manager.destroy();
});

test("activity stays volatile and duplicate focus does not rewrite storage", () => {
  const f = fixture();
  const opened = f.manager.open("nat");
  const writes = f.environment.writes.length;
  f.manager.focus(opened.id);
  assert.equal(f.environment.writes.length, writes);
  f.manager.setActivity(opened.id, { active: true, kind: "ping" });
  assert.equal(f.environment.writes.length, writes);
  assert.equal(f.find("workspace-activity-dot").hidden, false);
  const saved = JSON.stringify(f.manager.snapshot());
  assert.doesNotMatch(saved, /activity|ping|password|output/);
  f.manager.minimize(opened.id);
  assert.equal(f.find("workspace-task").children.at(-1).hidden, false);
  const copy = f.manager.snapshot();
  copy.windows[0].bounds.x = 999;
  assert.notEqual(f.manager.get(opened.id).bounds.x, 999);
  f.manager.destroy();
});

test("reset layout preserves frames and unsaved contents while restoring default geometry and zoom", () => {
  const f = fixture();
  const first = f.manager.open("interfaces");
  const last = f.manager.open("nat");
  const frames = f.manager.frames();
  frames.get(first.id).contentWindow.unsaved = {
    value: "typed draft",
    selection: [1, 4],
  };
  f.manager.setZoom(125, first.id);
  f.manager.maximize(first.id);
  f.manager.minimize(last.id);
  f.manager.resetLayout();
  assert.ok(
    f.manager
      .snapshot()
      .windows.every(
        (item) =>
          item.zoom === 100 && !item.minimized && item.mode === "normal",
      ),
  );
  assert.equal(f.manager.frames().get(first.id), frames.get(first.id));
  assert.deepEqual(frames.get(first.id).contentWindow.unsaved, {
    value: "typed draft",
    selection: [1, 4],
  });
  assert.equal(f.environment.detached.length, 0);
  assert.equal(f.environment.created.length, 2);
  f.manager.destroy();
});

test("manager exposes valid empty restoration without automatically starting any tool", () => {
  const empty = fixture({
    storage: {
      getItem: () => JSON.stringify({ version: 1, windows: [], active: null }),
      setItem() {},
    },
  });
  assert.equal(empty.manager.restored, true);
  assert.equal(empty.manager.frames().size, 0);
  assert.equal(empty.environment.created.length, 0);
  empty.manager.destroy();
  const missing = fixture();
  assert.equal(missing.manager.restored, false);
  assert.equal(missing.manager.frames().size, 0);
  missing.manager.destroy();
});

test("five tiled frames reflow without overlap or reload after focus, minimize and desktop resizing", () => {
  const registry = Array.from({ length: 5 }, (_, index) => ({
    id: `tool${index}`,
    view: `tool${index}`,
    title: `Tool ${index}`,
    minWidth: 620,
    minHeight: 340,
    width: 900,
    height: 620,
  }));
  const f = fixture({ tools: registry });
  f.environment.width = 1216;
  f.environment.height = 900;
  f.browser.emit("resize");
  const opened = registry.map((tool) => f.manager.open(tool.view));
  const frames = f.manager.frames();
  f.manager.arrange("tile");
  const assertNoOverlap = () => {
    const items = f.manager
      .snapshot()
      .windows.filter((item) => !item.minimized);
    for (let index = 0; index < items.length; index++)
      for (let other = index + 1; other < items.length; other++) {
        const a = items[index].bounds,
          b = items[other].bounds;
        assert.ok(
          a.x + a.width <= b.x ||
            b.x + b.width <= a.x ||
            a.y + a.height <= b.y ||
            b.y + b.height <= a.y,
        );
      }
  };
  assertNoOverlap();
  const original = f.manager.get(opened[0].id).bounds;
  f.manager.focus(opened[0].id);
  assert.deepEqual(
    f.manager.get(opened[0].id).bounds,
    original,
    "Focusing a tile must not move it",
  );
  f.manager.minimize(opened[2].id);
  assertNoOverlap();
  f.manager.focus(opened[2].id);
  assertNoOverlap();
  f.environment.width = 817;
  f.environment.height = 599;
  f.browser.emit("resize");
  assertNoOverlap();
  for (const [id, frame] of frames) {
    assert.equal(f.manager.frames().get(id), frame);
    const bounds = f.manager.get(id).bounds;
    assert.ok(
      bounds.x + bounds.width <= 817 && bounds.y + bounds.height <= 519,
    );
  }
  assert.equal(f.environment.detached.length, 0);
  assert.equal(f.environment.created.length, 5);
  f.manager.destroy();
});

test("taskbar accessible names follow localized titles and running state without losing pressed semantics", () => {
  setLanguage("ru");
  const f = fixture();
  try {
    const opened = f.manager.open("nat");
    const task = f.find("workspace-task");
    assert.equal(task.getAttribute("aria-label"), "NAT");
    assert.equal(task.getAttribute("aria-pressed"), "true");
    f.manager.setActivity(opened.id, { active: true, kind: "scan" });
    assert.equal(task.getAttribute("aria-label"), "NAT · Выполняется");
    f.manager.minimize(opened.id);
    assert.equal(task.getAttribute("aria-pressed"), "false");
    assert.equal(task.getAttribute("aria-label"), "NAT · Выполняется");
    setLanguage("en");
    f.manager.setTools(
      tools.map((tool) => ({
        ...tool,
        title: tool.id === "nat" ? "Firewall NAT" : tool.title,
      })),
    );
    assert.equal(task.getAttribute("aria-label"), "Firewall NAT · Running");
    f.manager.setActivity(opened.id, { active: false, kind: "" });
    assert.equal(task.getAttribute("aria-label"), "Firewall NAT");
    f.manager.focus(opened.id);
    assert.equal(task.getAttribute("aria-pressed"), "true");
  } finally {
    f.manager.destroy();
    setLanguage("ru");
  }
});

test("unchanged one-second activity, view and focus status causes no layout writes or redundant painting", () => {
  const f = fixture();
  const opened = f.manager.open("nat");
  f.manager.setActivity(opened.id, { active: true, kind: "scan" });
  const writes = f.environment.writes.length;
  const paints = f.environment.attributeWrites;
  const changes = f.changes.length;
  for (let tick = 0; tick < 60; tick++) {
    f.manager.setActivity(opened.id, {
      active: true,
      kind: "scan",
      elapsed_seconds: tick,
    });
    f.manager.setView(opened.id, "nat");
    f.manager.focus(opened.id);
  }
  assert.equal(f.environment.writes.length, writes);
  assert.equal(f.environment.attributeWrites, paints);
  assert.equal(f.changes.length, changes);
  assert.equal(f.environment.detached.length, 0);
  f.manager.destroy();
});
