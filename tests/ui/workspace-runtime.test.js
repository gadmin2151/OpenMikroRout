import test from "node:test";
import assert from "node:assert/strict";
import {
  getWorkspaceFrame,
  createWorkspaceHost,
  connectWorkspaceClient,
  createWorkspaceNavigation,
} from "../../app/static/workspace-runtime.js";
import {
  getWorkspaceTools,
  getWorkspaceTool,
  isWorkspaceView,
  sameWorkspaceTool,
} from "../../app/static/workspace-tools.js";

function fixture(view = "interfaces", id = "window-1") {
  const parent = {
    location: {
      href: "https://router.example/",
      origin: "https://router.example",
    },
  };
  parent.parent = parent;
  const src = `https://router.example/workspace-frame?view=${view}&window=${id}`;
  const child = {
    location: { href: src, origin: parent.location.origin },
    parent,
  };
  const iframe = { src, contentWindow: child };
  return { parent, child, iframe, id, view };
}
const fullContext = {
  state: { config: {}, auth_enabled: true },
  canWrite: () => true,
};

test("registry covers tool families once and hides full-only entries from read users", () => {
  const tools = getWorkspaceTools(fullContext);
  assert.ok(tools.length < 32);
  assert.equal(new Set(tools.map((tool) => tool.id)).size, tools.length);
  for (const tool of tools) {
    assert.ok(tool.width >= tool.minWidth && tool.height >= tool.minHeight);
    assert.ok(isWorkspaceView(tool.view));
    for (const alias of tool.aliases)
      assert.equal(getWorkspaceTool(alias, fullContext).id, tool.id);
  }
  assert.equal(
    getWorkspaceTool("dhcp_reservations", fullContext).id,
    "dhcp_servers",
  );
  assert.equal(getWorkspaceTool("dns_static", fullContext).id, "dns");
  assert.equal(sameWorkspaceTool("interfaces", "vlans"), true);
  assert.equal(sameWorkspaceTool("rules", "filter"), false);
  const read = getWorkspaceTools({ ...fullContext, canWrite: () => false });
  assert.ok(!read.some((tool) => ["users", "updates"].includes(tool.view)));
  assert.ok(read.some((tool) => tool.view === "security"));
  assert.equal(isWorkspaceView("login"), false);
});

test("frame context only accepts same-origin known views and exact safe query parameters", () => {
  const f = fixture();
  assert.deepEqual(getWorkspaceFrame(f.child.location, f.child), {
    id: f.id,
    view: f.view,
  });
  for (const location of [
    "https://evil.example/workspace-frame?view=rules&window=w1",
    "/?view=rules&window=w1",
    "/workspace-frame?view=login&window=w1",
    "/workspace-frame?view=rules&window=../secret",
    "/workspace-frame?view=rules&window=w1&token=secret",
    "/workspace-frame?view=rules&view=users&window=w1",
    "/workspace-frame?view=rules&window=w1#secret",
    "javascript:alert(1)",
  ])
    assert.equal(getWorkspaceFrame(location, f.parent), null, location);
});

test("host validates the current WindowProxy, same origin and registered frame before connecting", () => {
  const f = fixture();
  const host = createWorkspaceHost({
    window: f.parent,
    read: async () => ({ revision: 1 }),
  });
  f.parent.__omrWorkspaceHost = host;
  f.iframe.contentWindow = null;
  host.register(f.id, f.iframe);
  assert.equal(
    connectWorkspaceClient({ window: f.child, id: f.id, view: f.view }),
    null,
  );
  f.iframe.contentWindow = f.child;
  assert.equal(
    host.connect({ source: { ...f.child }, id: f.id, view: f.view }),
    null,
  );
  assert.equal(
    host.connect({ source: f.child, id: f.id, view: "users" }),
    null,
  );
  f.child.location.origin = "https://evil.example";
  assert.equal(
    connectWorkspaceClient({ window: f.child, id: f.id, view: f.view }),
    null,
  );
  f.child.location.origin = f.parent.location.origin;
  assert.ok(
    connectWorkspaceClient({ window: f.child, id: f.id, view: f.view }),
  );
  host.dispose();
});

test("client metadata and lifecycle hooks keep private content out of the host", async () => {
  const f = fixture();
  const events = [],
    visible = [],
    navigated = [];
  let refreshes = 0,
    cancelled = 0,
    disposed = 0;
  const host = createWorkspaceHost({
    window: f.parent,
    read: async () => ({ revision: 3 }),
    onMutation: (event) => events.push(event),
    onNavigate: (event) => events.push(event),
    onStatus: (event) => events.push(event),
    onFocus: (event) => events.push(event),
  });
  f.parent.__omrWorkspaceHost = host;
  host.register(f.id, f.iframe);
  host.setVisible(f.id, false);
  const client = connectWorkspaceClient({
    window: f.child,
    id: f.id,
    view: f.view,
    hooks: {
      setVisible: (value) => visible.push(value),
      requestRefresh: () => refreshes++,
      getCloseState: () => ({ dirty: true, active: true, password: "private" }),
      cancelScan: () => cancelled++,
      dispose: () => disposed++,
      navigate: (view) => navigated.push(view),
    },
  });
  assert.equal(client.visible, false);
  assert.deepEqual(visible, [false]);
  host.setVisible(f.id, true);
  assert.equal(client.visible, true);
  host.requestRefresh();
  host.cancelScan(f.id);
  assert.equal(refreshes, 1);
  assert.equal(cancelled, 1);
  assert.equal(host.navigate(f.id, "vlans"), true);
  assert.deepEqual(navigated, ["vlans"]);
  assert.equal(host.navigate(f.id, "users"), false);
  assert.deepEqual(await client.read("state"), { revision: 3 });
  await assert.rejects(client.read("me/totp"), /shared/);
  client.notifyMutation("config");
  client.focus();
  client.navigate("rules");
  client.publishStatus({
    kind: "scan",
    active: true,
    dirty: true,
    view: "interface_lists",
    jobId: "a".repeat(32),
    password: "private",
    output: "private",
  });
  const event = events.at(-1);
  assert.equal(event.view, "interface_lists");
  assert.deepEqual(event.status, {
    kind: "scan",
    active: true,
    dirty: true,
    view: "interface_lists",
    jobId: "a".repeat(32),
  });
  assert.deepEqual(host.getCloseState(f.id), {
    dirty: true,
    active: true,
    kind: "idle",
    jobId: null,
  });
  assert.doesNotMatch(JSON.stringify(events), /private|password|output/);
  host.unregister(f.id);
  assert.equal(disposed, 1);
  await assert.rejects(client.read("state"), { name: "AbortError" });
  host.dispose();
});

test("session end revokes all clients, disposes hooks and suppresses late read responses", async () => {
  const f = fixture();
  let resolve,
    sessionEnds = 0,
    disposed = 0;
  const host = createWorkspaceHost({
    window: f.parent,
    read: () =>
      new Promise((done) => {
        resolve = done;
      }),
    onSessionEnd: () => sessionEnds++,
  });
  f.parent.__omrWorkspaceHost = host;
  host.register(f.id, f.iframe);
  const client = connectWorkspaceClient({
    window: f.child,
    id: f.id,
    view: f.view,
    hooks: { dispose: () => disposed++ },
  });
  const pending = client.read("state");
  client.notifySessionEnd();
  resolve({ current_user: "old-session" });
  await assert.rejects(pending, { name: "AbortError" });
  assert.equal(disposed, 1);
  assert.equal(sessionEnds, 1);
  assert.throws(() => client.publishStatus({ active: true }), {
    name: "AbortError",
  });
  host.dispose();
});

test("navigated-away frames and replacement connections cannot retain bridge access", async () => {
  const f = fixture();
  const host = createWorkspaceHost({
    window: f.parent,
    read: async () => ({ ok: true }),
  });
  f.parent.__omrWorkspaceHost = host;
  host.register(f.id, f.iframe);
  const old = connectWorkspaceClient({
    window: f.child,
    id: f.id,
    view: f.view,
  });
  const fresh = connectWorkspaceClient({
    window: f.child,
    id: f.id,
    view: f.view,
  });
  await assert.rejects(old.read("state"), { name: "AbortError" });
  f.child.location.origin = "https://elsewhere.example";
  await assert.rejects(fresh.read("state"), { name: "AbortError" });
  host.dispose();
});

test("window count stays bounded and async close state remains sanitized", async () => {
  const f = fixture();
  const host = createWorkspaceHost({ window: f.parent });
  for (let index = 0; index < 32; index++)
    host.register(`window-${index}`, {
      src: f.iframe.src,
      contentWindow: null,
    });
  assert.throws(() => host.register("extra", f.iframe), /limit/);
  host.unregister("window-0");
  host.register(f.id, f.iframe);
  f.parent.__omrWorkspaceHost = host;
  connectWorkspaceClient({
    window: f.child,
    id: f.id,
    view: f.view,
    hooks: {
      getCloseState: async () => ({ dirty: true, private_key: "secret" }),
    },
  });
  assert.deepEqual(await host.getCloseState(f.id), {
    dirty: true,
    active: false,
    kind: "idle",
    jobId: null,
  });
  host.dispose();
  assert.throws(() => host.register("later", f.iframe), /Invalid/);
});

test("subview navigation waits for boot and a busy save, coalescing requests without overlap", async () => {
  let ready = false,
    release;
  const visited = [],
    errors = [];
  const queue = createWorkspaceNavigation({
    ready: () => ready,
    navigate: async (view) => {
      visited.push(view);
      if (view === "vlans")
        await new Promise((resolve) => {
          release = resolve;
        });
    },
    onError: (error) => errors.push(error),
  });
  assert.equal(queue.request("https://evil.example"), false);
  queue.request("interfaces");
  queue.request("vlans");
  assert.deepEqual(visited, []);
  ready = true;
  const pending = queue.flush();
  assert.deepEqual(visited, ["vlans"]);
  queue.request("virtual_interfaces");
  queue.request("interface_lists");
  release();
  await pending;
  assert.deepEqual(visited, ["vlans", "interface_lists"]);
  ready = false;
  queue.request("interfaces");
  assert.equal(visited.length, 2);
  ready = true;
  await queue.flush();
  assert.equal(visited.at(-1), "interfaces");
  queue.request("vlans");
  queue.request("interface_lists");
  queue.dispose();
  release();
  await queue.flush();
  assert.equal(queue.request("interfaces"), false);
  assert.equal(visited.at(-1), "vlans");
  assert.deepEqual(errors, []);
});

test("update health watching reaches the host with only a validated target version and survives closing its child", () => {
  const f = fixture("updates");
  const updates = [];
  const host = createWorkspaceHost({
    window: f.parent,
    onUpdate: (event) => updates.push(event),
  });
  f.parent.__omrWorkspaceHost = host;
  host.register(f.id, f.iframe);
  const client = connectWorkspaceClient({
    window: f.child,
    id: f.id,
    view: f.view,
  });
  for (const value of [
    null,
    [],
    { version: "0.8.0" },
    "https://evil.example",
    "0.8.0?token=secret",
  ])
    assert.equal(client.watchUpdate(value), false);
  assert.equal(client.watchUpdate("0.8.0"), true);
  assert.deepEqual(updates, [{ id: f.id, view: "updates", version: "0.8.0" }]);
  host.unregister(f.id);
  assert.throws(() => client.watchUpdate("0.8.1"), { name: "AbortError" });
  assert.equal(updates.length, 1);
  host.dispose();
});
