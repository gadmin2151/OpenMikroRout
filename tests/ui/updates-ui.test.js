import test from "node:test";
import assert from "node:assert/strict";
import {
  createUpdateReloadWatcher,
  refreshUpdates,
  resetUpdates,
} from "../../app/static/updates-ui.js";

const target = "0.7.0";
const health = (phase, version = target, jobVersion = target) => ({
  status: "ok",
  version,
  update: { version: jobVersion, phase },
});
const flush = () =>
  new Promise((resolve) => globalThis.queueMicrotask(resolve));

function watcherFixture(fetchHealth) {
  let clock = 0,
    reloads = 0,
    callbacks = [];
  const messages = [];
  const watcher = createUpdateReloadWatcher({
    fetchHealth,
    reload: () => reloads++,
    now: () => clock,
    schedule: (callback) => {
      callbacks.push(callback);
      return callback;
    },
    cancel: (callback) => {
      callbacks = callbacks.filter((entry) => entry !== callback);
    },
    onStopped: (message) => messages.push(message),
  });
  return {
    watcher,
    messages,
    get reloads() {
      return reloads;
    },
    get timers() {
      return callbacks.length;
    },
    advance(ms) {
      clock += ms;
    },
    async poll() {
      assert.equal(callbacks.length, 1, "one request at a time");
      await callbacks.shift()();
    },
  };
}

test("restart waits for the target version AND worker success, then reloads once", async () => {
  let result = health("succeeded", "0.6.3", "0.6.3");
  const fixture = watcherFixture(async () => result);
  fixture.watcher.watch(target);
  await flush();
  assert.equal(fixture.reloads, 0, "old server success must not reload");
  result = health("restarting");
  await fixture.poll();
  assert.equal(
    fixture.reloads,
    0,
    "listening server has not passed health checks",
  );
  result = health("succeeded", "0.6.3");
  await fixture.poll();
  assert.equal(fixture.reloads, 0, "do not reload an old process");
  result = health("succeeded");
  await fixture.poll();
  assert.equal(fixture.reloads, 1);
  assert.equal(fixture.timers, 0);
  fixture.watcher.watch(target);
  await flush();
  assert.equal(
    fixture.reloads,
    1,
    "repeated success cannot create a reload loop",
  );
});

test("temporary restart errors recover without duplicate parallel polling", async () => {
  let fail = true;
  const fixture = watcherFixture(async () => {
    if (fail) throw new Error("connection refused");
    return health("succeeded");
  });
  fixture.watcher.watch(target);
  fixture.watcher.watch(target);
  await flush();
  assert.equal(fixture.timers, 1);
  assert.equal(fixture.messages.length, 0);
  fail = false;
  await fixture.poll();
  assert.equal(fixture.reloads, 1);
});

test("failed or rolled-back release stops without a success reload", async () => {
  const fixture = watcherFixture(async () => health("failed", "0.6.3"));
  fixture.watcher.watch(target);
  await flush();
  assert.equal(fixture.reloads, 0);
  assert.equal(fixture.timers, 0);
  assert.match(fixture.messages[0], /не установлено/);
});

test("missing health progress is bounded and reports a timeout", async () => {
  const fixture = watcherFixture(async () => ({
    status: "ok",
    version: target,
  }));
  fixture.watcher.watch(target);
  await flush();
  fixture.advance(30 * 60 * 1000);
  await fixture.poll();
  assert.equal(fixture.reloads, 0);
  assert.equal(fixture.timers, 0);
  assert.match(fixture.messages[0], /Проверьте состояние сервиса/);
});

test("cancellation ignores late responses, and invalid versions cannot arm polling", async () => {
  let resolve;
  const fixture = watcherFixture(
    () => new Promise((complete) => (resolve = complete)),
  );
  fixture.watcher.watch("https://example.test/redirect");
  assert.equal(resolve, undefined);
  fixture.watcher.watch(target);
  fixture.watcher.stop();
  resolve(health("succeeded"));
  await flush();
  assert.equal(fixture.reloads, 0);
  assert.equal(fixture.timers, 0);
});

test("default health request bypasses stale API cache without changing browser storage", async () => {
  const originalFetch = globalThis.fetch;
  let options;
  globalThis.fetch = async (url, request) => {
    assert.equal(url, "/api/health");
    options = request;
    return { ok: true, json: async () => health("succeeded") };
  };
  let reloads = 0;
  const watcher = createUpdateReloadWatcher({ reload: () => reloads++ });
  try {
    watcher.watch(target);
    await flush();
    await flush();
    assert.equal(reloads, 1);
    assert.equal(options.cache, "no-store");
    assert.equal(options.credentials, "same-origin");
    assert.ok(options.signal instanceof globalThis.AbortSignal);
  } finally {
    watcher.stop();
    globalThis.fetch = originalFetch;
  }
});

test("an observed installation still reloads after restart logs the user out", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  let completeHealth,
    reloads = 0;
  const nextVersion = "0.7.1";
  globalThis.fetch = () => new Promise((resolve) => (completeHealth = resolve));
  globalThis.window = { location: { reload: () => reloads++ } };
  resetUpdates();
  try {
    await refreshUpdates({
      generation: 1,
      getGeneration: () => 1,
      isCurrentView: (view) => view === "updates",
      api: async () => ({ job: { version: nextVersion, phase: "restarting" } }),
      dialog: { open: false },
      render: () => {},
      toast: () => {},
    });
    resetUpdates();
    completeHealth({
      ok: true,
      json: async () => health("succeeded", nextVersion, nextVersion),
    });
    await flush();
    await flush();
    assert.equal(reloads, 1);
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.window = originalWindow;
    resetUpdates();
  }
});
