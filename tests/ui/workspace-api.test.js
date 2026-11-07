import test from "node:test";
import assert from "node:assert/strict";
import {
  createSharedWorkspaceApi,
  isSharedWorkspaceRead,
} from "../../app/static/workspace-api.js";

const flush = async () => {
  for (let index = 0; index < 8; index++) await Promise.resolve();
};
test("workspace sharing only accepts explicit public JSON GET endpoints", () => {
  for (const path of [
    "state",
    "interfaces",
    "statistics",
    "network/status",
    "telemetry?fast=true",
    "telemetry/history?seconds=60&after=1",
    "connections?source=192.0.2.0%2F24",
    "scans/jobs?limit=50",
  ])
    assert.equal(isSharedWorkspaceRead(path), true, path);
  for (const path of [
    "login",
    "logout",
    "session",
    "users",
    "me/totp",
    "me/preferences",
    "export",
    "backups/export",
    "wireguard/keys",
    "tools/stream",
    "tools/capture/stream",
    "https://evil.example/state",
    "/api/state",
    "../state",
    "state#private",
    "state?token=secret",
    "telemetry?fast=true&fast=false",
    "telemetry/history?seconds=60&since=1",
  ])
    assert.equal(isSharedWorkspaceRead(path), false, path);
  for (const options of [
    { method: "POST" },
    { responseType: "blob" },
    { headers: { Authorization: "secret" } },
    { body: "{}" },
    { method: 1 },
    null,
  ])
    assert.equal(isSharedWorkspaceRead("state", options), false);
});

test("concurrent reads share one fetch but caller abort and returned objects stay independent", async () => {
  let resolve,
    calls = 0,
    transportSignal;
  const api = createSharedWorkspaceApi((_path, { signal }) => {
    calls++;
    transportSignal = signal;
    return new Promise((done) => {
      resolve = done;
    });
  });
  const controller = new globalThis.AbortController();
  const first = api.read("connections?source=192.0.2.1&limit=10", {
    signal: controller.signal,
  });
  const second = api.read("connections?limit=10&source=192.0.2.1");
  const third = api.read("connections?source=192.0.2.1&limit=10");
  await flush();
  controller.abort();
  await assert.rejects(first, { name: "AbortError" });
  assert.equal(transportSignal.aborted, false);
  resolve({ items: [{ packets: 7 }] });
  const [left, right] = await Promise.all([second, third]);
  left.items[0].packets = 999;
  assert.equal(right.items[0].packets, 7);
  assert.equal(
    (await api.read("connections?limit=10&source=192.0.2.1")).items[0].packets,
    7,
  );
  assert.equal(calls, 1);
  api.dispose();
});

test("fast samples expire at 200ms while regular reads expire at one second", async () => {
  let now = 0,
    calls = 0;
  const api = createSharedWorkspaceApi(async () => ({ sample: ++calls }), {
    now: () => now,
  });
  assert.equal((await api.read("telemetry?fast=true")).sample, 1);
  now = 199;
  assert.equal((await api.read("telemetry?fast=true")).sample, 1);
  now = 200;
  assert.equal((await api.read("telemetry?fast=true")).sample, 2);
  assert.equal((await api.read("state")).sample, 3);
  now = 1199;
  assert.equal((await api.read("state")).sample, 3);
  now = 1200;
  assert.equal((await api.read("state")).sample, 4);
  api.dispose();
});

test("incremental history uses the backend after cursor and shares only equivalent requests", async () => {
  let calls = 0;
  const api = createSharedWorkspaceApi(async (path) => ({
    path,
    sample: ++calls,
    points: [],
  }));
  const [left, right] = await Promise.all([
    api.read("telemetry/history?after=1000&seconds=60&interface=eth0"),
    api.read("telemetry/history?interface=eth0&seconds=60&after=1000"),
  ]);
  assert.equal(calls, 1);
  assert.deepEqual(left, right);
  assert.notEqual(left.points, right.points);
  await api.read("telemetry/history?after=1001&seconds=60&interface=eth0");
  assert.equal(calls, 2, "A newer cursor requests the next history interval");
  api.dispose();
});

test("mutation invalidation cancels old reads and prevents late session snapshots from being cached", async () => {
  const requests = [];
  const api = createSharedWorkspaceApi(
    (_path, { signal }) =>
      new Promise((resolve) => requests.push({ signal, resolve })),
  );
  const stale = api.read("state");
  await flush();
  api.invalidate();
  await assert.rejects(stale, { name: "AbortError" });
  assert.equal(requests[0].signal.aborted, true);
  const fresh = api.read("state");
  await flush();
  requests[0].resolve({ revision: 1, current_user: "old-session" });
  requests[1].resolve({ revision: 2, current_user: "current-session" });
  assert.equal((await fresh).revision, 2);
  assert.equal((await api.read("state")).current_user, "current-session");
  assert.deepEqual(api.stats(), { cached: 1, inFlight: 0 });
  api.clear();
  assert.deepEqual(api.stats(), { cached: 0, inFlight: 0 });
  api.dispose();
});

test("LRU cache, simultaneous requests, timeouts and disposal remain bounded", async (t) => {
  let calls = 0;
  const api = createSharedWorkspaceApi(async () => ({ calls: ++calls }), {
    maxEntries: 4,
  });
  for (let index = 0; index < 20; index++)
    await api.read(`connections?search=${index}`);
  assert.equal(api.stats().cached, 4);
  await api.read("connections?search=0");
  assert.equal(calls, 21);
  api.dispose();
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = createSharedWorkspaceApi(() => new Promise(() => {}), {
    maxInFlight: 2,
    timeoutMs: 50,
  });
  const a = pending.read("state"),
    b = pending.read("interfaces");
  await assert.rejects(pending.read("audit"), /simultaneous/);
  t.mock.timers.tick(50);
  await assert.rejects(a, { name: "TimeoutError" });
  await assert.rejects(b, { name: "TimeoutError" });
  assert.deepEqual(pending.stats(), { cached: 0, inFlight: 0 });
  pending.dispose();
  await assert.rejects(pending.read("state"), { name: "AbortError" });
});

test("clear before dispatch prevents a stale fetch and rejected responses are never cached", async () => {
  let calls = 0;
  const api = createSharedWorkspaceApi(async () => {
    calls++;
    throw new Error("Offline");
  });
  const aborted = api.read("state");
  api.clear();
  await assert.rejects(aborted, { name: "AbortError" });
  assert.equal(calls, 0);
  await assert.rejects(api.read("state"), /Offline/);
  await assert.rejects(api.read("state"), /Offline/);
  assert.equal(calls, 2);
  assert.equal(api.stats().cached, 0);
  api.dispose();
});
