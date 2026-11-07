const endpoints = new Map([
  ["state", []],
  ["interfaces", []],
  ["network/status", []],
  ["statistics", []],
  ["audit", []],
  ["telemetry", ["fast"]],
  ["telemetry/history", ["seconds", "after", "interface"]],
  [
    "connections",
    [
      "kind",
      "source",
      "destination",
      "port",
      "protocol",
      "state",
      "interface",
      "search",
      "limit",
    ],
  ],
  ["wireguard/status", []],
  ["tools/capture/status", []],
  ["discovery/status", []],
  ["discovery/hosts", ["query", "interface", "offset", "limit"]],
  ["scans/status", []],
  ["scans/jobs", ["offset", "limit"]],
  ["security/fail2ban", []],
  ["security/fail2ban/bans", ["query", "offset", "limit"]],
  ["security/geoip", []],
  ["security/geoip/countries", ["query", "offset", "limit"]],
  ["security/lists", []],
]);

function sharedKey(path, options = {}) {
  if (
    !options ||
    typeof options !== "object" ||
    (options.method !== undefined && typeof options.method !== "string") ||
    typeof path !== "string" ||
    path.length > 1024 ||
    !/^[a-z][a-z0-9/]*(?:\?[^#]*)?$/.test(path) ||
    (options.method || "GET").toUpperCase() !== "GET" ||
    Object.keys(options).some((key) => !["method", "signal"].includes(key))
  )
    return null;
  const [endpoint, query = ""] = path.split("?");
  const allowed = endpoints.get(endpoint);
  if (!allowed) return null;
  const params = new URLSearchParams(query);
  if (
    [...params.keys()].some(
      (key) => !allowed.includes(key) || params.getAll(key).length !== 1,
    )
  )
    return null;
  params.sort();
  return endpoint + (params.size ? `?${params}` : "");
}
export const isSharedWorkspaceRead = (path, options = {}) =>
  sharedKey(path, options) !== null;
const cancelled = () =>
  new globalThis.DOMException("Workspace request cancelled", "AbortError");

function forCaller(promise, signal) {
  if (signal?.aborted) return Promise.reject(signal.reason || cancelled());
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason || cancelled());
    signal?.addEventListener("abort", abort, { once: true });
    promise
      .then((value) => {
        if (signal?.aborted) return;
        try {
          resolve(structuredClone(value));
        } catch (error) {
          reject(error);
        }
      }, reject)
      .finally(() => signal?.removeEventListener("abort", abort));
  });
}

/** One authenticated host owns the short-lived JSON cache. Streams, account and
 * secret endpoints always stay on the child's normal authenticated API path. */
export function createSharedWorkspaceApi(
  fetcher,
  { now = Date.now, maxEntries = 64, maxInFlight = 64, timeoutMs = 10000 } = {},
) {
  if (
    typeof fetcher !== "function" ||
    !Number.isInteger(maxEntries) ||
    maxEntries < 1 ||
    maxEntries > 64 ||
    !Number.isInteger(maxInFlight) ||
    maxInFlight < 1 ||
    maxInFlight > 64 ||
    !Number.isFinite(timeoutMs) ||
    timeoutMs <= 0
  )
    throw new TypeError("Invalid workspace API configuration");
  const cache = new Map(),
    pending = new Map();
  let generation = 0,
    disposed = false;
  const ttl = (key) => (key === "telemetry?fast=true" ? 200 : 1000);
  function clear() {
    generation++;
    cache.clear();
    for (const entry of pending.values()) entry.controller.abort(cancelled());
    pending.clear();
  }
  function read(path, options = {}) {
    const key = sharedKey(path, options);
    if (!key)
      return Promise.reject(
        new TypeError("This request cannot use the shared workspace API"),
      );
    if (disposed) return Promise.reject(cancelled());
    if (options.signal?.aborted)
      return Promise.reject(options.signal.reason || cancelled());
    for (const [name, entry] of cache)
      if (now() - entry.at >= ttl(name)) cache.delete(name);
    const saved = cache.get(key);
    if (saved) {
      cache.delete(key);
      cache.set(key, saved);
      return forCaller(Promise.resolve(saved.value), options.signal);
    }
    let entry = pending.get(key);
    if (!entry) {
      if (pending.size >= maxInFlight)
        return Promise.reject(
          new Error("Too many simultaneous workspace requests"),
        );
      const stamp = generation,
        controller = new AbortController();
      let rejectAbort;
      const aborted = new Promise((_, reject) => {
        rejectAbort = reject;
      });
      const onAbort = () =>
        rejectAbort(controller.signal.reason || cancelled());
      controller.signal.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(
        () =>
          controller.abort(
            new globalThis.DOMException(
              "Workspace request timed out",
              "TimeoutError",
            ),
          ),
        timeoutMs,
      );
      entry = { controller, promise: null };
      const record = entry;
      record.promise = Promise.race([
        Promise.resolve().then(() => {
          if (controller.signal.aborted || stamp !== generation)
            throw cancelled();
          return fetcher(key, { signal: controller.signal });
        }),
        aborted,
      ])
        .then((data) => {
          if (disposed || stamp !== generation || controller.signal.aborted)
            throw cancelled();
          const value = structuredClone(data);
          while (cache.size >= maxEntries)
            cache.delete(cache.keys().next().value);
          cache.set(key, { value, at: now() });
          return value;
        })
        .finally(() => {
          clearTimeout(timer);
          controller.signal.removeEventListener("abort", onAbort);
          if (pending.get(key) === record) pending.delete(key);
        });
      pending.set(key, record);
    }
    return forCaller(entry.promise, options.signal);
  }
  return {
    read,
    clear,
    invalidate: clear,
    dispose() {
      disposed = true;
      clear();
    },
    stats: () => ({ cached: cache.size, inFlight: pending.size }),
  };
}
