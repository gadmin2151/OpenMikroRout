import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  readDiagnosticStream,
  diagnosticOutputTail,
} from "../../app/static/live-stream.js";
import {
  handleToolsAction,
  resetTools,
  renderTools,
  getToolsActivity,
} from "../../app/static/tools-ui.js";

const originalDocument = globalThis.document;
const originalFormData = globalThis.FormData;
afterEach(() => {
  resetTools();
  globalThis.document = originalDocument;
  globalThis.FormData = originalFormData;
});
const flush = async () => {
  for (let index = 0; index < 8; index++) await Promise.resolve();
};
function diagnosticStream() {
  let controller;
  let cancelled = false;
  const body = new globalThis.ReadableStream({
    start(value) {
      controller = value;
    },
    cancel() {
      cancelled = true;
    },
  });
  const encoder = new globalThis.TextEncoder();
  return {
    response: new globalThis.Response(body, {
      headers: { "Content-Type": "application/x-ndjson; charset=utf-8" },
    }),
    bytes: (value) => controller.enqueue(value),
    send: (event) =>
      controller.enqueue(encoder.encode(JSON.stringify(event) + "\n")),
    close: () => controller.close(),
    cancelled: () => cancelled,
  };
}
const completed = (output) => ({
  type: "completed",
  result: {
    tool: "ping",
    elapsed_ms: 3000,
    success: true,
    demo: false,
    output,
  },
});
function fixture(tool = "ping") {
  const output = {
    textContent: "",
    scrollHeight: 100,
    scrollTop: 0,
    clientHeight: 100,
  };
  Object.defineProperty(output, "innerHTML", {
    set() {
      throw new Error("Diagnostic data must use textContent");
    },
  });
  const meta = { textContent: "" };
  const controls = [
    { name: "tool", dataset: {}, disabled: false },
    { name: "target", dataset: {}, disabled: false },
    { name: "port", dataset: {}, disabled: true },
    { dataset: { action: "tools-run" }, disabled: false },
    { dataset: { action: "tools-cancel" }, hidden: true, disabled: false },
  ];
  const form = { reportValidity: () => true, querySelectorAll: () => controls };
  globalThis.document = {
    querySelector: (selector) =>
      ({
        "#tools-form": form,
        "#tools-output": output,
        "#tools-result-meta": meta,
      })[selector] || null,
  };
  globalThis.FormData = class {
    get(name) {
      return { tool, target: "  192.0.2.1  " }[name] || null;
    }
    has(name) {
      return name !== "port";
    }
  };
  let generation = 0;
  const ctx = {
    e: String,
    icon: () => "",
    offline: false,
    canWrite: () => true,
    generation: 0,
    getGeneration: () => generation,
    run() {
      throw new Error("Streaming tools must not lock the entire interface");
    },
  };
  return { ctx, output, meta, controls, logout: () => generation++ };
}

test("minimized diagnostic windows keep their stream and recent output without touching DOM", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  let visible = true;
  f.ctx.isWindowVisible = () => visible;
  f.ctx.api = async () => stream.response;
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  await flush();
  assert.deepEqual(getToolsActivity(), { active: true, kind: "diagnostic" });
  const painted = f.output.textContent;
  visible = false;
  stream.send({ type: "started", continuous: true });
  stream.send({ type: "output", text: "reply while minimized\n" });
  await flush();
  assert.equal(f.output.textContent, painted);
  assert.equal(stream.cancelled(), false);
  const snapshot = getToolsActivity();
  snapshot.active = false;
  assert.equal(getToolsActivity().active, true);
  assert.deepEqual(Object.keys(getToolsActivity()), ["active", "kind"]);
  stream.send(completed("last reply while minimized\n"));
  stream.close();
  await pending;
  assert.equal(f.output.textContent, painted);
  assert.equal(getToolsActivity().active, false);
  visible = true;
  assert.match(renderTools(f.ctx), /last reply while minimized/);
});

test("closing a minimized diagnostic window cancels its reader and clears activity", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  f.ctx.api = async () => stream.response;
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  stream.send({ type: "started", continuous: true });
  await flush();
  f.ctx.isWindowVisible = () => false;
  resetTools();
  await pending;
  assert.equal(stream.cancelled(), true);
  assert.deepEqual(getToolsActivity(), { active: false, kind: "diagnostic" });
  assert.doesNotMatch(renderTools(f.ctx), /reply while minimized/);
});

test("NDJSON parser delivers early output and preserves UTF-8 split across network chunks", async () => {
  const stream = diagnosticStream();
  const received = [];
  let finished = false;
  const pending = readDiagnosticStream(stream.response, (event) =>
    received.push(event),
  ).then(() => {
    finished = true;
  });
  const encoder = new globalThis.TextEncoder();
  const line = encoder.encode(
    JSON.stringify({ type: "output", text: "ответ ✓\n" }) + "\n",
  );
  const split = line.findIndex((value) => value === 0xe2) + 1;
  stream.send({ type: "started" });
  stream.bytes(line.slice(0, split));
  await flush();
  assert.equal(received.length, 1);
  stream.bytes(line.slice(split));
  await flush();
  assert.equal(received[1].text, "ответ ✓\n");
  assert.equal(
    finished,
    false,
    "First packet must not wait for command completion",
  );
  stream.send(completed("ответ ✓\n"));
  stream.close();
  await pending;
  assert.equal(received.at(-1).type, "completed");
});

test("malformed or excessive diagnostic protocol cancels its reader instead of accepting arbitrary data", async () => {
  for (const invalid of [
    new globalThis.TextEncoder().encode('{"type":"execute"}\n'),
    new globalThis.TextEncoder().encode("not-json\n"),
    new Uint8Array(262145).fill(65),
    new Uint8Array(1048577).fill(65),
  ]) {
    const stream = diagnosticStream();
    const pending = readDiagnosticStream(stream.response, () =>
      assert.fail("Invalid event accepted"),
    );
    stream.bytes(invalid);
    await assert.rejects(pending);
    assert.equal(stream.cancelled(), true);
    assert.equal(stream.response.body.locked, false);
  }
  await assert.rejects(
    readDiagnosticStream(
      new globalThis.Response("{}", {
        headers: { "Content-Type": "application/json" },
      }),
      () => {},
    ),
    /потоковый|stream/i,
  );
});

test("Ping output reaches textContent before completion, remains local-busy and cannot start twice", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  let calls = 0;
  f.ctx.api = async (path, options) => {
    calls++;
    assert.equal(path, "tools/stream");
    assert.equal(options.responseType, "stream");
    assert.deepEqual(JSON.parse(options.body), {
      tool: "ping",
      continuous: true,
      target: "192.0.2.1",
      port: 443,
    });
    return stream.response;
  };
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  await flush();
  assert.equal(f.controls[3].disabled, true);
  assert.equal(f.controls[4].hidden, false);
  await handleToolsAction({ dataset: { action: "tools-run" } }, f.ctx);
  assert.equal(calls, 1);
  const packet = '<img src=x onerror="bad()"> packet 1\n';
  stream.send({ type: "started" });
  stream.send({ type: "output", text: packet });
  await flush();
  assert.equal(f.output.textContent, packet);
  assert.doesNotMatch(f.meta.textContent, /3000/);
  stream.send(completed(packet + "packet 2\n"));
  stream.close();
  await pending;
  assert.equal(f.output.textContent, packet + "packet 2\n");
  assert.equal(f.controls[3].disabled, false);
  assert.equal(f.controls[4].hidden, true);
});

test("cancel aborts the fetch signal and restores tool controls", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  let signal;
  f.ctx.api = async (_path, options) => {
    signal = options.signal;
    return stream.response;
  };
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  stream.send({ type: "started" });
  await flush();
  await handleToolsAction({ dataset: { action: "tools-cancel" } }, f.ctx);
  assert.equal(signal.aborted, true);
  await pending;
  assert.equal(
    stream.cancelled(),
    true,
    "Stop must wake even a waiting stream reader",
  );
  assert.match(f.meta.textContent, /отменена|cancelled/i);
  assert.equal(f.controls[3].disabled, false);
});

test("logout/reset suppresses a late diagnostic response from the previous session", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  let resolve;
  f.ctx.api = () =>
    new Promise((done) => {
      resolve = done;
    });
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  f.logout();
  resetTools();
  f.output.textContent = "next-session";
  f.meta.textContent = "next-session";
  stream.send({ type: "output", text: "secret previous-session output" });
  stream.close();
  resolve(stream.response);
  await pending;
  assert.equal(f.output.textContent, "next-session");
  assert.equal(f.meta.textContent, "next-session");
  assert.doesNotMatch(renderTools(f.ctx), /secret previous-session/);
});

test("read users cannot start or cancel diagnostic commands", async () => {
  const f = fixture();
  f.ctx.canWrite = () => false;
  f.ctx.api = () => assert.fail("Read user called diagnostic endpoint");
  for (const action of ["tools-run", "tools-cancel"])
    await assert.rejects(
      handleToolsAction({ dataset: { action } }, f.ctx),
      /full/,
    );
});

test("output after a completed result is rejected rather than silently altering the result", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  f.ctx.api = async () => stream.response;
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  stream.send(completed("finished\n"));
  stream.send({ type: "output", text: "late invalid output" });
  stream.close();
  await assert.rejects(pending, /Некорректный|Invalid/i);
  assert.doesNotMatch(f.output.textContent, /late invalid output/);
});

test("continuous Ping accepts more than 1 MiB over time while keeping each protocol frame bounded", async () => {
  const stream = diagnosticStream();
  let outputs = 0;
  const pending = readDiagnosticStream(
    stream.response,
    (event) => {
      if (event.type === "output") outputs++;
    },
    undefined,
    { continuous: true },
  );
  stream.send({ type: "started", continuous: true });
  for (let index = 0; index < 20; index++)
    stream.send({ type: "output", text: `${index}:` + "x".repeat(65500) });
  stream.send(completed("finished"));
  stream.close();
  await pending;
  assert.equal(outputs, 20);
  const oversized = diagnosticStream();
  const invalid = readDiagnosticStream(
    oversized.response,
    () => {},
    undefined,
    { continuous: true },
  );
  oversized.bytes(new Uint8Array(262145).fill(65));
  await assert.rejects(invalid, /лимит|limit/i);
  assert.equal(oversized.cancelled(), true);
});

test("continuous and finite streams reject missing terminals, malformed UTF-8 and duplicate terminal events", async () => {
  for (const continuous of [false, true]) {
    const incomplete = diagnosticStream();
    const missing = readDiagnosticStream(
      incomplete.response,
      () => {},
      undefined,
      { continuous },
    );
    incomplete.send({ type: "started" });
    incomplete.close();
    await assert.rejects(missing, /прерван|interrupted/i);
    const corrupt = diagnosticStream();
    const invalid = readDiagnosticStream(
      corrupt.response,
      () => {},
      undefined,
      { continuous },
    );
    corrupt.bytes(new Uint8Array([0xff, 10]));
    await assert.rejects(invalid);
    assert.equal(corrupt.cancelled(), true);
    const duplicate = diagnosticStream();
    const twice = readDiagnosticStream(
      duplicate.response,
      () => {},
      undefined,
      { continuous },
    );
    duplicate.send(completed("first"));
    duplicate.send(completed("second"));
    duplicate.close();
    await assert.rejects(twice, /Некорректный|Invalid/i);
  }
});

test("live Ping rolls the console to the latest 32 KiB and keeps full Unicode characters", async () => {
  const f = fixture();
  const stream = diagnosticStream();
  f.ctx.api = async () => stream.response;
  const pending = handleToolsAction(
    { dataset: { action: "tools-run" } },
    f.ctx,
  );
  stream.send({ type: "started", continuous: true });
  stream.send({
    type: "output",
    text: "old-first-packet\n" + "я".repeat(30000),
  });
  stream.send({ type: "output", text: "\nlatest-packet ✓\n" });
  await flush();
  assert.doesNotMatch(f.output.textContent, /old-first-packet/);
  assert.match(f.output.textContent, /latest-packet ✓/);
  assert.ok(
    new globalThis.TextEncoder().encode(f.output.textContent).byteLength <=
      32768,
  );
  assert.doesNotMatch(f.output.textContent, /�/);
  assert.match(f.meta.textContent, /до остановки|until stopped/i);
  assert.match(renderTools(f.ctx), /id="tools-output"[^>]*aria-live="off"/);
  await handleToolsAction({ dataset: { action: "tools-cancel" } }, f.ctx);
  await pending;
  const exact = diagnosticOutputTail("✓".repeat(12000) + "END");
  assert.ok(new globalThis.TextEncoder().encode(exact).byteLength <= 32768);
  assert.match(exact, /END$/);
  assert.doesNotMatch(exact, /�/);
});

test("Ping has no wall-clock timeout while finite tools retain their 30-second client guard", async () => {
  const originalTimeout = globalThis.AbortSignal.timeout;
  const limits = [];
  globalThis.AbortSignal.timeout = (milliseconds) => {
    limits.push(milliseconds);
    return originalTimeout(milliseconds);
  };
  try {
    for (const tool of ["ping", "traceroute"]) {
      const f = fixture(tool);
      const stream = diagnosticStream();
      let payload;
      f.ctx.api = async (_path, options) => {
        payload = JSON.parse(options.body);
        return stream.response;
      };
      const pending = handleToolsAction(
        { dataset: { action: "tools-run" } },
        f.ctx,
      );
      stream.send({ type: "started" });
      stream.send({
        ...completed("finished"),
        result: { ...completed("finished").result, tool },
      });
      stream.close();
      await pending;
      if (tool === "ping") {
        assert.equal(payload.continuous, true);
        assert.deepEqual(limits, []);
      } else {
        assert.equal(Object.hasOwn(payload, "continuous"), false);
        assert.deepEqual(limits, [30000]);
      }
      resetTools();
    }
  } finally {
    globalThis.AbortSignal.timeout = originalTimeout;
  }
});
