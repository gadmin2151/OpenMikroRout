import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  resetCapture,
  renderCapture,
  refreshCapture,
  handleCaptureAction,
  handleCaptureInput,
} from "../../app/static/capture-ui.js";
import { setLanguage } from "../../app/static/i18n.js";

const originalDocument = globalThis.document;
const originalFormData = globalThis.FormData;
afterEach(() => {
  resetCapture();
  globalThis.document = originalDocument;
  globalThis.FormData = originalFormData;
  setLanguage("ru");
});
const flush = async () => {
  for (let i = 0; i < 12; i++) await Promise.resolve();
};
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
function stream() {
  let controller;
  let cancelled = false;
  return {
    response: new globalThis.Response(
      new globalThis.ReadableStream({
        start(value) {
          controller = value;
        },
        cancel() {
          cancelled = true;
        },
      }),
      { headers: { "Content-Type": "application/x-ndjson" } },
    ),
    send: (event) =>
      controller.enqueue(
        new globalThis.TextEncoder().encode(JSON.stringify(event) + "\n"),
      ),
    close: () => controller.close(),
    cancelled: () => cancelled,
  };
}
function fixture() {
  const fields = {
    interface: "any",
    protocol: "tcp",
    source: "",
    destination: "",
    port: "443",
  };
  const controls = Object.keys(fields).map((name) => ({
    name,
    disabled: false,
    dataset: {},
  }));
  controls.push(
    ...["capture-start", "capture-stop", "capture-refresh"].map((action) => ({
      dataset: { action },
      disabled: false,
    })),
  );
  for (const name of ["protocol", "source", "destination", "port"])
    controls.push({
      dataset: { action: "capture-negate", displayNegate: name },
      disabled: true,
      setAttribute(name, value) {
        this[name] = value;
      },
    });
  const form = {
    reportValidity: () => true,
    querySelectorAll: () => controls,
    querySelector: (selector) => {
      const name = /data-display-negate="([^"]+)"/.exec(selector)?.[1];
      return name
        ? controls.find((node) => node.dataset.displayNegate === name)
        : { closest: () => form };
    },
  };
  let text = "",
    paints = 0;
  const output = { scrollHeight: 100, scrollTop: 0, clientHeight: 100 };
  Object.defineProperties(output, {
    textContent: {
      get: () => text,
      set(value) {
        text = value;
        paints++;
      },
    },
    innerHTML: {
      set() {
        throw new Error("Packet data must use textContent");
      },
    },
  });
  const nodes = {
    "#capture-form": form,
    "#capture-interface": { innerHTML: "", value: "any" },
    "#capture-output": output,
    "#capture-meta": { textContent: "" },
    "#capture-readiness": { textContent: "" },
    "#capture-error": { textContent: "", hidden: true },
  };
  globalThis.document = {
    querySelector: (selector) => nodes[selector] || null,
  };
  globalThis.FormData = class {
    get(name) {
      return fields[name] ?? null;
    }
    has(name) {
      return name in fields;
    }
  };
  let generation = 0;
  const ctx = {
    e: escape,
    icon: () => "",
    canWrite: () => true,
    offline: false,
    generation: 0,
    getGeneration: () => generation,
    run() {
      throw new Error("Packet capture must not lock the entire interface");
    },
  };
  return {
    ctx,
    fields,
    form,
    controls,
    nodes,
    output,
    paints: () => paints,
    logout: () => generation++,
  };
}
const status = {
  available: true,
  interfaces: ["any", "eth0", "lo"],
  demo: false,
  error: "",
};
const action = (name, ctx) =>
  handleCaptureAction({ dataset: { action: name } }, ctx);
const completed = (output) => ({
  type: "completed",
  result: { tool: "capture", success: true, output, demo: false },
});

test("capture is translated RU/EN and exposes only typed filters, Start and Stop", () => {
  const f = fixture();
  globalThis.document = originalDocument;
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const markup = renderCapture(f.ctx);
    for (const name of [
      "interface",
      "protocol",
      "source",
      "destination",
      "port",
    ])
      assert.match(markup, new RegExp(`name="${name}"`));
    assert.match(markup, /id="capture-interface" required/);
    assert.match(markup, /data-action="capture-stop"/);
    assert.doesNotMatch(markup, /name="(?:filter|command|payload)"/);
    if (language === "en") assert.doesNotMatch(markup, /[А-Яа-яЁё]/);
    else assert.match(markup, /Перехват пакетов/);
  }
});

test("status loading, unavailable tool and refresh failure keep Start disabled", async () => {
  const f = fixture();
  assert.match(renderCapture(f.ctx), /Загрузка интерфейсов/);
  f.ctx.api = async () => ({ ...status, available: false });
  await refreshCapture(f.ctx);
  assert.match(f.nodes["#capture-readiness"].textContent, /tcpdump/);
  assert.equal(
    f.controls.find((node) => node.dataset.action === "capture-start").disabled,
    true,
  );
  f.ctx.api = () => {
    throw new Error("Temporary failure");
  };
  await refreshCapture(f.ctx);
  assert.match(f.nodes["#capture-readiness"].textContent, /Temporary failure/);
  f.ctx.api = async () => status;
  await refreshCapture(f.ctx);
  assert.equal(
    f.controls.find((node) => node.dataset.action === "capture-start").disabled,
    false,
  );
});

test("normalized select markup is cached across status refresh and packet paints", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture();
  const wire = stream();
  const select = f.nodes["#capture-interface"];
  let markup = "",
    writes = 0;
  Object.defineProperty(select, "innerHTML", {
    get: () => markup,
    set(value) {
      // Browsers serialize a boolean selected attribute as selected="".
      markup = value.replace(/\bselected(?=\s|>)/g, 'selected=""');
      writes++;
    },
  });
  f.ctx.api = async (path) =>
    path.endsWith("status") ? status : wire.response;
  await refreshCapture(f.ctx);
  f.fields.interface = "eth0";
  f.fields.source = "192.0.2.7/32";
  const source = f.controls.find((control) => control.name === "source");
  source.value = f.fields.source;
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  const before = writes;
  assert.equal(select.value, "eth0");
  assert.match(select.innerHTML, /value="eth0" selected=""/);
  await refreshCapture(f.ctx);
  await refreshCapture(f.ctx);
  assert.equal(writes, before);
  const pending = action("capture-start", f.ctx);
  wire.send({ type: "started", tool: "capture", continuous: true });
  for (const packet of ["first packet\n", "second packet\n"]) {
    wire.send({ type: "output", text: packet });
    await flush();
    t.mock.timers.tick(100);
  }
  assert.equal(writes, before);
  assert.equal(select.value, "eth0");
  assert.equal(source.value, "192.0.2.7/32");
  assert.match(renderCapture(f.ctx), /name="source" value="192.0.2.7\/32"/);
  await action("capture-stop", f.ctx);
  await pending;
  f.fields.interface = "any";
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  const beforeReset = writes;
  resetCapture();
  await refreshCapture(f.ctx);
  assert.equal(
    writes,
    beforeReset + 1,
    "Reset invalidates the per-element cache",
  );
});

test("capture streams safely before completion, paints at most once per 100ms and submits typed filters", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(),
    wire = stream();
  f.fields.source = " 192.0.2.0/24 ";
  f.fields.destination = " 198.51.100.20 ";
  let posts = 0,
    signal;
  f.ctx.api = async (path, options) => {
    if (path === "tools/capture/status") return status;
    assert.equal(path, "tools/capture/stream");
    assert.equal(options.responseType, "stream");
    assert.deepEqual(JSON.parse(options.body), {
      interface: "any",
      protocol: "tcp",
      source: "192.0.2.0/24",
      destination: "198.51.100.20",
      port: 443,
      negate: [],
    });
    signal = options.signal;
    posts++;
    return wire.response;
  };
  await refreshCapture(f.ctx);
  const pending = action("capture-start", f.ctx);
  await flush();
  await action("capture-start", f.ctx);
  assert.equal(posts, 1);
  const before = f.paints();
  const packet = '<img src=x onerror="bad()"> 192.0.2.1 > 198.51.100.20\n';
  wire.send({ type: "started", tool: "capture", continuous: true });
  for (let index = 0; index < 8; index++)
    wire.send({ type: "output", text: packet });
  for (let index = 0; index < 8; index++) await flush();
  assert.equal(f.paints(), before);
  t.mock.timers.tick(100);
  assert.equal(f.paints(), before + 1);
  assert.equal(f.output.textContent, packet.repeat(8));
  assert.match(renderCapture(f.ctx), /&lt;img/);
  assert.doesNotMatch(renderCapture(f.ctx), /<img/);
  t.mock.timers.tick(60000);
  assert.equal(
    signal.aborted,
    false,
    "Continuous capture has no fixed fetch deadline",
  );
  wire.send(completed(packet));
  wire.close();
  await pending;
  assert.equal(f.output.textContent, packet);
  assert.equal(
    f.controls.find((node) => node.dataset.action === "capture-start").disabled,
    false,
  );
});

test("Stop wakes a waiting reader, preserves received data and leaves scrolling under user control", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(),
    wire = stream();
  let signal;
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    signal = options.signal;
    return wire.response;
  };
  await refreshCapture(f.ctx);
  const pending = action("capture-start", f.ctx);
  wire.send({ type: "started", tool: "capture", continuous: true });
  wire.send({ type: "output", text: "packet\n" });
  await flush();
  f.output.scrollTop = 4;
  f.output.scrollHeight = 500;
  t.mock.timers.tick(100);
  assert.equal(f.output.scrollTop, 4);
  await action("capture-stop", f.ctx);
  await pending;
  assert.equal(signal.aborted, true);
  assert.equal(wire.cancelled(), true);
  assert.equal(f.output.textContent, "packet\n");
  assert.match(f.nodes["#capture-meta"].textContent, /остановлен/);
});

test("capture keeps a rolling 32 KiB UTF-8 tail over more than 1 MiB of live output", async () => {
  const f = fixture(),
    wire = stream();
  f.ctx.api = async (path) =>
    path.endsWith("status") ? status : wire.response;
  await refreshCapture(f.ctx);
  const pending = action("capture-start", f.ctx);
  wire.send({ type: "started", tool: "capture", continuous: true });
  const packet = "я".repeat(40000) + "\n";
  for (let index = 0; index < 20; index++)
    wire.send({ type: "output", text: packet });
  wire.send(completed(packet));
  wire.close();
  await pending;
  assert.ok(
    new globalThis.TextEncoder().encode(f.output.textContent).byteLength <=
      32768,
  );
  assert.doesNotMatch(f.output.textContent, /\uFFFD/);
  assert.equal(f.nodes["#capture-error"].hidden, true);
});

test("ICMP disables ports, read users cannot start, and packet errors use textContent", async () => {
  const f = fixture(),
    wire = stream();
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    assert.equal(JSON.parse(options.body).port, null);
    return wire.response;
  };
  await refreshCapture(f.ctx);
  f.fields.protocol = "icmp";
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  assert.equal(f.controls.find((node) => node.name === "port").disabled, true);
  f.ctx.canWrite = () => false;
  await assert.rejects(action("capture-start", f.ctx), /full/);
  f.ctx.canWrite = () => true;
  const pending = action("capture-start", f.ctx);
  wire.send({ type: "error", message: '<img src=x onerror="bad()"> denied' });
  wire.close();
  await pending;
  assert.match(f.nodes["#capture-error"].textContent, /<img/);
  assert.doesNotMatch(renderCapture(f.ctx), /<img/);
});

test("capture ! controls preserve inputs and submit typed exclusions only for populated packet criteria", async () => {
  const f = fixture(),
    wire = stream();
  let posted;
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    posted = JSON.parse(options.body);
    return wire.response;
  };
  await refreshCapture(f.ctx);
  f.fields.source = "192.0.2.0/24";
  f.fields.destination = "198.51.100.10";
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  for (const name of ["source", "destination", "port", "protocol"])
    await handleCaptureAction(
      { dataset: { action: "capture-negate", displayNegate: name } },
      f.ctx,
    );
  assert.equal(f.fields.source, "192.0.2.0/24");
  assert.equal(f.fields.port, "443");
  assert.equal(
    f.controls.find((node) => node.dataset.displayNegate === "source")[
      "aria-pressed"
    ],
    "true",
  );
  const pending = action("capture-start", f.ctx);
  wire.send(completed("packet"));
  wire.close();
  await pending;
  assert.deepEqual(posted.negate, [
    "protocol",
    "source",
    "destination",
    "port",
  ]);
  assert.equal(posted.interface, "any");
  assert.equal(posted.port, 443);
  f.fields.source = "";
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  const toggle = f.controls.find(
    (node) => node.dataset.displayNegate === "source",
  );
  assert.equal(toggle.disabled, true);
  assert.equal(toggle["aria-pressed"], "false");
  assert.doesNotMatch(renderCapture(f.ctx), /data-display-negate="interface"/);
  f.ctx.canWrite = () => false;
  await assert.rejects(
    handleCaptureAction(
      { dataset: { action: "capture-negate", displayNegate: "port" } },
      f.ctx,
    ),
    /full/,
  );
});

test("capture ports become usable for !ICMP and are safely cleared from negation for positive ICMP", async () => {
  const f = fixture();
  f.ctx.api = async () => status;
  await refreshCapture(f.ctx);
  f.fields.protocol = "icmp";
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  const port = f.controls.find((node) => node.name === "port");
  assert.equal(port.disabled, true);
  const toggle = (name) =>
    handleCaptureAction(
      { dataset: { action: "capture-negate", displayNegate: name } },
      f.ctx,
    );
  await toggle("protocol");
  assert.equal(port.disabled, false);
  await toggle("port");
  assert.equal(
    f.controls.find((node) => node.dataset.displayNegate === "port")[
      "aria-pressed"
    ],
    "true",
  );
  await toggle("protocol");
  assert.equal(port.disabled, true);
  assert.equal(
    f.controls.find((node) => node.dataset.displayNegate === "port")[
      "aria-pressed"
    ],
    "false",
  );
});

test("reset/logout ignores late capture responses and aborts pending status requests", async () => {
  const f = fixture(),
    wire = stream();
  let resolve, signal;
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    signal = options.signal;
    return new Promise((done) => {
      resolve = done;
    });
  };
  await refreshCapture(f.ctx);
  const pending = action("capture-start", f.ctx);
  await flush();
  f.logout();
  resetCapture();
  f.output.textContent = "next-session";
  wire.send({ type: "output", text: "previous session secret" });
  wire.close();
  resolve(wire.response);
  await pending;
  assert.equal(signal.aborted, true);
  assert.equal(f.output.textContent, "next-session");
  assert.doesNotMatch(renderCapture(f.ctx), /previous session secret/);
  let resolveStatus;
  f.ctx.generation = f.ctx.getGeneration();
  f.ctx.api = (_path, options) => {
    signal = options.signal;
    return new Promise((done) => {
      resolveStatus = done;
    });
  };
  const loading = refreshCapture(f.ctx);
  await flush();
  resetCapture();
  resolveStatus(status);
  await loading;
  assert.equal(signal.aborted, true);
  assert.doesNotMatch(renderCapture(f.ctx), /value="eth0"/);
});
