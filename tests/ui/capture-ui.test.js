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
import {
  handleQueryBuilderAction,
  handleQueryBuilderInput,
  getAppliedQuery,
} from "../../app/static/query-builder.js";

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
  };
  const controls = Object.keys(fields).map((name) => ({
    name,
    disabled: false,
    dataset: {},
  }));
  controls.push(
    ...[
      "capture-start",
      "capture-stop",
      "capture-refresh",
      "capture-query-apply",
    ].map((action) => ({
      dataset: { action },
      disabled: false,
    })),
  );
  const form = {
    reportValidity: () => true,
    querySelectorAll: () => controls,
    querySelector: () => ({ closest: () => form }),
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
    "#capture-query-builder": { disabled: false },
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
function addQuery(path = "", kind = "condition") {
  return handleQueryBuilderAction({
    dataset: {
      action: "query-builder-add",
      scope: "packet-capture",
      kind,
      queryPath: path,
    },
  });
}
function editQuery(path, part, value) {
  const region = {
    dataset: { queryBuilder: "packet-capture" },
    querySelector: () => null,
  };
  return handleQueryBuilderInput({
    target: {
      dataset: { queryPath: path, queryPart: part },
      value,
      closest: () => region,
    },
  });
}

test("capture is translated RU/EN and exposes only acquisition interface, builder and stream controls", () => {
  const f = fixture();
  globalThis.document = originalDocument;
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const markup = renderCapture(f.ctx);
    assert.match(markup, /name="interface"/);
    assert.match(markup, /id="capture-interface" required/);
    assert.match(markup, /data-action="capture-stop"/);
    assert.match(markup, /data-query-builder="packet-capture"/);
    assert.match(markup, /data-action="capture-query-apply"/);
    assert.doesNotMatch(
      markup,
      /name="(?:protocol|source|destination|port)"|data-display-negate|capture-negate/,
    );
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
  renderCapture(f.ctx);
  addQuery();
  editQuery("0", "field", "source");
  editQuery("0", "op", "in");
  editQuery("0", "value", "192.0.2.7/32");
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
  assert.match(renderCapture(f.ctx), /value="192.0.2.7\/32"/);
  assert.equal(
    getAppliedQuery("packet-capture").children[0].value,
    "192.0.2.7/32",
  );
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

test("capture streams safely before completion and posts only interface plus expression", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(),
    wire = stream();
  // Stale form entries must not resurrect the removed legacy filter mechanism.
  Object.assign(f.fields, {
    protocol: "tcp",
    source: "192.0.2.0/24",
    port: "443",
    negate: "source",
  });
  let posts = 0,
    signal;
  f.ctx.api = async (path, options) => {
    if (path === "tools/capture/status") return status;
    assert.equal(path, "tools/capture/stream");
    assert.equal(options.responseType, "stream");
    assert.deepEqual(JSON.parse(options.body), {
      interface: "any",
      expression: null,
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

test("read users cannot acquire packets and stream errors remain escaped text", async () => {
  const f = fixture(),
    wire = stream();
  let posts = 0;
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    posts++;
    assert.deepEqual(Object.keys(JSON.parse(options.body)).sort(), [
      "expression",
      "interface",
    ]);
    return wire.response;
  };
  f.ctx.canWrite = () => false;
  await refreshCapture(f.ctx);
  assert.equal(f.nodes["#capture-query-builder"].disabled, true);
  await assert.rejects(action("capture-start", f.ctx), /full/);
  assert.equal(posts, 0);
  f.ctx.canWrite = () => true;
  await refreshCapture(f.ctx);
  const pending = action("capture-start", f.ctx);
  wire.send({ type: "error", message: '<img src=x onerror="bad()"> denied' });
  wire.close();
  await pending;
  assert.match(f.nodes["#capture-error"].textContent, /<img/);
  assert.doesNotMatch(renderCapture(f.ctx), /<img/);
});

test("incomplete builder drafts block both Apply and acquisition without posting", async () => {
  const f = fixture();
  let posts = 0;
  f.ctx.api = async (path) => {
    if (path.endsWith("status")) return status;
    posts++;
    throw new Error("Invalid drafts must not reach the API");
  };
  await refreshCapture(f.ctx);
  renderCapture(f.ctx);
  addQuery();
  editQuery("0", "field", "source");
  editQuery("0", "op", "in");
  await assert.rejects(action("capture-query-apply", f.ctx));
  await assert.rejects(action("capture-start", f.ctx));
  assert.equal(posts, 0);
  assert.equal(f.nodes["#capture-query-builder"].disabled, false);
  assert.equal(getAppliedQuery("packet-capture"), null);
  assert.equal(await action("capture-negate", f.ctx), false);
});

test("applying an OR of protocol and ports only arms the builder; Start acquires separately", async () => {
  const f = fixture(),
    wire = stream();
  let posts = 0,
    posted;
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    posts++;
    posted = JSON.parse(options.body);
    return wire.response;
  };
  await refreshCapture(f.ctx);
  renderCapture(f.ctx);
  addQuery();
  addQuery();
  editQuery("", "join", "or");
  editQuery("0", "field", "protocol");
  editQuery("0", "op", "eq");
  editQuery("0", "value", "icmp");
  editQuery("1", "field", "port");
  editQuery("1", "op", "in");
  editQuery("1", "value", "443");
  await action("capture-query-apply", f.ctx);
  assert.equal(posts, 0);
  assert.equal(getAppliedQuery("packet-capture").join, "or");
  assert.match(f.nodes["#capture-meta"].textContent, /выключен/);
  const pending = action("capture-start", f.ctx);
  await flush();
  assert.equal(posts, 1);
  assert.deepEqual(Object.keys(posted).sort(), ["expression", "interface"]);
  assert.deepEqual(posted.expression, getAppliedQuery("packet-capture"));
  assert.equal(posted.expression.children[0].value, "icmp");
  assert.equal(posted.expression.children[1].value, "443");
  wire.send(completed("headers"));
  wire.close();
  await pending;
});

test("capture submits the applied Boolean tree and locks its builder until the stream stops", async () => {
  const f = fixture(),
    wire = stream();
  let body;
  f.ctx.api = async (path, options) => {
    if (path.endsWith("status")) return status;
    body = JSON.parse(options.body);
    return wire.response;
  };
  await refreshCapture(f.ctx);
  renderCapture(f.ctx);
  const scope = "packet-capture",
    region = { dataset: { queryBuilder: scope }, querySelector: () => null };
  const edit = (path, part, value) =>
    handleQueryBuilderInput({
      target: {
        dataset: { queryPath: path, queryPart: part },
        value,
        closest: () => region,
      },
    });
  for (let index = 0; index < 2; index++)
    handleQueryBuilderAction({
      dataset: {
        action: "query-builder-add",
        scope,
        kind: "condition",
        queryPath: "",
      },
    });
  edit("", "join", "or");
  edit("0", "field", "source");
  edit("0", "op", "not_in");
  edit("0", "value", "192.0.2.0/24");
  edit("1", "field", "port");
  edit("1", "op", "in");
  edit("1", "value", "443,8000-8010");
  const pending = action("capture-start", f.ctx);
  await flush();
  assert.equal(f.nodes["#capture-query-builder"].disabled, true);
  assert.deepEqual(body.expression, {
    kind: "group",
    join: "or",
    children: [
      {
        kind: "condition",
        field: "source",
        op: "not_in",
        value: "192.0.2.0/24",
      },
      { kind: "condition", field: "port", op: "in", value: "443,8000-8010" },
    ],
  });
  assert.deepEqual(Object.keys(body).sort(), ["expression", "interface"]);
  assert.equal(body.interface, "any");
  const applied = getAppliedQuery("packet-capture");
  // Even a queued draft edit cannot change the filter used by an active stream.
  editQuery("0", "value", "203.0.113.0/24");
  f.fields.interface = "eth0";
  handleCaptureInput({ target: { closest: () => f.form } }, f.ctx);
  await action("capture-query-apply", f.ctx);
  assert.deepEqual(getAppliedQuery("packet-capture"), applied);
  assert.equal(f.nodes["#capture-interface"].value, "any");
  assert.equal(
    f.controls.find((control) => control.dataset.action === "capture-stop")
      .disabled,
    false,
  );
  wire.send(completed("packet"));
  wire.close();
  await pending;
  assert.equal(f.nodes["#capture-query-builder"].disabled, false);
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
