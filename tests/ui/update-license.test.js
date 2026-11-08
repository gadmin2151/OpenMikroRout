import test, { afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  renderUpdates,
  refreshUpdates,
  resetUpdates,
  handleUpdatesAction,
} from "../../app/static/updates-ui.js";
import { setLanguage } from "../../app/static/i18n.js";

afterEach(() => {
  resetUpdates();
  setLanguage("ru");
});
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );
const terms =
  "https://github.com/ntop/nDPI/blob/0123456789abcdef/README.license.md";
function fixture(license = undefined) {
  const calls = [],
    frames = [];
  const value = {
    enabled: true,
    current_version: "0.10.0",
    latest: {
      available: true,
      version: "0.11.0",
      commit: "a".repeat(40),
      check_id: "b".repeat(32),
    },
    job: null,
    ...(license === undefined ? {} : { ndpi_license: license }),
  };
  const ctx = {
    canWrite: () => true,
    currentUser: { role: "full" },
    state: { version: "0.10.0", dirty: false, pending: null },
    busy: false,
    offline: false,
    generation: 1,
    getGeneration: () => 1,
    isCurrentView: (name) => name === "updates",
    e: escape,
    icon: () => "",
    render: () => {},
    run: (operation) => operation(),
    api: async (path, options = {}) => {
      calls.push({ path, options });
      assert.notEqual(
        path,
        "updates/apply",
        "A blocked update must not post credentials or queue a job",
      );
      return globalThis.structuredClone(value);
    },
    dialog: {
      open: false,
      querySelector: () => {
        throw new Error("Blocked update must not read proof credentials");
      },
    },
    dialogFrame: (...parts) => {
      frames.push(parts);
      ctx.dialog.open = true;
    },
  };
  return { ctx, calls, frames, value };
}
const action = (name) => ({ dataset: { action: name } });
const missing = {
  required: true,
  accepted: false,
  profile: "",
  version: "6.0",
  terms_url: terms,
  notice: "Original vendor terms",
};

test("missing license acceptance explains terms and disables Install without writing acceptance", async () => {
  const f = fixture(missing);
  await refreshUpdates(f.ctx);
  const markup = renderUpdates(f.ctx);
  assert.match(markup, /LGPLv3/);
  assert.match(markup, /прямого и косвенного дохода/);
  assert.match(markup, /коммерческое соглашение с ntop/);
  assert.match(markup, /sudo \.\/deploy\/accept-ndpi-license\.sh/);
  assert.match(markup, /Отказ отменяет установку/);
  assert.match(markup, /data-action="updates-open" disabled/);
  assert.doesNotMatch(markup, /data-action="(?:license-accept|ndpi-accept)"/);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].path, "updates");
});

test("forged Open and Apply reject before a dialog or proof request", async () => {
  const f = fixture(missing);
  await refreshUpdates(f.ctx);
  for (const name of ["updates-open", "updates-apply"])
    await assert.rejects(
      handleUpdatesAction(action(name), f.ctx),
      /accept-ndpi-license/,
    );
  assert.equal(f.frames.length, 0);
  assert.equal(f.calls.length, 1);
});

test("acceptance revoked while a proof dialog is open blocks Apply on refreshed status", async () => {
  const f = fixture({
    ...missing,
    accepted: true,
    profile: "commercial-license",
  });
  await refreshUpdates(f.ctx);
  await handleUpdatesAction(action("updates-open"), f.ctx);
  assert.equal(f.frames.length, 1);
  f.value.ndpi_license.accepted = false;
  await refreshUpdates(f.ctx);
  await assert.rejects(
    handleUpdatesAction(action("updates-apply"), f.ctx),
    /accept-ndpi-license/,
  );
  assert.equal(
    f.calls.filter((call) => call.path === "updates/apply").length,
    0,
  );
});

for (const [profile, text] of [
  ["not-for-profit", "Без прямого и косвенного дохода"],
  ["commercial-license", "Коммерческое соглашение с ntop"],
  ["lgpl-only", "Только LGPL core"],
]) {
  test(`accepted ${profile} profile is shown and permits the normal proof dialog`, async () => {
    const f = fixture({ ...missing, accepted: true, profile });
    await refreshUpdates(f.ctx);
    const markup = renderUpdates(f.ctx);
    assert.match(markup, new RegExp(text));
    assert.doesNotMatch(markup, /data-action="updates-open" disabled/);
    assert.match(markup, /не предоставляет коммерческую лицензию/);
    await handleUpdatesAction(action("updates-open"), f.ctx);
    assert.equal(f.frames.length, 1);
    assert.match(f.frames[0][2], /update-proof-form/);
  });
}

test("older servers without the license field retain their update behavior", async () => {
  const f = fixture();
  await refreshUpdates(f.ctx);
  assert.doesNotMatch(renderUpdates(f.ctx), /update-license/);
  await handleUpdatesAction(action("updates-open"), f.ctx);
  assert.equal(f.frames.length, 1);
});

test("checking GitHub remains available before acceptance and cannot itself accept terms", async () => {
  const f = fixture(missing);
  await refreshUpdates(f.ctx);
  await handleUpdatesAction(action("updates-check"), f.ctx);
  assert.equal(f.calls.at(-1).path, "updates/check");
  assert.equal(f.calls.at(-1).options.method, "POST");
  assert.equal(f.value.ndpi_license.accepted, false);
});

test("license notices, profile and version are escaped; metadata cannot inject an outbound URL", async () => {
  const unsafe = '<img src=x onerror="bad()">';
  const f = fixture({
    ...missing,
    accepted: true,
    profile: unsafe,
    version: unsafe,
    notice: unsafe,
    terms_url: "javascript:bad()",
  });
  await refreshUpdates(f.ctx);
  const markup = renderUpdates(f.ctx);
  assert.doesNotMatch(markup, /<img|javascript:|href="https:\/\/attacker/);
  assert.match(markup, /&lt;img/);
});

test("RU and EN describe the same commercial restriction and CLI-only acceptance", async () => {
  const f = fixture(missing);
  await refreshUpdates(f.ctx);
  for (const language of ["ru", "en"]) {
    setLanguage(language);
    const markup = renderUpdates(f.ctx);
    assert.match(markup, /LGPLv3/);
    assert.match(markup, /sudo \.\/deploy\/accept-ndpi-license\.sh/);
    assert.match(markup, /ntop/);
    if (language === "en") {
      assert.match(markup, /no direct or indirect revenue/);
      assert.match(markup, /does not grant a commercial ntop license/);
      assert.match(markup, /does not write acceptance to \/etc/);
      assert.doesNotMatch(markup, /Ядро|Отказ отменяет|Принятие условий/);
    }
  }
});
