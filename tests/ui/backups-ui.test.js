import test from "node:test";
import assert from "node:assert/strict";
import {
  renderBackups,
  handleBackupAction,
  resetBackups,
} from "../../app/static/backups-ui.js";
import { isReadAction } from "../../app/static/access-ui.js";

const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function context() {
  return {
    state: { revision: 0, auth_enabled: true },
    e: escape,
    icon: () => "",
    canWrite: () => true,
    generation: 1,
    getGeneration: () => 1,
    run: async (fn) => fn(),
    render: () => {},
  };
}

test("read users may export public configuration but cannot create backups or stage imports", async () => {
  const ctx = { ...context(), canWrite: () => false };
  const html = renderBackups(ctx);
  assert.match(html, /Export \.rsc/);
  assert.match(html, /data-action="backup-create-open" disabled/);
  for (const action of [
    "backup-create-open",
    "backup-inspect",
    "backup-stage-open",
    "backup-stage",
  ])
    await assert.rejects(
      handleBackupAction({ dataset: { action } }, ctx),
      /full/,
    );
  assert.equal(isReadAction("backup-export-rsc"), true);
  assert.equal(isReadAction("backup-export-json"), true);
  assert.equal(isReadAction("backup-create"), false);
});

function inspectFixture() {
  const pass = { value: "" };
  const file = {
    name: "test.rsc",
    size: 100,
    text: async () => "# OpenMikroRout RSC 1",
  };
  const form = {
    reportValidity: () => true,
    dataset: { revision: "0" },
    querySelector: (selector) =>
      selector === '[name="file"]'
        ? {
            files: [file],
          }
        : pass,
  };
  return {
    querySelector: (selector) =>
      selector === "#backup-import-form" ? form : null,
  };
}

test("preview escapes uploaded text and cannot stage after another session edits the draft", async () => {
  const previous = globalThis.document;
  globalThis.document = inspectFixture();
  resetBackups();
  const ctx = {
    ...context(),
    api: async () => ({
      preview_id: "preview",
      before: { rules: 1 },
      after: { rules: 2 },
      accounts: [{ username: "<admin>", role: "full" }],
      warnings: ["<warning>"],
      script: "<script>bad</script>",
    }),
  };
  try {
    await handleBackupAction({ dataset: { action: "backup-inspect" } }, ctx);
    const html = renderBackups(ctx);
    assert.match(html, /&lt;script&gt;/);
    assert.ok(!html.includes("<admin>") && !html.includes("<script>"));
    assert.match(
      renderBackups({ ...ctx, busy: true }),
      /data-action="backup-stage-open" >Загрузить/,
    );
    ctx.state.revision = 1;
    await assert.rejects(
      handleBackupAction({ dataset: { action: "backup-stage-open" } }, ctx),
      /другой сессии/,
    );
  } finally {
    globalThis.document = previous;
    resetBackups();
  }
});

test("a late file preview cannot populate another user's session", async () => {
  const previous = globalThis.document;
  globalThis.document = inspectFixture();
  resetBackups();
  let generation = 1,
    renders = 0;
  const ctx = {
    ...context(),
    getGeneration: () => generation,
    render: () => renders++,
    api: async () => {
      generation = 2;
      return {
        accounts: [{ username: "PRIVATE-USER" }],
        script: "PRIVATE-SCRIPT",
      };
    },
  };
  try {
    await handleBackupAction({ dataset: { action: "backup-inspect" } }, ctx);
    assert.equal(renders, 0);
    assert.ok(!renderBackups(ctx).includes("PRIVATE-USER"));
  } finally {
    globalThis.document = previous;
    resetBackups();
  }
});
