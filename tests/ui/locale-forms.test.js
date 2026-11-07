import test from "node:test";
import assert from "node:assert/strict";
import { setLanguage } from "../../app/static/i18n.js";
import {
  routerViews,
  renderRouterView,
  handleRouterAction,
} from "../../app/static/router-pages.js";
import {
  discoveryViews,
  renderDiscovery,
  resetDiscovery,
} from "../../app/static/discovery-ui.js";

const e = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );
const editorKinds =
  "dns_static addresses bridges vlans virtual_interfaces routes pools dhcp_servers dhcp_reservations interface_lists filter".split(
    " ",
  );
const contractAttributes =
  "name type min max step minlength maxlength pattern".split(" ");
function context() {
  return {
    state: {
      revision: 4,
      config: {
        rules: [],
        filter_rules: [],
        address_lists: [],
        system_lists: [],
        network: {},
        discovery: { enabled: false, interfaces: ["eth0"] },
        scanning: { enabled: false, interfaces: ["eth0"] },
        fail2ban: { enabled: false, profiles: [] },
      },
    },
    interfaces: [{ name: "eth0" }, { name: "eth1" }],
    networkStatus: {},
    offline: false,
    canWrite: () => true,
    isDemo: () => true,
    e,
    icon: () => "",
    actionBadge: e,
    empty: (_icon, title, note) => `<p>${e(title)} ${e(note)}</p>`,
    dialog: { classList: { add() {} } },
  };
}
const noRussian = (markup, label) =>
  assert.doesNotMatch(markup, /[А-Яа-яЁё]/u, label);
// Compare browser validation and submitted names, rather than translated labels.
function controls(markup) {
  return [...markup.matchAll(/<(input|select|textarea)\b([^>]*)>/g)].map(
    ([, tag, attrs]) => [
      tag,
      ...contractAttributes.map(
        (name) => attrs.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1] || "",
      ),
      /\brequired\b/.test(attrs),
      /\bdisabled\b/.test(attrs),
    ],
  );
}
async function editor(ctx, kind) {
  let frame;
  ctx.dialogFrame = (...parts) => {
    frame = parts;
  };
  assert.equal(
    await handleRouterAction({ dataset: { action: "router-new", kind } }, ctx),
    true,
  );
  assert.ok(frame, kind);
  return frame;
}

test.afterEach(() => {
  setLanguage("ru");
  resetDiscovery();
});

test("English after module import translates every router and discovery page", () => {
  setLanguage("en");
  const ctx = context();
  for (const view of Object.keys(routerViews))
    noRussian(renderRouterView(view, ctx), `router page: ${view}`);
  for (const view of Object.keys(discoveryViews))
    noRussian(renderDiscovery(view, ctx), `discovery page: ${view}`);
});

test("every schema editor translates title, fields and help without changing validation", async () => {
  for (const kind of editorKinds) {
    setLanguage("ru");
    const russian = await editor(context(), kind);
    assert.match(russian[0], /Создать/, kind);
    setLanguage("en");
    const english = await editor(context(), kind);
    noRussian(english.join(""), `editor: ${kind}`);
    assert.match(english[0], /^(?:New|Create):/, kind);
    assert.deepEqual(controls(english[2]), controls(russian[2]), kind);
  }
});

test("Filter advanced, Fail2ban and action tabs translate while retaining form names", async () => {
  const collect = async (language) => {
    setLanguage(language);
    const ctx = context();
    await editor(ctx, "filter");
    // A read-only tab switch uses the already captured item and needs no browser DOM.
    ctx.canWrite = () => false;
    const frames = [];
    ctx.dialogFrame = (...parts) => frames.push(parts);
    for (const tab of ["advanced", "fail2ban", "action"])
      await handleRouterAction(
        { dataset: { action: "router-editor-tab", tab } },
        ctx,
      );
    return frames;
  };
  const russian = await collect("ru"),
    english = await collect("en");
  assert.equal(english.length, 3);
  for (const [index, frame] of english.entries()) {
    noRussian(frame.join(""), `filter tab ${index}`);
    assert.deepEqual(controls(frame[2]), controls(russian[index][2]));
  }
});

test("switching back to Russian restores page and editor labels", async () => {
  setLanguage("en");
  assert.match(renderRouterView("dns", context()), /Listen Interfaces/);
  setLanguage("ru");
  assert.match(renderRouterView("dns", context()), /Интерфейсы прослушивания/);
  assert.match(
    renderDiscovery("port_scan", context()),
    /Запустить сканирование/,
  );
  assert.match((await editor(context(), "addresses"))[0], /Создать/);
});
