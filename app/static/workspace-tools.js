import { navigationItems } from "./navigation-ui.js?v=1";

export const WORKSPACE_MAX_WINDOWS = 32;
const leaves = (items) =>
  items.flatMap((item) => (item.children ? leaves(item.children) : [item]));
const allContext = {
  state: { config: {}, auth_enabled: true },
  interfaces: [],
  canWrite: () => true,
};
const knownItems = leaves(navigationItems(allContext));
const families = new Map(
  knownItems.flatMap((item) =>
    (item.views || [item.view]).map((view) => [view, item.view]),
  ),
);

export const isWorkspaceView = (view) =>
  typeof view === "string" && families.has(view);
export const sameWorkspaceTool = (left, right) =>
  isWorkspaceView(left) && families.get(left) === families.get(right);

/** The menu is the source of tool families and role visibility; no router values
 * or private editor state are copied into desktop/window definitions. */
export function getWorkspaceTools(ctx) {
  return leaves(navigationItems({ ...allContext, ...ctx })).map((item) => {
    const compact = ["security", "web_settings", "updates"].includes(item.view);
    return {
      id: item.view,
      view: item.view,
      title: item.label,
      icon: item.icon,
      aliases: (item.views || [item.view]).filter((view) => view !== item.view),
      minWidth: compact ? 460 : 620,
      minHeight: 340,
      width: item.view === "overview" ? 1120 : compact ? 760 : 980,
      height: item.view === "overview" ? 760 : 650,
    };
  });
}

export function getWorkspaceTool(view, ctx) {
  return (
    getWorkspaceTools(ctx).find(
      (tool) => tool.view === view || tool.aliases.includes(view),
    ) || null
  );
}
