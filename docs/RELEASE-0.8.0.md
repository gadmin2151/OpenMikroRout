# OpenMikroRout 0.8.0

## A WinBox-style desktop inside one browser tab

The left menu now opens independent tool windows. Overview, Interfaces, NAT,
Ping and Packet Sniffer can remain open together, with their own forms, filters,
selection, scroll positions and live operations. Selecting an open tool brings
its existing window forward instead of creating a duplicate.

Drag the title bar, resize any edge or corner, minimize, maximize, restore or
double-click the title. The desktop toolbar offers cascade, tile, gather,
left/right placement and independent content zoom from 80% to 125%. Tile layout
adapts to the available area without overlapping windows. Keyboard controls are
Alt + arrows to move and Alt + Shift + arrows to resize a focused title.

The bottom taskbar and **Open windows** item in the left menu show all tools,
including minimized windows and running operations. On phones, one full-screen
tool panel is visible at a time, with the same window switcher.

Tool interiors use compact tabs, command bars, tables and property editors, with
matte light surfaces and navy accents. RU/EN follows the existing user profile.

## Live tools, forms and shared configuration

Switching or minimizing keeps Ping and packet capture running. Closing a live
tool stops only that window's operation. Closing an active server scan offers
Cancel, Continue in background, or Stop and close. Reopening the scan reconnects
to its server-stored progress and partial results.

Unsaved editor and settings changes are protected when closing or navigating.
Background refresh also preserves input entered while requests are pending.
Rapid subview selection waits for initialization or an ongoing save. Existing
server revision checks reject stale saves from another window.

Configuration stays shared. Saving refreshes the other tools and the common
apply bar; its connectivity confirmation timer always remains outside windows.
Existing read/full permissions and server limits of one diagnostic, one capture
and one scan are preserved.

## Persistence and update behavior

Only window geometry, zoom, selected subviews and minimized/open state are saved
locally, separately by account, router and origin. Form values, credentials,
keys and packet/diagnostic output are excluded. Restoring the desktop never
starts diagnostic commands automatically. Reset layout preserves active tools
and unfinished forms while restoring their geometry and zoom.

Safe shared JSON reads are bounded and deduplicated. Writes, streams, account
secrets and archives keep their normal authenticated transport. Only the exact
same-origin `/workspace-frame` endpoint permits embedding; the main document,
API and assets retain their previous frame restrictions.

The public update-health watcher now belongs to the main document. It survives
closing Updates or session expiration during restart and reloads the whole
desktop after the target version passes health checks. Mandatory JS/CSS cache
revalidation remains enabled.

No database or network configuration migration is required. Updating the UI does
not apply router drafts, alter firewall/NAT/routes or change accounts/VPN keys.

## Verification

- Python: 720 passed, 19 platform-specific skips on macOS; local TCP/UNIX socket
  fixtures were verified outside the filesystem sandbox.
- UI: 251 tests passed, including frame isolation, layout validation, unchanged
  iframe attachment, navigation queues, form refresh races and update delegation.
- Ruff format/lint, mypy, dependency validation, ESLint and Prettier passed.
- Browser acceptance covered five simultaneous windows, real pointer drag and
  resize with caret/form preservation, minimize/restore of continuous Ping,
  independent UDP capture, scan continue/stop after closing, common apply and
  timed confirmation, persisted RU/EN, account-isolated read/full layouts,
  restore without command autostart and a 390px mobile view without page overflow.

See [the workspace guide](WORKSPACE.md) for implementation and usage details.
