# OpenMikroRout 0.7.0

## RU / EN

Choose **My profile → Interface language → Save**. Russian is the default;
English and Russian are stored per account on the server and restored after
sign-in on another browser. Both `read` and `full` users can change their own
language. This does not change permissions, passwords, TOTP, sessions or the
network draft. The sign-in screen also offers a temporary RU / EN selector.

Navigation, editors, help, accessible labels, country names and number/date
formats follow the selected language. Names, addresses, keys, comments, protocol
identifiers and imported configuration values retain their original content.

## Forms and responsiveness

- Multiple interface/state selections use native checkboxes, with a selected
  count, search, Select all and Clear. Ctrl/Cmd is no longer required.
- Scan controls use a responsive field grid and a separate action row. Buttons
  fit their text and no longer stretch to the height of neighboring controls.
- Shared fieldsets, tables, long labels and narrow-screen action rows have
  consistent spacing and sizing.
- Expanding menu groups preserves the current form. Switching pages starts at
  the top of the content while retaining sidebar scroll.

## Performance

- Stable 200 ms telemetry samples update numeric targets and chart regions;
  unchanged interface/device/destination tables are retained. Inventory, errors,
  interface/period selection and language changes use the full rendering path.
- One measuring canvas is reused. Existing graph interpolation, reduced-motion
  behavior and collected values are preserved.
- In the instrumented 128-interface fixture, incremental samples parse about
  98% less HTML than rebuilding the dashboard. This measures rendering work,
  not a universal latency improvement on every device.
- NAT search/filter and menu expansion update their own regions. Unchanged user
  lists and discovery results are not replaced on every poll.
- Static text assets are gzip-compressed where supported, retaining ETag and
  mandatory cache revalidation. Account/API responses keep their existing
  transport and `no-store` behavior.

## Compatibility

The account database gains a `language` column with default `ru`. Old account
backups without this field remain valid; new encrypted backups preserve it.
No network configuration migration is required. IPv4 firewall, NAT, VPN and PVE
policy are outside this release's changes.

See [the forms audit](UI-AUDIT-2026-11-07.md) for verification scope and results.

## Release validation

- Python: 645 passed, 16 platform-specific skips on macOS.
- UI: 164 tests passed, including the all-editor locale matrix.
- Ruff formatting/lint, mypy (107 source files), ESLint, Prettier and pip check passed.
- Browser: isolated full/read accounts, RU/EN profile persistence and desktop/mobile forms.
- GitHub CI verifies the exact release commit, Linux network suite and both container smokes.
