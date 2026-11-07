# OpenMikroRout 0.8.1

## Classic interface restored

This release restores the familiar interface from 0.7.2: a fixed left menu,
one full-width settings page and the existing property editors. It removes the
window desktop, embedded tool documents, taskbar and window-layout controls.
Navigation loads sections directly within the main document.

The server again rejects embedding everywhere. Mandatory asset revalidation
and automatic whole-page reload after an update remain enabled. Old desktop
layout preferences are ignored; no browser data or router settings are erased.

## Connections table sorting

Click a column heading to sort the loaded connections ascending; click again
for descending order. IPv4 endpoints use numeric address and port ordering,
and packet, byte and time values use numeric ordering. Missing values remain
last. Sorting survives live refresh and is available to read and full accounts.

Sorting affects the displayed monitoring records only. Existing filters and
the bounded result set remain; Firewall/NAT rule execution order is preserved.

## Compatibility

This is a forward update from 0.8.0, with the classic UI restored. No database
migration or configuration restore is required. Existing network settings,
drafts, users, RU/EN preferences, TOTP and WireGuard keys are preserved.

Diagnostic concurrency is unchanged: the existing server supports one active
diagnostic, one packet capture and one scan in their respective subsystems.
