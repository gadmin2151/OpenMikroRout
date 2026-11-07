# OpenMikroRout 0.10.0

## Visual Boolean filter builder

Lists now provide a shared visual builder with field, operator and value rows,
AND/OR groups, explicit parentheses, and individual condition/group removal.
Operators depend on field type: text, choices, IPv4/CIDR, ports and counters.
The builder is the single list-filter interface. Exclusions use the appropriate
not-equal, does-not-contain and not-in operators within the condition rows.

Available in Connections (both modes), NAT, WireGuard Peers, Neighbors, Fail2ban
bans, GeoIP country lists, system-list contents and Packet Sniffer. Read accounts
can use list filters; packet capture still requires full access. Capture criteria
are locked while a capture runs.

Incomplete edits remain in the form until applied. Polling does not apply a
partially entered expression or replace the active input. Each display scope has
its own draft and applied expression. Applying an empty root group removes the
active filter; logout clears editor state.

## Bounded evaluation

Expressions are typed data with up to 16 conditions, 31 nodes, four levels,
128 characters per value and 4096 bytes of JSON. Unknown fields, operators,
properties and malformed values are rejected. SQL parameters and grouped BPF
predicates come only from fixed server mappings. There is no arbitrary query,
shell or tcpdump expression execution.

Server-side expressions are evaluated before totals and pagination. Fixed
resource scopes remain outside user-controlled OR groups. Python and browser
matching share Unicode case folding, IPv4 interval rules and exact decimal
comparison. Connections also offers separate source/destination/translated ports
and the translated destination address.

## Compatibility

No database migration or router-policy change is required. Existing API query
parameters remain accepted for integrations. Updating preserves NAT, Firewall, VPN, Fail2ban,
accounts, 2FA and keys. The classic interface remains in place.

See [the builder guide](https://github.com/gadmin2151/OpenMikroRout/blob/main/docs/QUERY-BUILDER.md)
for examples and limits.

## Validation

853 Python tests and 277 interface tests passed, with Ruff, mypy, ESLint,
syntax, formatting and dependency checks. Shared browser/server fixtures cover
typed values and exact matching; schema-contract checks cover all seven server
display scopes. Real libpcap checks use synthetic captures. Browser validation
covered nested AND/OR results, unapplied drafts, RU/EN and a 390px layout.
