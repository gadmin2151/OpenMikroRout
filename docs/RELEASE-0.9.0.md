# OpenMikroRout 0.9.0

## Match negation in NAT and Firewall

The classic rule editors now provide a compact **!** control beside match
criteria. It means “everything except the selected value”, for example all
source addresses except one IPv4 host or subnet. Inverted conditions remain
visible in the rule table and survive tab changes, copying, JSON/RSC export
and backup/restore.

Supported criteria are IPv4 addresses, address lists, countries, ports,
protocol, individual interfaces and connection states. Empty values and
unsupported combinations are rejected. Interface-list inversion is not offered.

An inverted address list excludes the union of all its members. System lists
use native inverted ipset matches; ordinary lists use bounded IPv4 complement
calculation, with the existing rule-expansion limits enforced. No arbitrary
iptables arguments or shell text are accepted.

Automatic rule-level Fail2ban protection respects excluded source addresses,
lists and countries. Incompatible inversions are rejected rather than silently
broadening the scope of automatic bans.

## Compatibility

The classic interface remains in place. Existing rules default to positive
matching; updating does not change active network policy or enable Fail2ban.
No database migration is required. Configuration changes continue to use
draft, preview, timed apply, confirmation and rollback.

## Validation

724 Python tests and 205 interface tests passed, together with Ruff, mypy,
ESLint, syntax and formatting checks. Isolated Linux packet tests verified
native negation, whole-list exclusion and Fail2ban source exclusions.

See [the negation guide](https://github.com/gadmin2151/OpenMikroRout/blob/main/docs/MATCH-NEGATION.md)
for examples and limits.
