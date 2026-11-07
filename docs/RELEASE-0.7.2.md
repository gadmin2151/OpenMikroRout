# OpenMikroRout 0.7.2

## Selected outgoing interface, independent destination

Network Scan and Port Scan now use the selected interface as the outgoing
interface. The destination can be an IPv4 host, a DNS name for a port scan,
or an IPv4 subnet for network discovery, including destinations reached through
a gateway or WireGuard. It no longer has to belong to that interface's directly
connected network. The displayed connected subnets are informational.

Select **Tools → Network Scan / Port Scan → Outgoing interface**, enter the
destination and start. The selected interface remains explicit; no automatic
interface substitution occurs. Connectivity depends on that interface's routes,
VPN peer policy and the remote host's responses. Network discovery uses Nmap's
normal local/routed host-discovery probes instead of forcing ARP-only discovery.

Existing active-scan enablement, outgoing-interface permissions, full access,
host/rate/time/output limits and cancellation remain in effect. Invalid,
multicast and broadcast host targets remain rejected. DNS names are resolved
and pinned to a literal IPv4 before execution. There is no arbitrary Nmap
argument or shell input.

## Continuous Ping

The web Ping runs at one packet per second until **Stop**. There is no four-packet
or fixed-duration limit. Leaving the diagnostics section, closing the page,
signing out or losing the session terminates the subprocess. The latest 32 KiB
of output remain visible while running; old lines roll out without growing the
page indefinitely. Other diagnostic tools retain their time limits.

`POST /api/tools/stream` defaults to continuous mode for Ping and also accepts
an explicit `continuous` boolean for Ping. The legacy `POST /api/tools/run`
remains a bounded four-packet check. Shared admission/rate limits and session
revalidation remain; stalled consumers are disconnected.

## Packet Sniffer

Open **Tools → Packet Sniffer** to monitor IPv4 packet headers in real time.
Choose one interface or **All interfaces (any)**, then filter by TCP, UDP, ICMP,
source/destination IPv4 or CIDR, and an optional TCP/UDP port. **Stop** or leaving
the section stops the capture. Ping and capture have independent admission
locks, allowing a diagnostic in another tab during capture.

The viewer uses `tcpdump` with structured, server-validated filters, numeric
addresses, bounded live text and no promiscuous-mode request. It displays packet
headers without a payload dump or file export. Filters do not modify firewall,
interfaces or routes. Capture requires full access and a valid session; the
demo does not capture host traffic. Text output is transient in the current
window and retains the latest 32 KiB.

Linux hosts need `tcpdump` and the service's existing `CAP_NET_RAW` capability.
The Docker image includes it; on an existing Debian/Proxmox host without the
utility, install the distribution's `tcpdump` package. The status panel explains
when the utility is missing.

## Compatibility and verification

No database or network-configuration migration is required. Existing outgoing
interface permissions and rate/host limits are preserved. Their permitted
destination scope now includes routed IPv4 targets, as described above.
Accounts, languages, passwords, TOTP, firewall rules, drafts and VPN keys are
unchanged. Asset versions and mandatory cache revalidation load the new UI.

Verification includes real local/routed TCP, UDP and network discovery in
isolated Linux namespaces, plus real WireGuard scanning to a destination outside
the interface's connected subnet. Live-stream tests cover continuous output,
rolling buffers, strict framing, cancellation, stale sessions and process cleanup.
Packet capture is verified using synthetic traffic in an isolated Linux network.

- Python: 702 passed, 19 platform-specific skips on macOS.
- UI: 191 tests passed, including routed targets, continuous output, capture
  filtering, rolling buffers, cancellation and stable form selection.
- Isolated Linux gate: 53 tests passed, including real routed/WireGuard scans
  and TCP/UDP capture under the service's capability restrictions.
- Ruff formatting/lint, mypy (112 source files), ESLint, Prettier and dependency
  checks passed.
- Browser: Ping remained active beyond 60 replies; Stop terminated it. Packet
  Sniffer displayed synthetic UDP headers while active, and Stop reaped tcpdump.
  Traceroute produced its hop result. Capture layout had no overflow at 390 px.
- Queued updates stop live tools before the updater restarts the service.
