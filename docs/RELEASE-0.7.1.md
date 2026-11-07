# OpenMikroRout 0.7.1

## Live network tools

Ping and traceroute show output as it arrives, before the command finishes.
The diagnostic panel stays usable and offers Cancel; cancelling preserves the
output already received and terminates the server-side process. DNS, route and
TCP checks use the same bounded runner. TCP checks send no application payload.

The new full-role, CSRF-protected `POST /api/tools/stream` endpoint returns
newline-delimited JSON events (`started`, `output`, `completed`, `error`).
The existing `POST /api/tools/run` response remains compatible. Both endpoints
share one active diagnostic and a limit of 12 starts per minute. Output is
bounded to 32 KiB; disconnects, session revocation and timeouts stop the runner.
Reverse proxies should pass this response without buffering.

## Scan interfaces and setup

Network Scan and Port Scan now show discovered directly connected IPv4
interfaces even when scanning is disabled or the allowed-interface list is
empty. Interfaces requiring permission are labelled; unavailable saved
interfaces remain visible with an explanation.

To enable scanning, open **Tools → Network Scan → Scan settings**, enable active
scanning, select only the intended interfaces, save the draft and apply and
confirm the configuration. These are the shared settings for both scan pages.
The interface dropdown does not itself grant permission. Targets remain
restricted to the selected interface's approved directly connected networks.

## Live scan progress

- Active jobs show the current Nmap phase, elapsed time and phase progress.
- The selected active job refreshes every 500 ms without rebuilding the form
  or repeatedly loading the full inventory. Hidden pages pause this polling.
- Found hosts and open ports appear during execution. Partial observations
  are marked and replaced by authoritative XML results as they become available.
- Cancelled or failed jobs retain the results already collected. History and
  results remain server-side and can be reopened after refreshing the browser.
- A phase percentage is not an overall time estimate; 100% is reserved for a
  successfully completed job. No response does not prove a host is absent.

Scans retain fixed argument profiles, one active job, rate/host/port/output
limits and continuous checks of the applied interface policy. No automatic
network or firewall policy changes are introduced.

## Compatibility and verification

No database or router-configuration migration is required. Existing accounts,
language preferences, network drafts, firewall rules and VPN keys are preserved.
The entry asset versions are bumped and existing mandatory cache revalidation
ensures updated modules are loaded after installation.

- Python: 668 passed, 16 platform-specific skips on macOS.
- UI: 177 tests passed, including live output, cancellation, interface readiness,
  incremental job updates, escaping and stale-session handling.
- Ruff formatting/lint, mypy, ESLint, Prettier and dependency checks passed.
- Real Linux browser: first Ping response appeared while the command was still
  running; completion and cancellation were verified separately.
- Nmap network, TCP and UDP acceptance runs in isolated Linux namespaces.
- GitHub CI also checks the exact release commit and container startup.
