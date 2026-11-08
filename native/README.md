# Native application companion

The Python control plane stays outside the packet path. This companion uses
libnetfilter_queue/libmnl for IPv4 FORWARD classification and a separate nDPI
worker over a private bounded Unix socketpair. It writes only bounded, owned
runtime snapshots; it never writes iptables rules or modifies skb routing marks.

The pinned engine is the current nDPI 6.0 stable support revision
`cd1d03a52f0c968f1835110d70f5da652171a5d5`. Core LGPL and additional restricted ntop
components have different upstream terms. Engine initialization uses the explicit
policy `engine_license_profile` (`lgpl-only`, `not-for-profit`, or
`commercial-license`); it does not infer eligibility from OpenMikroRout's license.
The installer/control plane must verify its required acceptance receipt before
installation or use, including the selected intended-use declaration.

## Commands

- `capabilities --json [--license-profile PROFILE]`: actual engine protocol names,
  source revision, profile, and compiled datapath features. These features do not
  certify a particular host kernel or application's detection accuracy.
- `validate --policy PATH --json`: validate a bounded generated schema-1 policy.
- `run --policy PATH --state-dir PATH`: foreground Observe or Enforce runtime.
- `replay --policy PATH --pcap PATH --json`: bounded offline classic PCAP replay
  (raw IPv4/Ethernet; no PCAPNG), using the same classifier and policy decisions.

Policy, verdict CT layout and runtime JSON follow the Python application service.
The default mask is `0x00ffffff`: low six bits are NEW/ESTABLISHED/RELATED outcomes,
`0x40` valid, `0x80` Pending, generation epoch shifted by eight. Verdicts use
nested NFQA_CT/CTA_MARK and CTA_MARK_MASK. NFQA_MARK/skb marks are never changed.
Pending by itself is not a PROBE permission. Rules use first match for each real
conntrack state, and only verified application capabilities can authorize a probe
or an Allow above an eligible port denial. Hostnames, IP guesses and port guesses
never grant that exception.

The classifier drops UID/GID and supplementary groups, clears inherited file
descriptors, uses no-new-privileges, a default-deny syscall allowlist and bounded resources, and
is killed if the supervisor dies. The supervisor needs NET_ADMIN for Enforce,
NET_RAW for Observe, and SETUID/SETGID for the worker identity drop. No broad
container privilege or kernel module installation is required.

`status.json` and `flows.json` are private atomic snapshots. Queue byte/packet
counts describe classification observations, not complete kernel accounting of
flows after fast path. Observe interface metadata is capture-based; real
Netfilter interfaces/states are available in Enforce. Payload, full URLs, secrets
and cookies are not written to these snapshots.

Observe uses interface-bound `ETH_P_ALL` packet taps so both outgoing requests
and incoming replies reach the classifier. Network-header parsing then admits
only scoped IPv4 TCP/UDP; it does not activate NFQUEUE or change firewall rules.
Catalog protocol names and literal domains are indexed once. The longest DNS
suffix wins, while shared ambiguous suffixes remain unattributed. Generic
protocol labels and weak hostname/IP/heuristic evidence cannot bypass strict
Unknown blocking or grant a port exception. Runtime policies are bounded to
4,096 concrete application/protocol records and 4 MiB.

## Build and verification

`Dockerfile.build` pins the distro base and engine commit. Build the `engine`
stage for compilation; `verification` adds the Python backend and verification
dependencies. The `companion` stage assembles
`/output/app/native/{bin,lib,licenses,manifest.json}` with regular files only.
Pass the exact committed OpenMikroRout source revision as `OMR_SOURCE_COMMIT`.
The runtime loader uses a relative private library path. The stock signed updater
checks the bundle manifest and all files before installation.

Run `make check` on a native Linux architecture. Tests exercise real synthetic
BitTorrent DPI, Allow/Block and HTTP negative cases on the same port, unsupported
Allow capability, malformed packets and bounded policy/replay input.
`make check-emulated` is only for functional x86 tests under Rosetta: guest
RLIMIT_AS/seccomp are not supported there. Its binary explicitly reports
`test_instrumentation:true` and the bundle builder refuses to package it. Production
keeps those controls; verify its sandbox and nested conntrack metadata on the
actual target architecture before enabling enforcement.

Run the production namespace proof explicitly as root:
`OMR_RUN_NATIVE_KERNEL_TESTS=1 python3 native/tests/test_kernel.py --binary
/absolute/path/to/app/native/bin/omr-app-supervisor --backend-quarantine --json`.
Select the previously accepted profile with `--license-profile not-for-profit`
or `--license-profile commercial-license` only when its actual eligibility or
agreement applies. The default is `lgpl-only`. The proof creates and removes
three private network namespaces; it never modifies the host firewall or host
forwarding settings. It verifies the first-SYN conntrack metadata, reserved CT
mask and routing-mark preservation, real BitTorrent Allow above an eligible port
denial, an unrelated HTTP negative, later IP denial, Block before established
acceptance, production worker sandbox, real compiler restore validation and
same-connection quarantine after worker failure. Results bind the kernel release,
binary hash, declared license profile and complete native bundle inventory.

Selected TCP/UDP IPv4 fragments and malformed/truncated packets are dropped;
this first implementation does not reassemble fragmented application payloads.
The classifier cache holds at most 4,096 flows and monitor snapshots expose at
most 500. New-flow admission is bounded to 20 per second per client and 256 per
second globally. Rate and pending-capacity failures follow `failure_policy`
(Block by default); a full flow cache drops new admissions without evicting live
classifications. These limits are reported by capabilities/status.

Native protocol recognition is not cryptographic process identity. Catalog
capabilities, malformed/Unknown behavior, initial probe budgets, selected scopes,
recovery and effective firewall verdicts remain explicit control-plane policy.
