# Repository images

The application screenshots were captured from **OpenMikroRout 0.5.0**, running
locally in `demo` mode. The screenshot session used a separate data directory;
it did not access production/PVE settings or modify host networking.

Addresses, devices, counters and traffic charts are demo examples. The WireGuard
server and its three peers were created in that isolated demo. No tunnels were
started, and no private keys, client profiles, passwords or 2FA seeds are shown.

| Image                | View                                                                   |
| -------------------- | ---------------------------------------------------------------------- |
| `cover.jpg`          | Repository cover, rendered from [the HTML source](../brand/cover.html) |
| `overview.jpg`       | Network overview: counters and one-minute charts                       |
| `nat.jpg`            | Firewall → NAT                                                         |
| `rule-editor.jpg`    | NAT properties editor                                                  |
| `wireguard.jpg`      | WireGuard → Peers                                                      |
| `dhcp.jpg`           | IP → DHCP Server                                                       |
| `connections.jpg`    | Firewall → Connections                                                 |
| `backup-restore.jpg` | System → Backup / Restore                                              |

Screenshots are unretouched browser JPEG captures. The cover reuses the accepted
[Folded Route logo](../../app/static/logo.png) without changing its artwork and
uses a diagram of the implemented network functions. It is not an application screenshot.

Keep screenshots and the README aligned with the application. Re-capture in an
isolated demo when the relevant interface changes. The cover is 1280 × 640 pixels;
the screenshot files keep their captured dimensions and aspect ratios.
