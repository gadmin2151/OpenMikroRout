#!/bin/sh
# Install the optional private engine only. This does not enable protection or host jails.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
command -v fail2ban-server >/dev/null
command -v fail2ban-client >/dev/null
command -v ipset >/dev/null
command -v modprobe >/dev/null
[ -x /opt/openmikrorout/.venv/bin/python ]
[ -f /opt/openmikrorout/deploy/openmikrorout-fail2ban.service ]
[ -f /opt/openmikrorout/deploy/openmikrorout-fail2ban.conf ]
[ -f /opt/openmikrorout/deploy/openmikrorout-security-modules.conf ]
systemctl cat openmikrorout.service >/dev/null
if systemctl is-active --quiet openmikrorout-update.service; then
  echo 'Wait for the active OpenMikroRout update before installing its companion.' >&2
  exit 1
fi
# Additive kernel support only; never flush sets/rules or unload networking modules.
modprobe -a ip_set ip_set_hash_ip ip_set_hash_net xt_set nfnetlink_log nf_conntrack_netlink xt_NFLOG xt_hashlimit
install -d -m 0755 /etc/modules-load.d
install -m 0644 /opt/openmikrorout/deploy/openmikrorout-security-modules.conf \
  /etc/modules-load.d/openmikrorout-security.conf
install -m 0644 /opt/openmikrorout/deploy/openmikrorout-fail2ban.service /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/openmikrorout.service.d
install -m 0644 /opt/openmikrorout/deploy/openmikrorout-fail2ban.conf \
  /etc/systemd/system/openmikrorout.service.d/20-fail2ban.conf
systemd-analyze verify /etc/systemd/system/openmikrorout-fail2ban.service
systemctl daemon-reload
systemctl enable --now openmikrorout-fail2ban.service
