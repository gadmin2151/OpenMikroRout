"""Opt-in real Linux test: every mutation is confined to a NEW network namespace."""

import os
import platform
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux root / network namespaces; never touches host networking",
)
def test_real_iptables_in_isolated_namespace() -> None:
    unshare = shutil.which("unshare")
    assert unshare, "Install util-linux"
    code = """
import shutil
from app.compiler import patch, rollback_patch
from app.firewall import LinuxDriver
from app.models import Configuration, NatRule
iptables = shutil.which('iptables')
assert iptables, 'Install iptables'
driver = LinuxDriver()
driver.run([iptables, '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.99.0.0/16', '-j', 'ACCEPT'])
before = driver.snapshot()
config = Configuration(rules=[
    NatRule(name='Web', dst_ports='443,8000-8010', src_ports='1024-65535',
            to_address='192.168.1.10', to_ports='8443'),
    NatRule(name='Internet', chain='srcnat', action='masquerade', protocol='any',
            src_address='192.168.1.0/24'),
])
payload = patch(before, config)
driver.restore(payload, test=True)
assert driver.snapshot() == before, '--test changed the table'
driver.restore(payload)
after = driver.snapshot()
assert after.count('nat-panel:anchor') == 3
assert '-j DNAT' in after and '-j MASQUERADE' in after
assert '-s 10.99.0.0/16 -j ACCEPT' in after
assert 'nat-panel:anchor' not in patch(after, config)
# A separate administrator adds a rule AFTER our snapshot.
driver.run([iptables, '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.98.0.0/16', '-j', 'ACCEPT'])
rollback = rollback_patch(driver.snapshot(), before)
driver.restore(rollback, test=True)
driver.restore(rollback)
restored = driver.snapshot()
assert 'nat-panel:anchor' not in restored
assert '-j DNAT' not in restored
assert '-s 10.99.0.0/16 -j ACCEPT' in restored
assert '-s 10.98.0.0/16 -j ACCEPT' in restored
"""
    result = subprocess.run(
        [unshare, "--net", sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    assert result.returncode == 0, result.stderr
