"""Opt-in real Fail2ban/ipset test; all networking is inside a new namespace."""

import os
import platform
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(
    os.environ.get("NAT_RUN_KERNEL_TESTS") != "1" or platform.system() != "Linux",
    reason="Requires opt-in Linux root/network namespaces; never touches host networking",
)
def test_real_fail2ban_detects_five_failures_scopes_blocks_unbans_and_expires() -> None:
    assert shutil.which("unshare"), "Install util-linux"
    code = r"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from app.fail2ban_models import F2BConfiguration
from app.fail2ban_runtime import Fail2banService
from app.filtering import LinuxFilterDriver, filter_patch, filter_rollback
from app.ipsets import LinuxIPSetDriver
from app.models import Configuration

for binary in ('ip', 'iptables', 'ipset', 'fail2ban-client', 'fail2ban-server', 'fail2ban-regex'):
    assert shutil.which(binary), 'Install ' + binary

def run(*args):
    return subprocess.run(list(args), check=True, capture_output=True, text=True, timeout=10).stdout

def wait_for(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(.1)
    raise AssertionError('Condition did not complete before deadline')

run('ip', 'link', 'set', 'lo', 'up')
run('ip', 'addr', 'add', '10.55.0.1/24', 'dev', 'lo')
run('ip', 'addr', 'add', '10.55.0.2/24', 'dev', 'lo')
# Even an existing foreign ACCEPT cannot bypass the inserted owned protection hook.
run('iptables', '-A', 'INPUT', '-j', 'ACCEPT')
filters = LinuxFilterDriver()
before = filters.snapshot()
listeners = []
stop = threading.Event()
def listen(port):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('10.55.0.1', port))
    sock.listen(16)
    sock.settimeout(.2)
    listeners.append(sock)
    def accept():
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                conn.close()
            except TimeoutError:
                pass
            except OSError:
                return
    threading.Thread(target=accept, daemon=True).start()

def connects(port):
    with socket.socket() as sock:
        sock.settimeout(.4)
        sock.bind(('10.55.0.2', 0))
        return sock.connect_ex(('10.55.0.1', port)) == 0

listen(18080)
listen(18081)
with tempfile.TemporaryDirectory(prefix='omr-f2b-') as temporary:
    data = Path(temporary)
    ipsets = LinuxIPSetDriver(data)
    ipsets.ensure_temporary('f2b_web')
    settings = F2BConfiguration(enabled=True)
    settings.profiles[0].ports = [18080]
    settings.profiles[0].ban_time = 8
    settings.profiles[0].find_time = 60
    service = Fail2banService(data, False, ipsets)
    service.initialize_files(settings)
    service.settings = settings
    config = Configuration(fail2ban=settings)
    filters.restore(filter_patch(before, config), test=True)
    filters.restore(filter_patch(before, config))
    assert connects(18080) and connects(18081)
    process = subprocess.Popen([sys.executable, '-m', 'app.fail2ban_runtime', 'daemon',
                               '--data-dir', str(data)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        wait_for(lambda: 'pong' in service._client(['ping']).lower())
        service.check(F2BConfiguration(), settings)
        service._client(['set', 'loglevel', 'INFO'])
        for _ in range(5):
            assert service.journal.failure(settings, '10.55.0.2')
        regex = run('fail2ban-regex', str(service.journal.path),
                    str(service.config_dir / 'filter.d' / 'omr-web.conf'))
        assert '5 matched' in regex, regex
        wait_for(lambda: len(ipsets.temporary_entries('f2b_web')) == 1)
        assert not connects(18080), 'The protected service is reachable during a ban'
        assert connects(18081), 'A ban incorrectly blocked a different service'
        assert service.bans.page()['items'][0]['kernel_present']
        filters.restore(filter_patch(filters.snapshot(), config))
        service.apply(settings, settings)
        service._client(['set', 'loglevel', 'INFO'])
        assert not connects(18080), 'Reapply erased active bans'
        assert service.status()['effective']
        service.unban('web', '10.55.0.2')
        wait_for(lambda: connects(18080))
        assert service.bans.page()['total'] == 0
        # A fresh ticket after manual unban must be counted independently.
        time.sleep(1.1)
        for _ in range(5):
            service.journal.failure(settings, '10.55.0.2')
        wait_for(lambda: len(ipsets.temporary_entries('f2b_web')) == 1)
        service._client(['stop'])
        process.wait(timeout=10)
        assert not connects(18080), 'Stopping the engine prematurely removed kernel timeouts'
        wait_for(lambda: connects(18080), timeout=12)
        assert ipsets.temporary_entries('f2b_web') == []
        assert service.bans.page()['total'] == 0
        filters.restore(filter_rollback(filters.snapshot(), before))
        assert '-A INPUT -j ACCEPT' in filters.snapshot()
        assert 'f2b-anchor' not in filters.snapshot()
    finally:
        service.journal.close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        output = process.stdout.read().decode() if process.stdout else ''
        if sys.exc_info()[0] is not None:
            print(output, file=sys.stderr)
        if process.returncode not in (0, -15):
            raise AssertionError('Fail2ban daemon failed')
        stop.set()
        for listener in listeners:
            listener.close()
"""
    result = subprocess.run(
        ["unshare", "--net", sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=70,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
