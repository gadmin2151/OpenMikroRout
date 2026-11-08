#!/bin/sh
# Prepare the optional signed application companion; never enable scopes or rules.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ -x /opt/openmikrorout/.venv/bin/python ]
[ -x /opt/openmikrorout/app/native/bin/omr-app-supervisor ]
[ -f /opt/openmikrorout/app/native/manifest.json ]
cd /opt/openmikrorout
python3 -m app.third_party_license --check >/dev/null 2>&1 || \
  python3 -m app.third_party_license
systemctl cat openmikrorout.service >/dev/null
if systemctl is-active --quiet openmikrorout-update.service; then
  echo 'Wait for the stock update job to finish first.' >&2
  exit 1
fi
/opt/openmikrorout/.venv/bin/python - <<'PY'
import hashlib
import json
import re
import stat
from pathlib import Path, PurePosixPath

root = Path('/opt/openmikrorout').resolve(strict=True)
native = root / 'app/native'

def fail(message):
    raise SystemExit('Application companion validation failed: ' + message)

def bounded_file(path, limit):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            fail('expected a bounded regular file')
        content = path.read_bytes()
        if len(content) > limit:
            fail('file exceeds its size limit')
        return content
    except OSError:
        fail('required file is missing or unreadable')

if (root / 'app').is_symlink() or native.is_symlink():
    fail('native directories must not be symbolic links')
try:
    manifest = json.loads(bounded_file(native / 'manifest.json', 65536))
    release = json.loads(bounded_file(root / 'release.json', 65536))
except (ValueError, TypeError):
    fail('invalid release metadata')
if not isinstance(manifest, dict) or not isinstance(release, dict):
    fail('release metadata must be objects')
if (
    type(manifest.get('format')) is not int or manifest['format'] != 1
    or manifest.get('purpose') != 'OpenMikroRout native companion'
    or not isinstance(release.get('commit'), str)
    or not re.fullmatch(r'[a-f0-9]{40}', release['commit'])
    or manifest.get('source_commit') != release['commit']
    or manifest.get('platform') != 'linux-amd64'
):
    fail('manifest does not match this committed release and platform')
files = manifest.get('files')
if not isinstance(files, dict) or not 1 <= len(files) <= 127 or 'bin/omr-app-supervisor' not in files:
    fail('native executable inventory is missing or exceeds its limit')
total = 0
for name, digest in files.items():
    relative = PurePosixPath(name)
    if (
        not name or len(name) > 225 or relative.is_absolute() or '..' in relative.parts
        or '\\' in name or str(relative) != name
        or relative.parts[0] not in ('bin', 'lib', 'licenses')
        or (relative.parts[0] == 'bin' and name != 'bin/omr-app-supervisor')
        or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)
    ):
        fail('unsafe native inventory entry')
    path = native.joinpath(*relative.parts)
    if any(native.joinpath(*relative.parts[:index]).is_symlink() for index in range(1, len(relative.parts) + 1)):
        fail('symbolic links are not permitted in native paths')
    content = bounded_file(path, 20 * 1024 * 1024)
    total += len(content)
    if total > 96 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != digest:
        fail('native file hash or total size does not match the inventory')
print('Signed release companion inventory verified; application policy remains unchanged.')
PY
modprobe -a nf_conntrack_netlink nfnetlink_queue xt_connmark xt_NFQUEUE iptable_mangle
install -d -m 0755 /etc/modules-load.d /etc/systemd/system/openmikrorout.service.d
install -d -m 0755 /etc/openmikrorout
if [ -e /etc/openmikrorout/catalog-public-key.pem ]; then
  cmp /opt/openmikrorout/deploy/catalog-signing.pub /etc/openmikrorout/catalog-public-key.pem
else
  install -m 0644 /opt/openmikrorout/deploy/catalog-signing.pub \
    /etc/openmikrorout/catalog-public-key.pem
fi
install -m 0644 /opt/openmikrorout/deploy/openmikrorout-applications-modules.conf \
  /etc/modules-load.d/openmikrorout-applications.conf
install -m 0644 /opt/openmikrorout/deploy/openmikrorout-applications.conf \
  /etc/systemd/system/openmikrorout.service.d/40-applications-safety.conf
systemctl daemon-reload
systemd-analyze verify openmikrorout.service
echo 'Application companion prepared. No service restart or policy activation was requested.'
