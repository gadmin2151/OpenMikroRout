#!/bin/bash
# One-time administrator bootstrap from a locally verified source tree.
set -euo pipefail
umask 077
if [ "$(id -u)" != 0 ]; then
  echo "Run this bootstrap as root." >&2
  exit 1
fi
source_dir="$(cd -- "$(dirname -- "$0")/.." && pwd)"
maintenance=/usr/local/libexec/openmikrorout-maintenance
if [ -e "$maintenance" ] || [ -L "$maintenance" ]; then
  echo "The maintenance controller already exists. This one-time bootstrap will not overwrite it." >&2
  echo "For a failed first installation, review and remove its incomplete controller manually before retrying." >&2
  exit 1
fi
if systemctl is-active --quiet openmikrorout-update.service; then
  echo "An update is already running." >&2
  exit 1
fi
bootstrap_backup="/var/backups/openmikrorout/bootstrap-$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 700 "$bootstrap_backup"
cp -p /etc/openmikrorout.env "$bootstrap_backup/environment.before"
for service in openmikrorout openmikrorout-firewall; do
  recovery_dropin="/etc/systemd/system/$service.service.d/10-update-recovery.conf"
  if [ -e "$recovery_dropin" ] || [ -L "$recovery_dropin" ]; then
    cp -Pp "$recovery_dropin" "$bootstrap_backup/$service-update-recovery.conf.before"
  fi
done
for unit in openmikrorout.service openmikrorout-update.service openmikrorout-update-recover.service; do
  if [ -e "/etc/systemd/system/$unit" ]; then
    cp -p "/etc/systemd/system/$unit" "$bootstrap_backup/$unit"
  fi
done
recover_bootstrap() {
  result=$?
  if [ "$result" != 0 ]; then
    set +e
    cp -p "$bootstrap_backup/environment.before" /etc/openmikrorout.env
    for service in openmikrorout openmikrorout-firewall; do
      recovery_dropin="/etc/systemd/system/$service.service.d/10-update-recovery.conf"
      rm -f -- "$recovery_dropin"
      if [ -e "$bootstrap_backup/$service-update-recovery.conf.before" ] || [ -L "$bootstrap_backup/$service-update-recovery.conf.before" ]; then
        cp -Pp "$bootstrap_backup/$service-update-recovery.conf.before" "$recovery_dropin"
      fi
    done
    for unit in openmikrorout.service openmikrorout-update.service openmikrorout-update-recover.service; do
      if [ -e "$bootstrap_backup/$unit" ]; then
        cp -p "$bootstrap_backup/$unit" "/etc/systemd/system/$unit"
      elif [ -e "/etc/systemd/system/$unit" ]; then
        systemctl disable "$unit"
        rm -- "/etc/systemd/system/$unit"
      fi
    done
    systemctl daemon-reload
    systemctl start openmikrorout
    echo "Bootstrap failed; previous service configuration restored. Backup: $bootstrap_backup" >&2
  fi
  exit "$result"
}
trap recover_bootstrap EXIT
test -f "$source_dir/deploy/update-signing.pub"
if [ -e /etc/openmikrorout-update.pub ]; then
  cmp "$source_dir/deploy/update-signing.pub" /etc/openmikrorout-update.pub
else
  install -m 644 "$source_dir/deploy/update-signing.pub" /etc/openmikrorout-update.pub
fi
install -d -m 755 "$maintenance" "$maintenance/app" /opt/openmikrorout-releases
install -d -m 700 /var/backups/openmikrorout /var/lib/openmikrorout/updates
for module in __init__.py updates.py update_worker.py totp.py version.py; do
  install -m 644 "$source_dir/app/$module" "$maintenance/app/$module"
done
python3 -m venv "$maintenance/.venv"
"$maintenance/.venv/bin/python" -m pip install --isolated --disable-pip-version-check --no-cache-dir --only-binary=:all: -r "$source_dir/requirements.lock"
if [ ! -e /etc/openmikrorout-update.json ]; then
  install -m 600 "$source_dir/deploy/openmikrorout-update.example.json" /etc/openmikrorout-update.json
fi
cd "$maintenance"
"$maintenance/.venv/bin/python" -c 'from pathlib import Path; from app.updates import UpdateConfig; UpdateConfig.load(Path("/etc/openmikrorout-update.json"))'
if [ ! -L /opt/openmikrorout ]; then
  test -d /opt/openmikrorout
  legacy="/opt/openmikrorout-releases/legacy-$(date -u +%Y%m%dT%H%M%SZ)"
  test ! -e "$legacy"
  systemctl stop openmikrorout
  mv /opt/openmikrorout "$legacy"
  if ! ln -s "$legacy" /opt/openmikrorout; then
    mv "$legacy" /opt/openmikrorout
    systemctl start openmikrorout
    exit 1
  fi
fi
python3 - <<'PY'
from pathlib import Path
import os,re,tempfile
path=Path('/etc/openmikrorout.env')
text=path.read_text()
for name in ['OMR_UPDATES_ENABLED','OMR_MONITOR_ENABLED']:
    line=name+'=1'
    text=re.sub(r'^'+name+r'=.*$',line,text,flags=re.M) if re.search(r'^'+name+r'=',text,re.M) else text.rstrip()+'\n'+line+'\n'
with tempfile.NamedTemporaryFile('w',dir=path.parent,delete=False) as output:
    os.chmod(output.name,0o600)
    output.write(text)
    output.flush();os.fsync(output.fileno())
    temporary=output.name
os.replace(temporary,path)
PY
for unit in openmikrorout.service openmikrorout-update.service openmikrorout-update-recover.service; do
  install -m 644 "$source_dir/deploy/$unit" "/etc/systemd/system/$unit"
done
for service in openmikrorout openmikrorout-firewall; do
  recovery_dropin="/etc/systemd/system/$service.service.d/10-update-recovery.conf"
  install -d -m 755 "$(dirname -- "$recovery_dropin")"
  rm -f -- "$recovery_dropin"
  install -m 644 "$source_dir/deploy/openmikrorout-update-recovery.conf" "$recovery_dropin"
done
systemd-analyze verify /etc/systemd/system/openmikrorout.service /etc/systemd/system/openmikrorout-update.service /etc/systemd/system/openmikrorout-update-recover.service
systemctl daemon-reload
systemctl enable openmikrorout openmikrorout-update-recover
systemctl start openmikrorout-update-recover
systemctl start openmikrorout
echo "Signed updater installed. The application release has not yet been replaced."
