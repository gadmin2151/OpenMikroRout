#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f app/native/manifest.json ] || [ -f app/native/bin/omr-app-supervisor ]; then
    python3 -m app.third_party_license --check >/dev/null 2>&1 || \
        python3 -m app.third_party_license
fi
if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.lock
fi
exec .venv/bin/python -m uvicorn app.main:create_app --factory \
    --host "${OMR_BIND:-${NAT_BIND:-127.0.0.1}}" --port "${OMR_PORT:-${NAT_PORT:-8088}}" \
    --workers 1 --no-access-log --no-proxy-headers
