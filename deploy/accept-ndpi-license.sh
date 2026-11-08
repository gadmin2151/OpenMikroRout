#!/bin/sh
# Explicit local administrator acceptance; no packages or services are changed.
set -eu
cd "$(dirname "$0")/.."
exec python3 -m app.third_party_license "$@"
