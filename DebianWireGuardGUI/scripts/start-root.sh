#!/usr/bin/env bash
set -euo pipefail

echo "[wireguard-ui] start-root.sh is deprecated. Launching unprivileged UI." >&2

exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/start.sh"
