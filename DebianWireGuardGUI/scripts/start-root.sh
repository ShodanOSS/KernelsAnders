#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ELECTRON_BIN="$APP_DIR/node_modules/electron/dist/electron"

if [[ ! -x "$ELECTRON_BIN" ]]; then
  echo "Electron binary not found. Run: npm install" >&2
  exit 1
fi

CMD=(/usr/bin/env -u ELECTRON_RUN_AS_NODE)
if [[ "${WG_FORCE_SOFTWARE:-}" == "1" ]]; then
  CMD+=(WG_FORCE_SOFTWARE=1)
fi
CMD+=("$ELECTRON_BIN" --no-sandbox --disable-gpu-sandbox "$APP_DIR")

if [[ "$(id -u)" -eq 0 ]]; then
  exec "${CMD[@]}"
fi

if command -v pkexec >/dev/null 2>&1; then
  DISPLAY_VALUE="${DISPLAY:-:0}"
  XAUTH_VALUE="${XAUTHORITY:-$HOME/.Xauthority}"
  exec pkexec env DISPLAY="$DISPLAY_VALUE" XAUTHORITY="$XAUTH_VALUE" "${CMD[@]}"
fi

exec sudo -E "${CMD[@]}"
