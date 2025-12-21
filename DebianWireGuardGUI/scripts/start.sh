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
CMD+=("$ELECTRON_BIN" "$APP_DIR")

exec "${CMD[@]}"
