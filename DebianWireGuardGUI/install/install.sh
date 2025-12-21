#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESKTOP_TEMPLATE="$APP_DIR/install/wireguard-ui.desktop.in"
DESKTOP_TARGET="$HOME/.local/share/applications/wireguard-ui.desktop"
DESKTOP_DESKTOP="$HOME/Desktop/WireGuard-UI.desktop"

mkdir -p "$HOME/.local/share/applications"
if [[ -d "$HOME/Desktop" ]]; then
  mkdir -p "$HOME/Desktop"
fi

sed "s|__APP_DIR__|$APP_DIR|g" "$DESKTOP_TEMPLATE" > "$DESKTOP_TARGET"
chmod +x "$DESKTOP_TARGET"

if [[ -d "$HOME/Desktop" ]]; then
  cp "$DESKTOP_TARGET" "$DESKTOP_DESKTOP"
  chmod +x "$DESKTOP_DESKTOP"
  if command -v gio >/dev/null 2>&1; then
    gio set "$DESKTOP_DESKTOP" metadata::trusted true || true
  fi
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications" || true
fi

echo "WireGuard UI launcher installed."
