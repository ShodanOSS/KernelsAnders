#!/usr/bin/env bash
set -euo pipefail

umask 077

WG_DIR="/etc/wireguard"
WG_BIN="/usr/bin/wg"
WG_QUICK_BIN="/usr/bin/wg-quick"

NAME_RE='^[A-Za-z0-9_=+.-]{1,32}$'

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

require_name() {
  local name="$1"
  if [[ -z "$name" || ! "$name" =~ $NAME_RE ]]; then
    fail "Invalid tunnel name."
  fi
}

cmd="${1:-}"
case "$cmd" in
  list)
    shopt -s nullglob
    for file in "$WG_DIR"/*.conf; do
      basename "$file" .conf
    done
    ;;
  read)
    name="${2:-}"
    require_name "$name"
    cat "$WG_DIR/$name.conf"
    ;;
  write)
    name="${2:-}"
    require_name "$name"
    tmp_file="$(mktemp "$WG_DIR/.tmp-${name}.XXXXXX")"
    cat > "$tmp_file"
    chmod 600 "$tmp_file"
    chown root:root "$tmp_file"
    mv -f "$tmp_file" "$WG_DIR/$name.conf"
    ;;
  delete)
    name="${2:-}"
    require_name "$name"
    rm -f "$WG_DIR/$name.conf"
    ;;
  wg_show_dump)
    name="${2:-}"
    require_name "$name"
    "$WG_BIN" show "$name" dump
    ;;
  wg_show_allowed_ips)
    name="${2:-}"
    require_name "$name"
    "$WG_BIN" show "$name" allowed-ips
    ;;
  wg_show_interfaces)
    "$WG_BIN" show interfaces
    ;;
  wg_show_all)
    "$WG_BIN" show all
    ;;
  wg_up)
    name="${2:-}"
    require_name "$name"
    "$WG_QUICK_BIN" up "$name"
    ;;
  wg_down)
    name="${2:-}"
    require_name "$name"
    "$WG_QUICK_BIN" down "$name"
    ;;
  wg_restart)
    name="${2:-}"
    require_name "$name"
    "$WG_QUICK_BIN" down "$name" || true
    "$WG_QUICK_BIN" up "$name"
    ;;
  *)
    fail "Unsupported command."
    ;;
esac
