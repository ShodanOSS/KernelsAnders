# Debian WireGuard GUI

Electron-based WireGuard GUI for Debian that mirrors the Windows WireGuard client. It manages
`/etc/wireguard` configs and uses `wg`/`wg-quick` to bring tunnels up/down. The UI runs as an
unprivileged user and invokes a minimal privileged helper via polkit (pkexec) only when needed.

## Features
- List, create, import, export, edit, and delete WireGuard tunnels.
- Activate/deactivate tunnels with `wg-quick`.
- Live tunnel status, transfer stats, and handshake age updates.
- Per-peer details (endpoint, allowed IPs, keepalive, handshake, transfer).
- Log and About/Settings modals.
- Desktop launcher installer.

## Requirements
- Debian-based system
- `wireguard-tools`
- `policykit-1` (pkexec) and a polkit agent for GUI prompts
- Node.js + npm

Install dependencies:
```bash
sudo apt install -y wireguard-tools nodejs npm
```

## Setup
```bash
npm install
```

## Run
```bash
npm run start
```

If GPU/GBM errors prevent the window from opening:
```bash
npm run start:software
```

## Desktop Launcher
```bash
bash install/install.sh
```

## Security / Privacy
This repository contains no private keys, configs, or personal data. Tunnel configs live in
`/etc/wireguard` at runtime and are not included here. Do not commit real `.conf` files.

## Project Layout
- `app/` Electron main/renderer source
- `scripts/start.sh` app launcher
- `scripts/wg-helper.js` privileged helper (pkexec)
- `install/` desktop launcher template + installer
