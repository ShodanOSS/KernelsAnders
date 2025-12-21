# Debian WireGuard GUI

Electron-based WireGuard GUI for Debian that mirrors the Windows WireGuard client. It manages
`/etc/wireguard` configs and uses `wg`/`wg-quick` to bring tunnels up/down. The app is designed
to run as root at startup (via pkexec/sudo), so there are no in-app privilege prompts.

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
- Node.js + npm

Install dependencies:
```bash
sudo apt install -y wireguard-tools nodejs npm
```

## Setup
```bash
npm install
```

## Run (root required)
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
- `scripts/start-root.sh` root launcher
- `install/` desktop launcher template + installer

