const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const { execFile } = require("child_process");

const WG_DIR = "/etc/wireguard";
const NAME_RE = /^[a-zA-Z0-9_=+.-]{1,32}$/;

if (process.env.WG_FORCE_SOFTWARE === "1") {
  app.commandLine.appendSwitch("use-gl", "swiftshader");
  app.commandLine.appendSwitch("enable-features", "UseSkiaRenderer");
  app.commandLine.appendSwitch("disable-features", "Vulkan");
}

const execFileAsync = (command, args = [], options = {}) =>
  new Promise((resolve, reject) => {
    execFile(command, args, options, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });

const isRoot = () => typeof process.getuid === "function" && process.getuid() === 0;

const runCommand = async (command, args = [], options = {}) => {
  const { requireRoot = false, allowFail = false } = options;
  if (requireRoot && !isRoot()) {
    throw new Error(
      "This app must be run as root. Use `npm run start` which starts with sudo/pkexec."
    );
  }

  try {
    return await execFileAsync(command, args);
  } catch (error) {
    if (allowFail) {
      return {
        stdout: error.stdout || "",
        stderr: error.stderr || "",
        code: error.code
      };
    }
    const detail = error.stderr || error.stdout || error.message || String(error);
    throw new Error(`Command failed: ${command} ${args.join(" ")}\n${detail}`.trim());
  }
};

const normalizeName = (name) => {
  const trimmed = (name || "").trim();
  if (!trimmed) throw new Error("Tunnel name is required.");
  if (!NAME_RE.test(trimmed)) {
    throw new Error(
      "Tunnel name must be 1-32 chars: letters, numbers, '=', '+', '-', '.', or '_'."
    );
  }
  return trimmed;
};

const emptyConfigTemplate = (name) =>
  `[Interface]\n# ${name}\nPrivateKey = \nAddress = \n\n[Peer]\nPublicKey = \nAllowedIPs = 0.0.0.0/0\nEndpoint = \n`;

const parseConfigMeta = (content) => {
  const meta = { address: "", hasPrivateKey: false };
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const addressMatch = trimmed.match(/^Address\s*=\s*(.+)$/i);
    if (addressMatch && !meta.address) meta.address = addressMatch[1].trim();
    if (/^PrivateKey\s*=/.test(trimmed)) meta.hasPrivateKey = true;
  }
  return meta;
};

const listConfigPaths = async () => {
  const entries = await fsp.readdir(WG_DIR, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".conf"))
    .map((entry) => path.join(WG_DIR, entry.name));
};

const getActiveInterfaces = async () => {
  const result = await runCommand("wg", ["show", "interfaces"], {
    requireRoot: true,
    allowFail: true
  });
  const list = result.stdout.trim();
  if (!list) return new Set();
  return new Set(list.split(/\s+/).filter(Boolean));
};

const readConfig = async (name) => {
  const safeName = normalizeName(name);
  const filePath = path.join(WG_DIR, `${safeName}.conf`);
  return fsp.readFile(filePath, "utf8");
};

const writeConfig = async (name, content) => {
  const safeName = normalizeName(name);
  const target = path.join(WG_DIR, `${safeName}.conf`);
  await fsp.writeFile(target, content, { mode: 0o600 });
  return target;
};

const formatBytes = (value) => {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let current = bytes;
  let unitIndex = -1;
  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024;
    unitIndex += 1;
  }
  return `${current.toFixed(current >= 10 ? 1 : 2)} ${units[unitIndex]}`;
};

const parseKeepalive = (value) => {
  if (value === undefined || value === null) return 0;
  const trimmed = String(value).trim();
  if (!trimmed || trimmed === "off") return 0;
  const num = Number(trimmed);
  return Number.isFinite(num) ? num : 0;
};

const splitFields = (line) => {
  const tabParts = line.split("\t");
  if (tabParts.length > 1) return tabParts;
  return line.trim().split(/\s+/);
};

const parsePeerFields = (line) => {
  const tabParts = line.split("\t");
  if (tabParts.length > 1) return tabParts;

  const parts = line.trim().split(/\s+/);
  if (parts.length < 8) return parts;

  const keepalive = parts[parts.length - 1];
  const transferTx = parts[parts.length - 2];
  const transferRx = parts[parts.length - 3];
  const latestHandshake = parts[parts.length - 4];
  const allowedIps = parts.slice(3, parts.length - 4).join(" ");

  return [
    parts[0],
    parts[1],
    parts[2],
    allowedIps,
    latestHandshake,
    transferRx,
    transferTx,
    keepalive
  ];
};

const parseAllowedIpsMap = (output) => {
  const map = new Map();
  const lines = (output || "").trim().split(/\r?\n/).filter(Boolean);
  lines.forEach((line) => {
    const match = line.trim().match(/^(\S+)\s+(.+)$/);
    if (!match) return;
    map.set(match[1], match[2].trim());
  });
  return map;
};

const parseDump = (dump) => {
  const lines = dump.trim().split(/\r?\n/).filter(Boolean);
  if (!lines.length) return null;
  const iface = splitFields(lines[0]);

  let publicKey = "";
  let listenPort = "";
  if (iface.length >= 5) {
    publicKey = iface[2] || "";
    listenPort = iface[3] || "";
  } else if (iface.length >= 4) {
    publicKey = iface[1] || "";
    listenPort = iface[2] || "";
  } else {
    publicKey = iface[1] || "";
    listenPort = iface[2] || "";
  }

  const details = {
    interfaceName: iface[0] || "",
    publicKey,
    listenPort,
    peers: []
  };

  for (const line of lines.slice(1)) {
    const parts = parsePeerFields(line);
    const keepaliveSeconds = parseKeepalive(parts[7]);
    details.peers.push({
      publicKey: parts[0] || "",
      endpoint: parts[2] || "",
      allowedIps: parts[3] || "",
      latestHandshakeAt: Number(parts[4]) || 0,
      transferRx: formatBytes(parts[5]),
      transferTx: formatBytes(parts[6]),
      keepaliveSeconds
    });
  }
  return details;
};

const listTunnels = async () => {
  const [configPaths, activeSet] = await Promise.all([
    listConfigPaths(),
    getActiveInterfaces()
  ]);
  const tunnels = [];
  for (const configPath of configPaths) {
    const name = path.basename(configPath, ".conf");
    let meta = { address: "", hasPrivateKey: false };
    try {
      const content = await readConfig(name);
      meta = parseConfigMeta(content);
    } catch (error) {
      meta = { address: "", hasPrivateKey: false };
    }
    tunnels.push({
      name,
      path: configPath,
      active: activeSet.has(name),
      address: meta.address,
      hasPrivateKey: meta.hasPrivateKey
    });
  }
  tunnels.sort((a, b) => a.name.localeCompare(b.name));
  return tunnels;
};

const getTunnelStatus = async (name) => {
  const safeName = normalizeName(name);
  const result = await runCommand("wg", ["show", safeName, "dump"], {
    requireRoot: true,
    allowFail: true
  });
  if (!result.stdout.trim()) {
    return { active: false };
  }
  const parsed = parseDump(result.stdout);
  if (!parsed) return { active: false };
  const allowedResult = await runCommand("wg", ["show", safeName, "allowed-ips"], {
    requireRoot: true,
    allowFail: true
  });
  const allowedMap = parseAllowedIpsMap(allowedResult.stdout);
  if (allowedMap.size) {
    parsed.peers = parsed.peers.map((peer) => ({
      ...peer,
      allowedIps: allowedMap.get(peer.publicKey) || peer.allowedIps
    }));
  }
  const primaryPeer = parsed.peers[0] || null;
  return {
    active: true,
    interfaceName: parsed.interfaceName,
    publicKey: parsed.publicKey,
    listenPort: parsed.listenPort,
    peer: primaryPeer,
    peerCount: parsed.peers.length,
    peers: parsed.peers
  };
};

const createWindow = () => {
  const win = new BrowserWindow({
    width: 860,
    height: 560,
    minWidth: 760,
    minHeight: 520,
    backgroundColor: "#f3f5f8",
    title: "WireGuard",
    icon: path.join(__dirname, "assets", "shodan.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, "index.html"));
};

const wrapHandler = (fn) => async (...args) => {
  try {
    const data = await fn(...args);
    return { ok: true, data };
  } catch (error) {
    return { ok: false, error: error.message || String(error) };
  }
};

const ensureWireguardAvailable = async () => {
  await runCommand("wg", ["--version"], { allowFail: true });
};

const setupIpc = () => {
  ipcMain.handle("tunnels:list", wrapHandler(async () => {
    await ensureWireguardAvailable();
    return listTunnels();
  }));

  ipcMain.handle("tunnels:status", wrapHandler(async (_event, name) => {
    return getTunnelStatus(name);
  }));

  ipcMain.handle("tunnels:up", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await runCommand("wg-quick", ["up", safeName], { requireRoot: true });
    return true;
  }));

  ipcMain.handle("tunnels:down", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await runCommand("wg-quick", ["down", safeName], {
      requireRoot: true,
      allowFail: true
    });
    return true;
  }));

  ipcMain.handle("tunnels:restart", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await runCommand("wg-quick", ["down", safeName], {
      requireRoot: true,
      allowFail: true
    });
    await runCommand("wg-quick", ["up", safeName], { requireRoot: true });
    return true;
  }));

  ipcMain.handle("tunnels:import", wrapHandler(async () => {
    const result = await dialog.showOpenDialog({
      title: "Import WireGuard tunnel",
      properties: ["openFile"],
      filters: [{ name: "WireGuard", extensions: ["conf"] }]
    });
    if (result.canceled || !result.filePaths.length) return { canceled: true };
    const sourcePath = result.filePaths[0];
    const baseName = path.basename(sourcePath, ".conf");
    const safeName = normalizeName(baseName);
    const content = await fsp.readFile(sourcePath, "utf8");
    const targetPath = path.join(WG_DIR, `${safeName}.conf`);
    if (fs.existsSync(targetPath)) {
      const overwrite = await dialog.showMessageBox({
        type: "warning",
        buttons: ["Cancel", "Overwrite"],
        defaultId: 1,
        message: `Tunnel ${safeName} already exists. Overwrite it?`
      });
      if (overwrite.response !== 1) return { canceled: true };
    }
    await writeConfig(safeName, content);
    return { name: safeName };
  }));

  ipcMain.handle("tunnels:create", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    const targetPath = path.join(WG_DIR, `${safeName}.conf`);
    if (fs.existsSync(targetPath)) {
      throw new Error("Tunnel already exists.");
    }
    await writeConfig(safeName, emptyConfigTemplate(safeName));
    return { name: safeName };
  }));

  ipcMain.handle("tunnels:delete", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await runCommand("wg-quick", ["down", safeName], {
      requireRoot: true,
      allowFail: true
    });
    await runCommand("rm", ["-f", path.join(WG_DIR, `${safeName}.conf`)], {
      requireRoot: true
    });
    return true;
  }));

  ipcMain.handle("tunnels:readConfig", wrapHandler(async (_event, name) => {
    return readConfig(name);
  }));

  ipcMain.handle("tunnels:writeConfig", wrapHandler(async (_event, payload) => {
    const { name, content } = payload || {};
    await writeConfig(name, content || "");
    return true;
  }));

  ipcMain.handle("tunnels:export", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    const result = await dialog.showSaveDialog({
      title: "Export WireGuard tunnel",
      defaultPath: `${safeName}.conf`,
      filters: [{ name: "WireGuard", extensions: ["conf"] }]
    });
    if (result.canceled || !result.filePath) return { canceled: true };
    const content = await readConfig(safeName);
    await fsp.writeFile(result.filePath, content, "utf8");
    return { path: result.filePath };
  }));

  ipcMain.handle("app:log", wrapHandler(async () => {
    const result = await runCommand("wg", ["show", "all"], {
      requireRoot: true,
      allowFail: true
    });
    const output = result.stdout.trim();
    return output || "No WireGuard interfaces are active.";
  }));

  ipcMain.handle("app:info", wrapHandler(async () => {
    const wgResult = await runCommand("wg", ["--version"], { allowFail: true });
    return {
      appVersion: app.getVersion(),
      electronVersion: process.versions.electron,
      nodeVersion: process.versions.node,
      wgVersion: (wgResult.stdout || "").trim(),
      configDir: WG_DIR
    };
  }));

  ipcMain.handle("app:quit", wrapHandler(async () => {
    app.quit();
    return true;
  }));
};

app.whenReady().then(() => {
  if (!isRoot()) {
    dialog.showErrorBox(
      "Run as Administrator",
      "This app must be started as root. Use `npm run start` which invokes sudo/pkexec."
    );
    app.quit();
    return;
  }

  setupIpc();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
