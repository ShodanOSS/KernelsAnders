const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const { execFile, spawn } = require("child_process");

const WG_DIR = "/etc/wireguard";
const NAME_RE = /^[a-zA-Z0-9_=+.-]{1,32}$/;
const PKEXEC_PATH = "/usr/bin/pkexec";
const HELPER_PATH = path.join(__dirname, "..", "scripts", "wg-helper.js");
const NODE_BIN = fs.existsSync("/usr/bin/node") ? "/usr/bin/node" : "node";

if (process.env.WG_FORCE_SOFTWARE === "1") {
  app.commandLine.appendSwitch("use-gl", "swiftshader");
  app.commandLine.appendSwitch("enable-features", "UseSkiaRenderer");
  app.commandLine.appendSwitch("disable-features", "Vulkan");
}

class PublicError extends Error {
  constructor(message) {
    super(message);
    this.public = true;
  }
}

const execFileAsync = (command, args = []) =>
  new Promise((resolve, reject) => {
    execFile(command, args, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });

const runCommand = async (command, args = []) => {
  try {
    return await execFileAsync(command, args);
  } catch (error) {
    const detail = error.stderr || error.stdout || error.message || String(error);
    throw new Error(`Command failed: ${command} ${args.join(" ")}\n${detail}`.trim());
  }
};

let helperProcess = null;
let helperBuffer = "";
let helperReady = false;
let helperReadyPromise = null;
let helperReadyResolve = null;
const pendingRequests = new Map();
let requestId = 1;

const resetHelperState = () => {
  helperProcess = null;
  helperBuffer = "";
  helperReady = false;
  if (helperReadyResolve) {
    helperReadyResolve();
  }
  helperReadyResolve = null;
  helperReadyPromise = null;
  pendingRequests.forEach(({ reject }) => reject(new PublicError("Helper stopped.")));
  pendingRequests.clear();
};

const ensureHelper = async () => {
  if (helperProcess && helperReady) return;
  if (!fs.existsSync(PKEXEC_PATH)) {
    throw new PublicError("pkexec not found. Install policykit-1.");
  }
  if (!fs.existsSync(HELPER_PATH)) {
    throw new PublicError("Privilege helper missing.");
  }

  if (!helperReadyPromise) {
    helperReadyPromise = new Promise((resolve) => {
      helperReadyResolve = resolve;
    });

    const env = {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C"
    };
    if (process.env.DISPLAY) env.DISPLAY = process.env.DISPLAY;
    if (process.env.XAUTHORITY) env.XAUTHORITY = process.env.XAUTHORITY;

    helperProcess = spawn(PKEXEC_PATH, [NODE_BIN, HELPER_PATH], { env });

    helperProcess.stdout.on("data", (chunk) => {
      helperBuffer += chunk.toString();
      const lines = helperBuffer.split(/\r?\n/);
      helperBuffer = lines.pop() || "";
      lines.forEach((line) => {
        if (!line.trim()) return;
        let message;
        try {
          message = JSON.parse(line);
        } catch (error) {
          return;
        }
        if (message.type === "ready") {
          helperReady = true;
          if (helperReadyResolve) helperReadyResolve();
          return;
        }
        if (!message.id) return;
        const pending = pendingRequests.get(message.id);
        if (!pending) return;
        pendingRequests.delete(message.id);
        if (message.ok) {
          pending.resolve(message.data);
        } else {
          pending.reject(new PublicError(message.error || "Operation failed."));
        }
      });
    });

    helperProcess.on("error", () => {
      resetHelperState();
    });

    helperProcess.on("close", () => {
      resetHelperState();
    });
  }

  await helperReadyPromise;
  if (!helperReady) {
    throw new PublicError("Authorization was canceled or failed.");
  }
};

const sendPrivileged = async (command, args = {}, content = "") => {
  await ensureHelper();
  return new Promise((resolve, reject) => {
    if (!helperProcess || !helperProcess.stdin.writable) {
      reject(new PublicError("Helper is unavailable."));
      return;
    }
    const id = requestId++;
    pendingRequests.set(id, { resolve, reject });
    const payload = { id, command, args, content };
    helperProcess.stdin.write(`${JSON.stringify(payload)}\n`);
  });
};

const normalizeName = (name) => {
  const trimmed = (name || "").trim();
  if (!trimmed) throw new PublicError("Tunnel name is required.");
  if (!NAME_RE.test(trimmed)) {
    throw new PublicError(
      "Tunnel name must be 1-32 chars: letters, numbers, '=', '+', '-', '.', or '_'."
    );
  }
  return trimmed;
};

const emptyConfigTemplate = (name) =>
  `[Interface]\n# ${name}\nPrivateKey = \nAddress = \n\n[Peer]\nPublicKey = \nAllowedIPs = 0.0.0.0/0\nEndpoint = \n`;

const looksLikeWireguard = (content) =>
  /\[Interface\]/i.test(content) && /\[Peer\]/i.test(content);

const hasPrivateKey = (content) => /\n\s*PrivateKey\s*=\s*\S+/i.test(content);

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

const listConfigNames = async () => {
  const result = await sendPrivileged("list");
  if (!Array.isArray(result)) return [];
  return result;
};

const getActiveInterfaces = async () => {
  const output = await sendPrivileged("wg_show_interfaces");
  const list = String(output || "").trim();
  if (!list) return new Set();
  return new Set(list.split(/\s+/).filter(Boolean));
};

const readConfig = async (name) => {
  const safeName = normalizeName(name);
  return sendPrivileged("read", { name: safeName });
};

const writeConfig = async (name, content) => {
  const safeName = normalizeName(name);
  await sendPrivileged("write", { name: safeName }, content || "");
  return path.join(WG_DIR, `${safeName}.conf`);
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
  const [names, activeSet] = await Promise.all([
    listConfigNames(),
    getActiveInterfaces()
  ]);
  const tunnels = [];
  for (const name of names) {
    let meta = { address: "", hasPrivateKey: false };
    try {
      const content = await readConfig(name);
      meta = parseConfigMeta(content);
    } catch (error) {
      meta = { address: "", hasPrivateKey: false };
    }
    tunnels.push({
      name,
      path: path.join(WG_DIR, `${name}.conf`),
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
  const dumpOutput = await sendPrivileged("wg_show_dump", { name: safeName });
  if (!String(dumpOutput || "").trim()) {
    return { active: false };
  }
  const parsed = parseDump(String(dumpOutput));
  if (!parsed) return { active: false };

  const allowedOutput = await sendPrivileged("wg_show_allowed_ips", { name: safeName });
  const allowedMap = parseAllowedIpsMap(String(allowedOutput));
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
    backgroundColor: "#000000",
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
    const message = error && error.public ? error.message : "Operation failed.";
    return { ok: false, error: message };
  }
};

const ensureWireguardAvailable = async () => {
  await runCommand("wg", ["--version"]).catch(() => {});
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
    await sendPrivileged("wg_up", { name: safeName });
    return true;
  }));

  ipcMain.handle("tunnels:down", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await sendPrivileged("wg_down", { name: safeName });
    return true;
  }));

  ipcMain.handle("tunnels:restart", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await sendPrivileged("wg_restart", { name: safeName });
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

    if (!looksLikeWireguard(content)) {
      const confirm = await dialog.showMessageBox({
        type: "warning",
        buttons: ["Cancel", "Import"],
        defaultId: 1,
        message: "This file does not look like a WireGuard config. Import anyway?"
      });
      if (confirm.response !== 1) return { canceled: true };
    }

    if (hasPrivateKey(content)) {
      const confirm = await dialog.showMessageBox({
        type: "warning",
        buttons: ["Cancel", "Import"],
        defaultId: 1,
        message: "This config contains a PrivateKey. Importing will store it in /etc/wireguard. Continue?"
      });
      if (confirm.response !== 1) return { canceled: true };
    }

    const existing = await listConfigNames();
    if (existing.includes(safeName)) {
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
    const existing = await listConfigNames();
    if (existing.includes(safeName)) {
      throw new PublicError("Tunnel already exists.");
    }
    await writeConfig(safeName, emptyConfigTemplate(safeName));
    return { name: safeName };
  }));

  ipcMain.handle("tunnels:delete", wrapHandler(async (_event, name) => {
    const safeName = normalizeName(name);
    await sendPrivileged("wg_down", { name: safeName });
    await sendPrivileged("delete", { name: safeName });
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
    const output = await sendPrivileged("wg_show_all");
    const trimmed = String(output || "").trim();
    return trimmed || "No WireGuard interfaces are active.";
  }));

  ipcMain.handle("app:info", wrapHandler(async () => {
    const wgResult = await runCommand("wg", ["--version"]).catch(() => ({ stdout: "" }));
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
  setupIpc();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", () => {
  if (helperProcess) {
    helperProcess.kill("SIGTERM");
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
