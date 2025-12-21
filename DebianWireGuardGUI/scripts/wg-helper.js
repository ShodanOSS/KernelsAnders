#!/usr/bin/env node
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const readline = require("readline");
const { execFile } = require("child_process");

const WG_DIR = "/etc/wireguard";
const WG_BIN = "/usr/bin/wg";
const WG_QUICK_BIN = "/usr/bin/wg-quick";
const NAME_RE = /^[a-zA-Z0-9_=+.-]{1,32}$/;

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

const respond = (id, ok, payload) => {
  const message = ok ? { id, ok: true, data: payload } : { id, ok: false, error: payload };
  process.stdout.write(`${JSON.stringify(message)}\n`);
};

const requireName = (name) => {
  if (!name || !NAME_RE.test(name)) {
    throw new Error("Invalid tunnel name.");
  }
  return name;
};

const readConfig = async (name) => {
  const safeName = requireName(name);
  const filePath = path.join(WG_DIR, `${safeName}.conf`);
  return fsp.readFile(filePath, "utf8");
};

const writeConfig = async (name, content) => {
  const safeName = requireName(name);
  const filePath = path.join(WG_DIR, `${safeName}.conf`);
  const tmpPath = path.join(WG_DIR, `.tmp-${safeName}-${process.pid}-${Date.now()}`);
  await fsp.writeFile(tmpPath, content, { mode: 0o600 });
  await fsp.chown(tmpPath, 0, 0);
  await fsp.rename(tmpPath, filePath);
  return filePath;
};

const deleteConfig = async (name) => {
  const safeName = requireName(name);
  const filePath = path.join(WG_DIR, `${safeName}.conf`);
  await fsp.unlink(filePath).catch(() => {});
  return true;
};

const listConfigs = async () => {
  const entries = await fsp.readdir(WG_DIR, { withFileTypes: true }).catch(() => []);
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".conf"))
    .map((entry) => path.basename(entry.name, ".conf"));
};

const runWg = async (args, allowFail = false) => {
  try {
    return await execFileAsync(WG_BIN, args);
  } catch (error) {
    if (allowFail) return { stdout: error.stdout || "", stderr: error.stderr || "" };
    throw new Error("WireGuard command failed.");
  }
};

const runWgQuick = async (args, allowFail = false) => {
  try {
    return await execFileAsync(WG_QUICK_BIN, args);
  } catch (error) {
    if (allowFail) return { stdout: error.stdout || "", stderr: error.stderr || "" };
    throw new Error("wg-quick failed.");
  }
};

const handleCommand = async (payload) => {
  const { command, args = {}, content } = payload || {};

  switch (command) {
    case "list":
      return listConfigs();
    case "read":
      return readConfig(args.name);
    case "write":
      return writeConfig(args.name, content || "");
    case "delete":
      return deleteConfig(args.name);
    case "wg_show_dump":
      return (await runWg(["show", requireName(args.name), "dump"]))?.stdout || "";
    case "wg_show_allowed_ips":
      return (await runWg(["show", requireName(args.name), "allowed-ips"]))?.stdout || "";
    case "wg_show_interfaces":
      return (await runWg(["show", "interfaces"], true))?.stdout || "";
    case "wg_show_all":
      return (await runWg(["show", "all"], true))?.stdout || "";
    case "wg_up":
      await runWgQuick(["up", requireName(args.name)]);
      return true;
    case "wg_down":
      await runWgQuick(["down", requireName(args.name)], true);
      return true;
    case "wg_restart":
      await runWgQuick(["down", requireName(args.name)], true);
      await runWgQuick(["up", requireName(args.name)]);
      return true;
    default:
      throw new Error("Unsupported command.");
  }
};

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity
});

process.stdout.write(`${JSON.stringify({ type: "ready" })}\n`);

rl.on("line", async (line) => {
  if (!line.trim()) return;
  let payload;
  try {
    payload = JSON.parse(line);
  } catch (error) {
    return;
  }
  const id = payload.id;
  if (!id) return;

  try {
    const data = await handleCommand(payload);
    respond(id, true, data);
  } catch (error) {
    const message = error && error.message ? error.message : "Operation failed.";
    respond(id, false, message);
  }
});
