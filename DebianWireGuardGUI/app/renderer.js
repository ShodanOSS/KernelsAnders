const state = {
  tunnels: [],
  selected: null,
  status: null,
  busy: false
};

const byId = (id) => document.getElementById(id);

const errorBanner = byId("error-banner");
const tunnelList = byId("tunnel-list");
const detailName = byId("detail-name");
const detailToggle = byId("detail-toggle");
const detailPublicKey = byId("detail-public-key");
const detailEndpoint = byId("detail-endpoint");
const detailTransfer = byId("detail-transfer");
const detailHandshake = byId("detail-handshake");
const detailAddress = byId("detail-address");
const detailListenPort = byId("detail-listen-port");
const detailStatus = byId("detail-status");
const detailPeerCount = byId("detail-peer-count");
const peerList = byId("peer-list");
const peerRefreshNote = byId("peer-refresh-note");

const importButton = byId("import-button");
const addButton = byId("add-button");
const exportButton = byId("export-button");
const editButton = byId("edit-button");
const deleteButton = byId("delete-button");
const restartButton = byId("restart-button");
const quitButton = byId("quit-button");
const copyKeyButton = byId("copy-key-button");
const viewConfigButton = byId("view-config-button");

const navLog = byId("nav-log");
const navSettings = byId("nav-settings");
const navAbout = byId("nav-about");

const modal = byId("config-modal");
const modalTitle = byId("config-modal-title");
const modalTextarea = byId("config-text");
const modalSave = byId("config-save");
const modalCancel = byId("config-cancel");

const inputModal = byId("input-modal");
const inputTitle = byId("input-modal-title");
const inputMessage = byId("input-modal-message");
const inputField = byId("input-modal-field");
const inputSubmit = byId("input-modal-submit");
const inputCancel = byId("input-modal-cancel");
let inputResolver = null;

const infoModal = byId("info-modal");
const infoTitle = byId("info-modal-title");
const infoBody = byId("info-modal-body");
const infoClose = byId("info-modal-close");
let refreshTimer = null;
let handshakeTimer = null;

const setBusy = (busy) => {
  state.busy = busy;
  const disabled = busy || !state.selected;
  detailToggle.disabled = disabled;
  exportButton.disabled = disabled;
  editButton.disabled = disabled;
  deleteButton.disabled = disabled;
  restartButton.disabled = disabled;
  copyKeyButton.disabled = disabled;
  viewConfigButton.disabled = disabled;
  importButton.disabled = busy;
  addButton.disabled = busy;
};

const showError = (message) => {
  if (!message) {
    errorBanner.hidden = true;
    errorBanner.textContent = "";
    return;
  }
  errorBanner.textContent = message;
  errorBanner.hidden = false;
};

const setDetailPlaceholder = () => {
  detailName.textContent = "No tunnel selected";
  detailToggle.textContent = "Activate";
  detailToggle.disabled = true;
  detailPublicKey.textContent = "--";
  detailEndpoint.textContent = "--";
  detailTransfer.textContent = "--";
  detailHandshake.textContent = "--";
  detailAddress.textContent = "--";
  detailListenPort.textContent = "--";
  detailStatus.textContent = "--";
  detailPeerCount.textContent = "--";
  if (peerList) {
    peerList.innerHTML = "";
    const empty = document.createElement("div");
    empty.className = "peer-empty";
    empty.textContent = "No peer data available.";
    peerList.appendChild(empty);
  }
  if (peerRefreshNote) peerRefreshNote.textContent = "";
  if (handshakeTimer) {
    clearInterval(handshakeTimer);
    handshakeTimer = null;
  }
};

const renderList = () => {
  tunnelList.innerHTML = "";
  if (!state.tunnels.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No tunnels found. Import a .conf or add an empty tunnel.";
    tunnelList.appendChild(empty);
    return;
  }

  state.tunnels.forEach((tunnel) => {
    const item = document.createElement("div");
    item.className = `tunnel${tunnel.active ? " active" : ""}`;
    if (tunnel.name === state.selected) item.classList.add("selected");
    item.addEventListener("click", () => {
      state.selected = tunnel.name;
      renderList();
      refreshDetails();
    });

    const left = document.createElement("div");
    const name = document.createElement("div");
    name.className = "tunnel-name";
    name.textContent = tunnel.name;
    const meta = document.createElement("div");
    meta.className = "tunnel-meta";
    meta.textContent = tunnel.address || "No address set";
    left.appendChild(name);
    left.appendChild(meta);

    const status = document.createElement("div");
    status.className = `tunnel-status${tunnel.active ? "" : " idle"}`;
    status.textContent = tunnel.active ? "Connected" : "Disconnected";

    item.appendChild(left);
    item.appendChild(status);
    tunnelList.appendChild(item);
  });
};

const formatHandshakeAge = (unixSeconds) => {
  const seconds = Number(unixSeconds) || 0;
  if (!seconds) return "Never";
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (diff < 60) return `${diff} seconds ago`;
  const minutes = Math.floor(diff / 60);
  const remainder = diff % 60;
  return `${minutes}m ${remainder}s ago`;
};

const renderPeerList = (status) => {
  if (!peerList) return;
  peerList.innerHTML = "";
  if (!status || !status.active || !status.peers || !status.peers.length) {
    const empty = document.createElement("div");
    empty.className = "peer-empty";
    empty.textContent = "No peers connected.";
    peerList.appendChild(empty);
    return;
  }

  status.peers.forEach((peer) => {
    const card = document.createElement("div");
    card.className = "peer-card";

    const rows = [
      ["Public key", peer.publicKey || "--"],
      ["Endpoint", peer.endpoint || "--"],
      ["Allowed IPs", peer.allowedIps || "--"],
      ["Latest handshake", formatHandshakeAge(peer.latestHandshakeAt)],
      [
        "Transfer",
        peer.transferRx && peer.transferTx
          ? `${peer.transferRx} received | ${peer.transferTx} sent`
          : "--"
      ],
      [
        "Persistent keepalive",
        peer.keepaliveSeconds ? `${peer.keepaliveSeconds}s` : "off"
      ]
    ];

    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "peer-row";
      const labelEl = document.createElement("div");
      labelEl.className = "peer-label";
      labelEl.textContent = label;
      const valueEl = document.createElement("div");
      valueEl.className = "peer-value";
      if (label === "Latest handshake") {
        valueEl.dataset.handshakeAt = String(peer.latestHandshakeAt || 0);
        valueEl.dataset.peerKey = peer.publicKey || "";
      }
      valueEl.textContent = value;
      row.appendChild(labelEl);
      row.appendChild(valueEl);
      card.appendChild(row);
    });

    peerList.appendChild(card);
  });
};

const updateDetails = (tunnel, status) => {
  if (!tunnel) {
    setDetailPlaceholder();
    return;
  }

  detailName.textContent = tunnel.name;
  detailAddress.textContent = tunnel.address || "--";

  const active = status && status.active;
  detailToggle.textContent = active ? "Deactivate" : "Activate";
  detailToggle.disabled = state.busy;
  detailStatus.textContent = active ? "Connected" : "Disconnected";
  detailListenPort.textContent = status && status.listenPort ? status.listenPort : "--";

  if (active) {
    detailPublicKey.textContent = status.publicKey || "--";
    detailPeerCount.textContent =
      typeof status.peerCount === "number" ? status.peerCount : "--";
    if (status.peer) {
      detailEndpoint.textContent = status.peer.endpoint || "--";
      detailTransfer.textContent =
        status.peer.transferRx && status.peer.transferTx
          ? `${status.peer.transferRx} received | ${status.peer.transferTx} sent`
          : "--";
      detailHandshake.textContent = formatHandshakeAge(status.peer.latestHandshakeAt);
    } else {
      detailEndpoint.textContent = "--";
      detailTransfer.textContent = "--";
      detailHandshake.textContent = "--";
    }
  } else {
    detailPublicKey.textContent = "--";
    detailEndpoint.textContent = "--";
    detailTransfer.textContent = "--";
    detailHandshake.textContent = "--";
    detailPeerCount.textContent = "--";
  }

  renderPeerList(status);
  startHandshakeTicker();
};

const refreshTunnels = async (preserveSelection = true) => {
  setBusy(true);
  const result = await window.wg.listTunnels();
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  showError("");
  state.tunnels = result.data;
  if (!preserveSelection || !state.selected) {
    state.selected = state.tunnels[0] ? state.tunnels[0].name : null;
  } else if (!state.tunnels.find((tunnel) => tunnel.name === state.selected)) {
    state.selected = state.tunnels[0] ? state.tunnels[0].name : null;
  }
  setBusy(state.busy);
  renderList();
  await refreshDetails();
};

const clearRefreshTimer = () => {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
};

const getRefreshIntervalSeconds = (status) => {
  if (!status || !status.active || !status.peers || !status.peers.length) return 10;
  const keepalives = status.peers
    .map((peer) => Number(peer.keepaliveSeconds) || 0)
    .filter((value) => value > 0);
  if (!keepalives.length) return 10;
  return Math.min(...keepalives);
};

const scheduleRefresh = (seconds) => {
  clearRefreshTimer();
  const interval = Number(seconds) || 0;
  if (!interval) return;
  refreshTimer = setTimeout(() => {
    refreshDetails();
  }, interval * 1000);
};

const updateHandshakeDisplay = () => {
  if (!state.status || !state.status.active) return;
  if (state.status.peer) {
    detailHandshake.textContent = formatHandshakeAge(
      state.status.peer.latestHandshakeAt
    );
  }
  if (!peerList || !state.status.peers) return;
  const peerMap = new Map(
    state.status.peers.map((peer) => [peer.publicKey || "", peer])
  );
  peerList.querySelectorAll("[data-handshake-at]").forEach((el) => {
    const peer = peerMap.get(el.dataset.peerKey || "");
    const at = peer ? peer.latestHandshakeAt : Number(el.dataset.handshakeAt) || 0;
    el.dataset.handshakeAt = String(at || 0);
    el.textContent = formatHandshakeAge(at);
  });
};

let handshakeInFlight = false;

const pollHandshake = async () => {
  if (!state.selected || handshakeInFlight) return;
  handshakeInFlight = true;
  try {
    const result = await window.wg.getStatus(state.selected);
    if (result.ok) {
      state.status = result.data;
      updateHandshakeDisplay();
    }
  } finally {
    handshakeInFlight = false;
  }
};

const startHandshakeTicker = () => {
  if (handshakeTimer) {
    clearInterval(handshakeTimer);
    handshakeTimer = null;
  }
  if (!state.status || !state.status.active) return;
  updateHandshakeDisplay();
  handshakeTimer = setInterval(pollHandshake, 1000);
};

const refreshDetails = async () => {
  clearRefreshTimer();
  if (!state.selected) {
    updateDetails(null, null);
    return;
  }
  const tunnel = state.tunnels.find((item) => item.name === state.selected);
  if (!tunnel) {
    updateDetails(null, null);
    return;
  }
  const result = await window.wg.getStatus(tunnel.name);
  if (!result.ok) {
    showError(result.error);
    updateDetails(tunnel, { active: false });
    return;
  }
  showError("");
  state.status = result.data;
  updateDetails(tunnel, state.status);
  const refreshInterval = getRefreshIntervalSeconds(state.status);
  if (peerRefreshNote) {
    peerRefreshNote.textContent = `Auto-refresh every ${refreshInterval}s (handshake live)`;
  }
  scheduleRefresh(refreshInterval);
};

const openConfigModal = (mode, content, name) => {
  modalTitle.textContent =
    mode === "edit" ? `Edit ${name}.conf` : `View ${name}.conf`;
  modalTextarea.value = content || "";
  modalTextarea.readOnly = mode !== "edit";
  modalSave.hidden = mode !== "edit";
  modal.hidden = false;
};

const closeConfigModal = () => {
  modal.hidden = true;
  modalTextarea.value = "";
};

const openInputModal = ({ title, message, placeholder, defaultValue, submitLabel }) =>
  new Promise((resolve) => {
    inputTitle.textContent = title;
    inputMessage.textContent = message || "";
    inputField.placeholder = placeholder || "";
    inputField.value = defaultValue || "";
    inputSubmit.textContent = submitLabel || "Confirm";
    inputModal.hidden = false;
    inputField.focus();
    inputField.select();
    inputResolver = resolve;
  });

const closeInputModal = (value = null) => {
  inputModal.hidden = true;
  inputField.value = "";
  if (inputResolver) {
    inputResolver(value);
    inputResolver = null;
  }
};

const openInfoModal = (title, body) => {
  infoTitle.textContent = title;
  infoBody.textContent = body || "";
  infoModal.hidden = false;
};

const closeInfoModal = () => {
  infoModal.hidden = true;
  infoBody.textContent = "";
};

const handleToggle = async () => {
  if (!state.selected) return;
  setBusy(true);
  const active = state.status && state.status.active;
  const result = active
    ? await window.wg.down(state.selected)
    : await window.wg.up(state.selected);
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  await refreshTunnels(true);
};

const handleImport = async () => {
  setBusy(true);
  const result = await window.wg.import();
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  if (result.data && result.data.canceled) return;
  if (result.data) state.selected = result.data.name;
  await refreshTunnels(true);
};

const handleCreate = async () => {
  const name = await openInputModal({
    title: "Create tunnel",
    message: "Enter a tunnel name (wg0, home, office, etc.)",
    placeholder: "wg0",
    submitLabel: "Create"
  });
  if (!name) return;
  setBusy(true);
  const result = await window.wg.create(name);
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  if (result.data) state.selected = result.data.name;
  await refreshTunnels(true);
  await openAndEditConfig();
};

const openAndEditConfig = async () => {
  if (!state.selected) return;
  const result = await window.wg.readConfig(state.selected);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  openConfigModal("edit", result.data, state.selected);
};

const handleExport = async () => {
  if (!state.selected) return;
  setBusy(true);
  const result = await window.wg.export(state.selected);
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
  }
};

const handleDelete = async () => {
  if (!state.selected) return;
  const confirmed = window.confirm(
    `Delete ${state.selected}.conf? This cannot be undone.`
  );
  if (!confirmed) return;
  setBusy(true);
  const result = await window.wg.remove(state.selected);
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  await refreshTunnels(false);
};

const handleRestart = async () => {
  if (!state.selected) return;
  setBusy(true);
  const result = await window.wg.restart(state.selected);
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  await refreshTunnels(true);
};

const handleCopyKey = async () => {
  if (!state.status || !state.status.publicKey) return;
  const text = state.status.publicKey;
  try {
    await navigator.clipboard.writeText(text);
  } catch (error) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
};

const handleViewConfig = async () => {
  if (!state.selected) return;
  const result = await window.wg.readConfig(state.selected);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  openConfigModal("view", result.data, state.selected);
};

const handleSaveConfig = async () => {
  if (!state.selected) return;
  setBusy(true);
  const result = await window.wg.writeConfig(state.selected, modalTextarea.value);
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  closeConfigModal();
  await refreshTunnels(true);
};

const handleLog = async () => {
  setBusy(true);
  const result = await window.wg.getLog();
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  openInfoModal("WireGuard Log", result.data);
};

const handleSettings = async () => {
  setBusy(true);
  const result = await window.wg.getInfo();
  setBusy(false);
  if (!result.ok) {
    showError(result.error);
    return;
  }
  const info = result.data;
  const body = [
    `App version: ${info.appVersion}`,
    `Electron: ${info.electronVersion}`,
    `Node: ${info.nodeVersion}`,
    `WireGuard: ${info.wgVersion || "unknown"}`,
    `Config directory: ${info.configDir}`
  ].join("\n");
  openInfoModal("Settings", body);
};

const handleAbout = () => {
  const body = [
    "WireGuard UI for Debian",
    "Replicates the Windows WireGuard client interface.",
    "",
    "Built with Electron."
  ].join("\n");
  openInfoModal("About", body);
};

const init = async () => {
  setDetailPlaceholder();
  importButton.addEventListener("click", handleImport);
  addButton.addEventListener("click", handleCreate);
  exportButton.addEventListener("click", handleExport);
  editButton.addEventListener("click", openAndEditConfig);
  deleteButton.addEventListener("click", handleDelete);
  detailToggle.addEventListener("click", handleToggle);
  restartButton.addEventListener("click", handleRestart);
  quitButton.addEventListener("click", () => window.wg.quit());
  copyKeyButton.addEventListener("click", handleCopyKey);
  viewConfigButton.addEventListener("click", handleViewConfig);
  modalCancel.addEventListener("click", closeConfigModal);
  modalSave.addEventListener("click", handleSaveConfig);
  modal.addEventListener("click", (event) => {
    if (event.target === modal) closeConfigModal();
  });

  inputCancel.addEventListener("click", () => closeInputModal(null));
  inputSubmit.addEventListener("click", () => closeInputModal(inputField.value.trim()));
  inputField.addEventListener("keydown", (event) => {
    if (event.key === "Enter") closeInputModal(inputField.value.trim());
    if (event.key === "Escape") closeInputModal(null);
  });
  inputModal.addEventListener("click", (event) => {
    if (event.target === inputModal) closeInputModal(null);
  });

  infoClose.addEventListener("click", closeInfoModal);
  infoModal.addEventListener("click", (event) => {
    if (event.target === infoModal) closeInfoModal();
  });

  navLog.addEventListener("click", handleLog);
  navSettings.addEventListener("click", handleSettings);
  navAbout.addEventListener("click", handleAbout);

  await refreshTunnels(false);
};

document.addEventListener("DOMContentLoaded", init);
