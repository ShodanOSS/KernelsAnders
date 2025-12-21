const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("wg", {
  listTunnels: () => ipcRenderer.invoke("tunnels:list"),
  getStatus: (name) => ipcRenderer.invoke("tunnels:status", name),
  up: (name) => ipcRenderer.invoke("tunnels:up", name),
  down: (name) => ipcRenderer.invoke("tunnels:down", name),
  restart: (name) => ipcRenderer.invoke("tunnels:restart", name),
  import: () => ipcRenderer.invoke("tunnels:import"),
  create: (name) => ipcRenderer.invoke("tunnels:create", name),
  remove: (name) => ipcRenderer.invoke("tunnels:delete", name),
  readConfig: (name) => ipcRenderer.invoke("tunnels:readConfig", name),
  writeConfig: (name, content) =>
    ipcRenderer.invoke("tunnels:writeConfig", { name, content }),
  export: (name) => ipcRenderer.invoke("tunnels:export", name),
  getLog: () => ipcRenderer.invoke("app:log"),
  getInfo: () => ipcRenderer.invoke("app:info"),
  quit: () => ipcRenderer.invoke("app:quit")
});
