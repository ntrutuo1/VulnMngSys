// Minimal preload — expand to expose safe IPC as needed
const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('vulnmngsys', {
  platform: process.platform,
});
