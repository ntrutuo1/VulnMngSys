const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('vulnmngsys', {
  platform: process.platform,
});
