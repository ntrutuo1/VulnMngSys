const { app, BrowserWindow, dialog } = require('electron');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const READY_PREFIX = 'VULNMNGSYS_BACKEND_READY ';
let backendProcess = null;

function repoRoot() {
  return path.resolve(__dirname, '..', '..');
}

function backendCwd() {
  return app.isPackaged ? process.resourcesPath : repoRoot();
}

function resolvePythonExe() {
  if (process.env.VULNMNGSYS_PYTHON) return process.env.VULNMNGSYS_PYTHON;
  const localVenv = path.resolve(repoRoot(), '..', '.venv', 'Scripts', 'python.exe');
  return fs.existsSync(localVenv) ? localVenv : 'python';
}

function resolveBackendCommand() {
  if (process.env.VULNMNGSYS_BACKEND_EXE) {
    return { command: process.env.VULNMNGSYS_BACKEND_EXE, args: [] };
  }

  if (app.isPackaged) {
    return {
      command: path.join(process.resourcesPath, 'backend', 'VulnMngSysBackend.exe'),
      args: [],
    };
  }

  return {
    command: resolvePythonExe(),
    args: ['-m', 'vulnmngsys_app.backend_service'],
  };
}

function startBackend() {
  const token = process.env.VULNMNGSYS_API_TOKEN || crypto.randomBytes(24).toString('hex');
  const { command, args } = resolveBackendCommand();
  const backendArgs = [
    ...args,
    '--host',
    process.env.VULNMNGSYS_API_HOST || '127.0.0.1',
    '--port',
    process.env.VULNMNGSYS_API_PORT || '0',
    '--token',
    token,
    '--allowed-origin',
    'null,http://127.0.0.1:5173,http://localhost:5173',
  ];

  backendProcess = spawn(command, backendArgs, {
    cwd: backendCwd(),
    env: {
      ...process.env,
      VULNMNGSYS_API_TOKEN: token,
      VULNMNGSYS_ALLOWED_ORIGINS:
        process.env.VULNMNGSYS_ALLOWED_ORIGINS || 'null,http://127.0.0.1:5173,http://localhost:5173',
    },
    windowsHide: true,
  });

  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      reject(new Error(`Backend did not become ready in time.\n${stderr}`));
    }, 45000);

    backendProcess.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      const lines = stdout.split(/\r?\n/);
      stdout = lines.pop() || '';
      for (const line of lines) {
        if (!line.startsWith(READY_PREFIX)) continue;
        clearTimeout(timer);
        resolve(JSON.parse(line.slice(READY_PREFIX.length)));
      }
    });

    backendProcess.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    backendProcess.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });

    backendProcess.on('exit', (code) => {
      if (code !== 0) {
        clearTimeout(timer);
        reject(new Error(`Backend exited with code ${code}.\n${stderr}`));
      }
    });
  });
}

function createWindow(backend) {
  const win = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 980,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  const query = new URLSearchParams({
    apiBase: backend.apiBase,
    apiToken: backend.apiToken,
  });
  const startUrl =
    process.env.ELECTRON_START_URL ||
    `${pathToFileURL(path.join(__dirname, '..', 'dist', 'index.html')).toString()}?${query.toString()}`;
  win.loadURL(startUrl);
}

app.whenReady().then(async () => {
  try {
    const backend = await startBackend();
    createWindow(backend);

    app.on('activate', function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow(backend);
    });
  } catch (error) {
    dialog.showErrorBox('VulnMngSys backend failed to start', String(error && error.stack ? error.stack : error));
    app.quit();
  }
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill();
  }
});
