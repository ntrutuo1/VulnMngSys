/**
 * VulnMngSys - Electron Main Process
 *
 * Boot sequence:
 *  1. Show splash screen immediately.
 *  2. Start Metasploit msfrpcd from the external Metasploit install.
 *  3. Wait until the msfrpcd TCP port is open.
 *  4. Start the packaged Python backend on the machine LAN IP.
 *  5. Poll /api/status, then load the main app.
 */

"use strict";

const { app, BrowserWindow } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const net = require("net");
const os = require("os");
const path = require("path");
const fs = require("fs");

const PORT = Number(process.env.VMS_PORT || 8765);
const MSF_ROOT = process.env.VMS_MSF_ROOT || "E:\\VulnMngApp\\Tools\\metasploit-framework";
const MSFRPCD_PATH = path.join(MSF_ROOT, "bin", "msfrpcd.bat");
const MSFRPC_HOST = process.env.VMS_MSF_RPC_HOST || "127.0.0.1";
const MSFRPC_PORT = Number(process.env.VMS_MSF_RPC_PORT || 55552);
const MSFRPC_USER = process.env.VMS_MSF_RPC_USER || "msf";
const MSFRPC_PASS = process.env.VMS_MSF_RPC_PASS || "vulnmngsys";

let mainWin = null;
let backend = null;
let msfrpcd = null;
let appHost = "127.0.0.1";
let appUrl = `http://${appHost}:${PORT}`;

function getLanIp() {
  const interfaces = os.networkInterfaces();
  for (const entries of Object.values(interfaces)) {
    for (const item of entries || []) {
      if (item.family === "IPv4" && !item.internal && item.address && !item.address.startsWith("169.254.")) {
        return item.address;
      }
    }
  }
  return "127.0.0.1";
}

function getPythonPath() {
  const venvPy = path.join(__dirname, ".venv", "Scripts", "python.exe");
  return fs.existsSync(venvPy) ? venvPy : "python";
}

function getBackendEnv() {
  return {
    ...process.env,
    VMS_APP_ROOT: __dirname,
    VMS_DATA_DIR: app.getPath("userData"),
    VMS_HOST: appHost,
    VMS_PORT: String(PORT),
    VMS_MSF_ROOT: MSF_ROOT,
    VMS_MSF_RPC_HOST: MSFRPC_HOST,
    VMS_MSF_RPC_PORT: String(MSFRPC_PORT),
    VMS_MSF_RPC_USER: MSFRPC_USER,
    VMS_MSF_RPC_PASS: MSFRPC_PASS,
  };
}

function startBackend() {
  const packagedBackend = path.join(__dirname, "backend_dist", "backend.exe");
  if (fs.existsSync(packagedBackend)) {
    backend = spawn(packagedBackend, ["--host", appHost, "--port", String(PORT)], {
      cwd: __dirname,
      env: getBackendEnv(),
      windowsHide: true,
    });
  } else {
    const script = path.join(__dirname, "backend.py");
    backend = spawn(getPythonPath(), [script, "--host", appHost, "--port", String(PORT)], {
      cwd: __dirname,
      env: getBackendEnv(),
      windowsHide: true,
    });
  }
  backend.on("error", err => console.error("[backend] spawn error:", err));
  backend.stdout.on("data", buf => console.log("[backend]", String(buf).trim()));
  backend.stderr.on("data", buf => console.error("[backend]", String(buf).trim()));
}

function startMsfrpcd() {
  if (!fs.existsSync(MSFRPCD_PATH)) {
    throw new Error(`msfrpcd.bat not found: ${MSFRPCD_PATH}`);
  }
  msfrpcd = spawn(
    "cmd.exe",
    ["/c", MSFRPCD_PATH, "-U", MSFRPC_USER, "-P", MSFRPC_PASS, "-a", MSFRPC_HOST, "-p", String(MSFRPC_PORT), "-S"],
    {
      cwd: path.join(MSF_ROOT, "embedded", "framework"),
      env: getBackendEnv(),
      windowsHide: true,
    }
  );
  msfrpcd.on("error", err => console.error("[msfrpcd] spawn error:", err));
  msfrpcd.stdout.on("data", buf => console.log("[msfrpcd]", String(buf).trim()));
  msfrpcd.stderr.on("data", buf => console.error("[msfrpcd]", String(buf).trim()));
}

function waitForTcp(host, port, retries = 120, delay = 1500) {
  return new Promise((resolve, reject) => {
    const check = remaining => {
      const socket = net.createConnection({ host, port, timeout: 1200 }, () => {
        socket.destroy();
        resolve();
      });
      socket.on("error", () => retry(remaining));
      socket.on("timeout", () => {
        socket.destroy();
        retry(remaining);
      });
    };
    const retry = remaining => {
      if (remaining <= 0) {
        reject(new Error(`Timed out waiting for ${host}:${port}`));
        return;
      }
      setTimeout(() => check(remaining - 1), delay);
    };
    check(retries);
  });
}

function isTcpOpen(host, port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host, port, timeout: 700 }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

function setSplashStatus(text, percent, stepId, state) {
  if (!mainWin || mainWin.isDestroyed()) return;
  const script = `
    typeof setBootStatus === 'function' && setBootStatus(
      ${JSON.stringify(text)},
      ${percent},
      ${JSON.stringify(stepId || "")},
      ${JSON.stringify(state || "active")}
    );
  `;
  mainWin.webContents.executeJavaScript(script).catch(() => {});
}

function pollBackendReady(onReady, retries = 60, delay = 1500) {
  const req = http.get(
    { hostname: appHost, port: PORT, path: "/api/status", timeout: 1000 },
    res => {
      let body = "";
      res.on("data", chunk => (body += chunk));
      res.on("end", () => {
        try {
          const data = JSON.parse(body);
          if (data && data.ready === true) {
            onReady(data);
            return;
          }
        } catch (_) {
          // Keep retrying until backend is ready.
        }
        retry();
      });
    }
  );
  req.on("error", () => retry());
  req.on("timeout", () => {
    req.destroy();
    retry();
  });

  function retry() {
    if (retries <= 0) {
      console.error("[electron] Backend did not become ready.");
      if (mainWin && !mainWin.isDestroyed()) mainWin.loadURL(appUrl);
      return;
    }
    setTimeout(() => pollBackendReady(onReady, retries - 1, delay), delay);
  }
}

function createWindow() {
  mainWin = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 980,
    minHeight: 680,
    title: "VulnMngSys",
    show: false,
    backgroundColor: "#080d1a",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWin.setMenuBarVisibility(false);
  mainWin.loadFile(path.join(__dirname, "web", "splash.html"));
  mainWin.once("ready-to-show", () => {
    mainWin.show();
    beginBootSequence();
  });
}

async function beginBootSequence() {
  try {
    setSplashStatus(`Using host ${appHost}`, 10, "step-backend", "active");

    setSplashStatus("Starting Metasploit RPC daemon...", 22, "step-msf", "active");
    if (await isTcpOpen(MSFRPC_HOST, MSFRPC_PORT)) {
      setSplashStatus("Metasploit RPC daemon already running", 30, "step-msf", "active");
    } else {
      startMsfrpcd();
    }
    setSplashStatus("Waiting for msfrpcd...", 34, "step-msf", "active");
    await waitForTcp(MSFRPC_HOST, MSFRPC_PORT);
    setSplashStatus("Metasploit RPC daemon ready", 48, "step-msf", "done");

    setSplashStatus("Starting backend...", 58, "step-backend", "active");
    startBackend();
    setSplashStatus("Waiting for backend...", 68, "step-backend", "active");

    pollBackendReady(status => {
      setSplashStatus("Backend ready", 78, "step-backend", "done");
      setTimeout(() => {
        setSplashStatus("Loading database and CIS rules...", 88, "step-db", "active");
        setTimeout(() => {
          setSplashStatus("Launching interface...", 96, "step-ui", "active");
          setTimeout(() => {
            setSplashStatus("Ready", 100, "step-ui", "done");
            setTimeout(() => {
              if (mainWin && !mainWin.isDestroyed()) mainWin.loadURL(appUrl);
            }, 400);
          }, 500);
        }, 800);
      }, 400);
      if (!status.msfrpcd_available) {
        console.warn("[electron] msfrpcd not found at:", status.msfrpcd_path);
      }
    });
  } catch (err) {
    console.error("[electron] boot failed:", err);
    setSplashStatus(String(err.message || err), 100, "step-msf", "warn");
  }
}

app.whenReady().then(() => {
  appHost = process.env.VMS_HOST || getLanIp();
  appUrl = `http://${appHost}:${PORT}`;
  createWindow();
});

app.on("window-all-closed", () => app.quit());

app.on("before-quit", () => {
  if (backend) {
    backend.kill();
    backend = null;
  }
  if (msfrpcd) {
    msfrpcd.kill();
    msfrpcd = null;
  }
});

app.on("web-contents-created", (_, contents) => {
  contents.on("will-navigate", (event, url) => {
    const allow = [appUrl, "file://"];
    if (!allow.some(prefix => url.startsWith(prefix))) {
      event.preventDefault();
    }
  });
});
