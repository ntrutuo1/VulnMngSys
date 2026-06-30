const { app, BrowserWindow } = require("electron");
const { spawn } = require("child_process");
const path = require("path");

let backend;

function startBackend() {
  const script = path.join(__dirname, "backend.py");
  backend = spawn("python", [script, "--port", "8765"], { cwd: __dirname, windowsHide: true });
  backend.stdout.on("data", chunk => console.log(String(chunk).trim()));
  backend.stderr.on("data", chunk => console.error(String(chunk).trim()));
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 980,
    minHeight: 680,
    title: "VulnMngSys",
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.loadURL("http://127.0.0.1:8765");
}

app.whenReady().then(() => {
  startBackend();
  setTimeout(createWindow, 1200);
});

app.on("window-all-closed", () => app.quit());
app.on("before-quit", () => backend && backend.kill());
