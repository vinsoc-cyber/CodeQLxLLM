// Safe Electron defaults — nodeIntegration off, contextIsolation on
const { BrowserWindow } = require("electron");

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: "./preload.js",
    },
  });
  win.loadURL("https://example.com");
  return win;
}
