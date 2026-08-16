// CWE-1188: Electron BrowserWindow with nodeIntegration enabled
const { BrowserWindow } = require("electron");

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  win.loadURL("https://example.com");
  return win;
}
