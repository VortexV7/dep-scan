const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('depscan', {
  getSysinfo: () => ipcRenderer.invoke('get-sysinfo'),
  pickFolder: () => ipcRenderer.invoke('pick-folder'),
  listDir: (dir) => ipcRenderer.invoke('list-dir', dir),
  openPath: (p) => ipcRenderer.invoke('open-path', p),
  checkJava: () => ipcRenderer.invoke('check-java'),
  runShell: (cmd, cwd) => ipcRenderer.send('run-shell', { cmd, cwd }),
  runDepscan: (args) => ipcRenderer.send('run-depscan', { args }),
  onShellOutput: (cb) => ipcRenderer.on('shell-output', (_e, d) => cb(d)),
  onShellDone: (cb) => ipcRenderer.on('shell-done', (_e, d) => cb(d)),
  onScanOutput: (cb) => ipcRenderer.on('scan-output', (_e, d) => cb(d)),
  onScanDone: (cb) => ipcRenderer.on('scan-done', (_e, d) => cb(d)),
  windowControl: (action) => ipcRenderer.send('window-control', action),
  // CI setup guides
  openGuide: (which) => ipcRenderer.send('open-guide', which),
  setCwd: (dir) => ipcRenderer.send('set-cwd', dir),
  getCwd: () => ipcRenderer.invoke('get-cwd'),
  addCiFile: (type) => ipcRenderer.invoke('add-ci-file', type),
});
