const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn, execFile } = require('child_process');

let win = null;
let guideWin = null;
let currentCwd = os.homedir();

// Resolve the java executable: JAVA_HOME first, then PATH, then common
// install locations (the VM's /opt/jdk17, /usr/lib/jvm/*). On Ved's PC
// java is on PATH, so the first check wins there.
function resolveJava() {
  const { execFileSync } = require('child_process');
  if (process.env.JAVA_HOME) {
    const j = path.join(process.env.JAVA_HOME, 'bin', process.platform === 'win32' ? 'java.exe' : 'java');
    if (fs.existsSync(j)) return j;
  }
  try { execFileSync('java', ['-version'], { stdio: 'ignore' }); return 'java'; } catch (e) { /* not on PATH */ }
  for (const c of ['/opt/jdk17/bin/java', '/opt/jdk/bin/java']) if (fs.existsSync(c)) return c;
  try {
    const dirs = fs.readdirSync('/usr/lib/jvm');
    for (const d of dirs) {
      const j = path.join('/usr/lib/jvm', d, 'bin', 'java');
      if (fs.existsSync(j)) return j;
    }
  } catch (e) { /* no /usr/lib/jvm */ }
  return 'java';
}

function jarPath() {
  // Packaged: extraResources lands next to the exe (portable) / in resources.
  const candidates = [
    path.join(process.resourcesPath || '', 'dep-scan.jar'),
    path.join(app.getAppPath(), 'assets', 'dep-scan.jar'),
    path.join(__dirname, '..', 'assets', 'dep-scan.jar'),
  ];
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return candidates[2];
}

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 900,
    fullscreen: true,
    frame: false,
    title: 'DepScan Desktop',
    backgroundColor: '#0f172a',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.once('ready-to-show', () => win.show());
  win.on('closed', () => { win = null; });
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });

// ---- CI setup guides (local, offline HTML pages) ----
function guideFile(which) {
  const name = which === 'jenkins' ? 'jenkins.html' : 'github-actions.html';
  const candidates = [
    path.join(process.resourcesPath || '', 'app', 'guides', name),
    path.join(app.getAppPath(), 'app', 'guides', name),
    path.join(__dirname, 'guides', name),
  ];
  return candidates.find(c => fs.existsSync(c)) || candidates[2];
}

function ciTemplatePath(type) {
  const name = type === 'jenkins' ? 'Jenkinsfile' : 'depscan.yml';
  const candidates = [
    path.join(process.resourcesPath || '', 'app', 'guides', 'templates', name),
    path.join(app.getAppPath(), 'app', 'guides', 'templates', name),
    path.join(__dirname, 'guides', 'templates', name),
  ];
  return candidates.find(c => fs.existsSync(c)) || candidates[2];
}

function openGuide(which) {
  const title = which === 'jenkins' ? 'DepScan — Jenkins Setup' : 'DepScan — GitHub Actions Setup';
  if (guideWin && !guideWin.isDestroyed()) {
    guideWin.loadFile(guideFile(which));
    guideWin.setTitle(title);
    guideWin.focus();
    return;
  }
  guideWin = new BrowserWindow({
    width: 980,
    height: 820,
    frame: true,
    title,
    backgroundColor: '#0f172a',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  guideWin.loadFile(guideFile(which));
  guideWin.once('ready-to-show', () => guideWin.show());
  guideWin.on('closed', () => { guideWin = null; });
}

ipcMain.on('open-guide', (_e, which) => openGuide(which === 'jenkins' ? 'jenkins' : 'github'));

// The renderer tells main which folder is open, so "Add to this project"
// on a guide page writes into the right place.
ipcMain.on('set-cwd', (_e, dir) => { if (typeof dir === 'string' && dir) currentCwd = dir; });
ipcMain.handle('get-cwd', async () => currentCwd);

ipcMain.handle('add-ci-file', async (_e, type) => {
  const isJenkins = type === 'jenkins';
  const relPath = isJenkins ? 'Jenkinsfile' : path.join('.github', 'workflows', 'depscan.yml');
  const dest = path.join(currentCwd, relPath);
  try {
    const content = await fs.promises.readFile(ciTemplatePath(isJenkins ? 'jenkins' : 'github'), 'utf8');
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });
    const existed = fs.existsSync(dest);
    await fs.promises.writeFile(dest, content, 'utf8');
    return { ok: true, path: dest, existed };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

// ---- system info (polled by the renderer for the monitor panel) ----
ipcMain.handle('get-sysinfo', async () => {
  const cpus = os.cpus();
  let idle = 0, total = 0;
  for (const c of cpus) {
    idle += c.times.idle;
    total += c.times.user + c.times.nice + c.times.sys + c.times.irq + c.times.idle;
  }
  return {
    platform: os.platform(),
    hostname: os.hostname(),
    cpuModel: cpus[0] ? cpus[0].model : 'unknown',
    cpuCount: cpus.length,
    cpuIdle: idle, cpuTotal: total,
    memTotal: os.totalmem(), memFree: os.freemem(),
    uptime: os.uptime(),
    user: os.userInfo().username,
    home: os.homedir(),
    java: jarPath(),
    sampleDir: (() => {
      const cands = [
        path.join(process.resourcesPath || '', 'assets', 'samples', 'vulnerable-app'),
        path.join(app.getAppPath(), 'assets', 'samples', 'vulnerable-app'),
        path.join(__dirname, '..', 'assets', 'samples', 'vulnerable-app'),
      ];
      return cands.find(c => fs.existsSync(path.join(c, 'pom.xml'))) || cands[2];
    })(),
  };
});

ipcMain.handle('pick-folder', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.handle('list-dir', async (_e, dir) => {
  try {
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    return entries
      .sort((a, b) => (a.isDirectory() === b.isDirectory() ? a.name.localeCompare(b.name) : a.isDirectory() ? -1 : 1))
      .slice(0, 200)
      .map(e => ({ name: e.name, dir: e.isDirectory(), path: path.join(dir, e.name) }));
  } catch (err) {
    return { error: err.message };
  }
});

ipcMain.handle('open-path', async (_e, p) => shell.openPath(p));

// ---- run a shell command, streaming output back to the terminal ----
ipcMain.on('run-shell', (event, { cmd, cwd }) => {
  const shellCmd = process.platform === 'win32' ? 'cmd.exe' : '/bin/sh';
  const args = process.platform === 'win32' ? ['/c', cmd] : ['-c', cmd];
  const child = spawn(shellCmd, args, { cwd: cwd || os.homedir(), env: process.env });
  child.stdout.on('data', d => event.sender.send('shell-output', { text: d.toString(), err: false }));
  child.stderr.on('data', d => event.sender.send('shell-output', { text: d.toString(), err: true }));
  child.on('close', code => event.sender.send('shell-done', { code }));
  child.on('error', err => {
    event.sender.send('shell-output', { text: err.message + '\r\n', err: true });
    event.sender.send('shell-done', { code: 1 });
  });
});

// ---- run DepScan itself (java -jar dep-scan.jar ...) ----
ipcMain.on('run-depscan', (event, { args }) => {
  const java = resolveJava();
  const child = spawn(java, ['-jar', jarPath(), ...args], { env: process.env });
  let buf = '';
  child.stdout.on('data', d => { buf += d.toString(); event.sender.send('scan-output', { text: d.toString(), err: false }); });
  child.stderr.on('data', d => { buf += d.toString(); event.sender.send('scan-output', { text: d.toString(), err: true }); });
  child.on('close', code => event.sender.send('scan-done', { code, output: buf }));
  child.on('error', err => {
    event.sender.send('scan-output', { text: 'Could not start java: ' + err.message + '\r\nIs Java 17+ installed? Run: java -version\r\n', err: true });
    event.sender.send('scan-done', { code: 1, output: buf });
  });
});

ipcMain.on('window-control', (_e, action) => {
  if (!win) return;
  if (action === 'close') win.close();
  if (action === 'minimize') win.minimize();
  if (action === 'fullscreen') win.setFullScreen(!win.isFullScreen());
});

ipcMain.handle('check-java', async () => new Promise(resolve => {
  const java = resolveJava();
  execFile(java, ['-version'], (err, _out, stderr) => {
    if (err) return resolve({ ok: false, version: '' });
    resolve({ ok: true, version: (stderr || '').split('\n')[0] });
  });
}));
