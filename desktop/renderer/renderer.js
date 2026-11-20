// DepScan Desktop renderer: boot screen -> terminal -> scan results.
const $ = id => document.getElementById(id);
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------------- boot sequence ----------------
const BOOT_LINES = [
  ['> DepScan Desktop v0.5.0 — starting up', ''],
  ['> loading vulnerability database client (OSV.dev) ............ ', 'ok'],
  ['> loading call-graph engine (JavaParser + JGraphT) ............ ', 'ok'],
  ['> loading reachability analyzer ............ ', 'ok'],
  ['> preparing workspace ............ ', 'ok'],
  ['> checking Java runtime ............ ', 'ok'],
  ['> ready', ''],
];
let bootDone = false;
async function boot() {
  const log = $('boot-log'), bar = $('boot-bar');
  for (let i = 0; i < BOOT_LINES.length; i++) {
    if (bootDone) return;
    const [text, status] = BOOT_LINES[i];
    const div = document.createElement('div');
    div.textContent = text;
    if (status) { const s = document.createElement('span'); s.className = 'ok'; s.textContent = '[OK]'; div.appendChild(s); }
    log.appendChild(div);
    bar.style.width = Math.round(((i + 1) / BOOT_LINES.length) * 100) + '%';
    await sleep(260);
  }
  finishBoot();
}
function finishBoot() {
  if (bootDone) return;
  bootDone = true;
  $('boot').classList.add('fade');
  setTimeout(() => $('boot').remove(), 650);
  $('app').classList.remove('hidden');
  initTerminal();
  initApp();
}
document.addEventListener('keydown', () => { if (!bootDone) finishBoot(); }, { once: false });
$('boot').addEventListener('click', () => finishBoot());

// ---------------- terminal (xterm.js, real commands via main) ----------------
let term, fit, cwd = null, home = null, inputBuf = '', running = false, scanBuf = '';
const PROMPT = () => `depscan:${(cwd || '~').split(/[/\\]/).pop() || '/'}$ `;

function print(text) { term.write(text.replace(/\n/g, '\r\n')); }
function printPrompt() { term.write('\r\n' + PROMPT()); }

// Tell the main process which folder is open, so the CI guide pages
// ("Add to this project") write into the right project folder.
function syncCwd() { if (cwd) window.depscan.setCwd(cwd); }

function initTerminal() {
  term = new Terminal({
    cursorBlink: true, fontSize: 14, fontFamily: '"JetBrains Mono", Consolas, monospace',
    theme: { background: '#0b1220', foreground: '#e2e8f0', cursor: '#0ea5e9', selectionBackground: 'rgba(14,165,233,.3)' },
    scrollback: 5000,
  });
  fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($('terminal'));
  fit.fit();
  window.addEventListener('resize', () => fit.fit());
  term.writeln('\x1b[1;34mDepScan Desktop — type \x1b[1;36mhelp\x1b[0m\x1b[1;34m to begin.\x1b[0m');
  term.writeln('Try:  \x1b[36mscan samples/vulnerable-app\x1b[0m   or   \x1b[36mscan <your-project-folder>\x1b[0m');
  printPrompt();
  term.onData(handleKey);
  window.depscan.onShellOutput(d => { print(d.text); });
  window.depscan.onShellDone(() => { running = false; printPrompt(); });
  window.depscan.onScanOutput(d => { scanBuf += d.text; print(colorize(d.text)); });
  window.depscan.onScanDone(d => {
    running = false;
    const res = parseFindings(scanBuf) || { total: 0, crit: 0 };
    $('status').textContent = res.crit > 0
      ? `SCAN DONE — ${res.crit} CRITICAL, ${res.total - res.crit} LOW (exit ${d.code})`
      : res.total > 0
        ? `SCAN DONE — ${res.total} LOW, no reachable findings (exit ${d.code})`
        : `SCAN DONE — clean, no findings (exit ${d.code})`;
    printPrompt();
  });
}

function colorize(text) {
  return text
    .replace(/\[!!\] CRITICAL/g, '\x1b[1;31m[!!] CRITICAL\x1b[0m')
    .replace(/\[..\] LOW/g, '\x1b[33m[..] LOW\x1b[0m');
}

function handleKey(data) {
  if (running) return;
  if (data === '\r') { // Enter
    const line = inputBuf.trim();
    term.write('\r\n');
    inputBuf = '';
    if (line) runCommand(line);
    else printPrompt();
    return;
  }
  if (data === '\u007f') { // Backspace
    if (inputBuf.length) { inputBuf = inputBuf.slice(0, -1); term.write('\b \b'); }
    return;
  }
  if (data === '\u0003') { term.write('^C\r\n'); inputBuf = ''; printPrompt(); return; } // Ctrl+C
  if (data.charCodeAt(0) < 32) return; // ignore other control keys
  inputBuf += data;
  term.write(data);
}

async function runCommand(line) {
  const [cmd, ...rest] = line.split(/\s+/);
  const arg = rest.join(' ');
  switch (cmd.toLowerCase()) {
    case 'help':
      print([
        '', '  DepScan commands:',
        '    scan <folder> [--offline] [--fail-on critical|high|none] [--format sarif] [--out file]',
        '    report <folder> --format pdf|html|json|sarif|csv|sbom --out file',
        '    ls / cd <dir> / pwd        browse folders (sets scan target)',
        '    clear                      clear the terminal',
        '    exit                       close DepScan Desktop',
        '  Anything else runs in your real shell (java, mvn, dir, ...).',
        '',
      ].join('\r\n'));
      printPrompt();
      return;
    case 'clear': term.clear(); printPrompt(); return;
    case 'exit': window.depscan.windowControl('close'); return;
    case 'pwd': print(cwd || ''); printPrompt(); return;
    case 'ls': listDir(cwd); printPrompt(); return;
    case 'cd': {
      const target = arg || home;
      const resolved = await resolveDir(target);
      if (resolved) { cwd = resolved; syncCwd(); setTarget(resolved); refreshFiles(); }
      else print('cd: no such directory: ' + target);
      printPrompt();
      return;
    }
    case 'scan': case 'report': {
      const target = rest.find(a => !a.startsWith('-')) || $('target-box').textContent.trim();
      // flags = everything except the target token, in original order
      const flags = rest.filter(a => a !== target);
      scanBuf = '';
      running = true;
      $('status').textContent = 'SCANNING ' + target + ' …';
      $('findings').innerHTML = '<div class="dim small">Scanning…</div>';
      window.depscan.runDepscan([cmd, target, ...flags]);
      return;
    }
    default: {
      running = true;
      window.depscan.runShell(line, cwd);
    }
  }
}

async function resolveDir(p) {
  const path = p.replace(/^~/, home || '');
  const list = await window.depscan.listDir(path);
  return list && !list.error ? path : null;
}

// ---------------- file browser ----------------
async function refreshFiles() {
  $('cwd-label').textContent = cwd || '';
  const list = await window.depscan.listDir(cwd);
  const box = $('file-list');
  box.innerHTML = '';
  if (!list || list.error) { box.innerHTML = '<div class="dim small">' + (list?.error || 'cannot list') + '</div>'; return; }
  const up = document.createElement('div');
  up.className = 'entry dir'; up.textContent = '📁 .. (up)';
  up.onclick = async () => {
    const parent = cwd.replace(/[/\\][^/\\]+$/, '') || cwd;
    const r = await resolveDir(parent); if (r) { cwd = r; syncCwd(); refreshFiles(); }
  };
  box.appendChild(up);
  for (const e of list) {
    const div = document.createElement('div');
    div.className = 'entry' + (e.dir ? ' dir' : '');
    div.textContent = (e.dir ? '📁 ' : '📄 ') + e.name;
    div.onclick = async () => {
      if (e.dir) {
        const hasPom = (await window.depscan.listDir(e.path)).some?.(x => x.name === 'pom.xml');
        cwd = e.path; syncCwd(); setTarget(e.path); refreshFiles();
        if (hasPom) $('status').textContent = 'TARGET SET: ' + e.path + ' (Maven project)';
      }
    };
    div.ondblclick = () => window.depscan.openPath(e.path);
    box.appendChild(div);
  }
}
function setTarget(p) { $('target-box').textContent = p; }
function listDir(dir) { refreshFiles(); }

// ---------------- system monitor ----------------
let prevCpu = null, cpuHistory = [];
async function pollSys() {
  const s = await window.depscan.getSysinfo();
  const cpuPct = s.cpuTotal && prevCpu
    ? Math.max(0, Math.min(100, 100 * (1 - (s.cpuIdle - prevCpu.idle) / (s.cpuTotal - prevCpu.total))))
    : 0;
  prevCpu = { idle: s.cpuIdle, total: s.cpuTotal };
  const ramPct = Math.round(100 * (1 - s.memFree / s.memTotal));
  $('cpu-bar').style.width = cpuPct + '%';
  $('ram-bar').style.width = ramPct + '%';
  $('ram-bar').style.background = ramPct > 85 ? 'var(--red)' : 'var(--teal)';
  $('cpu-val').textContent = Math.round(cpuPct) + '%';
  $('ram-val').textContent = ramPct + '%';
  $('top-sys').textContent = `CPU ${Math.round(cpuPct)}% · RAM ${ramPct}%`;
  cpuHistory.push(cpuPct); if (cpuHistory.length > 60) cpuHistory.shift();
  drawGraph();
  $('sys-lines').innerHTML =
    `HOST&nbsp;&nbsp;${s.hostname}<br>USER&nbsp;&nbsp;${s.user}<br>OS&nbsp;&nbsp;&nbsp;&nbsp;${s.platform}<br>` +
    `CPU&nbsp;&nbsp;&nbsp;${s.cpuModel.slice(0, 28)}<br>CORES&nbsp;${s.cpuCount}<br>` +
    `RAM&nbsp;&nbsp;&nbsp;${(s.memTotal / 1e9).toFixed(1)} GB total<br>UPTIME ${Math.floor(s.uptime / 60)} min`;
}
function drawGraph() {
  const c = $('cpu-graph'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  ctx.strokeStyle = '#0ea5e9'; ctx.lineWidth = 1.5; ctx.beginPath();
  cpuHistory.forEach((v, i) => {
    const x = (i / 59) * c.width, y = c.height - (v / 100) * c.height;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = 'rgba(14,165,233,.12)'; ctx.lineTo(c.width, c.height); ctx.lineTo(0, c.height); ctx.fill();
}

// ---------------- findings panel ----------------
function parseFindings(output) {
  const findings = [];
  // Simpler: line-based parse of the boxed/text report.
  const lines = output.split('\n');
  let cur = null;
  for (const line of lines) {
    if (line.includes('[!!] CRITICAL')) {
      if (cur) findings.push(cur);
      cur = { sev: 'CRITICAL', pkg: line.replace(/.*CRITICAL\s+/, '').trim(), adv: '', loc: '', upg: '' };
    } else if (line.includes('[..] LOW')) {
      if (cur) findings.push(cur);
      cur = { sev: 'LOW', pkg: line.replace(/.*LOW\s+/, '').trim(), adv: '', loc: '', upg: '' };
    } else if (cur) {
      if (line.includes('Advisory:')) cur.adv = line.replace(/.*Advisory:\s*/, '').trim();
      if (line.includes('Location:')) cur.loc = line.replace(/.*Location:\s*/, '').trim();
      if (line.includes('Upgrade:')) cur.upg = line.replace(/.*Upgrade:\s*/, '').trim();
    }
  }
  if (cur) findings.push(cur);
  const box = $('findings');
  $('find-count').textContent = findings.length;
  if (!findings.length) { box.innerHTML = '<div class="dim small">Scan finished — no findings parsed. See terminal output.</div>'; return { total: 0, crit: 0 }; }
  box.innerHTML = '';
  for (const f of findings) {
    const div = document.createElement('div');
    div.className = 'find ' + (f.sev === 'CRITICAL' ? 'crit' : 'low');
    div.innerHTML = `<div class="sev">[${f.sev === 'CRITICAL' ? '!!' : '..'}] ${f.sev}</div>` +
      `<div>${f.adv || f.pkg}</div><div class="loc">${f.pkg}<br>${f.loc || ''}</div>` +
      (f.upg ? `<div class="small">${f.upg}</div>` : '');
    box.appendChild(div);
  }
  return { total: findings.length, crit: findings.filter(f => f.sev === 'CRITICAL').length };
}

// ---------------- app init (after boot) ----------------
async function initApp() {
  const s = await window.depscan.getSysinfo();
  home = s.home; cwd = home;
  syncCwd();
  $('sys-lines').textContent = 'loading…';
  setInterval(() => { $('clock').textContent = new Date().toLocaleTimeString(); }, 1000);
  $('clock').textContent = new Date().toLocaleTimeString();
  setInterval(pollSys, 1000); pollSys();
  const java = await window.depscan.checkJava();
  const badge = $('java-badge');
  badge.textContent = java.ok ? 'JAVA: ' + java.version.replace('openjdk version ', '') : 'JAVA: NOT FOUND';
  badge.classList.add(java.ok ? 'good' : 'bad');
  // default scan target: bundled sample (absolute path from main)
  setTarget(s.sampleDir || home);
  window.__sampleDir = s.sampleDir;
  refreshFiles();

  $('btn-browse').onclick = async () => {
    const dir = await window.depscan.pickFolder();
    if (dir) { cwd = dir; syncCwd(); setTarget(dir); refreshFiles(); $('status').textContent = 'TARGET SET: ' + dir; }
  };
  $('btn-scan-sample').onclick = () => runCommand('scan ' + (window.__sampleDir || $('target-box').textContent.trim()));
  $('btn-scan-target').onclick = () => runCommand('scan ' + $('target-box').textContent.trim());
  $('btn-report-pdf').onclick = () => runCommand('report ' + $('target-box').textContent.trim() + ' --format pdf --out depscan-report.pdf');
  $('btn-ci-github').onclick = () => window.depscan.openGuide('github');
  $('btn-ci-jenkins').onclick = () => window.depscan.openGuide('jenkins');
  document.querySelectorAll('.quick button').forEach(b => b.onclick = () => {
    term.write(b.dataset.cmd); inputBuf = b.dataset.cmd;
    term.write('\r\n'); inputBuf = ''; runCommand(b.dataset.cmd);
  });
  $('btn-close').onclick = () => window.depscan.windowControl('close');
  $('btn-min').onclick = () => window.depscan.windowControl('minimize');
  $('btn-full').onclick = () => window.depscan.windowControl('fullscreen');
  $('btn-kbd').onclick = () => $('keyboard').classList.toggle('hidden');
  buildKeyboard();
  document.addEventListener('keydown', e => {
    if (e.key === 'F11') { e.preventDefault(); window.depscan.windowControl('fullscreen'); }
    if (e.ctrlKey && e.key.toLowerCase() === 'q') window.depscan.windowControl('close');
  });
}

function buildKeyboard() {
  const rows = ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  const kb = $('keyboard');
  rows.forEach(r => {
    const div = document.createElement('div'); div.className = 'row';
    for (const ch of r) {
      const b = document.createElement('button'); b.textContent = ch;
      b.onclick = () => { inputBuf += ch; term.write(ch); term.focus(); };
      div.appendChild(b);
    }
    kb.appendChild(div);
  });
  const div = document.createElement('div'); div.className = 'row';
  const space = document.createElement('button'); space.textContent = 'SPACE'; space.className = 'wide';
  space.onclick = () => { inputBuf += ' '; term.write(' '); };
  const enter = document.createElement('button'); enter.textContent = '⏎ ENTER'; enter.className = 'wide';
  enter.onclick = () => { const line = inputBuf.trim(); term.write('\r\n'); inputBuf = ''; if (line) runCommand(line); else printPrompt(); };
  const bs = document.createElement('button'); bs.textContent = '⌫'; bs.className = 'wide';
  bs.onclick = () => { if (inputBuf.length) { inputBuf = inputBuf.slice(0, -1); term.write('\b \b'); } };
  div.append(space, enter, bs); kb.appendChild(div);
}

// start the boot screen
boot();
