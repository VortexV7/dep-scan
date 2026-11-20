# DepScan Desktop

A professional desktop app for **DepScan** — a reachability-aware
vulnerability scanner for Maven and npm projects. Double-click it and you
get a short boot screen, then the app — no black cmd window, no
`java -jar` typing.

DepScan checks your project's dependencies against the free
[OSV.dev](https://osv.dev) database, builds a call graph of your own code,
and tells you whether each vulnerable function is actually reachable.
Reachable = **CRITICAL**, unreachable = **LOW** (still shown, never hidden).

## What you see

1. **Boot screen** — DepScan logo, startup checks with a progress bar.
   Press any key to skip.
2. **Main screen**
   - **Left:** file browser (click a folder to set it as scan target),
     SCAN SAMPLE PROJECT / SCAN THIS FOLDER / PDF REPORT buttons, and a
     **CI SETUP** section — **GitHub Actions** and **Jenkins** buttons open
     a step-by-step setup guide.
   - **Center:** a real terminal. Type `help`, `scan <folder>`,
     `report <folder> --format pdf --out depscan-report.pdf`, or any normal
     shell command (`java -version`, `mvn -v`, `dir` …).
   - **Right:** live system monitor (CPU / RAM bars + graph, host info) and
     a FINDINGS panel.
   - **Bottom:** status bar + on-screen keyboard (⌨ KEYBOARD button).
3. **Keys:** F11 fullscreen, Ctrl+Q quit (or use the ✕ button to close).

## CI setup guides

The **CI SETUP** buttons open a local guide page (works fully offline, no
internet needed) with:

- what DepScan does in CI, step by step;
- the exact file to add — `.github/workflows/depscan.yml` or `Jenkinsfile`
  — with a **Copy** button on the code block;
- where to see the results (SARIF upload, pull-request annotations,
  exit codes);
- an **Add to this project** button that writes the CI file straight into
  the project folder currently open in the app.

## Run it (no build needed)

Prerequisites: **Node.js 20+** and **Java 17+**.

```bat
cd dep-scan-desktop
npm install
npm start
```

or simply double-click **`DepScan.bat`**.

That opens the app full-screen. The DepScan jar (`assets/dep-scan.jar`,
v0.5.0) is bundled inside — the terminal runs it with
`java -jar dep-scan.jar scan <folder>`. First scan needs internet (OSV.dev);
later scans work with `scan <folder> --offline`.

## Build the Windows executable

On your Windows PC, in this folder:

```bat
npm run dist:win
```

That makes `dist\DepScan-0.5.0-win-x64-Portable.exe` — a single
double-clickable exe, no install. Copy it anywhere and run it. (The Linux
AppImage equivalent is `npm run dist:linux`.)

## Try it first

In the terminal inside the app, run:

```
scan <sample folder>
```

or click **SCAN SAMPLE PROJECT**. Expected: 1 CRITICAL (commons-text,
CVE-2022-42889, reachable) + 3 LOW (snakeyaml, unreachable). The npm
sample (`samples/vulnerable-npm-app` in the CLI repo) gives 4 CRITICAL
(lodash) + 1 LOW (minimist).

## Files

```
dep-scan-desktop/
  package.json          Electron app (electron, xterm.js, electron-builder)
  DepScan.bat           double-click launcher (npm install on first run)
  app/main.js           window, java spawn, shell, file dialogs, sysinfo,
                        CI guide windows, "Add to this project" file writing
  app/preload.js        safe bridge to the renderer
  app/guides/           offline CI setup guides (GitHub Actions, Jenkins)
    templates/          the exact .github/workflows/depscan.yml + Jenkinsfile
                        the guides show and "Add to this project" writes
  renderer/             index.html / styles.css / renderer.js (boot + UI + terminal)
  assets/dep-scan.jar   DepScan v0.5.0 fat jar (bundled, runs the scans)
  assets/samples/       vulnerable-app sample project
```
