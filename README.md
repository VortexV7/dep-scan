# DepScan

Reachability-aware vulnerability scanner for **Maven, npm and Python projects**.

Most scanners stop at "this dependency has a CVE". DepScan asks the
question that decides whether you need to fix it tonight: **can your code
actually reach the vulnerable function?**

- **Reachable = CRITICAL** — a call chain exists from an entry point
  (`main` or any public method) to the vulnerable function.
- **Unreachable = LOW** — still shown, never hidden. Shipped code can still
  be exploited another way, and a future caller can make it reachable.

Free / open source only: OSV.dev (free, no key), JavaParser, JGraphT,
Picocli, Jackson, Maven Model, Jansi. No AI claims. npm support landed in v0.4.0 (Stage 6) and Python (PyPI) support in
v0.5.0 (Stage 7, real OSV.dev PyPI data — see below). A project with none
of `pom.xml`, `package.json`, `requirements.txt`, `pyproject.toml` is refused
with a clear error naming all of them.

## How it works (Stage 1 — core engine)

| Package | What it does |
|---|---|
| `deps` | `PomParser` — parses `pom.xml` with Maven Model, resolves `${...}` properties (nested, up to 10 passes) and versions from `<dependencyManagement>` / a local parent pom. A version that only comes from an imported BOM is skipped with a warning, never guessed. |
| `osv` | `HttpOsvClient` — `POST https://api.osv.dev/v1/query` per dependency (`{package:{name:"g:a",ecosystem:"Maven"},version:"..."}`), parses id / aliases (CVE) / summary / severity / affected ranges / fixed version / `affected_functions` (searched recursively — OSV puts it under `database_specific` or `ecosystem_specific` depending on source DB). Responses are cached on disk (`~/.cache/depscan/osv`, 24 h TTL, SHA-256 filenames); stale cache is used on network failure / `--offline`. Two real-OSV quirks, verified live: `severity[].score` is usually a CVSS *vector* string, not a number — the word label comes from `database_specific.severity` (`CRITICAL`); and **Maven GHSA advisories in OSV carry no `affected_functions` at all** (checked live for commons-text + snakeyaml), so in practice the package-level fallback does the work and the function-level path is proven by unit tests with canned data. |
| `graph` | `CallGraphBuilder` — JavaParser over all `.java` under `src/`, no compilation or classpath needed. Methods are nodes (`FQN#name(arity)`), calls are edges, multi-hop. Interface/inheritance: a call on an interface or superclass also edges to every overriding implementation in the codebase (virtual dispatch). Calls to code outside the project are recorded as *external calls* — those are what reachability is checked against. |
| `reach` | `ReachabilityAnalyzer` — JGraphT directed graph, BFS from entry points. Function-level match (class + method name) when the advisory has function data; otherwise the package-level fallback: any call into the dependency's Java package (groupId heuristic, documented in `Dependency`) from reachable code counts as reachable. Returns the shortest call chain (Dijkstra) as evidence. |
| `report` | Boxed colour report (default) + plain text (`--simple`) + JSON (`--json`) reporters; upgrade suggestions. |
| `config` | `depscan.yml` loading — ignore list with justification + expiry, optional default `failOn`. |
| `cli` | Picocli `scan` command + `ScanService` wiring + exit codes (`ExitCodes`, `FailThreshold`). |
| `tui` | Hacker TUI (Stage 4): boot sequence, progress bars, radar, pulsing alert, `--tui` dashboard. |
| `ci` | CI support (Stage 3): auto-detection, GitHub annotations + step summary, SARIF. |
| `report` (export) | SARIF 2.1.0, CSV, HTML, CycloneDX SBOM, PDF (Stage 5). |

### Honest limits (Stage 1)

- Only **direct** dependencies are scanned (no transitive resolution yet).
- Call-graph resolution is heuristic (no symbol solver): overloads are
  distinguished by arity only, reflection / dynamic proxies / lambdas passed
  as callbacks are not followed, and the package fallback guesses the Java
  package from the groupId. When in doubt it errs toward flagging real use.
- A parent pom / BOM that is not on disk is not fetched.

### Honest limits (Stage 6 — npm)

- npm versions come from `package-lock.json` when present (exact). Without
  a lockfile the range minimum (`^4.17.20` → `4.17.20`) is used and flagged
  as approximate in the report notes — the installed version could be newer.
  Unresolvable ranges (`latest`, `*`, `file:`, `git:`, `||`) are skipped,
  never guessed.
- JS reachability is a regex-based import/call scan of your own `.js/.jsx/
  .ts/.tsx/.mjs/.cjs` (no external JS parser): an `import`/`require` of a
  package counts as reachable; never imported counts as unreachable. Blind
  spots: dynamic specifiers (`require(name)`), re-exports, computed member
  access (`_['trim'](...)`), calls hidden in template literals. An import
  alone is enough for CRITICAL — it errs toward flagging real use.

### Honest limits (Stage 7 — Python)

- Python versions come from `requirements.txt` when pinned (`==5.3.1` is
  exact). Ranges (`>=2.28`, `~=1.4.2`) resolve to their minimum and are
  flagged as approximate in the report notes — the installed version could
  be newer. Unpinned names, editable installs (`-e`), direct URLs
  (`name @ https://...`, `git+...`) and `<`-only bounds are skipped, never
  guessed. `pyproject.toml` is read from `[project] dependencies` (PEP 621)
  and `[tool.poetry.dependencies]` with a small line-oriented TOML reader —
  no TOML library; exotic TOML (multi-line inline tables, `tool.uv`
  sources) is not parsed.
- Python reachability is a regex-based import/call scan of your own `.py`
  files (`venv`, `.venv`, `__pycache__`, `.git`, `node_modules` excluded):
  an `import` of a package counts as reachable; never imported counts as
  unreachable. Import names map to PyPI distributions through a small alias
  map (`yaml` → `pyyaml`, `PIL` → `pillow`, `sklearn` → `scikit-learn`,
  `bs4` → `beautifulsoup4`); anything unlisted defaults to module name ==
  package name. Blind spots: dynamic imports (`importlib.import_module`,
  `__import__`), `exec()` strings, and conditional imports inside functions
  that never run (still counted — the import is in the shipped source).
  Stdlib modules are never treated as packages.

## Run it

Prerequisites: **Java 17+** and **Maven 3.9+**. On Windows, use Windows
Terminal (UTF-8) so the box borders and colours render; in plain `cmd`
run `chcp 65001` first.

```bash
# Build (downloads dependencies from Maven Central on first run)
mvn -q package -DskipTests

# Scan a project (boxed, colour-coded report by default).
# pom.xml -> Maven; package.json -> npm; requirements.txt / pyproject.toml -> Python;
# any combination present -> all of them, merged into one report.
java -jar target/dep-scan-0.5.0.jar scan /path/to/your-project
java -jar target/dep-scan-0.5.0.jar scan samples/vulnerable-python-app

# Plain text, JSON, offline (cache only), fail CI on reachable vulns
java -jar target/dep-scan-0.5.0.jar scan . --simple
java -jar target/dep-scan-0.5.0.jar scan . --json --offline --fail-on critical
java -jar target/dep-scan-0.5.0.jar scan . --fail-on high --no-color --no-animation
```

### Flags

| Flag | Meaning |
|---|---|
| `--simple` | Plain unboxed text report (same data, no boxes). |
| `--json` | Machine-readable JSON report (includes `location`, `upgradeSuggestion`, `ignoredFindings`). |
| `--fail-on <critical\|reachable\|high\|none>` | Exit 1 when breached. Default `critical`. `critical`/`reachable` = any reachable finding; `high` = any HIGH-severity finding, reachable or not (CVSS ≥ 7 or a HIGH/CRITICAL label — the word label is what live OSV usually carries); `none` = never fail on findings. `--fail-on-critical` still works as an alias for `--fail-on critical`. |
| `--offline` | Never touch the network; cache only. |
| `--no-color` | Disable coloured output. |
| `--no-animation` | Disable the scanning spinner (spinner is on stderr, only on a TTY, never in `--json`). |
| `--config depscan.yml` | Config file (default: `depscan.yml` in the scanned project dir, if present). |
| `--cache-dir <dir>` | OSV cache directory (default `~/.cache/depscan/osv`). |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, or only unreachable (LOW) findings under the chosen threshold. |
| `1` | `--fail-on` threshold breached. |
| `2` | Usage or tool error: bad flags, bad config, missing directory, no `pom.xml`. |
| `3` | Network error with no cache: OSV.dev unreachable and no cached response (or `--offline` with an empty cache). Run once online first. |

### Report

Default output is one box per finding:

- **RED `[!!] CRITICAL`** — reachable. **YELLOW `[..] LOW`** — unreachable, still shown.
- Each box shows package + version, advisory id (+ CVE alias), **file:line**
  (the call site for reachable findings, the `pom.xml` declaration line for
  unreachable ones), severity, a **safe-upgrade suggestion** and the evidence
  + call chain. A major-version upgrade is flagged as likely breaking:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ [!!] CRITICAL  org.apache.commons:commons-text:1.9                           │
│ Advisory: GHSA-599f-7c49-w659 (CVE-2022-42889)                               │
│ Location: src/main/java/com/example/app/InterpolatorService.java:10          │
│ Severity: CRITICAL                                                           │
│ Upgrade: Upgrade to 1.10.0 (minor bump from 1.9 - usually safe, test before  │
│ shipping)                                                                    │
│ Evidence: PACKAGE: call into org.apache.commons.* ...                        │
│ Call chain:                                                                  │
│   com.example.app.App#main(1)                                                │
│   com.example.app.InterpolatorService#interpolate(1)                         │
│   org.apache.commons.text.StringSubstitutor#createInterpolator(0)            │
└──────────────────────────────────────────────────────────────────────────────┘
Summary: 1 CRITICAL (reachable), 3 LOW (unreachable, still shown).
```

A major bump reads e.g. `Upgrade to 2.0 (MAJOR bump from 1.31 - likely
breaking, check the changelog and test)`; a patch bump reads `(patch bump
from 1.9 - safe)`. No fixed version: `No fixed version published yet`.

### Ignoring a finding — `depscan.yml`

Copy `depscan.yml.example` to `depscan.yml` in the project root (or pass
`--config`). Every ignore needs a justification **and** an expiry date;
an ignore without either is a config error (exit 2). Expired ignores stop
applying — the finding counts normally again, with a note in the report.
Ignored findings are still shown, under `[--] IGNORED`, with their reason
and expiry; they never breach a `--fail-on` threshold.

```yaml
failOn: critical
ignore:
  - id: CVE-2022-1471
    package: org.yaml:snakeyaml   # optional scope; omit to match any package
    reason: Only used in tests, never on untrusted input
    expires: 2027-06-30
```

`id` can be a GHSA id or a CVE alias; `package`/`dependency` is optional;
`reason`/`justification` and `expires`/`expiry` are accepted as aliases.

Note the evidence line: live OSV advisories for Maven carry no
function-level data, so the sample's CRITICAL comes from the package
fallback (a real call into `org.apache.commons.text.*` from `main`).
The function-level path is exercised by the unit tests with canned OSV
data that does include `affected_functions`.

## Test it

```bash
mvn test
```

Tests (109 total, no network — OSV is faked / canned JSON; the sample-scan tests use a canned OSV cache in `src/test/resources/osv-cache/`):

- `PomParserTest` — property + dependencyManagement resolution, unresolvable version skipped.
- `OsvClientTest` — canned OSV response parsing (severity, fixed version, affected functions), version-range checks, cache round-trip.
- `CallGraphBuilderTest` — multi-hop calls, interface → implementation resolution, dead private method not an entry point.
- `ReachabilityAnalyzerTest` — **reachable case is CRITICAL with a call chain; unreachable case is LOW, still present**; package-fallback cases both ways.
- `ScanServiceTest` — end-to-end on `samples/vulnerable-app` with a fake OSV client: 1 CRITICAL + 1 LOW.
- `ExitCodesTest` — exit-code contract for every threshold (clean, only-unreachable, reachable, high-by-word-label, `none`), `FailThreshold.parse`.
- `ScanCommandTest` — CLI exit codes: clean project 0, missing dir / no pom / bad `--fail-on` / `--simple`+`--json` / missing or unjustified config 2, `--offline` with empty cache 3.
- `ScanServiceIgnoreTest` — live ignore moves a finding to the ignored list, expired ignore does not suppress, reachable finding carries a call-site `file:line`, `NetworkException` propagates.
- `ConfigLoaderTest` — valid config, alias + package-scope matching, inclusive expiry, missing reason/expires/date errors, auto-discovery.
- `ReporterTest` — boxed report markers, package/version/advisory/location/upgrade, red/yellow ANSI, JSON fields, upgrade major/minor/patch text.
- `CiDetectorTest` — CI detection per variable (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`), `NO_COLOR`, provider names.
- `GitHubActionsTest` — `::error`/`::warning` annotations with file:line, step-summary Markdown table, summary file append.
- `SarifReporterTest` — SARIF 2.1.0 shape, driver name/version, error vs warning levels, file:line locations.
- `HackerTuiTest` — banner, progress-bar percentages, radar frames, boot lines, pulsing-alert degrade, dashboard filter/toggle/quit keys, dashboard render.
- `ExportReporterTest` — risk-score formula, CSV rows, HTML themes + exclude-unreachable, CycloneDX 1.6 SBOM, PDF sections + selectable text + embedded Inter / JetBrains Mono fonts.
- `ReportCommandTest` — `scan --format sarif` (exit 1, valid SARIF), CI plain output, `report` for all six formats, bad format/theme exit 2, `--exclude-unreachable`.
- `NpmParserTest` — lockfile v1/v3 pinning, range-minimum + approximate flag, unresolvable ranges skipped, scoped packages, declaration lines.
- `JsCallGraphTest` — `require` / ESM / destructured / subpath / scoped / dynamic imports, member calls through bindings, `node_modules` excluded, calls in strings/comments ignored.
- `NpmScanServiceTest` — sample npm app (lodash reachable CRITICAL, minimist unreachable LOW), both ecosystems merged into one report, neither-manifest error names both files.
- `PyParserTest` — pinned exact, range minimum + approximate flag, extras/markers/PEP 503 normalisation, unpinned/editable/URL skipped, `[project]` + Poetry dependencies, requirements.txt wins on a clash.
- `PyCallGraphTest` — `import yaml` → pyyaml, `from` imports / aliases / submodules, multi-line imports, member calls through bindings, `venv`/`__pycache__` excluded, calls in strings/comments/docstrings ignored.
- `PyScanServiceTest` — sample Python app (pyyaml reachable CRITICAL, flask unreachable LOW), pyproject-only detection, all three ecosystems merged into one report, no-manifest error names all three manifests.

## Try the sample (live OSV.dev)

```bash
mvn -q package -DskipTests
java -jar target/dep-scan-0.5.0.jar scan samples/vulnerable-app
java -jar target/dep-scan-0.5.0.jar scan samples/vulnerable-npm-app
java -jar target/dep-scan-0.5.0.jar scan samples/vulnerable-python-app
```

`samples/vulnerable-app` is a small Maven project with two deliberately
vulnerable dependencies:

| Dependency | Vulnerability | Expected verdict | Why |
|---|---|---|---|
| `commons-text:1.9` | CVE-2022-42889 (Text4Shell) | **CRITICAL** | `App.main → InterpolatorService.interpolate → StringSubstitutor.createInterpolator` |
| `snakeyaml:1.31` | 3 advisories (CVE-2022-38752, CVE-2022-1471, CVE-2022-41854) | **LOW ×3** | Only referenced from `UnusedHelper.loadYaml`, a private method nothing calls |

The first run needs network (OSV.dev); later runs reuse `~/.cache/depscan/osv`
and work with `--offline`.

`samples/vulnerable-npm-app` is a small npm project with two deliberately
vulnerable dependencies:

| Dependency | Vulnerability | Expected verdict | Why |
|---|---|---|---|
| `lodash:4.17.20` | 4 advisories incl. CVE-2020-28500 (ReDoS) | **CRITICAL ×4** | `index.js` does `require('lodash')` and calls `_.trim(...)` |
| `minimist:1.2.5` | CVE-2021-44906 (prototype pollution) | **LOW** | Listed in `package.json` but never imported anywhere |

`samples/vulnerable-python-app` is a small Python project with two deliberately
vulnerable dependencies:

| Dependency | Vulnerability | Expected verdict | Why |
|---|---|---|---|
| `pyyaml:5.3.1` | CVE-2020-14343 (improper input validation) | **CRITICAL ×2** | `app.py` does `import yaml` and calls `yaml.safe_load(...)` |
| `flask:2.0.1` | 4 advisories incl. session-cookie issues | **LOW ×4** | Listed in `requirements.txt` but never imported anywhere |

## Project layout

```
dep-scan/
  pom.xml
  depscan.yml.example       # copy to depscan.yml to ignore findings
  src/main/java/com/depscan/{cli,config,deps,osv,graph,reach,report,tui,ci}/
  src/test/java/com/depscan/{cli,config,deps,osv,graph,reach,report}/
  samples/vulnerable-app/     # deliberately vulnerable demo project (Maven)
  samples/vulnerable-npm-app/ # deliberately vulnerable demo project (npm)
  samples/vulnerable-python-app/ # deliberately vulnerable demo project (Python)
```

## Stage 3 — CI/CD

DepScan auto-detects CI (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`,
`TF_BUILD`, `CIRCLECI`, or a non-TTY) and switches to plain, colour-free,
animation-free logs. In GitHub Actions it also emits `::error` / `::warning`
annotations with file and line (stderr, so stdout stays clean for piping)
and appends a Markdown table to `$GITHUB_STEP_SUMMARY`.

```bash
# SARIF 2.1.0 for GitHub code scanning / GitLab SAST
java -jar target/dep-scan-0.5.0.jar scan . --format sarif --fail-on critical --out depscan.sarif
```

Files: `action.yml` (composite action), `.github/workflows/depscan.yml`
(sample: push, PR, weekly schedule, upload-sarif + upload-artifact),
`.github/workflows/ci.yml` (builds and tests DepScan itself, Java 17 + 21),
`.gitlab-ci.yml`, `Jenkinsfile`, `Dockerfile` (multi-stage, `docker run
--rm -v "$PWD:/work" -w /work dep-scan:0.5.0 scan .`).

## Stage 4 — Hacker-style terminal UI

On a real terminal (TTY, not CI) `scan` opens with the ASCII-art DepScan
banner typing in, `> initializing scanner... [OK]` lines, animated progress
bars for pom parsing and call-graph building, a radar spinner while OSV.dev
is queried, and a pulsing red alert when a reachable CRITICAL is found.
Neon cyan / green / red / amber. Everything degrades cleanly: `--no-animation`,
`NO_COLOR`, `--no-color`, CI or a non-TTY all fall back to the plain report
with no ANSI codes.

```bash
java -jar target/dep-scan-0.5.0.jar scan . --tui   # full-screen dashboard
```

Dashboard shortcuts: `a` all findings, `c` critical only, `l` low only,
`s` toggle simple mode, `q` quit. The dashboard shows a dependency tree,
scan stats, the vulnerability list and a status bar.

## Stage 5 — PDF and export formats

```bash
depscan report <path> --format <pdf|html|json|sarif|csv|sbom> --out <file>
# options: --exclude-unreachable, --simple, --theme light|dark
# (plus --offline / --config / --cache-dir / --fail-on, as in scan)
```

- **PDF**: A4, page numbers + header/footer, embedded Inter (body/headings)
  and JetBrains Mono (code/paths) from `src/main/resources/fonts/`
  (OFL-licensed). Cover page, executive summary (counts + risk score / 10),
  severity chart, detailed findings table, recommendations, methodology and
  limitations (static analysis misses reflection and dynamic dispatch),
  glossary. Severity badges are labelled grey fills, readable in greyscale;
  text is selectable; advisory ids link to osv.dev.
- **Risk score** (all formats): reachable × 2.5 + unreachable × 0.5, capped
  at 10 — a triage aid, not a CVSS score.
- **HTML**: self-contained, light/dark theme, severity chart, clickable
  advisory links. **CSV**: one row per finding. **SBOM**: CycloneDX 1.6 JSON
  (components = direct dependencies, vulnerabilities = findings).

## Stage 6 — npm support (v0.4.0)

`scan` auto-detects the project type: `pom.xml` → Maven, `package.json` →
npm, both → both, merged into one report (each finding labelled by its
ecosystem, `npm:name:version` vs `group:artifact:version`). All existing
flags, exit codes, `depscan.yml` ignores, SARIF and `report` exports work
for npm findings exactly as for Maven ones.

- `deps/NpmParser` — `package.json` (`dependencies` + `devDependencies`)
  with exact versions from `package-lock.json` (v1/v2/v3); no lockfile →
  range minimum, flagged approximate in the report notes.
- `graph/JsCallGraph` — regex import/call map of your own JS/TS source
  (`.js/.jsx/.ts/.tsx/.mjs/.cjs`, `node_modules` excluded): `import` /
  `require` / dynamic `import()`, subpaths (`lodash/trim` → `lodash`),
  scoped packages, and which imported bindings are actually called.
- `reach/ReachabilityAnalyzer.analyzeJs` — imported → CRITICAL (import
  site as evidence), never imported → LOW; function-level match when the
  advisory carries `affected_functions`, package fallback otherwise
  (npm GHSA advisories usually carry none, same as Maven).
- OSV.dev npm data verified live (lodash 4.17.20 → GHSA-29mw-wpgm-hmr9,
  minimist 1.2.5 → GHSA-xvch-5gv4-984h).

## Stage 7 — Python support (v0.5.0)

`scan` auto-detects the project type: `pom.xml` → Maven, `package.json` →
npm, `requirements.txt` or `pyproject.toml` → Python (PyPI); any
combination → all of them, merged into one report (each finding labelled by
its ecosystem, `pypi:name:version` vs `npm:name:version` vs
`group:artifact:version`). All existing flags, exit codes, `depscan.yml`
ignores, SARIF and `report` exports work for Python findings exactly as for
Maven and npm ones.

- `deps/PyParser` — `requirements.txt` (PEP 508, pinned `==` exact;
  `>=`/`~=`/`==x.*` → range minimum, flagged approximate) and
  `pyproject.toml` (`[project] dependencies` + `[tool.poetry.dependencies]`);
  bare names, editables, direct URLs and `<`-only bounds skipped, never
  guessed; names normalised per PEP 503.
- `graph/PyCallGraph` — regex import/call map of your own `.py` source
  (`venv`/`.venv`/`__pycache__`/`.git` excluded): `import x`,
  `import x as y`, `from x import y` (incl. parenthesised multi-line),
  top-level module → PyPI distribution via a small alias map
  (`yaml` → `pyyaml`, `PIL` → `pillow`, `sklearn` → `scikit-learn`,
  `bs4` → `beautifulsoup4`), and which imported bindings are actually called.
- `reach/ReachabilityAnalyzer.analyzePy` — imported → CRITICAL (import
  site as evidence), never imported → LOW; function-level match when the
  advisory carries `affected_functions`, package fallback otherwise
  (PyPI advisories usually carry none, same as Maven/npm).
- OSV.dev PyPI data verified live (pyyaml 5.3.1 → GHSA-8q59-q68h-6hv4,
  flask 2.0.1 → GHSA-68rp-wp8r-4726; note pyyaml 5.4 is already clean, so
  the sample pins 5.3.1).

## Roadmap (not yet built)

- Transitive dependencies, symbol-solver resolution, Gradle support —
  each a separate stage, never faked.
