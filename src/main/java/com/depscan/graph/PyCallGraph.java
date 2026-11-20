package com.depscan.graph;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * A heuristic import/call map of a project's own Python source — the Python
 * counterpart of {@link JsCallGraph}. No external Python parser is used
 * (dependency-free by design); the source is scanned with regular
 * expressions, so this is an <i>approximation</i>, documented honestly:
 *
 * <ul>
 *   <li><b>What it records:</b> every {@code import x}, {@code import x as y},
 *       {@code from x import y} (incl. parenthesised multi-line imports),
 *       with the first {@code file:line} of each; every bare call
 *       ({@code load(...)}) and member call ({@code yaml.safe_load(...)})
 *       with its first location; and which local name belongs to which
 *       package ({@code import yaml as y} makes {@code y} a pyyaml binding,
 *       so {@code y.safe_load(...)} is recorded as a pyyaml
 *       {@code safe_load} call).</li>
 *   <li><b>Module &rarr; package:</b> the imported <i>top-level</i> module
 *       maps to its PyPI distribution name ({@code from yaml import ...}
 *       is pyyaml; {@code import os.path} is the stdlib, ignored). A small
 *       alias map covers the common cases where the import name differs
 *       from the distribution name ({@code yaml} &rarr; {@code pyyaml},
 *       {@code PIL} &rarr; {@code pillow}, {@code sklearn} &rarr;
 *       {@code scikit-learn}, {@code bs4} &rarr; {@code beautifulsoup4});
 *       anything else defaults to module name == package name.</li>
 *   <li><b>Entry points:</b> every source file's top level — an import
 *       anywhere in the project's own source counts as use. There is no
 *       inter-file call graph: a package imported in a dead file still
 *       counts as reachable, because the file ships with the project.</li>
 *   <li><b>Known blind spots (same honesty as the JS side):</b>
 *       {@code importlib.import_module()} and other dynamic imports,
 *       {@code __import__()}, imports hidden in {@code exec()} strings,
 *       conditional imports inside functions that never run (still counted
 *       as reachable — the import is in the shipped source), and
 *       {@code from x import *} (recorded as an import of {@code x}, with
 *       no individual bindings). When in doubt it errs toward flagging
 *       real use — an import alone is enough for CRITICAL.</li>
 * </ul>
 * Files scanned: {@code .py}, excluding {@code venv}, {@code .venv},
 * {@code __pycache__}, {@code .git}, {@code node_modules}, {@code .tox},
 * {@code build} and {@code dist} at any depth.
 */
public final class PyCallGraph {

    /** First import site of a package: file (relative, '/'-separated), line, local bindings. */
    public record ImportSite(String file, int line, Set<String> bindings) {
        public String location() {
            return file + ":" + line;
        }
    }

    /** Top-level module name &rarr; PyPI distribution name, where they differ. */
    static final Map<String, String> MODULE_TO_PACKAGE = Map.ofEntries(
            Map.entry("yaml", "pyyaml"),
            Map.entry("PIL", "pillow"),
            Map.entry("sklearn", "scikit-learn"),
            Map.entry("bs4", "beautifulsoup4"),
            Map.entry("cv2", "opencv-python"),
            Map.entry("Crypto", "pycryptodome"),
            Map.entry("Cryptodome", "pycryptodome"),
            Map.entry("dateutil", "python-dateutil"),
            Map.entry("dotenv", "python-dotenv"),
            Map.entry("flask", "flask"),
            Map.entry("requests", "requests"),
            Map.entry("numpy", "numpy"),
            Map.entry("pandas", "pandas"),
            Map.entry("django", "django"),
            Map.entry("jwt", "pyjwt"),
            Map.entry("serial", "pyserial"),
            Map.entry("usb", "pyusb"),
            Map.entry("gi", "pygobject"),
            Map.entry("attr", "attrs"),
            Map.entry("magic", "python-magic"));

    private static final Set<String> EXCLUDED_DIRS = Set.of(
            "venv", ".venv", "__pycache__", ".git", "node_modules", ".tox", "build", "dist", ".eggs");

    private static final Pattern IMPORT_STMT = Pattern.compile(
            "^import\\s+(.+)$");
    private static final Pattern FROM_IMPORT_STMT = Pattern.compile(
            "^from\\s+([A-Za-z_][\\w.]*)\\s+import\\s+(.+)$");
    private static final Pattern IMPORT_ITEM = Pattern.compile(
            "([A-Za-z_][\\w.]*)(?:\\s+as\\s+([A-Za-z_][\\w]*))?");
    private static final Pattern MEMBER_CALL = Pattern.compile(
            "([A-Za-z_][\\w]*)\\.([A-Za-z_][\\w]*)\\s*\\(");
    private static final Pattern BARE_CALL = Pattern.compile(
            "(?<![\\w$.])([A-Za-z_][\\w]*)\\s*\\(");

    private final Map<String, ImportSite> imports = new LinkedHashMap<>();
    private final Map<String, String> bindingToPackage = new LinkedHashMap<>();
    private final Set<String> calledBare = new LinkedHashSet<>();
    private final Set<String> calledMembers = new LinkedHashSet<>();
    private final Set<String> calledQualified = new LinkedHashSet<>();
    private final Map<String, String> callLocations = new LinkedHashMap<>();

    private PyCallGraph() {}

    /** Scan all Python sources under {@code projectDir} (excluding venvs, caches, .git). */
    public static PyCallGraph build(Path projectDir) throws IOException {
        PyCallGraph graph = new PyCallGraph();
        List<Path> files = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(projectDir)) {
            walk.filter(Files::isRegularFile)
                    .filter(p -> {
                        for (Path part : p) {
                            if (EXCLUDED_DIRS.contains(part.toString())) return false;
                        }
                        return true;
                    })
                    .filter(p -> p.getFileName().toString().endsWith(".py"))
                    .sorted()
                    .forEach(files::add);
        }
        for (Path file : files) {
            String rel = relativize(projectDir, file);
            graph.scanFile(rel, Files.readAllLines(file));
        }
        return graph;
    }

    /** All PyPI package names imported anywhere in the project source. */
    public Set<String> importedPackages() {
        return Set.copyOf(imports.keySet());
    }

    public boolean isImported(String pkg) {
        return imports.containsKey(pkg);
    }

    /** {@code file:line} of the first import of the package, or null. */
    public String importLocation(String pkg) {
        ImportSite site = imports.get(pkg);
        return site == null ? null : site.location();
    }

    public ImportSite importSite(String pkg) {
        return imports.get(pkg);
    }

    /**
     * True if the project calls a function matching the advisory's
     * {@code affected_functions} entry. Matching is by the function's last
     * segment ({@code "yaml.load"} / {@code "load"} both match a
     * {@code load(...)} call), or by the qualified
     * {@code <package>.<method>} form when the call went through a known
     * binding of that package.
     */
    public boolean isFunctionCalled(String affectedFunction) {
        return callLocation(affectedFunction) != null;
    }

    /** {@code file:line} of the first call matching the affected function, or null. */
    public String callLocation(String affectedFunction) {
        if (affectedFunction == null) return null;
        String fn = affectedFunction.trim();
        int paren = fn.indexOf('(');
        if (paren >= 0) fn = fn.substring(0, paren);
        if (fn.isBlank()) return null;
        // Qualified "<package>.<method>" — recorded when the call went
        // through a binding of that package.
        if (calledQualified.contains(fn)) return callLocations.get(fn);
        int lastDot = fn.lastIndexOf('.');
        String method = lastDot >= 0 ? fn.substring(lastDot + 1) : fn;
        if (method.isBlank()) return null;
        if (callLocations.containsKey(method)) return callLocations.get(method);
        for (String member : calledMembers) {
            if (member.endsWith("." + method)) return callLocations.get(member);
        }
        return null;
    }

    /**
     * PyPI distribution name for a top-level module, or null for relative
     * imports / empty names. {@code yaml} &rarr; {@code pyyaml},
     * {@code PIL} &rarr; {@code pillow}; anything unlisted defaults to the
     * module name itself (PEP 503-normalised).
     */
    static String packageOf(String module) {
        if (module == null || module.isBlank()) return null;
        String top = module.trim().split("\\.")[0];
        if (top.isEmpty()) return null;
        String mapped = MODULE_TO_PACKAGE.get(top);
        if (mapped != null) return mapped;
        return top.toLowerCase().replaceAll("[-_.]+", "-");
    }

    private void scanFile(String relFile, List<String> rawLines) {
        // Join parenthesised multi-line statements (from x import (...))
        // so one logical line carries the whole import.
        List<String> lines = new ArrayList<>();
        List<Integer> lineNos = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int startNo = 1;
        int depth = 0;
        for (int i = 0; i < rawLines.size(); i++) {
            String raw = rawLines.get(i);
            if (cur.length() == 0) startNo = i + 1;
            if (cur.length() > 0) cur.append(' ');
            cur.append(raw);
            // Brackets inside strings/comments must not affect the join:
            // a "# TODO (fix this" comment would otherwise swallow the
            // next line into this logical line.
            depth += netBrackets(blankStrings(stripComment(raw)));
            if (depth <= 0) {
                lines.add(cur.toString());
                lineNos.add(startNo);
                cur.setLength(0);
                depth = 0;
            }
        }
        if (cur.length() > 0) {
            lines.add(cur.toString());
            lineNos.add(startNo);
        }

        boolean inDocstring = false;
        char docQuote = 0;
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            int lineNo = lineNos.get(i);
            String line = raw;
            // Triple-quoted strings (docstrings) may span lines; drop them.
            if (inDocstring) {
                int end = line.indexOf(docQuote == '"' ? "\"\"\"" : "'''");
                if (end < 0) continue;
                line = line.substring(end + 3);
                inDocstring = false;
            }
            while (true) {
                int dq = line.indexOf("\"\"\"");
                int sq = line.indexOf("'''");
                int start = dq < 0 ? sq : (sq < 0 ? dq : Math.min(dq, sq));
                if (start < 0) break;
                char q = start == dq ? '"' : '\'';
                String close = q == '"' ? "\"\"\"" : "'''";
                int end = line.indexOf(close, start + 3);
                if (end < 0) {
                    line = line.substring(0, start);
                    inDocstring = true;
                    docQuote = q;
                    break;
                }
                line = line.substring(0, start) + " " + line.substring(end + 3);
            }
            line = stripComment(line);
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;
            scanImports(relFile, lineNo, trimmed);
            scanCalls(relFile, lineNo, blankStrings(line));
        }
    }

    private void scanImports(String file, int lineNo, String line) {
        Matcher m = FROM_IMPORT_STMT.matcher(line);
        if (m.matches()) {
            String module = m.group(1);
            // Relative imports (from . / from ..x) are the project's own code.
            if (module.startsWith(".")) return;
            String pkg = packageOf(module);
            if (pkg == null) return;
            // Bindings: the imported names (load, safe_load as sl, ...).
            Set<String> bindings = new LinkedHashSet<>();
            for (String item : m.group(2).replace("(", "").replace(")", "").split(",")) {
                Matcher im = IMPORT_ITEM.matcher(item.trim());
                if (im.matches() && !"*".equals(im.group(1))) {
                    bindings.add(im.group(2) != null ? im.group(2) : im.group(1));
                }
            }
            recordImport(file, lineNo, pkg, bindings);
            return;
        }
        m = IMPORT_STMT.matcher(line);
        if (m.matches()) {
            for (String item : m.group(1).split(",")) {
                Matcher im = IMPORT_ITEM.matcher(item.trim());
                if (!im.matches()) continue;
                String module = im.group(1);
                String pkg = packageOf(module);
                if (pkg == null) continue;
                // Binding is the alias, else the top-level module name.
                String binding = im.group(2) != null ? im.group(2) : module.split("\\.")[0];
                recordImport(file, lineNo, pkg, Set.of(binding));
            }
        }
    }

    private void recordImport(String file, int lineNo, String pkg, Set<String> bindings) {
        ImportSite existing = imports.get(pkg);
        if (existing == null) {
            imports.put(pkg, new ImportSite(file, lineNo, Set.copyOf(bindings)));
        } else if (!bindings.isEmpty()) {
            Set<String> merged = new LinkedHashSet<>(existing.bindings());
            merged.addAll(bindings);
            imports.put(pkg, new ImportSite(existing.file(), existing.line(), Set.copyOf(merged)));
        }
        for (String b : bindings) bindingToPackage.putIfAbsent(b, pkg);
    }

    private void scanCalls(String file, int lineNo, String line) {
        String loc = file + ":" + lineNo;
        Matcher m = MEMBER_CALL.matcher(line);
        while (m.find()) {
            String obj = m.group(1), method = m.group(2);
            calledMembers.add(obj + "." + method);
            callLocations.putIfAbsent(obj + "." + method, loc);
            callLocations.putIfAbsent(method, loc);
            String pkg = bindingToPackage.get(obj);
            if (pkg != null) {
                calledQualified.add(pkg + "." + method);
                callLocations.putIfAbsent(pkg + "." + method, loc);
            }
        }
        m = BARE_CALL.matcher(line);
        while (m.find()) {
            String name = m.group(1);
            // A definition is not a call: "def foo(".
            String before = line.substring(0, m.start(1)).trim();
            if (before.endsWith("def")) continue;
            if (name.equals("if") || name.equals("elif") || name.equals("for") || name.equals("while")
                    || name.equals("with") || name.equals("return") || name.equals("def")
                    || name.equals("class") || name.equals("assert") || name.equals("raise")
                    || name.equals("print") || name.equals("import")) continue;
            calledBare.add(name);
            callLocations.putIfAbsent(name, loc);
        }
    }

    /** Net bracket depth change of one line (strings blanked, comments stripped by the caller). */
    private static int netBrackets(String line) {
        int d = 0;
        for (char c : line.toCharArray()) {
            if (c == '(' || c == '[' || c == '{') d++;
            else if (c == ')' || c == ']' || c == '}') d--;
        }
        return d;
    }

    /** Strip a trailing {@code #} comment, respecting single/double quotes. */
    static String stripComment(String line) {
        char quote = 0;
        boolean escaped = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quote == 0) {
                if (c == '\'' || c == '"') quote = c;
                else if (c == '#') return line.substring(0, i);
            } else if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == quote) {
                quote = 0;
            }
        }
        return line;
    }

    /** Replace the contents of '...' and "..." literals with spaces (keeps positions). */
    static String blankStrings(String line) {
        StringBuilder sb = new StringBuilder(line.length());
        char quote = 0;
        boolean escaped = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quote == 0) {
                if (c == '\'' || c == '"') {
                    quote = c;
                    sb.append(' ');
                } else {
                    sb.append(c);
                }
            } else if (escaped) {
                escaped = false;
                sb.append(' ');
            } else if (c == '\\') {
                escaped = true;
                sb.append(' ');
            } else if (c == quote) {
                quote = 0;
                sb.append(' ');
            } else {
                sb.append(' ');
            }
        }
        return sb.toString();
    }

    private static String relativize(Path projectDir, Path file) {
        Path abs = projectDir.toAbsolutePath().normalize();
        Path f = file.toAbsolutePath().normalize();
        if (f.startsWith(abs)) {
            String rest = abs.relativize(f).toString();
            return rest.replace('\\', '/');
        }
        return f.toString().replace('\\', '/');
    }
}
