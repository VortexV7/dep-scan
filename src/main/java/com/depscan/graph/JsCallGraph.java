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
 * A heuristic import/call map of a project's own JavaScript/TypeScript
 * source — the npm counterpart of {@link CallGraph}. No external JS parser
 * is used (dependency-free by design); the source is scanned with regular
 * expressions, so this is an <i>approximation</i>, documented honestly:
 *
 * <ul>
 *   <li><b>What it records:</b> every {@code import ... from '<pkg>'},
 *       {@code require('<pkg>')} (incl. destructured), side-effect imports
 *       and dynamic {@code import('<pkg>')}, with the first
 *       {@code file:line} of each; every bare call ({@code trim(...)}) and
 *       member call ({@code _.trim(...)}) with its first location; and which
 *       local binding belongs to which package ({@code import _ from 'lodash'}
 *       makes {@code _} a lodash binding, so {@code _.merge(...)} is recorded
 *       as a lodash {@code merge} call).</li>
 *   <li><b>Subpaths resolve to the package:</b> {@code 'lodash/trim'} and
 *       {@code '@babel/core/lib/x'} count as imports of {@code lodash} and
 *       {@code @babel/core}. Relative imports ({@code ./util}) are the
 *       project's own code and are ignored.</li>
 *   <li><b>Entry points:</b> every source file's top level and every
 *       exported function — i.e. an import anywhere in the project's own
 *       source counts as use. There is no inter-file call graph: a package
 *       imported in a dead file still counts as reachable, because the file
 *       ships with the project.</li>
 *   <li><b>Known blind spots (same honesty as the Java side):</b> dynamic
 *       specifiers ({@code require(name)} where {@code name} is a variable),
 *       re-exports ({@code export ... from}), computed member access
 *       ({@code _['trim'](...)}), string-blanked call detection missing
 *       calls hidden in template literals, and {@code function foo(...)}
 *       declarations (deliberately not counted as calls). When in doubt it
 *       errs toward flagging real use — an import alone is enough for
 *       CRITICAL.</li>
 * </ul>
 * Files scanned: {@code .js .jsx .ts .tsx .mjs .cjs}, excluding
 * {@code node_modules} and {@code .git} at any depth.
 */
public final class JsCallGraph {

    /** First import site of a package: file (relative, '/'-separated), line, local bindings. */
    public record ImportSite(String file, int line, Set<String> bindings) {
        public String location() {
            return file + ":" + line;
        }
    }

    private static final Set<String> EXTENSIONS = Set.of(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs");

    private static final Pattern IMPORT_FROM = Pattern.compile(
            "import\\s+([^'\";]*?)\\s+from\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern IMPORT_SIDE = Pattern.compile(
            "import\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern REQUIRE_ASSIGN = Pattern.compile(
            "(?:const|let|var)\\s+(\\{[^}]*\\}|[A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)");
    private static final Pattern REQUIRE_BARE = Pattern.compile(
            "require\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)");
    private static final Pattern DYNAMIC_IMPORT = Pattern.compile(
            "import\\s*\\(\\s*['\"]([^'\"]+)['\"]\\s*\\)");
    private static final Pattern NAMED_BINDING = Pattern.compile(
            "([A-Za-z_$][\\w$]*)(?:\\s+as\\s+([A-Za-z_$][\\w$]*))?");
    private static final Pattern MEMBER_CALL = Pattern.compile(
            "([A-Za-z_$][\\w$]*)\\.([A-Za-z_$][\\w$]*)\\s*\\(");
    private static final Pattern BARE_CALL = Pattern.compile(
            "(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*\\(");
    private static final Pattern NEW_CALL = Pattern.compile(
            "\\bnew\\s+([A-Za-z_$][\\w$]*)\\s*\\(");

    private final Map<String, ImportSite> imports = new LinkedHashMap<>();
    private final Map<String, String> bindingToPackage = new LinkedHashMap<>();
    private final Set<String> calledBare = new LinkedHashSet<>();
    private final Set<String> calledMethods = new LinkedHashSet<>();
    private final Set<String> calledMembers = new LinkedHashSet<>();
    private final Set<String> calledQualified = new LinkedHashSet<>();
    private final Map<String, String> callLocations = new LinkedHashMap<>();

    private JsCallGraph() {}

    /** Scan all JS/TS sources under {@code projectDir} (excluding node_modules/.git). */
    public static JsCallGraph build(Path projectDir) throws IOException {
        JsCallGraph graph = new JsCallGraph();
        List<Path> files = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(projectDir)) {
            walk.filter(Files::isRegularFile)
                    .filter(p -> {
                        for (Path part : p) {
                            String s = part.toString();
                            if (s.equals("node_modules") || s.equals(".git")) return false;
                        }
                        return true;
                    })
                    .filter(p -> {
                        String name = p.getFileName().toString();
                        int dot = name.lastIndexOf('.');
                        return dot >= 0 && EXTENSIONS.contains(name.substring(dot));
                    })
                    .sorted()
                    .forEach(files::add);
        }
        for (Path file : files) {
            String rel = relativize(projectDir, file);
            List<String> lines = Files.readAllLines(file);
            graph.scanFile(rel, lines);
        }
        return graph;
    }

    /** All npm package names imported/required anywhere in the project source. */
    public Set<String> importedPackages() {
        return Set.copyOf(imports.keySet());
    }

    public boolean isImported(String pkg) {
        return imports.containsKey(pkg);
    }

    /** {@code file:line} of the first import/require of the package, or null. */
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
     * segment ({@code "lodash.merge"} / {@code "_.merge"} / {@code "merge"}
     * all match a {@code merge(...)} call), or by the qualified
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

    /** Package name for a module specifier, or null for relative / empty specifiers. */
    static String packageOf(String specifier) {
        if (specifier == null || specifier.isBlank()) return null;
        String spec = specifier.trim();
        if (spec.startsWith(".") || spec.startsWith("/") || spec.startsWith("!")) return null;
        if (spec.startsWith("@")) {
            String[] parts = spec.split("/");
            return parts.length >= 2 ? parts[0] + "/" + parts[1] : spec;
        }
        int slash = spec.indexOf('/');
        return slash < 0 ? spec : spec.substring(0, slash);
    }

    private void scanFile(String relFile, List<String> lines) {
        boolean inBlockComment = false;
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            String line = raw;
            // Block comments may span lines; drop them before any matching.
            if (inBlockComment) {
                int end = line.indexOf("*/");
                if (end < 0) continue;
                line = line.substring(end + 2);
                inBlockComment = false;
            }
            while (true) {
                int start = line.indexOf("/*");
                if (start < 0) break;
                int end = line.indexOf("*/", start + 2);
                if (end < 0) {
                    line = line.substring(0, start);
                    inBlockComment = true;
                    break;
                }
                line = line.substring(0, start) + " " + line.substring(end + 2);
            }
            String trimmed = line.trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
            int lineNo = i + 1;
            scanImports(relFile, lineNo, line);
            scanCalls(relFile, lineNo, blankStrings(line));
        }
    }

    private void scanImports(String file, int lineNo, String line) {
        Matcher m = IMPORT_FROM.matcher(line);
        if (m.find()) {
            String clause = m.group(1);
            String pkg = packageOf(m.group(2));
            if (pkg != null) recordImport(file, lineNo, pkg, bindingsFromClause(clause));
            return;
        }
        m = IMPORT_SIDE.matcher(line);
        if (m.find()) {
            String pkg = packageOf(m.group(1));
            if (pkg != null) recordImport(file, lineNo, pkg, Set.of());
            return;
        }
        m = REQUIRE_ASSIGN.matcher(line);
        if (m.find()) {
            String pkg = packageOf(m.group(2));
            if (pkg != null) recordImport(file, lineNo, pkg, bindingsFromClause(m.group(1)));
            return;
        }
        m = DYNAMIC_IMPORT.matcher(line);
        if (m.find()) {
            String pkg = packageOf(m.group(1));
            if (pkg != null) recordImport(file, lineNo, pkg, Set.of());
            return;
        }
        m = REQUIRE_BARE.matcher(line);
        if (m.find()) {
            String pkg = packageOf(m.group(1));
            if (pkg != null) recordImport(file, lineNo, pkg, Set.of());
        }
    }

    /** Local names bound by an import/require clause: default, named ({@code {a, b as c}}), namespace. */
    static Set<String> bindingsFromClause(String clause) {
        Set<String> out = new LinkedHashSet<>();
        if (clause == null) return out;
        String c = clause.trim();
        if (c.isEmpty()) return out;
        if (c.startsWith("{")) {
            int end = c.indexOf('}');
            String inner = end >= 0 ? c.substring(1, end) : c.substring(1);
            for (String part : inner.split(",")) {
                Matcher m = NAMED_BINDING.matcher(part.trim());
                if (m.matches()) out.add(m.group(2) != null ? m.group(2) : m.group(1));
            }
            return out;
        }
        if (c.startsWith("*")) {
            Matcher m = Pattern.compile("\\*\\s+as\\s+([A-Za-z_$][\\w$]*)").matcher(c);
            if (m.find()) out.add(m.group(1));
            return out;
        }
        // Default import (possibly followed by ", { named }").
        String first = c.split(",")[0].trim();
        if (!first.isEmpty() && first.matches("[A-Za-z_$][\\w$]*")) out.add(first);
        int brace = c.indexOf('{');
        if (brace >= 0) out.addAll(bindingsFromClause(c.substring(brace)));
        return out;
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
            calledMethods.add(method);
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
            // A declaration is not a call: "function foo(" / "export function foo(".
            String before = line.substring(0, m.start(1)).trim();
            if (before.endsWith("function")) continue;
            if (name.equals("if") || name.equals("for") || name.equals("while") || name.equals("switch")
                    || name.equals("catch") || name.equals("return") || name.equals("function")) continue;
            calledBare.add(name);
            callLocations.putIfAbsent(name, loc);
        }
        m = NEW_CALL.matcher(line);
        while (m.find()) {
            calledBare.add(m.group(1));
            callLocations.putIfAbsent(m.group(1), loc);
        }
    }

    /** Replace the contents of '...', "..." and `...` literals with spaces (keeps positions). */
    static String blankStrings(String line) {
        StringBuilder sb = new StringBuilder(line.length());
        char quote = 0;
        boolean escaped = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quote == 0) {
                if (c == '\'' || c == '"' || c == '`') {
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
