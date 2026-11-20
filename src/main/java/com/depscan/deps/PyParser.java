package com.depscan.deps;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a Python project's dependencies into direct PyPI dependencies —
 * the Python counterpart of {@link NpmParser}.
 *
 * <p>Sources, in order (both may be present; they merge, requirements.txt
 * wins on a name clash because it is the pinned lock):
 * <ol>
 *   <li><b>{@code requirements.txt}</b> — one requirement per line (PEP 508):
 *       {@code name==1.2.3} pins the exact version; {@code name>=1.0},
 *       {@code name~=1.4.2}, {@code name>1.0,<2.0} resolve to their minimum
 *       version, recorded as <i>approximate</i> (the installed version could
 *       be newer). Extras ({@code name[extra]==1.0}) and environment markers
 *       ({@code name==1.0; python_version < "3.12"}) are stripped; the marker
 *       is not evaluated — the dependency is still scanned.</li>
 *   <li><b>{@code pyproject.toml}</b> — {@code [project] dependencies} (PEP 621)
 *       and {@code [tool.poetry.dependencies]}. Parsed with a small
 *       line-oriented TOML reader (no TOML library — dependency-free by
 *       design, same as the JS side): string arrays and simple
 *       {@code name = "spec"} / {@code name = {version = "spec", ...}}
 *       tables. The {@code python} entry in Poetry dependencies is skipped
 *       (it is the interpreter, not a package).</li>
 * </ol>
 * <p><b>Skipped, never guessed:</b> bare names with no version
 * ({@code requests}), {@code -e} editable installs, {@code -r} includes,
 * direct URLs ({@code name @ https://...} / {@code git+https://...}),
 * {@code <} / {@code !=} only bounds (no honest minimum), and {@code *}.
 * Names are normalised per PEP 503 (lowercase, runs of {@code -_.} &rarr;
 * {@code -}) so {@code PyYAML} and {@code pyyaml} query OSV as one package.
 */
public final class PyParser {

    private static final Pattern VERSION_LIKE = Pattern.compile("^\\d+(\\.\\d+){0,2}(-[0-9A-Za-z.\\-]+)?(\\+[0-9A-Za-z.\\-]+)?$");
    private static final Pattern SPEC_PREFIX = Pattern.compile("^[\\s=~><!^]*");
    private static final Pattern QUOTED = Pattern.compile("\"([^\"]*)\"|'([^']*)'");
    private static final Pattern POETRY_INLINE_VERSION = Pattern.compile("version\\s*=\\s*\"([^\"]*)\"");

    /**
     * @param dependencies parsed direct dependencies, manifest order
     *        (requirements.txt first, then pyproject.toml)
     * @param skipped entries skipped (no version, editable, URL, etc.)
     * @param declarationLocations PyPI name &rarr; {@code requirements.txt:<line>}
     *        or {@code pyproject.toml:<line>}
     * @param approximateVersions PyPI name &rarr; the spec the version is
     *        only the minimum of (not pinned)
     */
    public record ParseResult(List<Dependency> dependencies, List<String> skipped,
                              Map<String, String> declarationLocations,
                              Map<String, String> approximateVersions) {
        public ParseResult(List<Dependency> dependencies, List<String> skipped) {
            this(dependencies, skipped, Map.of(), Map.of());
        }
    }

    private PyParser() {}

    /** Parse requirements.txt and/or pyproject.toml under {@code projectDir}. */
    public static ParseResult parse(Path projectDir) throws IOException {
        List<Dependency> deps = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        Map<String, String> locations = new LinkedHashMap<>();
        Map<String, String> approximate = new LinkedHashMap<>();
        Map<String, Boolean> seen = new LinkedHashMap<>();

        Path req = projectDir.resolve("requirements.txt");
        if (Files.isRegularFile(req)) {
            parseRequirements(req, deps, skipped, locations, approximate, seen);
        }
        Path pyproject = projectDir.resolve("pyproject.toml");
        if (Files.isRegularFile(pyproject)) {
            parsePyproject(pyproject, deps, skipped, locations, approximate, seen);
        }
        return new ParseResult(List.copyOf(deps), List.copyOf(skipped),
                Map.copyOf(locations), Map.copyOf(approximate));
    }

    // ---------------------------------------------------------------- requirements.txt

    static void parseRequirements(Path reqFile, List<Dependency> deps, List<String> skipped,
                                  Map<String, String> locations, Map<String, String> approximate,
                                  Map<String, Boolean> seen) throws IOException {
        List<String> lines = Files.readAllLines(reqFile);
        for (int i = 0; i < lines.size(); i++) {
            String line = stripComment(lines.get(i)).trim();
            if (line.isEmpty()) continue;
            // pip options: -r / -c includes, --index-url, --extra-index-url, etc.
            if (line.startsWith("-")) {
                if (line.startsWith("-e ") || line.equals("-e") || line.startsWith("--editable")) {
                    skipped.add("editable install '" + line + "' (no pinned version to query; not guessed)");
                }
                continue;
            }
            // Direct URL reference: "name @ https://..." or a bare URL.
            if (line.contains(" @ ") || line.startsWith("git+") || line.startsWith("http://")
                    || line.startsWith("https://")) {
                String name = line.split("\\s+")[0];
                skipped.add(name + " - direct URL reference (no registry version to query; not guessed)");
                continue;
            }
            addRequirement(line, "requirements", "requirements.txt:" + (i + 1),
                    deps, skipped, locations, approximate, seen);
        }
    }

    // ---------------------------------------------------------------- pyproject.toml

    static void parsePyproject(Path tomlFile, List<Dependency> deps, List<String> skipped,
                               Map<String, String> locations, Map<String, String> approximate,
                               Map<String, Boolean> seen) throws IOException {
        List<String> lines = Files.readAllLines(tomlFile);
        String section = "";
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            String line = raw.trim();
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length() - 1).trim();
                continue;
            }
            if ("project".equals(section) && line.startsWith("dependencies")) {
                // dependencies = [ "a>=1", "b==2" ] — possibly multi-line.
                int lineNo = i + 1;
                StringBuilder array = new StringBuilder(line);
                while (!array.toString().contains("]") && i + 1 < lines.size()) {
                    array.append("\n").append(lines.get(++i));
                }
                Matcher q = QUOTED.matcher(array.toString());
                while (q.find()) {
                    String req = q.group(1) != null ? q.group(1) : q.group(2);
                    addRequirement(req, "pyproject", "pyproject.toml:" + lineNo,
                            deps, skipped, locations, approximate, seen);
                }
            } else if ("tool.poetry.dependencies".equals(section) && line.contains("=")) {
                String name = line.substring(0, line.indexOf('=')).trim();
                if (name.equals("python")) continue; // the interpreter, not a package
                if (!name.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) continue;
                String spec = "";
                String rhs = line.substring(line.indexOf('=') + 1).trim();
                if (rhs.startsWith("\"") || rhs.startsWith("'")) {
                    Matcher q = QUOTED.matcher(rhs);
                    if (q.find()) spec = q.group(1) != null ? q.group(1) : q.group(2);
                } else if (rhs.startsWith("{")) {
                    Matcher v = POETRY_INLINE_VERSION.matcher(rhs);
                    if (v.find()) spec = v.group(1);
                    else continue; // {git = ...} / {path = ...}: no registry version
                } else {
                    continue;
                }
                addRequirement(normalizeName(name) + spec, "pyproject", "pyproject.toml:" + (i + 1),
                        deps, skipped, locations, approximate, seen);
            }
        }
    }

    // ---------------------------------------------------------------- shared

    /**
     * Add one PEP 508 requirement string ({@code name[extras]spec; markers}).
     * A pinned {@code ==} version is exact; any other resolvable spec gives
     * its minimum and is recorded approximate; an unresolvable spec is
     * skipped, never guessed.
     */
    static void addRequirement(String req, String scope, String location,
                               List<Dependency> deps, List<String> skipped,
                               Map<String, String> locations, Map<String, String> approximate,
                               Map<String, Boolean> seen) {
        String s = req.trim();
        // Environment markers: everything after ';' is a marker, not a version.
        int marker = s.indexOf(';');
        if (marker >= 0) s = s.substring(0, marker).trim();
        if (s.isEmpty()) return;
        // Extras: name[extra1,extra2]spec
        int bracket = s.indexOf('[');
        int specStart = -1;
        if (bracket >= 0) {
            int close = s.indexOf(']', bracket);
            if (close >= 0) specStart = close + 1;
            s = s.substring(0, bracket) + (specStart >= 0 ? s.substring(specStart) : "");
        }
        // Split name from version spec at the first operator char
        // ('^' is Poetry's caret range, '~' is ~= / compatible).
        int op = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=' || c == '>' || c == '<' || c == '~' || c == '!' || c == '^') {
                op = i;
                break;
            }
        }
        String name = (op < 0 ? s : s.substring(0, op)).trim();
        String spec = op < 0 ? "" : s.substring(op).trim();
        if (name.isEmpty() || !name.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) {
            skipped.add(req + " - could not parse requirement name (not guessed)");
            return;
        }
        String norm = normalizeName(name);
        if (seen.containsKey(norm)) return; // requirements.txt wins on a clash
        if (spec.isEmpty()) {
            skipped.add(norm + " - no version pinned (bare name; installed version unknown, not guessed)");
            return;
        }
        if (spec.contains("||")) {
            skipped.add(norm + " - unresolvable version spec '" + spec + "' (not guessed)");
            return;
        }
        // Pinned: ==x.y.z (exact) or ==x.y.* (wildcard — minimum, approximate).
        if (spec.startsWith("==")) {
            String v = spec.substring(2).trim();
            if (v.endsWith(".*")) {
                String min = wildcardMinimum(v);
                if (min == null) {
                    skipped.add(norm + " - unresolvable version spec '" + spec + "' (not guessed)");
                    return;
                }
                addDep(norm, min, scope, location, spec, deps, locations, approximate, seen, true);
                return;
            }
            if (!VERSION_LIKE.matcher(v).matches()) {
                skipped.add(norm + " - unresolvable version spec '" + spec + "' (not guessed)");
                return;
            }
            addDep(norm, v, scope, location, null, deps, locations, approximate, seen, false);
            return;
        }
        String minimum = rangeMinimum(spec);
        if (minimum == null) {
            skipped.add(norm + " - unresolvable version spec '" + spec + "' (no honest minimum; not guessed)");
            return;
        }
        addDep(norm, minimum, scope, location, spec, deps, locations, approximate, seen, true);
    }

    private static void addDep(String name, String version, String scope, String location, String spec,
                               List<Dependency> deps, Map<String, String> locations,
                               Map<String, String> approximate, Map<String, Boolean> seen,
                               boolean isApproximate) {
        deps.add(Dependency.python(name, version, scope));
        locations.putIfAbsent(name, location);
        if (isApproximate) approximate.put(name, spec);
        seen.put(name, true);
    }

    /**
     * The minimum version a PEP 440 specifier set allows, or null when there
     * is no single honest minimum. {@code >=1.0.0} &rarr; {@code 1.0.0},
     * {@code ~=1.4.2} &rarr; {@code 1.4.2}, {@code >1.0,<2.0} &rarr;
     * {@code 1.0} (a strict {@code >} has no exact minimum — the spec's own
     * bound is the closest honest value and is flagged approximate),
     * {@code 1.2.*} &rarr; {@code 1.2.0}. Returns null for {@code <2.0.0} /
     * {@code !=1.0} alone (no lower bound), {@code *} and non-registry specs.
     */
    static String rangeMinimum(String spec) {
        if (spec == null) return null;
        String s = spec.trim();
        if (s.isEmpty() || s.equals("*")) return null;
        // First constraint only — the earliest lower bound is the minimum.
        String first = s.split(",")[0].trim();
        if (first.startsWith("<") || first.startsWith("!")) return null;
        String stripped = SPEC_PREFIX.matcher(first).replaceFirst("");
        if (stripped.isEmpty() || stripped.equals("*")) return null;
        if (stripped.endsWith(".*")) return wildcardMinimum(stripped);
        String[] parts = stripped.split("\\.", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length && i < 3; i++) {
            if (i > 0) sb.append('.');
            String p = parts[i];
            if (p.equalsIgnoreCase("x") || p.equals("*")) p = "0";
            sb.append(p);
        }
        while (sb.toString().split("\\.").length < 3) sb.append(".0");
        String candidate = sb.toString();
        if (!VERSION_LIKE.matcher(candidate).matches()) return null;
        return candidate;
    }

    /** {@code 1.2.*} &rarr; {@code 1.2.0}; null when the wildcard has no numeric prefix. */
    static String wildcardMinimum(String spec) {
        String base = spec.endsWith(".*") ? spec.substring(0, spec.length() - 2) : spec;
        String[] parts = base.split("\\.", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length && i < 3; i++) {
            if (i > 0) sb.append('.');
            if (!parts[i].matches("\\d+")) return null;
            sb.append(parts[i]);
        }
        while (sb.toString().split("\\.").length < 3) sb.append(".0");
        return sb.toString();
    }

    /** PEP 503 normalisation: lowercase, runs of {@code -_.} become {@code -}. */
    static String normalizeName(String name) {
        return name.toLowerCase().replaceAll("[-_.]+", "-");
    }

    /** Strip a trailing {@code #} comment (a {@code #} inside a URL fragment is kept: it has no preceding space). */
    static String stripComment(String line) {
        for (int i = 0; i < line.length(); i++) {
            if (line.charAt(i) == '#' && (i == 0 || Character.isWhitespace(line.charAt(i - 1)))) {
                return line.substring(0, i);
            }
        }
        return line;
    }
}
