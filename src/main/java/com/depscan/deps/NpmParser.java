package com.depscan.deps;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Parses a {@code package.json} (+ optional {@code package-lock.json}) into
 * direct npm dependencies.
 *
 * <p>Version resolution, in order:
 * <ol>
 *   <li><b>Lockfile wins.</b> {@code package-lock.json} next to the
 *       package.json pins the exact installed version: lockfileVersion 2/3
 *       uses the {@code packages} map ({@code node_modules/<name>} keys,
 *       scoped packages as {@code node_modules/@scope/name}); v1 uses the
 *       top-level {@code dependencies} map. The lockfile version is exact,
 *       never approximate.</li>
 *   <li><b>No lockfile (or package missing from it): the range minimum.</b>
 *       {@code ^4.17.20} / {@code ~1.2.5} / {@code >=1.0.0} resolve to their
 *       minimum version ({@code 4.17.20}, {@code 1.2.5}, {@code 1.0.0}).
 *       That is an <i>approximation</i> — the installed version could be
 *       newer — so the package is recorded in
 *       {@link ParseResult#approximateVersions()} and the scan report notes
 *       it. A version is never invented beyond the range's own minimum.</li>
 *   <li><b>Unresolvable ranges are skipped, never guessed:</b> {@code latest},
 *       {@code *}, {@code x}, {@code ||} alternatives, {@code file:}/{@code git:}/
 *       {@code http(s):} / {@code workspace:} / {@code npm:} specifiers.</li>
 * </ol>
 * {@code devDependencies} are scanned too (a vulnerable dev tool is still
 * shipped in the repo and can be exploited in CI); their scope is recorded
 * on the dependency.
 */
public final class NpmParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern VERSION_LIKE = Pattern.compile("^\\d+(\\.\\d+){0,2}(-[0-9A-Za-z.\\-]+)?$");
    private static final Pattern RANGE_PREFIX = Pattern.compile("^[\\^~>=<\\s=v]*");

    /**
     * @param dependencies parsed direct dependencies, package.json order
     * @param skipped entries skipped (unresolvable range, etc.)
     * @param declarationLocations npm name &rarr; {@code package.json:<line>}
     * @param approximateVersions npm name &rarr; the range the version is
     *        only the minimum of (no lockfile pinned it)
     */
    public record ParseResult(List<Dependency> dependencies, List<String> skipped,
                              Map<String, String> declarationLocations,
                              Map<String, String> approximateVersions) {
        public ParseResult(List<Dependency> dependencies, List<String> skipped) {
            this(dependencies, skipped, Map.of(), Map.of());
        }
    }

    private NpmParser() {}

    public static ParseResult parse(Path packageJson) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(packageJson));
        Map<String, String> lockVersions = loadLockfile(packageJson.getParent().resolve("package-lock.json"));
        Map<String, String> locations = declarationLocations(packageJson);

        List<Dependency> deps = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        Map<String, String> approximate = new LinkedHashMap<>();
        for (String section : new String[]{"dependencies", "devDependencies"}) {
            JsonNode sectionNode = root.path(section);
            if (!sectionNode.isObject()) continue;
            Iterator<Map.Entry<String, JsonNode>> fields = sectionNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> e = fields.next();
                String name = e.getKey();
                String range = e.getValue().isTextual() ? e.getValue().asText().trim() : "";
                String version = lockVersions.get(name);
                if (version != null) {
                    deps.add(Dependency.npm(name, version, section));
                    continue;
                }
                String minimum = rangeMinimum(range);
                if (minimum == null) {
                    skipped.add(name + " - unresolvable version range '" + range
                            + "' (no package-lock.json to pin it; not guessed)");
                    continue;
                }
                deps.add(Dependency.npm(name, minimum, section));
                approximate.put(name, range);
            }
        }
        return new ParseResult(List.copyOf(deps), List.copyOf(skipped),
                Map.copyOf(locations), Map.copyOf(approximate));
    }

    /**
     * Exact installed versions from a lockfile, or an empty map when there is
     * no lockfile. v2/v3: {@code packages["node_modules/<name>"].version};
     * v1: {@code dependencies[<name>].version} (top level only — nested
     * entries are transitive deps, not direct ones).
     */
    static Map<String, String> loadLockfile(Path lockPath) {
        Map<String, String> out = new LinkedHashMap<>();
        if (!Files.isRegularFile(lockPath)) return out;
        JsonNode lock;
        try {
            lock = MAPPER.readTree(Files.readString(lockPath));
        } catch (IOException e) {
            return out; // unreadable lockfile: fall back to range minimums
        }
        int lockVersion = lock.path("lockfileVersion").asInt(1);
        if (lockVersion >= 2) {
            JsonNode packages = lock.path("packages");
            if (packages.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> it = packages.fields();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> e = it.next();
                    String key = e.getKey();
                    if (!key.startsWith("node_modules/")) continue;
                    String name = key.substring("node_modules/".length());
                    if (name.isBlank() || name.contains("/node_modules/")) continue;
                    String v = e.getValue().path("version").asText("");
                    if (!v.isBlank()) out.put(name, v);
                }
            }
        } else {
            JsonNode deps = lock.path("dependencies");
            if (deps.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> it = deps.fields();
                while (it.hasNext()) {
                    Map.Entry<String, JsonNode> e = it.next();
                    String v = e.getValue().path("version").asText("");
                    if (!v.isBlank()) out.put(e.getKey(), v);
                }
            }
        }
        return out;
    }

    /**
     * The minimum version a range allows, or null when the range has no
     * single honest minimum. {@code ^4.17.20} &rarr; {@code 4.17.20},
     * {@code ~1.2.5} &rarr; {@code 1.2.5}, {@code >=1.0.0 <2.0.0} &rarr;
     * {@code 1.0.0}, {@code 1.2.x} &rarr; {@code 1.2.0}. Returns null for
     * {@code latest}, {@code *}, {@code x}, {@code ||} alternatives and
     * non-registry specifiers ({@code file:}, {@code git:}, {@code http:},
     * {@code workspace:}, {@code npm:}).
     */
    static String rangeMinimum(String range) {
        if (range == null) return null;
        String r = range.trim();
        if (r.isEmpty() || r.contains("||")) return null;
        if (r.startsWith("file:") || r.startsWith("git:") || r.startsWith("http:")
                || r.startsWith("workspace:") || r.startsWith("npm:")
                || r.startsWith("link:") || r.startsWith("patch:")) return null;
        // First constraint token only. A "<" / "<=" bound on its own has no
        // lower bound (any version below it qualifies), so there is no
        // honest minimum to report — return null.
        String token = r.split("\\s+")[0];
        if (token.startsWith("<")) return null;
        if (token.equals("*") || token.equalsIgnoreCase("x")) return null;
        String stripped = RANGE_PREFIX.matcher(token).replaceFirst("");
        if (stripped.isEmpty()) return null;
        // Wildcard components are the range's own minimum with zeros:
        // "1.x" means >=1.0.0 <2.0.0, so its minimum is 1.0.0.
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
        // Keep a prerelease suffix only if it was on the first token.
        if (!VERSION_LIKE.matcher(candidate).matches()) return null;
        return candidate;
    }

    /**
     * Raw-text scan for {@code "name":} lines inside the dependencies
     * sections (same style as PomParser). Works for pretty-printed and
     * single-line package.json alike: a key is recorded only when it sits
     * directly inside a {@code dependencies} / {@code devDependencies}
     * object (brace depth), so top-level keys ({@code name}, {@code version},
     * ...) are never mistaken for dependencies.
     */
    static Map<String, String> declarationLocations(Path packageJson) {
        Map<String, String> out = new LinkedHashMap<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(packageJson);
        } catch (IOException e) {
            return out;
        }
        boolean inSection = false;
        int depth = 0;
        int sectionDepth = -1;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            int j = 0;
            while (j < line.length()) {
                char c = line.charAt(j);
                if (c == '{') {
                    depth++;
                    j++;
                } else if (c == '}') {
                    depth--;
                    if (inSection && depth < sectionDepth) inSection = false;
                    j++;
                } else if (c == '"') {
                    int end = line.indexOf('"', j + 1);
                    if (end < 0) break;
                    String key = line.substring(j + 1, end);
                    int k = end + 1;
                    while (k < line.length() && Character.isWhitespace(line.charAt(k))) k++;
                    boolean isKey = k < line.length() && line.charAt(k) == ':';
                    if (isKey && !inSection
                            && ("dependencies".equals(key) || "devDependencies".equals(key))) {
                        // Section header: its '{' follows the ':'.
                        int b = k + 1;
                        while (b < line.length() && Character.isWhitespace(line.charAt(b))) b++;
                        if (b < line.length() && line.charAt(b) == '{') {
                            inSection = true;
                            sectionDepth = depth + 1;
                        }
                    } else if (isKey && inSection && depth == sectionDepth
                            && !"dependencies".equals(key) && !"devDependencies".equals(key)) {
                        out.putIfAbsent(key, "package.json:" + (i + 1));
                    }
                    j = end + 1;
                } else {
                    j++;
                }
            }
        }
        return out;
    }
}
