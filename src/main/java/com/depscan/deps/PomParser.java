package com.depscan.deps;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

/**
 * Parses a pom.xml into direct dependencies, resolving {@code ${...}}
 * properties and versions inherited from {@code <dependencyManagement>}.
 *
 * <p>Scope of resolution (Stage 1, deliberately honest about limits):
 * <ul>
 *   <li>Properties from the pom itself ({@code <properties>}) and the
 *       built-ins {@code project.version} / {@code project.groupId} /
 *       {@code project.artifactId}.</li>
 *   <li>Versions from this pom's {@code <dependencyManagement>}.</li>
 *   <li>A {@code <parent>} pom found next to this pom (same directory or
 *       {@code ../pom.xml}); its properties / dependencyManagement are read
 *       the same way. Remote parents (not on disk) are NOT fetched.</li>
 *   <li>Imported BOMs ({@code <scope>import</scope>}) are NOT resolved —
 *       a dependency whose version comes only from a BOM is skipped with a
 *       warning instead of guessed.</li>
 * </ul>
 * Placeholders are expanded iteratively (up to 10 passes) so nested
 * properties like {@code ${commons.version}} &rarr; {@code ${base.version}}
 * resolve. A dependency with no resolvable version is skipped, never
 * invented — {@link #parse(Path)} returns the skipped entries separately
 * via {@link ParseResult#skipped()}.
 */
public final class PomParser {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)\\}");

    /**
     * @param dependencies parsed direct dependencies
     * @param skipped entries skipped (no resolvable version, etc.)
     * @param declarationLocations {@code group:artifact} &rarr; {@code pom.xml:<line>}
     *        where the dependency is declared, for the report's file:line.
     *        A later declaration wins, so a main {@code <dependencies>} entry
     *        overwrites a {@code <dependencyManagement>} entry for the same artifact.
     */
    public record ParseResult(List<Dependency> dependencies, List<String> skipped,
                              Map<String, String> declarationLocations) {
        public ParseResult(List<Dependency> dependencies, List<String> skipped) {
            this(dependencies, skipped, Map.of());
        }
    }

    private PomParser() {}

    public static ParseResult parse(Path pomPath) throws IOException {
        Model model = readModel(pomPath);
        Map<String, String> locations = declarationLocations(pomPath);
        Map<String, String> props = new LinkedHashMap<>();
        Map<String, String> managedVersions = new LinkedHashMap<>();

        // Parent first (lowest precedence), then this pom overrides it.
        Model parent = findParentModel(pomPath, model);
        if (parent != null) {
            collect(parent, props, managedVersions);
        }
        collect(model, props, managedVersions);
        // Built-ins, lowest precedence so explicit properties win.
        props.putIfAbsent("project.version", nullToEmpty(model.getVersion()));
        props.putIfAbsent("project.groupId",
                nullToEmpty(model.getGroupId() != null ? model.getGroupId()
                        : (model.getParent() != null ? model.getParent().getGroupId() : null)));
        props.putIfAbsent("project.artifactId", nullToEmpty(model.getArtifactId()));

        List<Dependency> deps = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (org.apache.maven.model.Dependency d : model.getDependencies()) {
            String groupId = resolve(d.getGroupId(), props);
            String artifactId = resolve(d.getArtifactId(), props);
            String version = resolve(d.getVersion(), props);
            if (version == null || version.isBlank()) {
                version = managedVersions.get(groupId + ":" + artifactId);
                if (version != null) version = resolve(version, props);
            }
            String scope = d.getScope() == null ? "compile" : d.getScope();
            if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank()) {
                skipped.add("dependency with missing groupId/artifactId");
                continue;
            }
            if (version == null || version.isBlank() || PLACEHOLDER.matcher(version).find()) {
                skipped.add(groupId + ":" + artifactId
                        + " - no resolvable version (likely from an imported BOM; not fetched in Stage 1)");
                continue;
            }
            deps.add(new Dependency(groupId.trim(), artifactId.trim(), version.trim(), scope));
        }
        return new ParseResult(List.copyOf(deps), List.copyOf(skipped), Map.copyOf(locations));
    }

    /** Scan the raw pom text for {@code <dependency>} blocks and record the line of each {@code <artifactId>}. */
    static Map<String, String> declarationLocations(Path pomPath) {
        Map<String, String> out = new LinkedHashMap<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(pomPath);
        } catch (IOException e) {
            return out;
        }
        boolean inDep = false;
        String groupId = null, artifactId = null;
        int artifactLine = -1;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.contains("<dependency>")) {
                inDep = true;
                groupId = null;
                artifactId = null;
                artifactLine = -1;
                continue;
            }
            if (!inDep) continue;
            if (line.contains("</dependency>")) {
                if (groupId != null && artifactId != null) {
                    out.put(groupId + ":" + artifactId, "pom.xml:" + (artifactLine > 0 ? artifactLine : i + 1));
                }
                inDep = false;
                continue;
            }
            String g = tagText(line, "groupId");
            if (g != null) groupId = g;
            String a = tagText(line, "artifactId");
            if (a != null) {
                artifactId = a;
                artifactLine = i + 1;
            }
        }
        return out;
    }

    private static String tagText(String line, String tag) {
        String open = "<" + tag + ">";
        String close = "</" + tag + ">";
        int s = line.indexOf(open);
        int e = line.indexOf(close);
        if (s < 0 || e < 0 || e <= s) return null;
        String v = line.substring(s + open.length(), e).trim();
        return v.isEmpty() ? null : v;
    }

    private static void collect(Model model, Map<String, String> props, Map<String, String> managed) {
        model.getProperties().forEach((k, v) -> props.put(String.valueOf(k), String.valueOf(v)));
        DependencyManagement dm = model.getDependencyManagement();
        if (dm != null) {
            for (org.apache.maven.model.Dependency d : dm.getDependencies()) {
                if (d.getVersion() != null) {
                    managed.put(d.getGroupId() + ":" + d.getArtifactId(), d.getVersion());
                }
            }
        }
    }

    private static Model findParentModel(Path pomPath, Model model) {
        if (model.getParent() == null) return null;
        String rel = model.getParent().getRelativePath();
        Path candidate = rel == null || rel.isBlank()
                ? pomPath.getParent().resolve("../pom.xml").normalize()
                : pomPath.getParent().resolve(rel).normalize();
        // relativePath may point at a directory; Maven defaults to ../pom.xml.
        if (Files.isDirectory(candidate)) candidate = candidate.resolve("pom.xml");
        if (!Files.isRegularFile(candidate)) return null;
        try {
            return readModel(candidate);
        } catch (IOException e) {
            return null; // parent unreadable: continue with this pom alone
        }
    }

    private static Model readModel(Path path) throws IOException {
        try (Reader r = Files.newBufferedReader(path)) {
            return new MavenXpp3Reader().read(r);
        } catch (XmlPullParserException e) {
            throw new IOException("Cannot parse pom.xml at " + path + ": " + e.getMessage(), e);
        }
    }

    /** Expand ${...} placeholders using props; returns null if input is null. */
    static String resolve(String raw, Map<String, String> props) {
        if (raw == null) return null;
        String out = raw;
        for (int i = 0; i < 10; i++) {
            Matcher m = PLACEHOLDER.matcher(out);
            StringBuffer sb = new StringBuffer();
            boolean changed = false;
            while (m.find()) {
                String replacement = props.get(m.group(1));
                if (replacement == null) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
                } else {
                    changed = true;
                    m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
                }
            }
            m.appendTail(sb);
            out = sb.toString();
            if (!changed) break;
        }
        return out;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
