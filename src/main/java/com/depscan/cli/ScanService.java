package com.depscan.cli;

import com.depscan.config.DepScanConfig;
import com.depscan.config.IgnoreRule;
import com.depscan.deps.Dependency;
import com.depscan.deps.NpmParser;
import com.depscan.deps.PomParser;
import com.depscan.deps.PyParser;
import com.depscan.graph.CallGraph;
import com.depscan.graph.CallGraphBuilder;
import com.depscan.graph.JsCallGraph;
import com.depscan.graph.PyCallGraph;
import com.depscan.osv.OsvClient;
import com.depscan.osv.Vulnerability;
import com.depscan.reach.Finding;
import com.depscan.reach.ReachabilityAnalyzer;
import com.depscan.report.IgnoredFinding;
import com.depscan.report.ScanReport;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Orchestrates one scan: detect the project type &rarr; parse manifests
 * &rarr; query OSV per dependency &rarr; build the call graph once &rarr;
 * reachability per vulnerability &rarr; apply depscan.yml ignores. Pure
 * wiring — no CLI parsing, no printing — so tests can drive it with a fake
 * {@link OsvClient}.
 *
 * <p>Project detection (Stage 7): {@code pom.xml} present &rarr; Maven;
 * {@code package.json} present &rarr; npm; {@code requirements.txt} or
 * {@code pyproject.toml} present &rarr; Python (PyPI). <b>Any combination
 * present &rarr; all are scanned and merged into one report</b> (each
 * finding is labelled by its ecosystem via the dependency coordinate,
 * {@code npm:name:version} / {@code pypi:name:version} vs
 * {@code group:artifact:version}). None present &rarr; an error naming
 * all three manifests.
 *
 * <p>Location enrichment: a reachable finding keeps its call-site
 * {@code file:line} from the call graph; an unreachable finding gets the
 * manifest declaration line of its dependency. Locations are made relative
 * to the project dir so the report prints short paths.
 */
public final class ScanService {

    private final OsvClient osv;
    private final DepScanConfig config;

    public ScanService(OsvClient osv) {
        this(osv, DepScanConfig.empty());
    }

    public ScanService(OsvClient osv, DepScanConfig config) {
        this.osv = osv;
        this.config = config == null ? DepScanConfig.empty() : config;
    }

    public ScanReport scan(Path projectDir) throws IOException {
        return scan(projectDir, ScanProgress.NONE);
    }

    /** Scan with progress callbacks for the TUI (Stage 4). Stages: parsing manifests, building call graph(s), querying OSV, analysing. */
    public ScanReport scan(Path projectDir, ScanProgress progress) throws IOException {
        boolean hasPom = Files.isRegularFile(projectDir.resolve("pom.xml"));
        boolean hasPkg = Files.isRegularFile(projectDir.resolve("package.json"));
        boolean hasPy = Files.isRegularFile(projectDir.resolve("requirements.txt"))
                || Files.isRegularFile(projectDir.resolve("pyproject.toml"));
        if (!hasPom && !hasPkg && !hasPy) {
            throw new IOException("No pom.xml, package.json or requirements.txt/pyproject.toml in " + projectDir
                    + " - DepScan scans Maven projects (pom.xml), npm projects (package.json) "
                    + "and Python projects (requirements.txt or pyproject.toml).");
        }

        List<Finding> findings = new ArrayList<>();
        List<Dependency> allDeps = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        if (hasPom) scanMaven(projectDir, progress, findings, allDeps, skipped);
        if (hasPkg) scanNpm(projectDir, progress, findings, allDeps, skipped, notes);
        if (hasPy) scanPython(projectDir, progress, findings, allDeps, skipped, notes);

        // Reachable first, then by id — the order a human triages in.
        findings.sort((a, b) -> {
            int c = Boolean.compare(b.reachable(), a.reachable());
            return c != 0 ? c : a.vulnerability().id().compareTo(b.vulnerability().id());
        });

        // Apply ignores: expired rules do NOT suppress (finding counts
        // normally, with a note); live rules move the finding to the
        // ignored list, which never breaches a threshold.
        // (notes list declared above — scanNpm already appended to it.)
        List<IgnoredFinding> ignored = new ArrayList<>();
        Set<IgnoreRule> usedRules = new HashSet<>();
        LocalDate today = LocalDate.now();
        List<Finding> kept = new ArrayList<>();
        for (Finding f : findings) {
            IgnoreRule match = null;
            for (IgnoreRule rule : config.ignores()) {
                if (rule.matches(f)) {
                    match = rule;
                    break;
                }
            }
            if (match == null) {
                kept.add(f);
                continue;
            }
            if (match.isExpired(today)) {
                notes.add("Ignore for '" + match.id() + "' expired on " + match.expires()
                        + " - finding counts normally again");
                kept.add(f);
                continue;
            }
            usedRules.add(match);
            ignored.add(new IgnoredFinding(f, match));
        }
        for (IgnoreRule rule : config.ignores()) {
            if (!usedRules.contains(rule) && rule.expires() != null && !rule.isExpired(today)) {
                notes.add("Ignore for '" + rule.id() + "' matched no findings - check the id / package");
            }
        }
        ignored.sort((a, b) -> a.finding().vulnerability().id().compareTo(b.finding().vulnerability().id()));

        boolean stale = osv instanceof com.depscan.osv.HttpOsvClient http && http.usedStaleCache();
        return new ScanReport(projectDir.toString(), allDeps.size(),
                List.copyOf(kept), List.copyOf(skipped), stale,
                List.copyOf(ignored), List.copyOf(notes), List.copyOf(allDeps));
    }

    /** Maven half: parse pom, build the Java call graph, query OSV, analyse. Appends to the shared lists. */
    private void scanMaven(Path projectDir, ScanProgress progress,
                           List<Finding> findings, List<Dependency> allDeps,
                           List<String> skipped) throws IOException {
        progress.stage("parsing pom.xml", 0, 1);
        PomParser.ParseResult parsed = PomParser.parse(projectDir.resolve("pom.xml"));
        progress.stage("parsing pom.xml", 1, 1);

        progress.stage("building call graph", 0, 1);
        Path src = projectDir.resolve("src");
        CallGraph graph = Files.isDirectory(src)
                ? CallGraphBuilder.build(src)
                : CallGraphBuilder.build(projectDir); // fallback: scan whole dir for .java
        progress.stage("building call graph", 1, 1);

        int totalDeps = Math.max(1, parsed.dependencies().size());
        int i = 0;
        for (Dependency dep : parsed.dependencies()) {
            progress.stage("querying OSV.dev", i, totalDeps);
            List<Vulnerability> vulns = osv.query(dep);
            for (Vulnerability v : vulns) {
                Finding f = ReachabilityAnalyzer.analyze(graph, dep, v);
                findings.add(enrichLocation(f, parsed.declarationLocations(), projectDir));
            }
            i++;
        }
        progress.stage("querying OSV.dev", totalDeps, totalDeps);
        progress.stage("analysing reachability", 1, 1);
        allDeps.addAll(parsed.dependencies());
        skipped.addAll(parsed.skipped());
    }

    /** npm half: parse package.json (+ lockfile), build the JS import map, query OSV, analyse. */
    private void scanNpm(Path projectDir, ScanProgress progress,
                         List<Finding> findings, List<Dependency> allDeps,
                         List<String> skipped, List<String> notes) throws IOException {
        progress.stage("parsing package.json", 0, 1);
        NpmParser.ParseResult parsed = NpmParser.parse(projectDir.resolve("package.json"));
        progress.stage("parsing package.json", 1, 1);

        progress.stage("building JS call graph", 0, 1);
        JsCallGraph js = JsCallGraph.build(projectDir);
        progress.stage("building JS call graph", 1, 1);

        int totalDeps = Math.max(1, parsed.dependencies().size());
        int i = 0;
        for (Dependency dep : parsed.dependencies()) {
            progress.stage("querying OSV.dev", i, totalDeps);
            List<Vulnerability> vulns = osv.query(dep);
            for (Vulnerability v : vulns) {
                Finding f = ReachabilityAnalyzer.analyzeJs(js, dep, v);
                findings.add(enrichLocation(f, parsed.declarationLocations(), projectDir));
            }
            i++;
        }
        progress.stage("querying OSV.dev", totalDeps, totalDeps);
        progress.stage("analysing reachability", 1, 1);
        allDeps.addAll(parsed.dependencies());
        skipped.addAll(parsed.skipped());
        // Approximate versions (range minimum, no lockfile) are called out
        // in the report notes so a reader never mistakes them for pinned ones.
        for (Map.Entry<String, String> e : parsed.approximateVersions().entrySet()) {
            notes.add("npm package '" + e.getKey() + "' version is the minimum of range '"
                    + e.getValue() + "' (no package-lock.json pinned it) - treated as approximate");
        }
    }

    /** Python half: parse requirements.txt / pyproject.toml, build the Python import map, query OSV, analyse. */
    private void scanPython(Path projectDir, ScanProgress progress,
                            List<Finding> findings, List<Dependency> allDeps,
                            List<String> skipped, List<String> notes) throws IOException {
        progress.stage("parsing requirements.txt / pyproject.toml", 0, 1);
        PyParser.ParseResult parsed = PyParser.parse(projectDir);
        progress.stage("parsing requirements.txt / pyproject.toml", 1, 1);

        progress.stage("building Python call graph", 0, 1);
        PyCallGraph py = PyCallGraph.build(projectDir);
        progress.stage("building Python call graph", 1, 1);

        int totalDeps = Math.max(1, parsed.dependencies().size());
        int i = 0;
        for (Dependency dep : parsed.dependencies()) {
            progress.stage("querying OSV.dev", i, totalDeps);
            List<Vulnerability> vulns = osv.query(dep);
            for (Vulnerability v : vulns) {
                Finding f = ReachabilityAnalyzer.analyzePy(py, dep, v);
                findings.add(enrichLocation(f, parsed.declarationLocations(), projectDir));
            }
            i++;
        }
        progress.stage("querying OSV.dev", totalDeps, totalDeps);
        progress.stage("analysing reachability", 1, 1);
        allDeps.addAll(parsed.dependencies());
        skipped.addAll(parsed.skipped());
        // Approximate versions (range minimum, not pinned) are called out
        // in the report notes so a reader never mistakes them for pinned ones.
        for (Map.Entry<String, String> e : parsed.approximateVersions().entrySet()) {
            notes.add("Python package '" + e.getKey() + "' version is the minimum of spec '"
                    + e.getValue() + "' (not pinned in requirements.txt/pyproject.toml) - treated as approximate");
        }
    }

    private static Finding enrichLocation(Finding f, Map<String, String> declarationLocations, Path projectDir) {
        String loc = f.location();
        if (loc != null && !loc.isBlank()) {
            return f.withLocation(relativize(loc, projectDir));
        }
        String declLoc = declarationLocations.get(f.dependency().osvPackageName());
        if (declLoc != null) return f.withLocation(declLoc);
        return f;
    }

    /** Strip the project-dir prefix from an absolute file:line, if present. */
    static String relativize(String location, Path projectDir) {
        String prefix = projectDir.toAbsolutePath().normalize().toString();
        if (location.startsWith(prefix)) {
            String rest = location.substring(prefix.length());
            while (rest.startsWith("/") || rest.startsWith("\\")) rest = rest.substring(1);
            return rest;
        }
        return location;
    }
}
