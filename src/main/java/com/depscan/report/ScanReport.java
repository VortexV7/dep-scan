package com.depscan.report;

import com.depscan.deps.Dependency;
import com.depscan.reach.Finding;
import java.util.List;

/**
 * Result of one scan: findings + counts + what was skipped + what was ignored.
 * Ignored findings are NOT in {@code findings} (so they cannot breach a
 * threshold), but they are listed separately with their justification.
 * {@code dependencies} is the full direct-dependency list (for the SBOM /
 * PDF dependency tree); {@code dependenciesScanned} is its size.
 */
public record ScanReport(
        String projectPath,
        int dependenciesScanned,
        List<Finding> findings,
        List<String> skippedDependencies,
        boolean usedStaleCache,
        List<IgnoredFinding> ignoredFindings,
        List<String> configNotes,
        List<Dependency> dependencies) {

    /** Backwards-compatible constructor: no ignores, no config notes, no dependency list. */
    public ScanReport(String projectPath, int dependenciesScanned, List<Finding> findings,
                      List<String> skippedDependencies, boolean usedStaleCache) {
        this(projectPath, dependenciesScanned, findings, skippedDependencies, usedStaleCache,
                List.of(), List.of(), List.of());
    }

    /** Full constructor without the dependency list (older callers). */
    public ScanReport(String projectPath, int dependenciesScanned, List<Finding> findings,
                      List<String> skippedDependencies, boolean usedStaleCache,
                      List<IgnoredFinding> ignoredFindings, List<String> configNotes) {
        this(projectPath, dependenciesScanned, findings, skippedDependencies, usedStaleCache,
                ignoredFindings, configNotes, List.of());
    }

    public long criticalCount() {
        return findings.stream().filter(Finding::reachable).count();
    }

    public long lowCount() {
        return findings.stream().filter(f -> !f.reachable()).count();
    }

    public long ignoredCount() {
        return ignoredFindings.size();
    }
}
