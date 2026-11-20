package com.depscan.reach;

import com.depscan.deps.Dependency;
import com.depscan.osv.Vulnerability;
import com.depscan.report.UpgradeSuggestion;
import java.util.List;

/**
 * One vulnerability on one dependency, with its reachability verdict.
 *
 * <p>{@code location} is the file:line to look at first: the call site of
 * the vulnerable function when reachable, otherwise the pom.xml line where
 * the dependency is declared. {@code upgradeSuggestion} is the safe-upgrade
 * text for the fixed version (major bumps flagged as likely breaking).
 */
public record Finding(
        Dependency dependency,
        Vulnerability vulnerability,
        boolean reachable,
        /** How the verdict was reached: FUNCTION or PACKAGE (fallback). */
        String evidence,
        /** Shortest call chain entry-point &rarr; vulnerable call, empty when unreachable. */
        List<String> callChain,
        String location,
        String upgradeSuggestion) {

    /** Backwards-compatible constructor: location empty, upgrade derived from the fixed version. */
    public Finding(Dependency dependency, Vulnerability vulnerability, boolean reachable,
                   String evidence, List<String> callChain) {
        this(dependency, vulnerability, reachable, evidence, callChain, "",
                UpgradeSuggestion.suggest(dependency.version(), vulnerability.fixedVersion()).text());
    }

    /** CRITICAL when reachable, LOW when not — unreachable is still shown, never hidden. */
    public String severity() {
        return reachable ? "CRITICAL" : "LOW";
    }

    /** True if the suggested upgrade is a major-version bump (likely breaking). */
    public boolean upgradeIsMajorBump() {
        return UpgradeSuggestion.suggest(dependency.version(), vulnerability.fixedVersion()).majorBump();
    }

    /** Copy with a different location (used by ScanService to fill the pom/call-site line). */
    public Finding withLocation(String newLocation) {
        return new Finding(dependency, vulnerability, reachable, evidence, callChain,
                newLocation == null ? "" : newLocation, upgradeSuggestion);
    }
}
