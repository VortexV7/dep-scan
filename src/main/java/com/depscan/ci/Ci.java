package com.depscan.ci;

import com.depscan.cli.ExitCodes;
import com.depscan.cli.FailThreshold;

/**
 * CI integration helpers (Stage 3).
 *
 * <p>Detection lives in {@link CiDetector} (CI / GITHUB_ACTIONS / GITLAB_CI /
 * JENKINS_URL / non-TTY), GitHub annotations + step summary in
 * {@link GitHubActions}, SARIF output in
 * {@link com.depscan.report.SarifReporter}. This class keeps the Stage 1/2
 * exit-code helpers.
 */
public final class Ci {
    private Ci() {}

    /** Exit code for a scan result: 1 iff fail-on-critical and any CRITICAL finding. */
    public static int exitCode(com.depscan.report.ScanReport report, boolean failOnCritical) {
        return failOnCritical ? ExitCodes.forReport(report, FailThreshold.CRITICAL) : ExitCodes.CLEAN;
    }

    /** Exit code for a scan result under an explicit threshold. */
    public static int exitCode(com.depscan.report.ScanReport report, FailThreshold threshold) {
        return ExitCodes.forReport(report, threshold);
    }

    /** True iff this run is in CI (see {@link CiDetector}). */
    public static boolean isCi() {
        return CiDetector.isCi();
    }
}
