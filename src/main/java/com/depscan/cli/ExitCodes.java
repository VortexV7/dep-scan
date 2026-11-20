package com.depscan.cli;

import com.depscan.report.ScanReport;

/** Exit-code contract for {@code depscan scan}. */
public final class ExitCodes {

    public static final int CLEAN = 0;              // clean, or only unreachable findings
    public static final int THRESHOLD_BREACHED = 1; // --fail-on threshold breached
    public static final int USAGE_OR_TOOL_ERROR = 2; // bad flags, bad config, missing pom, bad project
    public static final int NETWORK_NO_CACHE = 3;    // OSV unreachable and no cached response

    private ExitCodes() {}

    /** Exit code for a completed scan under the given threshold. */
    public static int forReport(ScanReport report, FailThreshold threshold) {
        return threshold.breached(report) ? THRESHOLD_BREACHED : CLEAN;
    }
}
