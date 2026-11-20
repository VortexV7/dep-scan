package com.depscan.report;

/**
 * Risk score out of 10 for the executive summary (Stage 5).
 *
 * <p>Formula (documented, deterministic): each reachable (CRITICAL) finding
 * adds 2.5, each unreachable (LOW) adds 0.5, capped at 10. A clean scan
 * scores 0.0. The score is a triage aid, not a CVSS score — it measures
 * how much of the project's shipped code is exposed, which is exactly what
 * DepScan's reachability analysis adds over a plain CVE list.
 */
public final class RiskScore {

    private RiskScore() {}

    public static double score(ScanReport report) {
        double s = report.criticalCount() * 2.5 + report.lowCount() * 0.5;
        return Math.min(10.0, Math.round(s * 10.0) / 10.0);
    }

    public static String label(double score) {
        if (score == 0) return "None";
        if (score < 3) return "Low";
        if (score < 6) return "Medium";
        if (score < 8) return "High";
        return "Critical";
    }
}
