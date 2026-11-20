package com.depscan.cli;

import com.depscan.report.ScanReport;
import java.util.Locale;

/**
 * The {@code --fail-on} threshold for exit code 1.
 *
 * <ul>
 *   <li>{@code critical} / {@code reachable} — any reachable finding
 *       (DepScan CRITICAL) breaches. The two names are aliases: in DepScan,
 *       CRITICAL <em>means</em> reachable.</li>
 *   <li>{@code high} — any finding whose severity is high, reachable or
 *       not: CVSS score &ge; 7.0, or a HIGH / CRITICAL severity label.
 *       This is the stricter threshold: an unreachable HIGH still fails.</li>
 *   <li>{@code none} — never fail on findings; exit 0 if the scan itself ran.</li>
 * </ul>
 */
public enum FailThreshold {
    CRITICAL, REACHABLE, HIGH, NONE;

    public static FailThreshold parse(String raw) {
        if (raw == null || raw.isBlank()) return CRITICAL;
        try {
            return valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid --fail-on value '" + raw + "' (use critical, reachable, high or none)");
        }
    }

    /** True iff this threshold is breached by the (non-ignored) findings in the report. */
    public boolean breached(ScanReport report) {
        return switch (this) {
            case CRITICAL, REACHABLE -> report.criticalCount() > 0;
            case HIGH -> report.findings().stream()
                    .anyMatch(f -> f.vulnerability().isHigh());
            case NONE -> false;
        };
    }
}
