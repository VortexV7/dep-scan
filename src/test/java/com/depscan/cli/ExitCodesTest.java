package com.depscan.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.deps.Dependency;
import com.depscan.osv.Vulnerability;
import com.depscan.reach.Finding;
import com.depscan.report.ScanReport;
import java.util.List;
import org.junit.jupiter.api.Test;

class ExitCodesTest {

    private static Finding finding(boolean reachable, double cvss, String severityLabel) {
        var vuln = new Vulnerability("GHSA-test", "test", severityLabel, cvss,
                "2.0", List.of(), List.of());
        return new Finding(new Dependency("org.example", "lib", "1.0"), vuln,
                reachable, "test", List.of());
    }

    private static ScanReport report(Finding... findings) {
        return new ScanReport("/tmp/proj", 1, List.of(findings), List.of(), false);
    }

    @Test
    void cleanReportExitsZeroForEveryThreshold() {
        ScanReport clean = report();
        for (FailThreshold t : FailThreshold.values()) {
            assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(clean, t), t.toString());
        }
    }

    @Test
    void onlyUnreachableExitsZeroOnCriticalButOneOnHigh() {
        // Unreachable HIGH: LOW in DepScan terms, but --fail-on high is stricter.
        ScanReport r = report(finding(false, 7.5, "CVSS_V3:7.5"));
        assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(r, FailThreshold.CRITICAL));
        assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(r, FailThreshold.REACHABLE));
        assertEquals(ExitCodes.THRESHOLD_BREACHED, ExitCodes.forReport(r, FailThreshold.HIGH));
        assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(r, FailThreshold.NONE));
    }

    @Test
    void reachableBreachesCriticalAndReachableButNotHighWhenLowCvss() {
        ScanReport r = report(finding(true, 3.1, "CVSS_V3:3.1"));
        assertEquals(ExitCodes.THRESHOLD_BREACHED, ExitCodes.forReport(r, FailThreshold.CRITICAL));
        assertEquals(ExitCodes.THRESHOLD_BREACHED, ExitCodes.forReport(r, FailThreshold.REACHABLE));
        assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(r, FailThreshold.HIGH));
        assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(r, FailThreshold.NONE));
    }

    @Test
    void reachableHighBreachesAllExceptNone() {
        ScanReport r = report(finding(true, 9.8, "CVSS_V3:9.8"));
        assertEquals(ExitCodes.THRESHOLD_BREACHED, ExitCodes.forReport(r, FailThreshold.CRITICAL));
        assertEquals(ExitCodes.THRESHOLD_BREACHED, ExitCodes.forReport(r, FailThreshold.HIGH));
        assertEquals(ExitCodes.CLEAN, ExitCodes.forReport(r, FailThreshold.NONE));
    }

    @Test
    void highIsDecidedByWordLabelWhenNoNumericScore() {
        // Live OSV often has no numeric score, only "HIGH"/"CRITICAL".
        assertTrue(finding(false, -1, "HIGH").vulnerability().isHigh());
        assertTrue(finding(false, -1, "CRITICAL").vulnerability().isHigh());
        assertFalse(finding(false, -1, "MODERATE").vulnerability().isHigh());
        assertFalse(finding(false, -1, "").vulnerability().isHigh());
    }

    @Test
    void parseIsCaseInsensitiveAndRejectsBadValues() {
        assertEquals(FailThreshold.CRITICAL, FailThreshold.parse("critical"));
        assertEquals(FailThreshold.HIGH, FailThreshold.parse("HIGH"));
        assertEquals(FailThreshold.NONE, FailThreshold.parse("None"));
        assertThrows(IllegalArgumentException.class, () -> FailThreshold.parse("medium"));
    }

    @Test
    void exitCodeConstantsMatchContract() {
        assertEquals(0, ExitCodes.CLEAN);
        assertEquals(1, ExitCodes.THRESHOLD_BREACHED);
        assertEquals(2, ExitCodes.USAGE_OR_TOOL_ERROR);
        assertEquals(3, ExitCodes.NETWORK_NO_CACHE);
    }
}
