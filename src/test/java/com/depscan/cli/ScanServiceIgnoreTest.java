package com.depscan.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.config.DepScanConfig;
import com.depscan.config.IgnoreRule;
import com.depscan.osv.NetworkException;
import com.depscan.osv.OsvClient;
import com.depscan.osv.Vulnerability;
import com.depscan.report.ScanReport;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ScanServiceIgnoreTest {

    private static OsvClient fakeOsv() {
        Map<String, List<Vulnerability>> canned = Map.of(
                "org.apache.commons:commons-text:1.9", List.of(
                        new Vulnerability("GHSA-599f-7c49-w659", "Text4Shell", "CVSS_V3:9.8", 9.8,
                                "1.10.0", List.of(), List.of(
                                        "org.apache.commons.text.StringSubstitutor.createInterpolator"))),
                "org.yaml:snakeyaml:1.31", List.of(
                        new Vulnerability("GHSA-9w3m-gqgf-c4p9", "SnakeYAML", "CVSS_V3:7.5", 7.5,
                                "1.32", List.of(), List.of(), List.of("CVE-2022-38752"))));
        return dep -> canned.getOrDefault(dep.coordinates(), List.of());
    }

    @Test
    void liveIgnoreMovesFindingToIgnoredList() throws Exception {
        var cfg = new DepScanConfig(List.of(
                new IgnoreRule("CVE-2022-38752", "org.yaml:snakeyaml",
                        "Test-only use", LocalDate.now().plusDays(30))), null);
        ScanReport r = new ScanService(fakeOsv(), cfg).scan(Path.of("samples/vulnerable-app"));
        assertEquals(1, r.findings().size());
        assertEquals(1, r.criticalCount());
        assertEquals(1, r.ignoredCount());
        assertEquals("CVE-2022-38752", r.ignoredFindings().get(0).rule().id());
        // The ignored HIGH no longer counts: only 1 finding remains, so the
        // breach (if any) comes from the remaining reachable finding alone.
        assertEquals(1, r.findings().size());
        assertEquals(ExitCodes.THRESHOLD_BREACHED, ExitCodes.forReport(r, FailThreshold.HIGH),
                "remaining reachable 9.8 finding still breaches --fail-on high");
    }

    @Test
    void expiredIgnoreDoesNotSuppress() throws Exception {
        var cfg = new DepScanConfig(List.of(
                new IgnoreRule("CVE-2022-38752", "", "Expired", LocalDate.now().minusDays(1))), null);
        ScanReport r = new ScanService(fakeOsv(), cfg).scan(Path.of("samples/vulnerable-app"));
        assertEquals(2, r.findings().size());
        assertEquals(0, r.ignoredCount());
        assertTrue(r.configNotes().stream().anyMatch(n -> n.contains("expired")), r.configNotes().toString());
    }

    @Test
    void reachableFindingCarriesCallSiteFileLine() throws Exception {
        ScanReport r = new ScanService(fakeOsv()).scan(Path.of("samples/vulnerable-app"));
        var critical = r.findings().get(0);
        assertTrue(critical.reachable());
        assertTrue(critical.location().contains("InterpolatorService.java:"),
                "call-site file:line expected, got: " + critical.location());
        assertTrue(critical.upgradeSuggestion().contains("Upgrade to 1.10.0"), critical.upgradeSuggestion());
        var low = r.findings().get(1);
        assertTrue(low.location().startsWith("pom.xml:"), "unreachable location is the pom line, got: " + low.location());
    }

    @Test
    void networkExceptionPropagatesFromScanService() {
        OsvClient failing = dep -> { throw new NetworkException("no network, no cache"); };
        var svc = new ScanService(failing);
        org.junit.jupiter.api.Assertions.assertThrows(NetworkException.class,
                () -> svc.scan(Path.of("samples/vulnerable-app")));
    }
}
