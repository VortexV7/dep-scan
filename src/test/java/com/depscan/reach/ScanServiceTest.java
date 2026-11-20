package com.depscan.reach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.cli.ScanService;
import com.depscan.deps.Dependency;
import com.depscan.osv.OsvClient;
import com.depscan.osv.Vulnerability;
import com.depscan.report.ScanReport;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** End-to-end: real pom + real source from samples/vulnerable-app, fake OSV (no network). */
class ScanServiceTest {

    @org.junit.jupiter.api.Test
    void sampleProjectYieldsOneCriticalOneLow() throws Exception {
        Map<String, List<Vulnerability>> canned = Map.of(
                "org.apache.commons:commons-text:1.9", List.of(
                        new Vulnerability("GHSA-599f-7c49-w659", "Text4Shell", "CVSS_V3:9.8", 9.8,
                                "1.10.0", List.of(), List.of(
                                        "org.apache.commons.text.StringSubstitutor.createInterpolator"))),
                "org.yaml:snakeyaml:1.31", List.of(
                        new Vulnerability("CVE-2022-38751", "SnakeYAML", "CVSS_V3:7.5", 7.5,
                                "1.32", List.of(), List.of())));
        OsvClient fake = dep -> canned.getOrDefault(dep.coordinates(), List.of());
        ScanReport report = new ScanService(fake).scan(Path.of("samples/vulnerable-app"));
        assertEquals(2, report.dependenciesScanned());
        assertEquals(2, report.findings().size(), "both vulns shown — unreachable is LOW, never hidden");
        assertEquals(1, report.criticalCount());
        assertEquals(1, report.lowCount());
        Finding critical = report.findings().get(0);
        assertTrue(critical.reachable());
        assertEquals("GHSA-599f-7c49-w659", critical.vulnerability().id());
        assertTrue(critical.callChain().get(0).contains("App#main"), critical.callChain().toString());
        Finding low = report.findings().get(1);
        assertEquals("CVE-2022-38751", low.vulnerability().id());
        assertEquals("LOW", low.severity());
    }
}
