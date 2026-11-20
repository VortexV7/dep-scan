package com.depscan.ci;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.deps.Dependency;
import com.depscan.osv.Vulnerability;
import com.depscan.reach.Finding;
import com.depscan.report.ScanReport;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class GitHubActionsTest {

    public static ScanReport sampleReport() {
        var vuln = new Vulnerability("GHSA-599f-7c49-w659", "Text4Shell", "CRITICAL", -1,
                "1.10.0", List.of(), List.of(), List.of("CVE-2022-42889"));
        var critical = new Finding(new Dependency("org.apache.commons", "commons-text", "1.9"), vuln,
                true, "PACKAGE: call into org.apache.commons.*", List.of(),
                "src/main/java/com/example/app/InterpolatorService.java:10", "Upgrade to 1.10.0");
        var lowVuln = new Vulnerability("GHSA-9w3m-gqgf-c4p9", "DoS", "MODERATE", -1,
                "1.32", List.of(), List.of());
        var low = new Finding(new Dependency("org.yaml", "snakeyaml", "1.31"), lowVuln,
                false, "PACKAGE: no call", List.of(), "pom.xml:27", "Upgrade to 1.32");
        return new ScanReport("/tmp/proj", 2, List.of(critical, low), List.of(), false,
                List.of(), List.of(),
                List.of(new Dependency("org.apache.commons", "commons-text", "1.9"),
                        new Dependency("org.yaml", "snakeyaml", "1.31")));
    }

    @Test
    void annotationUsesErrorForCriticalAndWarningForLowWithFileAndLine() {
        ScanReport r = sampleReport();
        assertEquals("::error file=src/main/java/com/example/app/InterpolatorService.java,line=10::GHSA-599f-7c49-w659 (org.apache.commons:commons-text:1.9): Text4Shell - Upgrade to 1.10.0",
                GitHubActions.annotation(r.findings().get(0)));
        assertTrue(GitHubActions.annotation(r.findings().get(1))
                .startsWith("::warning file=pom.xml,line=27::GHSA-9w3m-gqgf-c4p9"));
    }

    @Test
    void stepSummaryIsMarkdownTable() {
        String md = GitHubActions.markdownSummary(sampleReport());
        assertTrue(md.contains("## DepScan report"), md);
        assertTrue(md.contains("| Severity | Advisory | Dependency | Location | Upgrade |"), md);
        assertTrue(md.contains("| CRITICAL | GHSA-599f-7c49-w659 (CVE-2022-42889) | org.apache.commons:commons-text:1.9 | src/main/java/com/example/app/InterpolatorService.java:10 | 1.10.0 |"), md);
        assertTrue(md.contains("**1 CRITICAL (reachable), 1 LOW (unreachable), 0 ignored**"), md);
    }

    @Test
    void writeStepSummaryAppendsToEnvFileAndReturnsFalseWhenUnset(@TempDir Path dir) throws Exception {
        Path summary = dir.resolve("summary.md");
        assertTrue(GitHubActions.writeStepSummary(sampleReport(), Map.of("GITHUB_STEP_SUMMARY", summary.toString())));
        assertTrue(Files.readString(summary).contains("## DepScan report"));
        assertFalse(GitHubActions.writeStepSummary(sampleReport(), Map.of()));
    }

    @Test
    void splitLocationDefaults() {
        assertEquals("1", GitHubActions.splitLocation("pom.xml")[1]);
        assertEquals("pom.xml", GitHubActions.splitLocation("")[0]);
    }
}
