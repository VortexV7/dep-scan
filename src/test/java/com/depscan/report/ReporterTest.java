package com.depscan.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.config.IgnoreRule;
import com.depscan.deps.Dependency;
import com.depscan.osv.Vulnerability;
import com.depscan.reach.Finding;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;

class ReporterTest {

    private static Finding critical() {
        var vuln = new Vulnerability("GHSA-599f-7c49-w659", "Arbitrary code execution", "CRITICAL", -1,
                "1.10.0", List.of(), List.of(), List.of("CVE-2022-42889"));
        return new Finding(new Dependency("org.apache.commons", "commons-text", "1.9"), vuln,
                true, "PACKAGE: call into org.apache.commons.*",
                List.of("com.example.app.App#main(1)",
                        "com.example.app.InterpolatorService#interpolate(1)",
                        "org.apache.commons.text.StringSubstitutor#createInterpolator(0)"),
                "src/main/java/com/example/app/InterpolatorService.java:8",
                "Upgrade to 1.10.0 (minor bump from 1.9 - usually safe, test before shipping)");
    }

    private static Finding low() {
        var vuln = new Vulnerability("GHSA-9w3m-gqgf-c4p9", "DoS", "MODERATE", -1,
                "1.32", List.of(), List.of());
        return new Finding(new Dependency("org.yaml", "snakeyaml", "1.31"), vuln,
                false, "PACKAGE: no call into org.yaml.* from reachable code", List.of(),
                "pom.xml:14", "Upgrade to 1.32 (minor bump from 1.31 - usually safe, test before shipping)");
    }

    private static ScanReport report() {
        return new ScanReport("/tmp/proj", 2, List.of(critical(), low()), List.of(), false,
                List.of(new IgnoredFinding(low(),
                        new IgnoreRule("GHSA-9w3m-gqgf-c4p9", "", "Accepted, test-only use",
                                LocalDate.of(2027, 1, 1)))),
                List.of());
    }

    @Test
    void boxedReportHasBoxesMarkersPackageVersionAdvisoryLocationAndUpgrade() {
        String out = new BoxedReporter(false).render(report());
        assertTrue(out.contains("┌"), out);
        assertTrue(out.contains("└"), out);
        assertTrue(out.contains("[!!] CRITICAL"), out);
        assertTrue(out.contains("[..] LOW"), out);
        assertTrue(out.contains("org.apache.commons:commons-text:1.9"), out);
        assertTrue(out.contains("GHSA-599f-7c49-w659"), out);
        assertTrue(out.contains("CVE-2022-42889"), out);
        assertTrue(out.contains("InterpolatorService.java:8"), out);
        assertTrue(out.contains("Upgrade to 1.10.0"), out);
        assertTrue(out.contains("pom.xml:14"), out);
        assertTrue(out.contains("IGNORED"), out);
        assertTrue(out.contains("Accepted, test-only use"), out);
    }

    @Test
    void boxedReportColoursCriticalRedAndLowYellow() {
        String out = new BoxedReporter(true).render(report());
        assertTrue(out.contains("\u001B[31m"), "red border/tag expected: " + out);
        assertTrue(out.contains("\u001B[33m"), "yellow border/tag expected");
    }

    @Test
    void simpleReportHasSameDataWithoutBoxes() {
        String out = new TextReporter(false).render(report());
        assertFalse(out.contains("┌"), out);
        assertTrue(out.contains("[!!] CRITICAL"), out);
        assertTrue(out.contains("[..] LOW"), out);
        assertTrue(out.contains("InterpolatorService.java:8"), out);
        assertTrue(out.contains("Upgrade to 1.10.0"), out);
    }

    @Test
    void jsonReportHasLocationUpgradeAndIgnored() throws Exception {
        String out = new JsonReporter().render(report());
        assertTrue(out.contains("\"location\" : \"src/main/java/com/example/app/InterpolatorService.java:8\""), out);
        assertTrue(out.contains("\"upgradeSuggestion\""), out);
        assertTrue(out.contains("\"ignoredFindings\""), out);
        assertTrue(out.contains("Accepted, test-only use"), out);
    }

    @Test
    void upgradeSuggestionFlagsMajorBump() {
        var major = UpgradeSuggestion.suggest("1.31", "2.0");
        assertTrue(major.majorBump());
        assertTrue(major.text().contains("likely breaking"), major.text());
        var minor = UpgradeSuggestion.suggest("1.9", "1.10.0");
        assertFalse(minor.majorBump());
        assertTrue(minor.text().contains("minor bump"), minor.text());
        var patch = UpgradeSuggestion.suggest("1.9", "1.9.1");
        assertFalse(patch.majorBump());
        assertTrue(patch.text().contains("patch bump"), patch.text());
        var none = UpgradeSuggestion.suggest("1.9", "");
        assertFalse(none.hasFix());
        assertTrue(none.text().contains("No fixed version"), none.text());
    }
}
