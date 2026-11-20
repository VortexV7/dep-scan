package com.depscan.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.ci.GitHubActionsTest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;

class ExportReporterTest {

    @Test
    void riskScoreFormula() {
        ScanReport r = GitHubActionsTest.sampleReport(); // 1 critical + 1 low
        assertEquals(3.0, RiskScore.score(r));
        assertEquals("Medium", RiskScore.label(3.0));
        assertEquals(0.0, RiskScore.score(new ScanReport("/tmp", 0, java.util.List.of(), java.util.List.of(), false)));
        assertEquals(10.0, RiskScore.score(new ScanReport("/tmp", 0,
                java.util.List.of(GitHubActionsTest.sampleReport().findings().get(0),
                        GitHubActionsTest.sampleReport().findings().get(0),
                        GitHubActionsTest.sampleReport().findings().get(0),
                        GitHubActionsTest.sampleReport().findings().get(0)),
                java.util.List.of(), false)));
    }

    @Test
    void csvHasHeaderAndBothFindings() {
        String csv = CsvReporter.render(GitHubActionsTest.sampleReport());
        assertTrue(csv.startsWith("severity,advisory,aliases,dependency,version,reachable,location,summary,fixed_version,upgrade_suggestion,evidence\n"), csv);
        assertTrue(csv.contains("CRITICAL,GHSA-599f-7c49-w659"), csv);
        assertTrue(csv.contains("LOW,GHSA-9w3m-gqgf-c4p9"), csv);
    }

    @Test
    void htmlHasThemeChartTableAndLinks() {
        String html = HtmlReporter.render(GitHubActionsTest.sampleReport(), "dark", false);
        assertTrue(html.contains("Risk score"), html);
        assertTrue(html.contains("https://osv.dev/vulnerability/GHSA-599f-7c49-w659"), html);
        assertTrue(html.contains("Methodology and limitations"), html);
        assertTrue(html.contains("Glossary"), html);
        String light = HtmlReporter.render(GitHubActionsTest.sampleReport(), "light", true);
        assertFalse(light.contains("GHSA-9w3m-gqgf-c4p9"), "exclude-unreachable must drop the LOW finding");
        assertTrue(light.contains("GHSA-599f-7c49-w659"), light);
    }

    @Test
    void sbomIsCycloneDx16WithComponentsAndVulnerabilities() throws Exception {
        String json = SbomReporter.render(GitHubActionsTest.sampleReport());
        JsonNode root = new ObjectMapper().readTree(json);
        assertEquals("CycloneDX", root.path("bomFormat").asText());
        assertEquals("1.6", root.path("specVersion").asText());
        assertEquals(2, root.path("components").size());
        assertEquals("pkg:maven/org.apache.commons/commons-text@1.9", root.path("components").get(0).path("purl").asText());
        assertEquals(2, root.path("vulnerabilities").size());
        assertEquals("critical", root.path("vulnerabilities").get(0).path("ratings").get(0).path("severity").asText());
        assertEquals("exploitable", root.path("vulnerabilities").get(0).path("analysis").path("state").asText());
    }

    @Test
    void pdfHasCoverSummaryChartFindingsAndGlossaryWithSelectableText() throws Exception {
        byte[] pdf = PdfReporter.render(GitHubActionsTest.sampleReport(), "light", false);
        assertTrue(pdf.length > 1000, "pdf too small: " + pdf.length);
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(doc.getNumberOfPages() >= 4, "expected >=4 pages, got " + doc.getNumberOfPages());
            String text = new PDFTextStripper().getText(doc);
            assertTrue(text.contains("DepScan"), text);
            assertTrue(text.contains("Executive summary"), text);
            assertTrue(text.contains("Risk score"), text);
            assertTrue(text.contains("GHSA-599f-7c49-w659"), text);
            assertTrue(text.contains("InterpolatorService.java:10"), text);
            assertTrue(text.contains("Recommendations"), text);
            assertTrue(text.contains("Methodology and limitations"), text);
            assertTrue(text.contains("reflection"), text);
            assertTrue(text.contains("Glossary"), text);
            assertTrue(text.contains("Page 1"), text);
            // Embedded fonts: Inter / JetBrains Mono (or fallback when resources missing)
            boolean hasEmbedded = false;
            for (var page : doc.getPages()) {
                try {
                    for (var name : page.getResources().getFontNames()) {
                        var f = page.getResources().getFont(name);
                        if (f != null && f.getName() != null
                                && (f.getName().contains("Inter") || f.getName().contains("JetBrainsMono"))) {
                            hasEmbedded = true;
                        }
                    }
                } catch (Exception ignored) {
                    // ignore a page with no fonts
                }
            }
            assertTrue(hasEmbedded, "expected embedded Inter / JetBrains Mono fonts");
        }
    }

    @Test
    void pdfExcludeUnreachableDropsLowFinding() throws Exception {
        byte[] pdf = PdfReporter.render(GitHubActionsTest.sampleReport(), "light", true);
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            String text = new PDFTextStripper().getText(doc);
            assertTrue(text.contains("GHSA-599f-7c49-w659"), text);
            assertFalse(text.contains("GHSA-9w3m-gqgf-c4p9"), text);
        }
    }
}
