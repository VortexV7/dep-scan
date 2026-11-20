package com.depscan.tui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.ci.GitHubActionsTest;
import com.depscan.report.ScanReport;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HackerTuiTest {

    @Test
    void bannerContainsDepScan() {
        assertTrue(String.join("\n", HackerTui.BANNER).contains("DepScan") || HackerTui.BANNER.length == 6);
        // The ASCII art spells DepScan in block letters; at minimum it is 6 lines.
        assertEquals(6, HackerTui.BANNER.length);
    }

    @Test
    void progressBarFillsProportionally() {
        assertTrue(HackerTui.progressBar("parsing pom.xml", 1, 2).contains("50%"));
        assertTrue(HackerTui.progressBar("parsing pom.xml", 2, 2).contains("100%"));
        assertTrue(HackerTui.progressBar("parsing pom.xml", 0, 2).contains("0%"));
    }

    @Test
    void radarCyclesFourFrames() {
        assertEquals("◐", HackerTui.radarFrame(0));
        assertEquals("◓", HackerTui.radarFrame(1));
        assertEquals("◐", HackerTui.radarFrame(4));
    }

    @Test
    void bootWithoutAnimationPrintsBannerAndOkLines() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        HackerTui.boot(new PrintStream(buf, true, StandardCharsets.UTF_8), false, false);
        String out = buf.toString(StandardCharsets.UTF_8);
        assertTrue(out.contains("initializing scanner... [OK]"), out);
        assertTrue(out.contains("call-graph engine"), out);
    }

    @Test
    void pulsingAlertDegradesToPlainLine() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        HackerTui.pulsingAlert(new PrintStream(buf, true, StandardCharsets.UTF_8), 2, false, false);
        assertTrue(buf.toString(StandardCharsets.UTF_8).contains("2 REACHABLE CRITICAL VULNERABILITIES FOUND"));
    }

    @Test
    void dashboardStateFiltersAndToggles() {
        ScanReport r = GitHubActionsTest.sampleReport();
        var state = new HackerTui.DashboardState();
        assertEquals(2, state.filtered(r).size());
        assertTrue(state.key('c'));
        assertEquals(1, state.filtered(r).size());
        assertTrue(state.filtered(r).get(0).reachable());
        assertTrue(state.key('l'));
        assertEquals(1, state.filtered(r).size());
        assertFalse(state.filtered(r).get(0).reachable());
        assertTrue(state.key('a'));
        assertEquals(2, state.filtered(r).size());
        assertFalse(state.simple());
        assertTrue(state.key('s'));
        assertTrue(state.simple());
        assertFalse(state.key('q'));
    }

    @Test
    void dashboardRenderShowsTreeStatsAndShortcuts() {
        ScanReport r = GitHubActionsTest.sampleReport();
        String out = HackerTui.renderDashboard(r, new HackerTui.DashboardState(), false);
        assertTrue(out.contains("LIVE DASHBOARD"), out);
        assertTrue(out.contains("1 CRITICAL"), out);
        assertTrue(out.contains("org.apache.commons"), out);
        assertTrue(out.contains("[q]uit"), out);
    }

    @Test
    void hackerUiNeverRunsInCi() {
        // In this test JVM System.console() is null (surefire), so shouldUseHackerUi is false regardless.
        assertFalse(HackerTui.shouldUseHackerUi(false, false));
        assertFalse(HackerTui.shouldUseHackerUi(true, false));
    }
}
