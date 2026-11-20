package com.depscan.tui;

import com.depscan.report.ScanReport;
import com.depscan.report.TextReporter;
import java.io.IOException;

/**
 * Interactive terminal UI entry point (Stage 4).
 *
 * <p>{@link #run(ScanReport)} shows the plain text report — the safe
 * fallback used in CI, non-TTY, {@code --no-animation} and {@code NO_COLOR}
 * contexts. {@link #runDashboard(ScanReport, boolean)} launches the
 * full-screen dashboard when the caller has already established a TTY.
 */
public final class Tui {
    private Tui() {}

    public static void run(ScanReport report) {
        System.out.println(new TextReporter(true).render(report));
        System.out.println("(Interactive TUI: run with --tui on a real terminal for the dashboard.)");
    }

    public static void runDashboard(ScanReport report, boolean colour) throws IOException {
        HackerTui.runDashboard(report, colour);
    }
}
