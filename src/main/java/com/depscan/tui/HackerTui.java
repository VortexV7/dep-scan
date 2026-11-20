package com.depscan.tui;

import com.depscan.ci.CiDetector;
import com.depscan.cli.ScanProgress;
import com.depscan.reach.Finding;
import com.depscan.report.BoxedReporter;
import com.depscan.report.ScanReport;
import com.depscan.report.TextReporter;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hacker-style terminal UI (Stage 4).
 *
 * <p>Used ONLY when stdout is a TTY and CI is not detected, and neither
 * {@code --no-animation} nor {@code NO_COLOR} is set. Everything degrades
 * cleanly: with {@code --no-animation} / {@code NO_COLOR} / CI / non-TTY
 * the caller falls back to the plain boxed/text report with no ANSI codes,
 * no banner typing and no progress bars.
 *
 * <p>Boot sequence: ASCII-art "DepScan" banner typed in, then
 * {@code > initializing scanner... [OK]} lines, animated progress bars for
 * dependency parsing and call-graph building, a radar/spinner scan
 * indicator, typewriter text, and a pulsing red alert when a reachable
 * CRITICAL is found. Neon cyan / green / red / amber via ANSI.
 */
public final class HackerTui {

    public static final String[] BANNER = {
            " ____            ____                       ",
            "|  _ \\  ___ _ __/ ___|  ___ __ _ _ __      ",
            "| | | |/ _ \\ '_ \\___ \\ / __/ _` | '_ \\     ",
            "| |_| |  __/ |_) |__) | (_| (_| | | | |    ",
            "|____/ \\___| .__/____/ \\___\\__,_|_| |_|    ",
            "           |_|                              "
    };

    private static final String[] RADAR = {"◐", "◓", "◑", "◒"};
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String AMBER = "\u001B[33m";
    private static final String BOLD = "\u001B[1m";
    private static final String RESET = "\u001B[0m";
    private static final String CLEAR = "\u001B[2J\u001B[H";

    private HackerTui() {}

    /** True iff the hacker boot sequence may run (TTY, not CI, animation + colour allowed). */
    public static boolean shouldUseHackerUi(boolean noAnimation, boolean noColor) {
        if (noAnimation || noColor) return false;
        if (CiDetector.noColorEnv()) return false;
        if (CiDetector.isCi()) return false;
        return System.console() != null;
    }

    /** Progress-bar text, pure and testable: "[██████░░░░] 60% label". */
    public static String progressBar(String label, int done, int total) {
        return progressBar(label, done, total, 30);
    }

    public static String progressBar(String label, int done, int total, int width) {
        double frac = total <= 0 ? 0 : Math.min(1.0, (double) done / total);
        int filled = (int) Math.round(frac * width);
        String bar = "█".repeat(filled) + "░".repeat(Math.max(0, width - filled));
        return "[" + bar + "] " + (int) Math.round(frac * 100) + "% " + label;
    }

    /** Radar frame for index i (cycles ◐ ◓ ◑ ◒). */
    public static String radarFrame(int i) {
        return RADAR[Math.floorMod(i, RADAR.length)];
    }

    /** Boot sequence. With animate=false everything prints instantly (tests / fast runs). */
    public static void boot(PrintStream out, boolean animate, boolean colour) {
        String c = colour ? CYAN : "";
        String r = colour ? RESET : "";
        for (String line : BANNER) {
            if (animate) {
                typewrite(out, c + line + r, 4);
                out.println();
            } else {
                out.println(c + line + r);
            }
        }
        String[] steps = {
                "> initializing scanner... [OK]",
                "> loading OSV.dev client... [OK]",
                "> loading call-graph engine (JavaParser + JGraphT)... [OK]",
                "> arming reachability analyzer... [OK]"
        };
        for (String s : steps) {
            if (animate) typewrite(out, (colour ? GREEN : "") + s + r, 8);
            else out.println((colour ? GREEN : "") + s + r);
            if (animate) out.println();
            sleep(animate ? 120 : 0);
        }
    }

    public static void typewrite(PrintStream out, String text, long millisPerChar) {
        if (millisPerChar <= 0) {
            out.println(text);
            return;
        }
        for (char ch : text.toCharArray()) {
            out.print(ch);
            out.flush();
            sleep(millisPerChar);
        }
        out.println();
    }

    /** A ScanProgress that draws animated bars + radar on stderr, leaving stdout clean. */
    public static ScanProgress progressListener(PrintStream err, boolean colour) {
        return (name, done, total) -> {
            String bar = progressBar(name, done, total);
            String radar = colour ? CYAN + radarFrame(done) + RESET : radarFrame(done);
            err.print("\r" + radar + " " + bar);
            if (done >= total) err.println();
            err.flush();
        };
    }

    /** Pulsing red alert for a reachable CRITICAL: 3 pulses, or 1 plain line when not animated/coloured. */
    public static void pulsingAlert(PrintStream out, long criticalCount, boolean animate, boolean colour) {
        String msg = "!! ALERT: " + criticalCount + " REACHABLE CRITICAL VULNERABILIT" + (criticalCount == 1 ? "Y" : "IES") + " FOUND !!";
        if (!animate || !colour) {
            out.println(msg);
            return;
        }
        for (int i = 0; i < 3; i++) {
            out.print("\r" + RED + BOLD + msg + RESET);
            out.flush();
            sleep(220);
            out.print("\r" + " ".repeat(msg.length()) + "\r");
            out.flush();
            sleep(120);
        }
        out.println(RED + BOLD + msg + RESET);
    }

    // ---- --tui dashboard ----

    public enum Filter { ALL, CRITICAL, LOW }

    /** Pure dashboard state: filter + simple toggle, testable without a terminal. */
    public static final class DashboardState {
        private Filter filter = Filter.ALL;
        private boolean simple = false;

        public Filter filter() { return filter; }
        public boolean simple() { return simple; }

        /** Apply one keypress: a=all, c=critical only, l=low only, s=toggle simple, q=quit (returns false). */
        public boolean key(char ch) {
            switch (Character.toLowerCase(ch)) {
                case 'a' -> filter = Filter.ALL;
                case 'c' -> filter = Filter.CRITICAL;
                case 'l' -> filter = Filter.LOW;
                case 's' -> simple = !simple;
                case 'q' -> { return false; }
                default -> { /* ignore */ }
            }
            return true;
        }

        public List<Finding> filtered(ScanReport report) {
            return switch (filter) {
                case CRITICAL -> report.findings().stream().filter(Finding::reachable).toList();
                case LOW -> report.findings().stream().filter(f -> !f.reachable()).toList();
                case ALL -> report.findings();
            };
        }
    }

    /** Render one dashboard screen as text (no terminal control codes except optional colour). */
    public static String renderDashboard(ScanReport report, DashboardState state, boolean colour) {
        StringBuilder sb = new StringBuilder();
        String title = colour ? CYAN + BOLD + " DepScan // LIVE DASHBOARD " + RESET : " DepScan // LIVE DASHBOARD ";
        sb.append(title).append("\n");
        sb.append("Project: ").append(report.projectPath()).append("\n");
        sb.append("Stats: ").append(report.dependenciesScanned()).append(" deps | ")
                .append(report.criticalCount()).append(" CRITICAL | ")
                .append(report.lowCount()).append(" LOW | ")
                .append(report.ignoredCount()).append(" ignored\n");
        sb.append("Dependency tree:\n");
        Map<String, List<String>> byGroup = new LinkedHashMap<>();
        for (var d : report.dependencies()) {
            // npm packages have no groupId — they group under "npm".
            byGroup.computeIfAbsent(d.isNpm() ? "npm" : d.groupId(), k -> new ArrayList<>())
                    .add(d.artifactId() + ":" + d.version());
        }
        if (byGroup.isEmpty()) sb.append("  (no dependencies listed)\n");
        for (var e : byGroup.entrySet()) {
            sb.append("  +- ").append(e.getKey()).append("\n");
            for (String a : e.getValue()) sb.append("  |   +- ").append(a).append("\n");
        }
        sb.append("Vulnerabilities [filter: ").append(state.filter()).append("]:\n");
        List<Finding> list = state.filtered(report);
        if (list.isEmpty()) sb.append("  (none match this filter)\n");
        for (Finding f : list) {
            String tag = f.reachable() ? "[!!] CRITICAL" : "[..] LOW";
            if (colour) tag = (f.reachable() ? RED + BOLD : AMBER) + tag + RESET;
            sb.append("  ").append(tag).append(" ").append(f.vulnerability().id())
                    .append(" ").append(f.dependency().coordinates());
            if (!state.simple()) sb.append(" @ ").append(f.location().isBlank() ? "pom.xml" : f.location());
            sb.append("\n");
            if (!state.simple()) sb.append("      ").append(f.upgradeSuggestion()).append("\n");
        }
        sb.append("─".repeat(60)).append("\n");
        sb.append("[a]ll  [c]ritical  [l]ow  [s]imple toggle  [q]uit\n");
        return sb.toString();
    }

    /** Full-screen dashboard loop. Reads single keys from stdin; q quits. Falls back to a static render when stdin is not a TTY. */
    public static void runDashboard(ScanReport report, boolean colour) throws IOException {
        DashboardState state = new DashboardState();
        PrintStream out = System.out;
        if (System.console() == null) {
            out.print(renderDashboard(report, state, colour));
            return;
        }
        out.print(CLEAR);
        out.print(renderDashboard(report, state, colour));
        out.flush();
        int ch;
        while ((ch = System.in.read()) != -1) {
            if (ch == '\n' || ch == '\r') continue;
            if (!state.key((char) ch)) break;
            out.print(CLEAR);
            out.print(renderDashboard(report, state, colour));
            out.flush();
        }
        out.print(CLEAR);
        out.print(new BoxedReporter(colour).render(report));
    }

    private static void sleep(long ms) {
        if (ms <= 0) return;
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    static String amber(String s, boolean colour) { return colour ? AMBER + s + RESET : s; }
    static String green(String s, boolean colour) { return colour ? GREEN + s + RESET : s; }
}
