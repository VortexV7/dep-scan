package com.depscan.report;

import com.depscan.reach.Finding;
import java.util.ArrayList;
import java.util.List;
import org.fusesource.jansi.Ansi;

/**
 * Boxed, colour-coded report — the default output.
 *
 * <p>RED {@code [!!] CRITICAL} for reachable findings, YELLOW {@code [..] LOW}
 * for unreachable ones. Each finding is one box with package, version,
 * advisory id, file:line, upgrade suggestion, evidence and call chain.
 * Colour is applied only to the header tag and the box border; wrapping is
 * done on plain text first so ANSI codes never break the box width.
 */
public final class BoxedReporter {

    private static final int INNER = 76;

    private final boolean colour;

    public BoxedReporter(boolean colour) {
        this.colour = colour;
    }

    public String render(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        // Title box.
        List<String> title = new ArrayList<>();
        title.add("DepScan - " + report.projectPath());
        title.add("Dependencies scanned: " + report.dependenciesScanned());
        if (report.usedStaleCache()) {
            title.add("Note: some OSV responses came from a stale cache (offline / network failure).");
        }
        for (String s : report.skippedDependencies()) title.add("Skipped: " + s);
        for (String n : report.configNotes()) title.add("Note: " + n);
        sb.append(box(title, null)).append("\n");

        if (report.findings().isEmpty() && report.ignoredFindings().isEmpty()) {
            sb.append(box(List.of("No known vulnerabilities found."), null)).append("\n");
        }
        for (Finding f : report.findings()) {
            sb.append(box(findingLines(f), f.reachable() ? Ansi.Color.RED : Ansi.Color.YELLOW)).append("\n");
        }
        for (IgnoredFinding ig : report.ignoredFindings()) {
            Finding f = ig.finding();
            List<String> lines = new ArrayList<>();
            lines.add("[--] IGNORED  " + f.dependency().coordinates());
            lines.add("Advisory: " + advisoryLabel(f));
            if (!f.location().isBlank()) lines.add("Location: " + f.location());
            lines.add("Ignored because: " + ig.rule().reason());
            lines.add("Expires: " + ig.rule().expires() + " (finding counts normally after this date)");
            lines.add("Upgrade: " + f.upgradeSuggestion());
            sb.append(box(lines, null)).append("\n");
        }
        sb.append("Summary: ").append(report.criticalCount()).append(" CRITICAL (reachable), ")
                .append(report.lowCount()).append(" LOW (unreachable, still shown)");
        if (report.ignoredCount() > 0) sb.append(", ").append(report.ignoredCount()).append(" ignored");
        sb.append(".\n");
        return sb.toString();
    }

    private List<String> findingLines(Finding f) {
        List<String> lines = new ArrayList<>();
        String tag = f.reachable() ? "[!!] CRITICAL" : "[..] LOW";
        String header = tag + "  " + f.dependency().coordinates();
        if (colour) {
            header = (f.reachable()
                    ? Ansi.ansi().fgRed().bold().a(tag).reset().toString()
                    : Ansi.ansi().fgYellow().bold().a(tag).reset().toString())
                    + "  " + f.dependency().coordinates();
        }
        // Header is added raw (it already contains ANSI codes); wrap the rest.
        lines.add("\u0000HEADER\u0000" + header);
        lines.add("Advisory: " + advisoryLabel(f));
        if (!f.location().isBlank()) lines.add("Location: " + f.location());
        if (!f.vulnerability().severity().isBlank()) lines.add("Severity: " + f.vulnerability().severity());
        lines.add("Upgrade: " + f.upgradeSuggestion());
        lines.addAll(wrap("Summary: " + f.vulnerability().summary()));
        lines.addAll(wrap("Evidence: " + f.evidence()));
        if (f.reachable() && !f.callChain().isEmpty()) {
            lines.add("Call chain:");
            for (String step : f.callChain()) lines.addAll(wrap("  " + step));
        }
        return lines;
    }

    private static String advisoryLabel(Finding f) {
        String label = f.vulnerability().id();
        if (!f.vulnerability().aliases().isEmpty()) {
            label += " (" + String.join(", ", f.vulnerability().aliases()) + ")";
        }
        return label;
    }

    /** Render one box. Lines may contain a "\u0000HEADER\u0000" prefix (raw, pre-coloured, already fits). */
    private String box(List<String> rawLines, Ansi.Color borderColour) {
        List<String> lines = new ArrayList<>();
        for (String raw : rawLines) {
            if (raw.startsWith("\u0000HEADER\u0000")) {
                lines.add(raw.substring("\u0000HEADER\u0000".length()));
            } else {
                lines.addAll(wrap(raw));
            }
        }
        String top = "┌" + "─".repeat(INNER + 2) + "┐";
        String bottom = "└" + "─".repeat(INNER + 2) + "┘";
        StringBuilder sb = new StringBuilder();
        sb.append(colourLine(top, borderColour)).append("\n");
        for (String line : lines) {
            String plain = stripAnsi(line);
            String padded = plain + " ".repeat(Math.max(0, INNER - plain.length()));
            // Rebuild with the coloured content if it had ANSI codes: pad on the plain length.
            String content = line.length() == plain.length() ? padded
                    : line + " ".repeat(Math.max(0, INNER - plain.length()));
            sb.append(colourLine("│ " + content + " │", borderColour)).append("\n");
        }
        sb.append(colourLine(bottom, borderColour));
        return sb.toString();
    }

    private String colourLine(String line, Ansi.Color borderColour) {
        if (!colour || borderColour == null) return line;
        return Ansi.ansi().fg(borderColour).a(line).reset().toString();
    }

    private static String stripAnsi(String s) {
        return s.replaceAll("\u001B\\[[0-9;]*m", "");
    }

    /** Word-wrap plain text to INNER columns, keeping a leading indent on continuation lines. */
    static List<String> wrap(String text) {
        List<String> out = new ArrayList<>();
        if (text == null || text.isBlank()) {
            out.add("");
            return out;
        }
        String indent = "";
        if (text.startsWith("  ")) indent = "  ";
        String[] words = text.trim().split("\\s+");
        StringBuilder cur = new StringBuilder(indent);
        for (String w : words) {
            if (cur.length() > indent.length() && cur.length() + 1 + w.length() > INNER) {
                out.add(cur.toString());
                cur = new StringBuilder(indent).append(w);
            } else {
                if (cur.length() > indent.length()) cur.append(' ');
                cur.append(w);
            }
        }
        out.add(cur.toString());
        return out;
    }
}
