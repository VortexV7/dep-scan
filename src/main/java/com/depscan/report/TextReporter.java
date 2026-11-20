package com.depscan.report;

import com.depscan.reach.Finding;
import org.fusesource.jansi.Ansi;

/**
 * Plain text report ({@code --simple}): same data as the boxed report,
 * no boxes. Colour is disabled when output is not a TTY.
 */
public final class TextReporter {

    private final boolean colour;

    public TextReporter(boolean colour) {
        this.colour = colour;
    }

    public String render(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("DepScan - ").append(report.projectPath()).append("\n");
        sb.append("Dependencies scanned: ").append(report.dependenciesScanned()).append("\n");
        if (report.usedStaleCache()) {
            sb.append("Note: some OSV responses came from a stale cache (offline / network failure).\n");
        }
        for (String s : report.skippedDependencies()) {
            sb.append("Skipped: ").append(s).append("\n");
        }
        for (String n : report.configNotes()) {
            sb.append("Note: ").append(n).append("\n");
        }
        sb.append("\n");
        if (report.findings().isEmpty() && report.ignoredFindings().isEmpty()) {
            sb.append("No known vulnerabilities found.\n");
            return sb.toString();
        }
        for (Finding f : report.findings()) {
            appendFinding(sb, f);
        }
        for (IgnoredFinding ig : report.ignoredFindings()) {
            Finding f = ig.finding();
            sb.append("[--] IGNORED  ").append(f.dependency().coordinates()).append("\n");
            sb.append("  Advisory: ").append(f.vulnerability().id());
            if (!f.vulnerability().aliases().isEmpty()) {
                sb.append(" (").append(String.join(", ", f.vulnerability().aliases())).append(")");
            }
            sb.append("\n");
            sb.append("  Ignored because: ").append(ig.rule().reason()).append("\n");
            sb.append("  Expires: ").append(ig.rule().expires()).append("\n");
            sb.append("  Upgrade: ").append(f.upgradeSuggestion()).append("\n\n");
        }
        sb.append("Summary: ").append(report.criticalCount()).append(" CRITICAL (reachable), ")
                .append(report.lowCount()).append(" LOW (unreachable, still shown)");
        if (report.ignoredCount() > 0) sb.append(", ").append(report.ignoredCount()).append(" ignored");
        sb.append(".\n");
        return sb.toString();
    }

    private void appendFinding(StringBuilder sb, Finding f) {
        String tag = f.reachable() ? "[!!] CRITICAL" : "[..] LOW";
        String coloured = colour
                ? (f.reachable()
                        ? Ansi.ansi().fgRed().bold().a(tag).reset().toString()
                        : Ansi.ansi().fgYellow().a(tag).reset().toString())
                : tag;
        sb.append(coloured).append("  ").append(f.dependency().coordinates()).append("\n");
        sb.append("  Advisory: ").append(f.vulnerability().id());
        if (!f.vulnerability().aliases().isEmpty()) {
            sb.append(" (").append(String.join(", ", f.vulnerability().aliases())).append(")");
        }
        sb.append("\n");
        if (!f.location().isBlank()) sb.append("  Location: ").append(f.location()).append("\n");
        sb.append("  ").append(f.vulnerability().summary()).append("\n");
        if (!f.vulnerability().severity().isBlank()) {
            sb.append("  Severity: ").append(f.vulnerability().severity()).append("\n");
        }
        sb.append("  Upgrade: ").append(f.upgradeSuggestion()).append("\n");
        sb.append("  Evidence: ").append(f.evidence()).append("\n");
        if (f.reachable() && !f.callChain().isEmpty()) {
            sb.append("  Call chain:\n");
            for (String step : f.callChain()) {
                sb.append("    ").append(step).append("\n");
            }
        }
        sb.append("\n");
    }
}
