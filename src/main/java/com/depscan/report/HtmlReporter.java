package com.depscan.report;

import com.depscan.reach.Finding;
import java.time.LocalDate;

/**
 * HTML export (Stage 5). Self-contained single file, no external assets.
 * Theme {@code light} (default) or {@code dark}. Severity is shown as a
 * labelled badge with text, not colour alone, so it stays readable in
 * greyscale / print. Advisory ids link to OSV.dev.
 */
public final class HtmlReporter {

    private HtmlReporter() {}

    public static String render(ScanReport report, String theme, boolean excludeUnreachable) {
        boolean dark = "dark".equalsIgnoreCase(theme);
        double score = RiskScore.score(report);
        var findings = excludeUnreachable
                ? report.findings().stream().filter(Finding::reachable).toList()
                : report.findings();
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
                .append("<title>DepScan report - ").append(esc(report.projectPath())).append("</title><style>")
                .append(dark
                        ? "body{background:#111827;color:#e5e7eb;font-family:Inter,system-ui,sans-serif;margin:40px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #374151;padding:8px;text-align:left}th{background:#1f2937}"
                        : "body{background:#fff;color:#111827;font-family:Inter,system-ui,sans-serif;margin:40px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d1d5db;padding:8px;text-align:left}th{background:#f3f4f6}")
                .append(".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px;border:1px solid currentColor}.crit{color:#b91c1c;background:#fee2e2}.low{color:#92400e;background:#fef3c7}.bar{height:14px;background:#dc2626}.barlow{height:14px;background:#d97706}code{font-family:'JetBrains Mono',monospace}")
                .append("</style></head><body>");
        sb.append("<h1>DepScan report</h1><p>Project: <code>").append(esc(report.projectPath()))
                .append("</code><br>Date: ").append(LocalDate.now())
                .append("<br>Tool: DepScan ").append(com.depscan.cli.Main.VERSION).append("</p>");
        sb.append("<h2>Executive summary</h2><p>").append(report.dependenciesScanned())
                .append(" dependencies scanned. <b>").append(report.criticalCount())
                .append(" CRITICAL (reachable)</b>, ").append(report.lowCount())
                .append(" LOW (unreachable), ").append(report.ignoredCount())
                .append(" ignored. Risk score: <b>").append(score).append(" / 10 (")
                .append(RiskScore.label(score)).append(")</b>.</p>");
        sb.append("<h2>Severity chart</h2><p>CRITICAL ").append(report.criticalCount())
                .append("</p><div class=\"bar\" style=\"width:").append(Math.min(100, report.criticalCount() * 20))
                .append("%\"></div><p>LOW ").append(report.lowCount())
                .append("</p><div class=\"barlow\" style=\"width:").append(Math.min(100, report.lowCount() * 20))
                .append("%\"></div>");
        sb.append("<h2>Findings</h2><table><tr><th>Severity</th><th>Advisory</th><th>Dependency</th><th>Location</th><th>Upgrade</th><th>Summary</th></tr>");
        for (Finding f : findings) {
            sb.append("<tr><td><span class=\"badge ").append(f.reachable() ? "crit" : "low").append("\">")
                    .append(f.severity()).append("</span></td><td><a href=\"https://osv.dev/vulnerability/")
                    .append(esc(f.vulnerability().id())).append("\">").append(esc(f.vulnerability().id()))
                    .append("</a></td><td><code>").append(esc(f.dependency().coordinates()))
                    .append("</code></td><td><code>").append(esc(f.location()))
                    .append("</code></td><td>").append(esc(f.upgradeSuggestion()))
                    .append("</td><td>").append(esc(f.vulnerability().summary())).append("</td></tr>");
        }
        sb.append("</table><h2>Methodology and limitations</h2><p>Static analysis only: DepScan builds a call graph from source with JavaParser and checks reachability with JGraphT. It misses reflection, dynamic dispatch, lambdas passed as callbacks, and code loaded at runtime. Unreachable findings are still shown because shipped code can be exploited another way or become reachable later.</p>");
        sb.append("<h2>Glossary</h2><p><b>CRITICAL</b>: a vulnerable function is reachable from an entry point (main or a public method). <b>LOW</b>: the vulnerable dependency is present but no reachable call into it was found. <b>OSV.dev</b>: the free vulnerability database queried per dependency. <b>SBOM</b>: software bill of materials, a list of every component in the project.</p>");
        sb.append("</body></html>");
        return sb.toString();
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
