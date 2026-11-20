package com.depscan.ci;

import com.depscan.reach.Finding;
import com.depscan.report.ScanReport;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;

/**
 * GitHub Actions integration (Stage 3): workflow-command annotations and
 * the job step summary.
 *
 * <p>Annotations go to stderr so stdout stays clean for {@code --json} /
 * {@code --format sarif} piping. Format (GitHub docs):
 * {@code ::error file={file},line={line}::{message}} and the same with
 * {@code ::warning}. File/line come from the finding's location
 * ({@code src/.../Foo.java:10} or {@code pom.xml:27}); a location without a
 * line falls back to line 1, a missing location to {@code pom.xml}.
 *
 * <p>The step summary is a Markdown table appended to the file named by
 * {@code $GITHUB_STEP_SUMMARY}. Nothing is written when that variable is
 * absent (e.g. local runs) — the method then returns false.
 */
public final class GitHubActions {

    private GitHubActions() {}

    /** One annotation line for a finding, or "" when annotations are disabled. */
    public static String annotation(Finding f) {
        String[] loc = splitLocation(f.location());
        String file = loc[0].isBlank() ? "pom.xml" : loc[0];
        String line = loc[1];
        String level = f.reachable() ? "error" : "warning";
        String message = escape(f.vulnerability().id() + " (" + f.dependency().coordinates() + "): "
                + f.vulnerability().summary() + " - " + f.upgradeSuggestion());
        return "::" + level + " file=" + escapeProperty(file) + ",line=" + line + "::" + message;
    }

    /** Emit one annotation per finding to stderr. Returns the count emitted. */
    public static int emitAnnotations(ScanReport report) {
        return emitAnnotations(report, System.err);
    }

    static int emitAnnotations(ScanReport report, java.io.PrintStream err) {
        int n = 0;
        for (Finding f : report.findings()) {
            err.println(annotation(f));
            n++;
        }
        return n;
    }

    /** Append the Markdown summary table to $GITHUB_STEP_SUMMARY. False when unset / unwritable. */
    public static boolean writeStepSummary(ScanReport report) {
        return writeStepSummary(report, System.getenv());
    }

    public static boolean writeStepSummary(ScanReport report, Map<String, String> env) {
        String path = env.get("GITHUB_STEP_SUMMARY");
        if (path == null || path.isBlank()) return false;
        try {
            Files.writeString(Path.of(path), markdownSummary(report),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** The Markdown table itself — pure, testable, no env access. */
    public static String markdownSummary(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("## DepScan report\n\n");
        sb.append("**").append(report.criticalCount()).append(" CRITICAL (reachable), ")
                .append(report.lowCount()).append(" LOW (unreachable), ")
                .append(report.ignoredCount()).append(" ignored** — ")
                .append(report.dependenciesScanned()).append(" dependencies scanned.\n\n");
        if (report.findings().isEmpty()) {
            sb.append("No known vulnerabilities found.\n");
            return sb.toString();
        }
        sb.append("| Severity | Advisory | Dependency | Location | Upgrade |\n");
        sb.append("|---|---|---|---|---|\n");
        for (Finding f : report.findings()) {
            sb.append("| ").append(f.reachable() ? "CRITICAL" : "LOW")
                    .append(" | ").append(f.vulnerability().id());
            if (!f.vulnerability().aliases().isEmpty()) {
                sb.append(" (").append(String.join(", ", f.vulnerability().aliases())).append(")");
            }
            sb.append(" | ").append(f.dependency().coordinates())
                    .append(" | ").append(f.location().isBlank() ? "-" : f.location())
                    .append(" | ").append(f.vulnerability().fixedVersion().isBlank()
                            ? "no fix published" : f.vulnerability().fixedVersion())
                    .append(" |\n");
        }
        return sb.toString();
    }

    /** Split "path/to/File.java:10" into [file, line]; line defaults to "1", missing file to "pom.xml". */
    static String[] splitLocation(String location) {
        if (location == null || location.isBlank()) return new String[]{"pom.xml", "1"};
        int colon = location.lastIndexOf(':');
        if (colon > 0) {
            String line = location.substring(colon + 1).trim();
            if (line.chars().allMatch(Character::isDigit)) {
                return new String[]{location.substring(0, colon), line};
            }
        }
        return new String[]{location, "1"};
    }

    private static String escape(String s) {
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A");
    }

    private static String escapeProperty(String s) {
        return escape(s).replace(":", "%3A").replace(",", "%2C");
    }
}
