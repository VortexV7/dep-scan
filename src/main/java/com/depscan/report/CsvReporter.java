package com.depscan.report;

import com.depscan.reach.Finding;

/** CSV export (Stage 5): one row per finding, RFC 4180 quoting. */
public final class CsvReporter {

    private CsvReporter() {}

    public static String render(ScanReport report) {
        StringBuilder sb = new StringBuilder();
        sb.append("severity,advisory,aliases,dependency,version,reachable,location,summary,fixed_version,upgrade_suggestion,evidence\n");
        for (Finding f : report.findings()) {
            sb.append(csv(f.severity())).append(',')
                    .append(csv(f.vulnerability().id())).append(',')
                    .append(csv(String.join(";", f.vulnerability().aliases()))).append(',')
                    .append(csv(f.dependency().osvPackageName())).append(',')
                    .append(csv(f.dependency().version())).append(',')
                    .append(f.reachable()).append(',')
                    .append(csv(f.location())).append(',')
                    .append(csv(f.vulnerability().summary())).append(',')
                    .append(csv(f.vulnerability().fixedVersion())).append(',')
                    .append(csv(f.upgradeSuggestion())).append(',')
                    .append(csv(f.evidence())).append('\n');
        }
        return sb.toString();
    }

    static String csv(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }
}
