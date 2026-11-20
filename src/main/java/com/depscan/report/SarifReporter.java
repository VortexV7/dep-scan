package com.depscan.report;

import com.depscan.reach.Finding;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * SARIF 2.1.0 report (Stage 3) for GitHub code scanning / GitLab / any
 * SARIF consumer. One rule per advisory id, one result per finding:
 * reachable findings are {@code error}, unreachable are {@code warning}.
 * Locations use the finding's file:line (call site, else pom.xml line).
 * The tool driver is {@code DepScan} with the version from
 * {@link com.depscan.cli.Main#VERSION}.
 */
public final class SarifReporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SarifReporter() {}

    public static String render(ScanReport report) throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.put("version", "2.1.0");
        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();
        ObjectNode tool = run.putObject("tool");
        ObjectNode driver = tool.putObject("driver");
        driver.put("name", "DepScan");
        driver.put("version", com.depscan.cli.Main.VERSION);
        driver.put("informationUri", "https://github.com/VortexV7/dep-scan");
        ArrayNode rules = driver.putArray("rules");
        // One rule per distinct advisory id, in first-seen order.
        var seen = new java.util.LinkedHashSet<String>();
        for (Finding f : report.findings()) {
            if (!seen.add(f.vulnerability().id())) continue;
            ObjectNode rule = rules.addObject();
            rule.put("id", f.vulnerability().id());
            rule.put("name", f.vulnerability().id());
            ObjectNode shortDesc = rule.putObject("shortDescription");
            shortDesc.put("text", f.vulnerability().summary());
            ObjectNode fullDesc = rule.putObject("fullDescription");
            fullDesc.put("text", f.vulnerability().summary());
            ObjectNode defCfg = rule.putObject("defaultConfiguration");
            defCfg.put("level", ruleLevel(f));
            ObjectNode help = rule.putObject("help");
            help.put("text", f.vulnerability().summary() + " Fixed in: "
                    + (f.vulnerability().fixedVersion().isBlank() ? "no fix published" : f.vulnerability().fixedVersion()));
            rule.put("helpUri", advisoryUrl(f));
        }
        ArrayNode results = run.putArray("results");
        for (Finding f : report.findings()) {
            ObjectNode result = results.addObject();
            result.put("ruleId", f.vulnerability().id());
            result.put("level", f.reachable() ? "error" : "warning");
            result.put("kind", "fail");
            ObjectNode message = result.putObject("message");
            message.put("text", f.vulnerability().id() + " in " + f.dependency().coordinates()
                    + " (" + f.severity() + "): " + f.vulnerability().summary()
                    + " Evidence: " + f.evidence() + " " + f.upgradeSuggestion());
            ArrayNode locations = result.putArray("locations");
            ObjectNode loc = locations.addObject();
            ObjectNode phys = loc.putObject("physicalLocation");
            ObjectNode artifact = phys.putObject("artifactLocation");
            String[] split = splitLocation(f.location());
            artifact.put("uri", split[0].isBlank() ? "pom.xml" : split[0]);
            ObjectNode region = phys.putObject("region");
            region.put("startLine", Integer.parseInt(split[1]));
            ObjectNode p = result.putObject("properties");
            p.put("dependency", f.dependency().coordinates());
            p.put("reachable", f.reachable());
            p.put("fixedVersion", f.vulnerability().fixedVersion());
        }
        ObjectNode props = run.putObject("properties");
        props.put("project", report.projectPath());
        props.put("dependenciesScanned", report.dependenciesScanned());
        props.put("critical", report.criticalCount());
        props.put("low", report.lowCount());
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    private static String ruleLevel(Finding f) {
        return f.reachable() ? "error" : "warning";
    }

    /** Advisory URL: OSV for GHSA ids, CVE database for CVE ids. */
    static String advisoryUrl(Finding f) {
        String id = f.vulnerability().id();
        if (id.startsWith("CVE-")) return "https://cveawg.mitre.org/api/cve/" + id;
        if (!f.vulnerability().aliases().isEmpty()) {
            for (String a : f.vulnerability().aliases()) {
                if (a.startsWith("CVE-")) return "https://cveawg.mitre.org/api/cve/" + a;
            }
        }
        return "https://osv.dev/vulnerability/" + id;
    }

    /** Split "path/File.java:10" into [file, "10"]; missing line -> "1", missing file -> "pom.xml" handled by caller. */
    public static String[] splitLocation(String location) {
        if (location == null || location.isBlank()) return new String[]{"pom.xml", "1"};
        int colon = location.lastIndexOf(':');
        if (colon > 0) {
            String line = location.substring(colon + 1).trim();
            if (!line.isEmpty() && line.chars().allMatch(Character::isDigit)) {
                return new String[]{location.substring(0, colon), line};
            }
        }
        return new String[]{location, "1"};
    }
}
