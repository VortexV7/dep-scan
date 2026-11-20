package com.depscan.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Machine-readable JSON report (for CI / piping). */
public final class JsonReporter {

    private final ObjectMapper mapper = new ObjectMapper();

    public String render(ScanReport report) throws Exception {
        ObjectNode root = mapper.createObjectNode();
        root.put("project", report.projectPath());
        root.put("dependenciesScanned", report.dependenciesScanned());
        root.put("critical", report.criticalCount());
        root.put("low", report.lowCount());
        root.put("ignored", report.ignoredCount());
        root.put("usedStaleCache", report.usedStaleCache());
        ArrayNode notes = root.putArray("configNotes");
        report.configNotes().forEach(notes::add);
        ArrayNode findings = root.putArray("findings");
        for (var f : report.findings()) {
            findings.add(findingNode(f));
        }
        ArrayNode ignored = root.putArray("ignoredFindings");
        for (var ig : report.ignoredFindings()) {
            ObjectNode n = findingNode(ig.finding());
            n.put("ignoreReason", ig.rule().reason());
            n.put("ignoreExpires", ig.rule().expires() == null ? "" : ig.rule().expires().toString());
            n.put("ignoreId", ig.rule().id());
            ignored.add(n);
        }
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    private ObjectNode findingNode(com.depscan.reach.Finding f) {
        ObjectNode n = mapper.createObjectNode();
        n.put("id", f.vulnerability().id());
        ArrayNode aliases = n.putArray("aliases");
        f.vulnerability().aliases().forEach(aliases::add);
        n.put("dependency", f.dependency().coordinates());
        n.put("package", f.dependency().osvPackageName());
        n.put("version", f.dependency().version());
        n.put("severity", f.severity());
        n.put("reachable", f.reachable());
        n.put("summary", f.vulnerability().summary());
        n.put("cvss", f.vulnerability().cvssScore());
        n.put("vulnerabilitySeverity", f.vulnerability().severity());
        n.put("fixedVersion", f.vulnerability().fixedVersion());
        n.put("location", f.location());
        n.put("upgradeSuggestion", f.upgradeSuggestion());
        n.put("upgradeIsMajorBump", f.upgradeIsMajorBump());
        n.put("evidence", f.evidence());
        ArrayNode chain = n.putArray("callChain");
        f.callChain().forEach(chain::add);
        return n;
    }
}
