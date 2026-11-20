package com.depscan.report;

import com.depscan.deps.Dependency;
import com.depscan.reach.Finding;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.UUID;

/**
 * CycloneDX 1.6 SBOM (JSON) export (Stage 5). Components are the scanned
 * direct dependencies; vulnerabilities are the findings (reachable ones
 * rated critical, unreachable ones low). Generated with Jackson rather
 * than the CycloneDX library so the output is stable and dependency-free
 * at runtime; the shape follows the CycloneDX 1.6 JSON schema.
 */
public final class SbomReporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SbomReporter() {}

    public static String render(ScanReport report) throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.6");
        root.put("serialNumber", "urn:uuid:" + UUID.randomUUID());
        root.put("version", 1);
        ObjectNode metadata = root.putObject("metadata");
        metadata.put("timestamp", java.time.Instant.now().toString());
        ObjectNode tool = metadata.putArray("tools").addObject();
        tool.put("vendor", "DepScan");
        tool.put("name", "DepScan");
        tool.put("version", com.depscan.cli.Main.VERSION);
        ArrayNode components = root.putArray("components");
        for (Dependency d : report.dependencies()) {
            ObjectNode c = components.addObject();
            c.put("type", "library");
            c.put("bom-ref", d.osvPackageName() + "@" + d.version());
            if (!d.isNpm()) c.put("group", d.groupId());
            c.put("name", d.artifactId());
            c.put("version", d.version());
            c.put("purl", d.isNpm()
                    ? "pkg:npm/" + d.artifactId().replace("/", "%2F") + "@" + d.version()
                    : "pkg:maven/" + d.groupId() + "/" + d.artifactId() + "@" + d.version());
        }
        ArrayNode vulns = root.putArray("vulnerabilities");
        for (Finding f : report.findings()) {
            ObjectNode v = vulns.addObject();
            v.put("bom-ref", f.vulnerability().id());
            v.put("id", f.vulnerability().id());
            ObjectNode source = v.putObject("source");
            source.put("name", "OSV.dev");
            source.put("url", "https://osv.dev/vulnerability/" + f.vulnerability().id());
            ArrayNode ratings = v.putArray("ratings");
            ObjectNode rating = ratings.addObject();
            rating.put("severity", f.reachable() ? "critical" : "low");
            if (f.vulnerability().cvssScore() >= 0) rating.put("score", f.vulnerability().cvssScore());
            v.put("description", f.vulnerability().summary());
            ObjectNode affects = v.putObject("affects");
            ArrayNode refs = affects.putArray("refs");
            refs.add(f.dependency().osvPackageName() + "@" + f.dependency().version());
            ObjectNode analysis = v.putObject("analysis");
            analysis.put("state", f.reachable() ? "exploitable" : "not_affected");
            analysis.put("justification", f.evidence());
        }
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }
}
