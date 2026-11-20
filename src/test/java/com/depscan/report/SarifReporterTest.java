package com.depscan.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.ci.GitHubActionsTest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class SarifReporterTest {

    @Test
    void sarifIsValid210WithErrorAndWarningLevels() throws Exception {
        String json = SarifReporter.render(GitHubActionsTest.sampleReport());
        JsonNode root = new ObjectMapper().readTree(json);
        assertEquals("2.1.0", root.path("version").asText());
        assertEquals("https://json.schemastore.org/sarif-2.1.0.json", root.path("$schema").asText());
        JsonNode run = root.path("runs").get(0);
        assertEquals("DepScan", run.path("tool").path("driver").path("name").asText());
        assertEquals("0.5.0", run.path("tool").path("driver").path("version").asText());
        assertEquals(2, run.path("tool").path("driver").path("rules").size());
        JsonNode results = run.path("results");
        assertEquals(2, results.size());
        assertEquals("error", results.get(0).path("level").asText());
        assertEquals("warning", results.get(1).path("level").asText());
        assertEquals("GHSA-599f-7c49-w659", results.get(0).path("ruleId").asText());
        JsonNode loc = results.get(0).path("locations").get(0).path("physicalLocation");
        assertEquals("src/main/java/com/example/app/InterpolatorService.java", loc.path("artifactLocation").path("uri").asText());
        assertEquals(10, loc.path("region").path("startLine").asInt());
        assertEquals("pom.xml", results.get(1).path("locations").get(0).path("physicalLocation").path("artifactLocation").path("uri").asText());
        assertEquals(27, results.get(1).path("locations").get(0).path("physicalLocation").path("region").path("startLine").asInt());
    }

    @Test
    void splitLocationHandlesMissingLine() {
        assertEquals("pom.xml", SarifReporter.splitLocation("")[0]);
        assertEquals("1", SarifReporter.splitLocation("pom.xml")[1]);
        assertEquals("10", SarifReporter.splitLocation("a/b.java:10")[1]);
    }
}
