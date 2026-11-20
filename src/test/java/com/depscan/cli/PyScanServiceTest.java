package com.depscan.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.osv.OsvClient;
import com.depscan.osv.Vulnerability;
import com.depscan.report.ScanReport;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PyScanServiceTest {

    private static OsvClient fakeOsv() {
        Map<String, List<Vulnerability>> canned = Map.of(
                "pypi:pyyaml:5.3.1", List.of(
                        new Vulnerability("GHSA-8q59-q68h-6hv4", "Improper Input Validation in PyYAML",
                                "HIGH", 7.5, "5.4", List.of(), List.of(), List.of("CVE-2020-14343"))),
                "pypi:flask:2.0.1", List.of(
                        new Vulnerability("GHSA-68rp-wp8r-4726", "Flask session Vary header",
                                "MEDIUM", 5.3, "3.1.3", List.of(), List.of(), List.of())));
        return dep -> canned.getOrDefault(dep.coordinates(), List.of());
    }

    @Test
    void samplePythonAppPyyamlReachableFlaskNot() throws Exception {
        ScanReport r = new ScanService(fakeOsv()).scan(Path.of("samples/vulnerable-python-app"));
        assertEquals(2, r.findings().size(), r.findings().toString());
        assertEquals(1, r.criticalCount());
        assertEquals(2, r.dependenciesScanned(), "pyyaml + flask");
        var crit = r.findings().stream().filter(f -> f.reachable()).findFirst().orElseThrow();
        assertEquals("GHSA-8q59-q68h-6hv4", crit.vulnerability().id());
        assertTrue(crit.dependency().isPython());
        assertEquals("pypi:pyyaml:5.3.1", crit.dependency().coordinates());
        assertTrue(crit.location().contains("app.py:3"), "import site (import yaml is line 3), got: " + crit.location());
        assertTrue(crit.evidence().contains("PACKAGE"), crit.evidence());
        var low = r.findings().stream().filter(f -> !f.reachable()).findFirst().orElseThrow();
        assertEquals("GHSA-68rp-wp8r-4726", low.vulnerability().id());
        assertTrue(low.location().contains("requirements.txt"), "unreachable points at the manifest, got: " + low.location());
    }

    @Test
    void pyprojectOnlyProjectIsDetected() throws Exception {
        var dir = Files.createTempDirectory("py-only");
        Files.writeString(dir.resolve("pyproject.toml"),
                "[project]\ndependencies = [\"pyyaml==5.3.1\"]\n");
        Files.writeString(dir.resolve("app.py"), "import yaml\nprint(yaml.safe_load('a: 1'))\n");
        ScanReport r = new ScanService(fakeOsv()).scan(dir);
        assertEquals(1, r.findings().size(), r.findings().toString());
        assertEquals(1, r.criticalCount());
        assertTrue(r.findings().get(0).location().contains("app.py:1"));
    }

    @Test
    void allThreeEcosystemsMergeIntoOneReport() throws Exception {
        // A folder with pom.xml + package.json + requirements.txt scans all
        // three; the Maven sample plus a package.json and requirements.txt
        // next to it must not error and must merge.
        var dir = Files.createTempDirectory("three-eco");
        Files.copy(Path.of("samples/vulnerable-app/pom.xml"), dir.resolve("pom.xml"));
        Files.copy(Path.of("samples/vulnerable-npm-app/package.json"), dir.resolve("package.json"));
        Files.copy(Path.of("samples/vulnerable-npm-app/package-lock.json"), dir.resolve("package-lock.json"));
        Files.copy(Path.of("samples/vulnerable-npm-app/index.js"), dir.resolve("index.js"));
        Files.copy(Path.of("samples/vulnerable-python-app/requirements.txt"), dir.resolve("requirements.txt"));
        Files.copy(Path.of("samples/vulnerable-python-app/app.py"), dir.resolve("app.py"));
        Files.createDirectories(dir.resolve("src/main/java/com/example/app"));
        for (String f : List.of("App.java", "InterpolatorService.java", "UnusedHelper.java")) {
            Files.copy(Path.of("samples/vulnerable-app/src/main/java/com/example/app/" + f),
                    dir.resolve("src/main/java/com/example/app/" + f));
        }
        OsvClient all = dep -> {
            if (dep.coordinates().startsWith("npm:")) {
                return dep.coordinates().equals("npm:lodash:4.17.20") ? List.of(
                        new Vulnerability("GHSA-29mw-wpgm-hmr9", "ReDoS in lodash", "HIGH", 7.5,
                                "4.17.21", List.of(), List.of(), List.of("CVE-2020-8203")))
                        : List.of();
            }
            if (dep.coordinates().startsWith("pypi:")) return fakeOsv().query(dep);
            if (dep.coordinates().equals("org.apache.commons:commons-text:1.9")) return List.of(
                    new Vulnerability("GHSA-599f-7c49-w659", "Text4Shell", "CVSS_V3:9.8", 9.8,
                            "1.10.0", List.of(), List.of("org.apache.commons.text.StringSubstitutor.createInterpolator")));
            if (dep.coordinates().equals("org.yaml:snakeyaml:1.31")) return List.of(
                    new Vulnerability("GHSA-9w3m-gqgf-c4p9", "SnakeYAML", "CVSS_V3:7.5", 7.5,
                            "1.32", List.of(), List.of()));
            return List.of();
        };
        ScanReport r = new ScanService(all).scan(dir);
        assertTrue(r.findings().stream().anyMatch(f -> f.dependency().isNpm()), "npm findings present");
        assertTrue(r.findings().stream().anyMatch(f -> f.dependency().isPython()), "Python findings present");
        assertTrue(r.findings().stream().anyMatch(f -> !f.dependency().isNpm() && !f.dependency().isPython()),
                "Maven findings present");
        assertEquals(3, r.criticalCount(), "commons-text + lodash + pyyaml reachable");
    }

    @Test
    void folderWithNoManifestErrorsNamingAllThree() {
        var dir = Path.of(System.getProperty("java.io.tmpdir"));
        var ex = org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
                () -> new ScanService(fakeOsv()).scan(dir));
        assertTrue(ex.getMessage().contains("pom.xml"), ex.getMessage());
        assertTrue(ex.getMessage().contains("package.json"), ex.getMessage());
        assertTrue(ex.getMessage().contains("requirements.txt"), ex.getMessage());
        assertTrue(ex.getMessage().contains("pyproject.toml"), ex.getMessage());
    }
}
