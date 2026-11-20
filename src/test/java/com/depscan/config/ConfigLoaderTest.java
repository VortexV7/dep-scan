package com.depscan.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.deps.Dependency;
import com.depscan.osv.Vulnerability;
import com.depscan.reach.Finding;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {

    private static Finding snakeyamlFinding(String id, String... aliases) {
        var vuln = new Vulnerability(id, "test", "CVSS_V3:7.5", 7.5, "1.32",
                List.of(), List.of(), List.of(aliases));
        return new Finding(new Dependency("org.yaml", "snakeyaml", "1.31"), vuln,
                false, "test", List.of());
    }

    @Test
    void loadsValidConfig() throws Exception {
        DepScanConfig cfg = ConfigLoader.load(Path.of("src/test/resources/config/depscan.yml"));
        assertEquals("high", cfg.failOn());
        assertEquals(2, cfg.ignores().size());
        IgnoreRule first = cfg.ignores().get(0);
        assertEquals("CVE-2022-1471", first.id());
        assertEquals("org.yaml:snakeyaml", first.dependency());
        assertEquals(LocalDate.of(2027, 6, 30), first.expires());
        assertTrue(first.reason().contains("tests"));
    }

    @Test
    void ignoreMatchesByAliasAndPackageScope() throws Exception {
        DepScanConfig cfg = ConfigLoader.load(Path.of("src/test/resources/config/depscan.yml"));
        IgnoreRule rule = cfg.ignores().get(0);
        // Finding id is the GHSA, alias is the CVE the rule names.
        assertTrue(rule.matches(snakeyamlFinding("GHSA-mjmj-j48q-9wg2", "CVE-2022-1471")));
        // Same CVE on a different dependency must not match (package scope).
        var other = new Finding(new Dependency("com.other", "lib", "1.0"),
                new Vulnerability("GHSA-x", "t", "", -1, "", List.of(), List.of(), List.of("CVE-2022-1471")),
                false, "t", List.of());
        assertFalse(rule.matches(other));
        // Unscoped rule (second entry) matches by id on any package.
        assertTrue(cfg.ignores().get(1).matches(snakeyamlFinding("GHSA-599f-7c49-w659")));
    }

    @Test
    void expiryIsInclusive() {
        IgnoreRule rule = new IgnoreRule("CVE-2022-1471", "", "reason", LocalDate.of(2026, 12, 31));
        assertFalse(rule.isExpired(LocalDate.of(2026, 12, 30)));
        assertTrue(rule.isExpired(LocalDate.of(2026, 12, 31)));
        assertTrue(rule.isExpired(LocalDate.of(2027, 1, 1)));
    }

    @Test
    void missingReasonIsConfigError() {
        assertThrows(ConfigException.class,
                () -> ConfigLoader.load(Path.of("src/test/resources/config/bad-no-reason.yml")));
    }

    @Test
    void missingExpiresIsConfigError(@TempDir Path dir) throws Exception {
        Path cfg = dir.resolve("depscan.yml");
        Files.writeString(cfg, "ignore:\n  - id: CVE-2022-1471\n    reason: no expiry given\n");
        assertThrows(ConfigException.class, () -> ConfigLoader.load(cfg));
    }

    @Test
    void badDateIsConfigError(@TempDir Path dir) throws Exception {
        Path cfg = dir.resolve("depscan.yml");
        Files.writeString(cfg, "ignore:\n  - id: CVE-2022-1471\n    reason: x\n    expires: 31-12-2026\n");
        assertThrows(ConfigException.class, () -> ConfigLoader.load(cfg));
    }

    @Test
    void missingFileIsConfigError() {
        assertThrows(ConfigException.class, () -> ConfigLoader.load(Path.of("does-not-exist.yml")));
    }

    @Test
    void discoverFindsDepscanYml(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("depscan.yml"),
                "ignore:\n  - id: CVE-1\n    reason: r\n    expires: 2027-01-01\n");
        DepScanConfig cfg = ConfigLoader.discover(dir);
        assertEquals(1, cfg.ignores().size());
        assertEquals(0, ConfigLoader.discover(dir.resolve("empty")).ignores().size());
    }
}
