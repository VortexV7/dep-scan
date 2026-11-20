package com.depscan.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NpmParserTest {

    private static Path writePkg(Path dir, String pkgJson, String lockJson) throws Exception {
        Path pkg = dir.resolve("package.json");
        Files.writeString(pkg, pkgJson);
        if (lockJson != null) Files.writeString(dir.resolve("package-lock.json"), lockJson);
        return pkg;
    }

    @Test
    void lockfileV3PinsExactVersion(@TempDir Path dir) throws Exception {
        Path pkg = writePkg(dir,
                "{\"dependencies\": {\"lodash\": \"^4.17.20\"}, \"devDependencies\": {\"minimist\": \"^1.2.5\"}}",
                "{\"lockfileVersion\": 3, \"packages\": {"
                        + "\"node_modules/lodash\": {\"version\": \"4.17.21\"}, "
                        + "\"node_modules/minimist\": {\"version\": \"1.2.8\"}}}");
        var r = NpmParser.parse(pkg);
        assertEquals(2, r.dependencies().size());
        assertEquals("4.17.21", r.dependencies().get(0).version());
        assertEquals("1.2.8", r.dependencies().get(1).version());
        assertTrue(r.approximateVersions().isEmpty(), "lockfile pins are exact, not approximate");
        assertTrue(r.skipped().isEmpty());
    }

    @Test
    void lockfileV1PinsExactVersion(@TempDir Path dir) throws Exception {
        Path pkg = writePkg(dir,
                "{\"dependencies\": {\"lodash\": \"^4.17.20\"}}",
                "{\"lockfileVersion\": 1, \"dependencies\": {\"lodash\": {\"version\": \"4.17.20\"}}}");
        var r = NpmParser.parse(pkg);
        assertEquals("4.17.20", r.dependencies().get(0).version());
        assertTrue(r.approximateVersions().isEmpty());
    }

    @Test
    void noLockfileUsesRangeMinimumAndFlagsApproximate(@TempDir Path dir) throws Exception {
        Path pkg = writePkg(dir, "{\"dependencies\": {\"lodash\": \"^4.17.20\", \"minimist\": \"~1.2.5\"}}", null);
        var r = NpmParser.parse(pkg);
        assertEquals("4.17.20", r.dependencies().get(0).version());
        assertEquals("1.2.5", r.dependencies().get(1).version());
        assertEquals(2, r.approximateVersions().size());
        assertTrue(r.approximateVersions().get("lodash").contains("^4.17.20"));
    }

    @Test
    void unresolvableRangesAreSkippedNeverGuessed(@TempDir Path dir) throws Exception {
        Path pkg = writePkg(dir,
                "{\"dependencies\": {\"a\": \"latest\", \"b\": \"*\", \"c\": \"file:../c\", \"d\": \"^1.0.0 || ^2.0.0\", \"e\": \"^1.2.3\"}}",
                null);
        var r = NpmParser.parse(pkg);
        assertEquals(1, r.dependencies().size(), "only the resolvable range survives");
        assertEquals("e", r.dependencies().get(0).osvPackageName());
        assertEquals(4, r.skipped().size());
    }

    @Test
    void scopedPackageAndDeclarationLocation(@TempDir Path dir) throws Exception {
        Path pkg = writePkg(dir,
                "{\n  \"dependencies\": {\n    \"@babel/core\": \"^7.0.0\",\n    \"lodash\": \"^4.17.20\"\n  }\n}",
                "{\"lockfileVersion\": 3, \"packages\": {\"node_modules/@babel/core\": {\"version\": \"7.24.0\"}}}");
        var r = NpmParser.parse(pkg);
        assertEquals("7.24.0", r.dependencies().get(0).version());
        assertEquals("@babel/core", r.dependencies().get(0).osvPackageName());
        assertEquals("package.json:3", r.declarationLocations().get("@babel/core"));
        assertEquals("package.json:4", r.declarationLocations().get("lodash"));
    }

    @Test
    void rangeMinimumCases() {
        assertEquals("4.17.20", NpmParser.rangeMinimum("^4.17.20"));
        assertEquals("1.2.5", NpmParser.rangeMinimum("~1.2.5"));
        assertEquals("1.0.0", NpmParser.rangeMinimum(">=1.0.0 <2.0.0"));
        assertEquals("1.2.0", NpmParser.rangeMinimum("1.2.x"));
        assertEquals("2.0.0", NpmParser.rangeMinimum("2.x"));
        assertEquals(null, NpmParser.rangeMinimum("latest"));
        assertEquals(null, NpmParser.rangeMinimum("*"));
        assertEquals(null, NpmParser.rangeMinimum("<2.0.0"));
        assertEquals(null, NpmParser.rangeMinimum("file:../local"));
        assertEquals(null, NpmParser.rangeMinimum("^1.0.0 || ^2.0.0"));
    }
}
