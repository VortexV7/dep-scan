package com.depscan.osv;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.deps.Dependency;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OsvClientTest {

    @Test
    void parsesCannedOsvResponse() throws Exception {
        String json = Files.readString(Path.of("src/test/resources/osv/commons-text-1.9.json"));
        var client = new HttpOsvClient(new OsvCache(Path.of("target/test-cache")), true);
        List<Vulnerability> vulns = client.parse(json, new Dependency("org.apache.commons", "commons-text", "1.9"));
        assertEquals(1, vulns.size());
        Vulnerability v = vulns.get(0);
        assertEquals("GHSA-599f-7c49-w659", v.id());
        assertEquals(List.of("CVE-2022-42889"), v.aliases());
        assertEquals(9.8, v.cvssScore(), 0.001);
        assertEquals("1.10.0", v.fixedVersion());
        assertTrue(v.hasFunctionData());
        assertEquals(List.of("org.apache.commons.text.StringSubstitutor.createInterpolator"), v.affectedFunctions());
    }

    @Test
    void emptyResponseMeansNoVulns() throws Exception {
        var client = new HttpOsvClient(new OsvCache(Path.of("target/test-cache")), true);
        List<Vulnerability> vulns = client.parse("{}", new Dependency("com.example", "safe", "1.0"));
        assertTrue(vulns.isEmpty());
    }

    @Test
    void versionRangeCheck() {
        assertTrue(VersionRange.isAffected("1.9", "1.5", "1.10.0", null));
        assertTrue(VersionRange.isAffected("1.10.0", "1.5", "1.10.0", null) == false);
        assertTrue(VersionRange.isAffected("1.4", "1.5", "1.10.0", null) == false);
        assertTrue(VersionRange.isAffected("1.10", "1.5", "1.9", null) == false); // 1.10 > 1.9, Maven ordering
    }

    @Test
    void cacheRoundTrip(@TempDir Path dir) throws Exception {
        OsvCache cache = new OsvCache(dir);
        String key = "org.apache.commons:commons-text:1.9";
        assertTrue(cache.readFresh(key).isEmpty());
        cache.write(key, "{\"vulns\":[]}");
        assertEquals("{\"vulns\":[]}", cache.readFresh(key).orElseThrow());
        assertEquals("{\"vulns\":[]}", cache.readStale(key).orElseThrow());
    }
}
