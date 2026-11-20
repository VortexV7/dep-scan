package com.depscan.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PomParserTest {

    @Test
    void resolvesPropertiesAndDependencyManagement(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0</version>
                  <properties><lib.version>1.9</lib.version></properties>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.31</version></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${lib.version}</version></dependency>
                    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId></dependency>
                    <dependency><groupId>com.example</groupId><artifactId>no-version</artifactId></dependency>
                  </dependencies>
                </project>""");
        PomParser.ParseResult r = PomParser.parse(pom);
        assertEquals(2, r.dependencies().size());
        assertEquals("org.apache.commons:commons-text:1.9", r.dependencies().get(0).coordinates());
        assertEquals("org.yaml:snakeyaml:1.31", r.dependencies().get(1).coordinates());
        assertEquals(1, r.skipped().size());
        assertTrue(r.skipped().get(0).contains("no-version"));
    }

    @Test
    void parsesSamplePom() throws Exception {
        Path pom = Path.of("samples/vulnerable-app/pom.xml");
        PomParser.ParseResult r = PomParser.parse(pom);
        assertEquals(2, r.dependencies().size());
        assertTrue(r.dependencies().stream().anyMatch(d -> d.coordinates().equals("org.apache.commons:commons-text:1.9")));
        assertTrue(r.dependencies().stream().anyMatch(d -> d.coordinates().equals("org.yaml:snakeyaml:1.31")));
        assertTrue(r.skipped().isEmpty());
    }
}
