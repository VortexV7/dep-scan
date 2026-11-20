package com.depscan.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

/**
 * CLI-level exit-code tests. No network is used: the clean project has no
 * dependencies (no OSV call), the network test uses --offline with an empty
 * cache dir, and threshold logic is covered by ExitCodesTest.
 */
class ScanCommandTest {

    private static int run(String... args) {
        return new CommandLine(new Main()).execute(args);
    }

    private static String runCapturing(String... args) {
        PrintStream old = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
        try {
            run(args);
        } finally {
            System.setOut(old);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    private static Path cleanProject(Path dir) throws Exception {
        Files.writeString(dir.resolve("pom.xml"), """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId><artifactId>clean</artifactId><version>1.0</version>
                </project>""");
        return dir;
    }

    @Test
    void cleanProjectExitsZero(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        assertEquals(0, run("scan", dir.toString(), "--no-color"));
    }

    @Test
    void cleanProjectJsonExitsZero(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        String out = runCapturing("scan", dir.toString(), "--json", "--no-color");
        assertTrue(out.contains("\"critical\" : 0"), out);
    }

    @Test
    void missingDirectoryExitsTwo() {
        assertEquals(2, run("scan", "/definitely/not/a/project"));
    }

    @Test
    void directoryWithoutPomExitsTwo(@TempDir Path dir) {
        assertEquals(2, run("scan", dir.toString()));
    }

    @Test
    void badFailOnValueExitsTwo(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        assertEquals(2, run("scan", dir.toString(), "--fail-on", "medium"));
    }

    @Test
    void simpleAndJsonTogetherExitsTwo(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        assertEquals(2, run("scan", dir.toString(), "--simple", "--json"));
    }

    @Test
    void missingConfigFileExitsTwo(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        assertEquals(2, run("scan", dir.toString(), "--config", dir.resolve("nope.yml").toString()));
    }

    @Test
    void configWithoutJustificationExitsTwo(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        assertEquals(2, run("scan", dir.toString(), "--config",
                "src/test/resources/config/bad-no-reason.yml"));
    }

    @Test
    void offlineWithEmptyCacheExitsThree(@TempDir Path dir, @TempDir Path cacheDir) throws Exception {
        Files.writeString(dir.resolve("pom.xml"), """
                <project><modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0</version>
                  <dependencies>
                    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>
                  </dependencies>
                </project>""");
        assertEquals(3, run("scan", dir.toString(), "--offline", "--cache-dir", cacheDir.toString()));
    }

    @Test
    void failOnNoneOnCleanProjectExitsZero(@TempDir Path dir) throws Exception {
        cleanProject(dir);
        assertEquals(0, run("scan", dir.toString(), "--fail-on", "none"));
    }
}
