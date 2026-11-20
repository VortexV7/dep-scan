package com.depscan.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class ReportCommandTest {

    private static int run(String... args) {
        return new CommandLine(new Main()).execute(args);
    }

    @Test
    void scanFormatSarifExitsOneAndIsValidJson(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("out.sarif");
        int code = run("scan", "samples/vulnerable-app", "--offline", "--cache-dir", "src/test/resources/osv-cache", "--no-animation", "--no-color",
                "--format", "sarif", "--out", out.toString());
        assertEquals(1, code, "sample has 1 reachable CRITICAL, default --fail-on critical");
        String json = Files.readString(out);
        assertTrue(json.contains("\"version\" : \"2.1.0\""), json);
        assertTrue(json.contains("GHSA-599f-7c49-w659"), json);
        assertTrue(json.contains("\"level\" : \"error\""), json);
    }

    @Test
    void scanInCiModeIsPlain(@TempDir Path dir) throws Exception {
        // Surefire has no console, so CiDetector treats this as non-TTY CI:
        // output must be the plain text report, not boxes.
        Path out = dir.resolve("out.txt");
        int code = run("scan", "samples/vulnerable-app", "--offline", "--cache-dir", "src/test/resources/osv-cache", "--no-animation",
                "--out", out.toString());
        assertEquals(1, code);
        assertTrue(Files.readString(out).contains("[!!] CRITICAL"), Files.readString(out));
    }

    @Test
    void reportPdfHtmlCsvSbomJson(@TempDir Path dir) throws Exception {
        for (String fmt : new String[]{"pdf", "html", "csv", "sbom", "json"}) {
            Path out = dir.resolve("r." + fmt);
            int code = run("report", "samples/vulnerable-app", "--offline", "--cache-dir", "src/test/resources/osv-cache",
                    "--format", fmt, "--out", out.toString(), "--fail-on", "none");
            assertEquals(0, code, fmt);
            assertTrue(Files.exists(out) && Files.size(out) > 100, fmt + " size " + Files.size(out));
        }
        assertTrue(Files.readString(dir.resolve("r.csv")).contains("GHSA-599f-7c49-w659"));
        assertTrue(Files.readString(dir.resolve("r.html")).contains("DepScan report"));
        assertTrue(Files.readString(dir.resolve("r.sbom")).contains("CycloneDX"));
        assertTrue(Files.readString(dir.resolve("r.json")).contains("GHSA-599f-7c49-w659"));
        byte[] pdf = Files.readAllBytes(dir.resolve("r.pdf"));
        assertEquals('%', (char) pdf[0]);
        assertTrue(new String(pdf, 0, 5).equals("%PDF-"));
    }

    @Test
    void reportBadFormatAndBadThemeExitTwo(@TempDir Path dir) {
        assertEquals(2, run("report", "samples/vulnerable-app", "--format", "docx", "--out", dir.resolve("x").toString()));
        assertEquals(2, run("report", "samples/vulnerable-app", "--format", "pdf", "--theme", "neon", "--out", dir.resolve("x.pdf").toString()));
    }

    @Test
    void reportExcludeUnreachable(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("r.csv");
        int code = run("report", "samples/vulnerable-app", "--offline", "--cache-dir", "src/test/resources/osv-cache", "--format", "csv",
                "--out", out.toString(), "--exclude-unreachable", "--fail-on", "none");
        assertEquals(0, code);
        String csv = Files.readString(out);
        assertTrue(csv.contains("GHSA-599f-7c49-w659"), csv);
        assertTrue(!csv.contains("GHSA-9w3m-gqgf-c4p9"), csv);
    }
}
