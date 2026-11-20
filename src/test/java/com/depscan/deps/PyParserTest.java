package com.depscan.deps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PyParserTest {

    private static Path writeReq(Path dir, String content) throws Exception {
        Path req = dir.resolve("requirements.txt");
        Files.writeString(req, content);
        return dir;
    }

    @Test
    void pinnedVersionsAreExact(@TempDir Path dir) throws Exception {
        writeReq(dir, "pyyaml==5.3.1\nflask==2.0.1  # web framework\n");
        var r = PyParser.parse(dir);
        assertEquals(2, r.dependencies().size());
        assertEquals("5.3.1", r.dependencies().get(0).version());
        assertEquals("pyyaml", r.dependencies().get(0).osvPackageName());
        assertTrue(r.dependencies().get(0).isPython());
        assertEquals("pypi:pyyaml:5.3.1", r.dependencies().get(0).coordinates());
        assertTrue(r.approximateVersions().isEmpty(), "pinned versions are exact, not approximate");
        assertTrue(r.skipped().isEmpty());
        assertEquals("requirements.txt:1", r.declarationLocations().get("pyyaml"));
        assertEquals("requirements.txt:2", r.declarationLocations().get("flask"));
    }

    @Test
    void rangesUseMinimumAndFlagApproximate(@TempDir Path dir) throws Exception {
        writeReq(dir, "requests>=2.28\nurllib3~=1.26.2\njinja2==3.0.*\n");
        var r = PyParser.parse(dir);
        assertEquals(3, r.dependencies().size());
        assertEquals("2.28.0", r.dependencies().get(0).version());
        assertEquals("1.26.2", r.dependencies().get(1).version());
        assertEquals("3.0.0", r.dependencies().get(2).version());
        assertEquals(3, r.approximateVersions().size());
        assertTrue(r.approximateVersions().get("requests").contains(">=2.28"));
    }

    @Test
    void extrasMarkersAndNameNormalisation(@TempDir Path dir) throws Exception {
        writeReq(dir, "PyYAML[full]==5.3.1\nrequests[socks]>=2.28; python_version < \"3.12\"\n");
        var r = PyParser.parse(dir);
        assertEquals(2, r.dependencies().size());
        assertEquals("pyyaml", r.dependencies().get(0).osvPackageName(), "PEP 503 normalisation");
        assertEquals("5.3.1", r.dependencies().get(0).version());
        assertEquals("requests", r.dependencies().get(1).osvPackageName());
        assertTrue(r.approximateVersions().containsKey("requests"), "marker stripped, range still approximate");
    }

    @Test
    void unpinnedEditableAndUrlsAreSkippedNeverGuessed(@TempDir Path dir) throws Exception {
        writeReq(dir, "requests\n-e git+https://github.com/x/y.git#egg=y\n"
                + "flask @ https://example.com/flask-2.0.1.tar.gz\n"
                + "django<4.0\n"
                + "celery==5.2.7\n");
        var r = PyParser.parse(dir);
        assertEquals(1, r.dependencies().size(), "only the pinned one survives");
        assertEquals("celery", r.dependencies().get(0).osvPackageName());
        assertEquals(4, r.skipped().size());
    }

    @Test
    void pyprojectProjectDependencies(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("pyproject.toml"),
                "[project]\nname = \"demo\"\ndependencies = [\n"
                        + "    \"requests>=2.28\",\n"
                        + "    \"flask==2.0.1\",\n"
                        + "]\n");
        var r = PyParser.parse(dir);
        assertEquals(2, r.dependencies().size());
        assertEquals("requests", r.dependencies().get(0).osvPackageName());
        assertEquals("2.28.0", r.dependencies().get(0).version());
        assertEquals("flask", r.dependencies().get(1).osvPackageName());
        assertTrue(r.declarationLocations().get("requests").startsWith("pyproject.toml:"));
        assertEquals("pyproject", r.dependencies().get(0).scope());
    }

    @Test
    void pyprojectPoetryDependencies(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("pyproject.toml"),
                "[tool.poetry.dependencies]\n"
                        + "python = \"^3.9\"\n"
                        + "requests = \"^2.28.1\"\n"
                        + "flask = {version = \"^2.0.1\", extras = [\"async\"]}\n"
                        + "local = {git = \"https://github.com/x/local.git\"}\n");
        var r = PyParser.parse(dir);
        assertEquals(2, r.dependencies().size(), "python + git dep are not packages");
        assertEquals("requests", r.dependencies().get(0).osvPackageName());
        assertEquals("2.28.1", r.dependencies().get(0).version());
        assertEquals("flask", r.dependencies().get(1).osvPackageName());
    }

    @Test
    void requirementsWinsOverPyprojectOnClash(@TempDir Path dir) throws Exception {
        writeReq(dir, "flask==2.0.1\n");
        Files.writeString(dir.resolve("pyproject.toml"),
                "[project]\ndependencies = [\"flask>=2.0\"]\n");
        var r = PyParser.parse(dir);
        assertEquals(1, r.dependencies().size());
        assertEquals("2.0.1", r.dependencies().get(0).version(), "pinned requirements.txt wins");
    }

    @Test
    void rangeMinimumCases() {
        assertEquals("1.0.0", PyParser.rangeMinimum(">=1.0.0"));
        assertEquals("1.4.2", PyParser.rangeMinimum("~=1.4.2"));
        assertEquals("2.28.1", PyParser.rangeMinimum("^2.28.1"), "Poetry caret range");
        assertEquals("1.0.0", PyParser.rangeMinimum(">1.0,<2.0"));
        assertEquals("1.2.0", PyParser.rangeMinimum("1.2.*"));
        assertEquals(null, PyParser.rangeMinimum("<2.0.0"));
        assertEquals(null, PyParser.rangeMinimum("!=1.0"));
        assertEquals(null, PyParser.rangeMinimum("*"));
        assertEquals("1.2.0", PyParser.wildcardMinimum("1.2.*"));
        assertEquals("pyyaml", PyParser.normalizeName("PyYAML"));
        assertEquals("python-dateutil", PyParser.normalizeName("python_dateutil"));
    }
}
