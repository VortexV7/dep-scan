package com.depscan.graph;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PyCallGraphTest {

    private static PyCallGraph build(Path dir, String... files) throws Exception {
        for (int i = 0; i < files.length; i += 2) {
            Path f = dir.resolve(files[i]);
            Files.createDirectories(f.getParent());
            Files.writeString(f, files[i + 1]);
        }
        return PyCallGraph.build(dir);
    }

    @Test
    void importYamlMapsToPyyamlAndMemberCallMatches(@TempDir Path dir) throws Exception {
        var g = build(dir, "app.py",
                "import yaml\n\ndef load(text):\n    return yaml.safe_load(text)\n");
        assertTrue(g.isImported("pyyaml"), "import yaml means the pyyaml distribution");
        assertEquals("app.py:1", g.importLocation("pyyaml"));
        assertTrue(g.isFunctionCalled("yaml.safe_load"), "member call through the yaml binding");
        assertTrue(g.isFunctionCalled("safe_load"), "bare method name also matches");
        assertTrue(g.isFunctionCalled("pyyaml.safe_load"), "qualified package.method matches");
        assertFalse(g.isFunctionCalled("yaml.load"), "unsafe load is never called");
    }

    @Test
    void fromImportAliasAndSubmodule(@TempDir Path dir) throws Exception {
        var g = build(dir, "src/a.py",
                "from yaml import safe_load\nimport requests as req\nfrom PIL import Image\n"
                        + "from . import local\nfrom os import path\n"
                        + "safe_load('x')\nreq.get('http://x')\n");
        assertTrue(g.isImported("pyyaml"));
        assertTrue(g.isImported("requests"));
        assertTrue(g.isImported("pillow"), "from PIL import ... maps to pillow");
        assertFalse(g.isImported("local"), "relative imports are the project's own code");
        assertFalse(g.isImported("."), "relative imports are the project's own code");
        assertTrue(g.isFunctionCalled("safe_load"), "from-import binds the name directly");
        assertTrue(g.isFunctionCalled("requests.get"), "aliased import still maps to requests");
        assertEquals("src/a.py:1", g.importLocation("pyyaml"));
    }

    @Test
    void multilineFromImportAndMultipleImports(@TempDir Path dir) throws Exception {
        var g = build(dir, "a.py",
                "from yaml import (\n    safe_load,\n    dump,\n)\nimport os, sys\ndump({})\n");
        assertTrue(g.isImported("pyyaml"));
        assertTrue(g.isFunctionCalled("dump"));
        assertEquals("a.py:1", g.importLocation("pyyaml"), "multi-line import reports its first line");
    }

    @Test
    void venvAndPycacheAreExcluded(@TempDir Path dir) throws Exception {
        var g = build(dir,
                "app.py", "print('own')\n",
                "venv/lib/requests.py", "import requests\n",
                ".venv/lib/x.py", "import flask\n",
                "__pycache__/cached.py", "import yaml\n");
        assertFalse(g.isImported("requests"), "imports inside venv must not count");
        assertFalse(g.isImported("flask"), "imports inside .venv must not count");
        assertFalse(g.isImported("pyyaml"), "imports inside __pycache__ must not count");
    }

    @Test
    void callsInsideStringsCommentsAndDocstringsDoNotCount(@TempDir Path dir) throws Exception {
        var g = build(dir, "a.py",
                "# yaml.safe_load('x') in a comment\n"
                        + "s = \"yaml.load('x')\"\n"
                        + "\"\"\"yaml.dump(x) in a docstring\"\"\"\n"
                        + "import yaml\n");
        assertTrue(g.isImported("pyyaml"), "the real import still counts");
        assertFalse(g.isFunctionCalled("safe_load"));
        assertFalse(g.isFunctionCalled("load"));
        assertFalse(g.isFunctionCalled("dump"));
    }

    @Test
    void packageOfAliases() {
        assertEquals("pyyaml", PyCallGraph.packageOf("yaml"));
        assertEquals("pillow", PyCallGraph.packageOf("PIL"));
        assertEquals("scikit-learn", PyCallGraph.packageOf("sklearn"));
        assertEquals("beautifulsoup4", PyCallGraph.packageOf("bs4"));
        assertEquals("requests", PyCallGraph.packageOf("requests"));
        assertEquals("requests", PyCallGraph.packageOf("requests.sessions"));
        assertEquals("pyyaml", PyCallGraph.packageOf("yaml.loader"));
        assertEquals(null, PyCallGraph.packageOf(""));
    }
}
