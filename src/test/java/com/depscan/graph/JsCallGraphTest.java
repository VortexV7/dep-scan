package com.depscan.graph;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JsCallGraphTest {

    private static JsCallGraph build(Path dir, String... files) throws Exception {
        for (int i = 0; i < files.length; i += 2) {
            Path f = dir.resolve(files[i]);
            Files.createDirectories(f.getParent());
            Files.writeString(f, files[i + 1]);
        }
        return JsCallGraph.build(dir);
    }

    @Test
    void requireAndMemberCallThroughBinding(@TempDir Path dir) throws Exception {
        var g = build(dir, "index.js",
                "const _ = require('lodash');\nconsole.log(_.trim('  x  '));\n");
        assertTrue(g.isImported("lodash"));
        assertEquals("index.js:1", g.importLocation("lodash"));
        assertTrue(g.isFunctionCalled("_.trim"), "member call through the lodash binding");
        assertTrue(g.isFunctionCalled("trim"), "bare method name also matches");
        assertTrue(g.isFunctionCalled("lodash.trim"), "qualified package.method matches");
        assertFalse(g.isFunctionCalled("merge"), "merge is never called");
    }

    @Test
    void esmImportsNamedDestructuredSubpathScoped(@TempDir Path dir) throws Exception {
        var g = build(dir, "src/a.ts",
                "import _ from 'lodash';\nimport { merge } from 'lodash/fp';\n"
                        + "import { parse } from '@babel/core';\nimport './local';\n"
                        + "merge({});\nparse('x');\n");
        assertTrue(g.isImported("lodash"));
        assertTrue(g.isImported("@babel/core"));
        assertFalse(g.isImported("./local"), "relative imports are the project's own code");
        assertTrue(g.isFunctionCalled("merge"));
        assertTrue(g.isFunctionCalled("parse"));
        assertEquals("src/a.ts:1", g.importLocation("lodash"));
    }

    @Test
    void dynamicImportAndSideEffectImport(@TempDir Path dir) throws Exception {
        var g = build(dir, "a.js",
                "import 'dotenv/config';\nawait import('minimist');\n");
        assertTrue(g.isImported("dotenv"));
        assertTrue(g.isImported("minimist"));
    }

    @Test
    void nodeModulesIsExcluded(@TempDir Path dir) throws Exception {
        var g = build(dir,
                "index.js", "console.log('own');\n",
                "node_modules/evil/index.js", "const _ = require('lodash');\n");
        assertFalse(g.isImported("lodash"), "imports inside node_modules must not count");
    }

    @Test
    void callsInsideStringsAndCommentsDoNotCount(@TempDir Path dir) throws Exception {
        var g = build(dir, "a.js",
                "// _.trim('x') in a comment\nconst s = \"_.merge({})\";\n/* _.clone(x) */\n");
        assertFalse(g.isFunctionCalled("trim"));
        assertFalse(g.isFunctionCalled("merge"));
        assertFalse(g.isFunctionCalled("clone"));
    }

    @Test
    void packageOfSpecifiers() {
        assertEquals("lodash", JsCallGraph.packageOf("lodash"));
        assertEquals("lodash", JsCallGraph.packageOf("lodash/trim"));
        assertEquals("@babel/core", JsCallGraph.packageOf("@babel/core"));
        assertEquals("@babel/core", JsCallGraph.packageOf("@babel/core/lib/x"));
        assertEquals(null, JsCallGraph.packageOf("./util"));
        assertEquals(null, JsCallGraph.packageOf("/abs/path"));
        assertEquals(null, JsCallGraph.packageOf(""));
    }
}
