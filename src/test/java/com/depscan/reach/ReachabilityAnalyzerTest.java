package com.depscan.reach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.depscan.deps.Dependency;
import com.depscan.graph.CallGraph;
import com.depscan.graph.CallGraphBuilder;
import com.depscan.osv.Vulnerability;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The two cases Stage 1 must prove: one reachable, one unreachable.
 * Both use the same fake advisory shape (function-level data for
 * commons-text, no function data for snakeyaml) as the live OSV responses.
 */
class ReachabilityAnalyzerTest {

    private static final Dependency COMMONS_TEXT =
            new Dependency("org.apache.commons", "commons-text", "1.9");
    private static final Dependency SNAKEYAML =
            new Dependency("org.yaml", "snakeyaml", "1.31");

    private static Vulnerability commonsTextVuln() {
        return new Vulnerability("GHSA-599f-7c49-w659", "Text4Shell", "CVSS_V3:9.8", 9.8,
                "1.10.0", List.of("ECOSYSTEM: introduced=1.5, fixed=1.10.0"),
                List.of("org.apache.commons.text.StringSubstitutor.createInterpolator"));
    }

    private static Vulnerability snakeyamlVuln() {
        // No affected_functions in this advisory -> package-level fallback.
        return new Vulnerability("CVE-2022-38751", "SnakeYAML billion laughs", "CVSS_V3:7.5", 7.5,
                "1.32", List.of("ECOSYSTEM: introduced=0, fixed=1.32"), List.of());
    }

    @Test
    void reachableVulnerableFunctionIsCritical(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("src");
        Files.createDirectories(src.resolve("com/example"));
        Files.writeString(src.resolve("com/example/App.java"), """
                package com.example;
                public class App {
                    public static void main(String[] args) { new Service().go(args[0]); }
                }""");
        Files.writeString(src.resolve("com/example/Service.java"), """
                package com.example;
                import org.apache.commons.text.StringSubstitutor;
                public class Service {
                    public void go(String in) { StringSubstitutor.createInterpolator().replace(in); }
                }""");
        CallGraph g = CallGraphBuilder.build(src);
        Finding f = ReachabilityAnalyzer.analyze(g, COMMONS_TEXT, commonsTextVuln());
        assertTrue(f.reachable(), "vulnerable function is called from main, must be reachable");
        assertEquals("CRITICAL", f.severity());
        assertTrue(f.evidence().startsWith("FUNCTION:"), f.evidence());
        assertFalse(f.callChain().isEmpty(), "call chain must show how it is reached");
        assertEquals("com.example.App#main(1)", f.callChain().get(0));
        assertTrue(f.callChain().get(f.callChain().size() - 1).contains("StringSubstitutor"),
                "chain ends at the vulnerable call: " + f.callChain());
    }

    @Test
    void unreachableVulnerableFunctionIsLowNotHidden(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("src");
        Files.createDirectories(src.resolve("com/example"));
        Files.writeString(src.resolve("com/example/App.java"), """
                package com.example;
                public class App {
                    public static void main(String[] args) { System.out.println("ok"); }
                    private void dead() { org.apache.commons.text.StringSubstitutor.createInterpolator(); }
                }""");
        CallGraph g = CallGraphBuilder.build(src);
        Finding f = ReachabilityAnalyzer.analyze(g, COMMONS_TEXT, commonsTextVuln());
        assertFalse(f.reachable(), "vulnerable function only in dead private method, must be unreachable");
        assertEquals("LOW", f.severity());
        assertTrue(f.callChain().isEmpty());
        // Still present in the findings list — never hidden.
    }

    @Test
    void packageFallbackFlagsAnyCallIntoPackage(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("src");
        Files.createDirectories(src.resolve("com/example"));
        Files.writeString(src.resolve("com/example/App.java"), """
                package com.example;
                import org.yaml.snakeyaml.Yaml;
                public class App {
                    public static void main(String[] args) { new Yaml().load(args[0]); }
                }""");
        CallGraph g = CallGraphBuilder.build(src);
        Finding f = ReachabilityAnalyzer.analyze(g, SNAKEYAML, snakeyamlVuln());
        assertTrue(f.reachable(), "no function data, but code calls into org.yaml.* from main");
        assertEquals("CRITICAL", f.severity());
        assertTrue(f.evidence().startsWith("PACKAGE:"), f.evidence());
    }

    @Test
    void packageFallbackIsLowWhenPackageNeverCalled(@TempDir Path dir) throws Exception {
        Path src = dir.resolve("src");
        Files.createDirectories(src.resolve("com/example"));
        Files.writeString(src.resolve("com/example/App.java"), """
                package com.example;
                public class App {
                    public static void main(String[] args) { System.out.println("ok"); }
                }""");
        CallGraph g = CallGraphBuilder.build(src);
        Finding f = ReachabilityAnalyzer.analyze(g, SNAKEYAML, snakeyamlVuln());
        assertFalse(f.reachable());
        assertEquals("LOW", f.severity());
    }
}
