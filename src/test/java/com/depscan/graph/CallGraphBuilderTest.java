package com.depscan.graph;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CallGraphBuilderTest {

    private Path writeSource(Path dir, String pkg, String file, String code) throws Exception {
        Path p = dir.resolve(pkg.replace('.', '/')).resolve(file);
        Files.createDirectories(p.getParent());
        Files.writeString(p, code);
        return p;
    }

    @Test
    void multiHopAndInterfaceResolution(@TempDir Path dir) throws Exception {
        writeSource(dir, "com.example", "App.java", """
                package com.example;
                public class App {
                    public static void main(String[] args) { new Service().run(); }
                    public void helper() { new Service().run(); }
                }""");
        writeSource(dir, "com.example", "Service.java", """
                package com.example;
                public class Service {
                    private final Greeter greeter = new LoudGreeter();
                    public void run() { greeter.greet(); }
                }""");
        writeSource(dir, "com.example", "Greeter.java", """
                package com.example;
                public interface Greeter { void greet(); }
                class LoudGreeter implements Greeter {
                    public void greet() { System.out.println("hi"); }
                }""");

        CallGraph g = CallGraphBuilder.build(dir);
        String main = "com.example.App#main(1)";
        String run = "com.example.Service#run(0)";
        String greetImpl = "com.example.LoudGreeter#greet(0)";
        assertTrue(g.entryPoints().contains(main), "main is an entry point");
        assertTrue(g.edges().getOrDefault(main, java.util.Set.of()).contains(run),
                "main -> Service.run (1 hop)");
        // Interface call greeter.greet() must resolve to the implementation.
        assertTrue(g.edges().getOrDefault(run, java.util.Set.of()).contains(greetImpl),
                "Service.run -> LoudGreeter.greet via interface, got " + g.edges().get(run));
    }

    @Test
    void deadPrivateMethodIsNotReachableFromEntries(@TempDir Path dir) throws Exception {
        writeSource(dir, "com.example", "App.java", """
                package com.example;
                public class App {
                    public static void main(String[] args) { System.out.println("ok"); }
                    private void dead() { external(); }
                    private void external() { System.out.println("dead"); }
                }""");
        CallGraph g = CallGraphBuilder.build(dir);
        // dead() exists in the graph but no entry point reaches it.
        assertTrue(g.userMethods().contains("com.example.App#dead(0)"));
        assertTrue(!g.entryPoints().contains("com.example.App#dead(0)"));
    }
}
