package com.depscan.reach;

import com.depscan.deps.Dependency;
import com.depscan.graph.CallGraph;
import com.depscan.graph.JsCallGraph;
import com.depscan.graph.PyCallGraph;
import com.depscan.osv.Vulnerability;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.jgrapht.Graph;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.BreadthFirstIterator;

/**
 * Reachability analysis over the call graph, using JGraphT.
 *
 * <p>Model: one directed graph whose vertices are user methods plus external
 * methods (library/JDK calls). Edges are calls. Entry points are
 * {@code main} methods + all public methods (see {@link CallGraph}).
 * A vulnerable function is reachable iff some entry point can reach, via
 * BFS, a user method that calls it.
 *
 * <p>Two matching modes, in order:
 * <ol>
 *   <li><b>Function-level</b> (when the advisory lists affected functions):
 *       an external call matches a listed function when class + method name
 *       match (arity is ignored — OSV function strings carry no reliable
 *       arity, e.g. {@code StringSubstitutor.createInterpolator}). A match
 *       from a reachable user method &rarr; CRITICAL, with the shortest
 *       call chain as evidence.</li>
 *   <li><b>Package-level fallback</b> (no function data): any external call
 *       whose declaring class is in the dependency's Java package
 *       (groupId heuristic, see {@link Dependency#guessedJavaPackage()})
 *       from a reachable user method &rarr; CRITICAL. No such call &rarr;
 *       LOW. This is deliberately conservative in the direction of flagging
 *       real use, and honest about the heuristic in the evidence string.</li>
 * </ol>
 * Unreachable findings are LOW, never hidden — a library you ship can still
 * be exploited by other code paths, reflection, or a future caller.
 */
public final class ReachabilityAnalyzer {

    private ReachabilityAnalyzer() {}

    public static Finding analyze(CallGraph graph, Dependency dep, Vulnerability vuln) {
        Graph<String, DefaultEdge> g = buildJGraph(graph);
        Set<String> reachable = reachableFromEntries(g, graph.entryPoints());

        if (vuln.hasFunctionData()) {
            for (String fn : vuln.affectedFunctions()) {
                String matched = findMatchingExternalCall(graph, reachable, fn);
                if (matched != null) {
                    String caller = callerOf(graph, reachable, matched);
                    List<String> chain = new ArrayList<>(shortestChain(g, graph, caller));
                    if (!chain.contains(matched)) chain.add(matched);
                    String loc = caller == null ? "" : firstNonNull(
                            graph.locationOfCall(caller, matched), graph.locationOfMethod(caller));
                    return new Finding(dep, vuln, true, "FUNCTION: " + fn + " called as " + matched,
                            List.copyOf(chain), loc,
                            com.depscan.report.UpgradeSuggestion.suggest(dep.version(), vuln.fixedVersion()).text());
                }
            }
            return new Finding(dep, vuln, false,
                    "FUNCTION: none of " + vuln.affectedFunctions().size()
                            + " affected function(s) is called from reachable code", List.of());
        }

        // Package fallback.
        String pkg = dep.guessedJavaPackage();
        for (String userMethod : reachable) {
            for (String ext : graph.externalCalls().getOrDefault(userMethod, Set.of())) {
                String extClass = ext.contains("#") ? ext.substring(0, ext.indexOf('#')) : ext;
                if (extClass.startsWith(pkg + ".") || extClass.equals(pkg)) {
                    List<String> chain = new ArrayList<>(shortestChain(g, graph, userMethod));
                    if (!chain.contains(ext)) chain.add(ext);
                    String loc = firstNonNull(
                            graph.locationOfCall(userMethod, ext), graph.locationOfMethod(userMethod));
                    return new Finding(dep, vuln, true,
                            "PACKAGE: call into " + pkg + ".* (" + ext + ") - no function-level data in advisory, "
                                    + "any call into the package counts as reachable", chain, loc,
                            com.depscan.report.UpgradeSuggestion.suggest(dep.version(), vuln.fixedVersion()).text());
                }
            }
        }
        return new Finding(dep, vuln, false,
                "PACKAGE: no call into " + pkg + ".* from reachable code (no function-level data in advisory)",
                List.of());

    }

    /**
     * npm reachability over a {@link JsCallGraph} — the npm counterpart of
     * {@link #analyze(CallGraph, Dependency, Vulnerability)}.
     *
     * <p>Two matching modes, in order:
     * <ol>
     *   <li><b>Function-level</b> (when the advisory lists affected functions):
     *       a listed function whose name is actually called in the project's
     *       own source &rarr; CRITICAL, with the call site as evidence.</li>
     *   <li><b>Package-level fallback</b> (no function data — the usual case:
     *       npm GHSA advisories in OSV carry no {@code affected_functions},
     *       same as Maven): any {@code import}/{@code require} of the package
     *       from the project's own source &rarr; CRITICAL, with the import
     *       site as evidence. Listed in package.json but never imported
     *       &rarr; LOW.</li>
     * </ol>
     * The call chain for a reachable npm finding is the import site (there
     * is no inter-file call graph for JS — see {@link JsCallGraph}).
     */
    public static Finding analyzeJs(JsCallGraph js, Dependency dep, Vulnerability vuln) {
        String pkg = dep.osvPackageName();
        String importLoc = js.importLocation(pkg);
        if (importLoc == null) {
            return new Finding(dep, vuln, false,
                    "PACKAGE: " + pkg + " is listed in package.json but never imported/required "
                            + "by the project's own source (no function-level data in advisory)",
                    List.of());
        }
        if (vuln.hasFunctionData()) {
            for (String fn : vuln.affectedFunctions()) {
                String callLoc = js.callLocation(fn);
                if (callLoc != null) {
                    return new Finding(dep, vuln, true, "FUNCTION: " + fn + " called at " + callLoc,
                            List.of(importLoc + " (import " + pkg + ")"), callLoc,
                            com.depscan.report.UpgradeSuggestion.suggest(dep.version(), vuln.fixedVersion()).text());
                }
            }
            return new Finding(dep, vuln, false,
                    "FUNCTION: none of " + vuln.affectedFunctions().size()
                            + " affected function(s) is called from project source, although "
                            + pkg + " is imported at " + importLoc, List.of());
        }
        return new Finding(dep, vuln, true,
                "PACKAGE: " + pkg + " is imported at " + importLoc
                        + " - no function-level data in advisory, any import counts as reachable",
                List.of(importLoc + " (import " + pkg + ")"), importLoc,
                com.depscan.report.UpgradeSuggestion.suggest(dep.version(), vuln.fixedVersion()).text());
    }

    /**
     * Python reachability over a {@link PyCallGraph} — the Python counterpart
     * of {@link #analyzeJs(JsCallGraph, Dependency, Vulnerability)}.
     *
     * <p>Two matching modes, in order:
     * <ol>
     *   <li><b>Function-level</b> (when the advisory lists affected functions):
     *       a listed function whose name is actually called in the project's
     *       own source &rarr; CRITICAL, with the call site as evidence.</li>
     *   <li><b>Package-level fallback</b> (no function data — the usual case:
     *       PyPI advisories in OSV carry no {@code affected_functions},
     *       same as Maven/npm): any {@code import} of the package from the
     *       project's own source &rarr; CRITICAL, with the import site as
     *       evidence. Listed in requirements.txt / pyproject.toml but never
     *       imported &rarr; LOW.</li>
     * </ol>
     * The call chain for a reachable Python finding is the import site (there
     * is no inter-file call graph for Python — see {@link PyCallGraph}).
     */
    public static Finding analyzePy(PyCallGraph py, Dependency dep, Vulnerability vuln) {
        String pkg = dep.osvPackageName();
        String importLoc = py.importLocation(pkg);
        if (importLoc == null) {
            return new Finding(dep, vuln, false,
                    "PACKAGE: " + pkg + " is listed in requirements.txt/pyproject.toml but never imported "
                            + "by the project's own Python source (no function-level data in advisory)",
                    List.of());
        }
        if (vuln.hasFunctionData()) {
            for (String fn : vuln.affectedFunctions()) {
                String callLoc = py.callLocation(fn);
                if (callLoc != null) {
                    return new Finding(dep, vuln, true, "FUNCTION: " + fn + " called at " + callLoc,
                            List.of(importLoc + " (import " + pkg + ")"), callLoc,
                            com.depscan.report.UpgradeSuggestion.suggest(dep.version(), vuln.fixedVersion()).text());
                }
            }
            return new Finding(dep, vuln, false,
                    "FUNCTION: none of " + vuln.affectedFunctions().size()
                            + " affected function(s) is called from project source, although "
                            + pkg + " is imported at " + importLoc, List.of());
        }
        return new Finding(dep, vuln, true,
                "PACKAGE: " + pkg + " is imported at " + importLoc
                        + " - no function-level data in advisory, any import counts as reachable",
                List.of(importLoc + " (import " + pkg + ")"), importLoc,
                com.depscan.report.UpgradeSuggestion.suggest(dep.version(), vuln.fixedVersion()).text());
    }

    private static String firstNonNull(String a, String b) {
        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;
        return "";
    }

    private static Graph<String, DefaultEdge> buildJGraph(CallGraph graph) {
        Graph<String, DefaultEdge> g = new DefaultDirectedGraph<>(DefaultEdge.class);
        for (String m : graph.userMethods()) g.addVertex(m);
        for (var e : graph.edges().entrySet()) {
            for (String to : e.getValue()) {
                g.addVertex(to);
                g.addEdge(e.getKey(), to);
            }
        }
        for (var e : graph.externalCalls().entrySet()) {
            for (String to : e.getValue()) {
                g.addVertex(to);
                g.addEdge(e.getKey(), to);
            }
        }
        return g;
    }

    private static Set<String> reachableFromEntries(Graph<String, DefaultEdge> g, Set<String> entries) {
        Set<String> reachable = new LinkedHashSet<>();
        for (String entry : entries) {
            if (!g.containsVertex(entry)) continue;
            var it = new BreadthFirstIterator<>(g, entry);
            while (it.hasNext()) reachable.add(it.next());
        }
        return reachable;
    }

    /** Returns the external-call id matching a listed vulnerable function, if called from reachable code. */
    private static String findMatchingExternalCall(CallGraph graph, Set<String> reachable, String function) {
        // Normalise: "com.foo.Bar.baz(...)" / "com.foo.Bar.baz" / "Bar.baz" -> class + method.
        String fn = function.trim();
        int paren = fn.indexOf('(');
        if (paren >= 0) fn = fn.substring(0, paren);
        int lastDot = fn.lastIndexOf('.');
        if (lastDot < 0) return null;
        String fnClass = fn.substring(0, lastDot);
        String fnMethod = fn.substring(lastDot + 1);
        for (String userMethod : reachable) {
            for (String ext : graph.externalCalls().getOrDefault(userMethod, Set.of())) {
                String extClass = ext.contains("#") ? ext.substring(0, ext.indexOf('#')) : ext;
                String extMethod = ext.contains("#")
                        ? ext.substring(ext.indexOf('#') + 1, ext.indexOf('('))
                        : "";
                if (!extMethod.equals(fnMethod)) continue;
                // Class match: exact, or simple-name match (covers "?" and
                // short names from chained calls), or suffix match.
                if (extClass.equals(fnClass)
                        || extClass.endsWith("." + simpleName(fnClass))
                        || simpleName(extClass).equals(simpleName(fnClass))
                        || "?".equals(extClass)) {
                    return ext;
                }
            }
        }
        return null;
    }

    private static String callerOf(CallGraph graph, Set<String> reachable, String externalCall) {
        for (String userMethod : reachable) {
            if (graph.externalCalls().getOrDefault(userMethod, Set.of()).contains(externalCall)) {
                return userMethod;
            }
        }
        return null;
    }

    /**
     * Shortest entry-point &rarr; caller chain. A chain starting at a
     * {@code main} method is preferred over one starting at another public
     * method, even if longer — it is the evidence a human triages from
     * ("run the app, this is how it gets there"). If no main reaches the
     * caller, the shortest path from any public entry point is used.
     * Reachability itself is unaffected: any entry point counts.
     */
    private static List<String> shortestChain(Graph<String, DefaultEdge> g, CallGraph graph, String caller) {
        if (caller == null) return List.of();
        List<String> best = shortestFrom(g, graph, caller,
                graph.entryPoints().stream().filter(e -> e.contains("#main(")).toList());
        if (best == null) {
            best = shortestFrom(g, graph, caller, List.copyOf(graph.entryPoints()));
        }
        if (best == null) return List.of(caller);
        return List.copyOf(best);
    }

    private static List<String> shortestFrom(Graph<String, DefaultEdge> g, CallGraph graph,
                                             String caller, List<String> entries) {
        List<String> best = null;
        for (String entry : entries) {
            if (!g.containsVertex(entry) || !g.containsVertex(caller)) continue;
            var path = DijkstraShortestPath.findPathBetween(g, entry, caller);
            if (path == null) continue;
            List<String> chain = new ArrayList<>(path.getVertexList());
            if (best == null || chain.size() < best.size()) best = chain;
        }
        return best;
    }

    private static String simpleName(String fqn) {
        int i = fqn.lastIndexOf('.');
        return i >= 0 ? fqn.substring(i + 1) : fqn;
    }
}
