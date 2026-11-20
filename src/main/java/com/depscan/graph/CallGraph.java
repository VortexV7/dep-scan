package com.depscan.graph;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The call graph of the user's own source.
 *
 * <p>A method id is {@code fully.qualified.Class#methodName(arity)}, e.g.
 * {@code com.example.App#process(1)}. External calls are recorded separately:
 * a call from user code to a method whose declaring type is not in the scanned
 * source (a library / JDK method). Those are the only way a vulnerable
 * library function can be reached, so they are first-class data, not noise.
 *
 * <p>{@code entryPoints} = {@code main} methods + every public method, per
 * the Stage 1 spec. {@code userMethods} maps method id &rarr; its source file
 * (for reporting). {@code edges} are user&rarr;user calls;
 * {@code externalCalls} are user&rarr;external calls.
 * {@code methodLocations} maps method id &rarr; {@code file:line} of its
 * declaration; {@code callSites} maps caller method id &rarr; external call
 * id &rarr; {@code file:line} of the call expression. Both are used for the
 * report's file:line.
 */
public record CallGraph(
        Set<String> userMethods,
        Set<String> entryPoints,
        Map<String, Set<String>> edges,
        Map<String, Set<String>> externalCalls,
        Map<String, String> methodFile,
        Map<String, String> methodLocations,
        Map<String, Map<String, String>> callSites) {

    /** Backwards-compatible constructor for callers that have no location data. */
    public CallGraph(Set<String> userMethods, Set<String> entryPoints,
                     Map<String, Set<String>> edges, Map<String, Set<String>> externalCalls,
                     Map<String, String> methodFile) {
        this(userMethods, entryPoints, edges, externalCalls, methodFile, Map.of(), Map.of());
    }

    /** All methods called (directly) by {@code method}, user or external. */
    public Set<String> calleesOf(String method) {
        var out = new java.util.HashSet<String>();
        out.addAll(edges.getOrDefault(method, Set.of()));
        out.addAll(externalCalls.getOrDefault(method, Set.of()));
        return out;
    }

    public List<String> sortedUserMethods() {
        return userMethods.stream().sorted().toList();
    }

    /** {@code file:line} of the call to {@code externalCall} from {@code caller}, or null. */
    public String locationOfCall(String caller, String externalCall) {
        Map<String, String> sites = callSites.getOrDefault(caller, Map.of());
        return sites.get(externalCall);
    }

    /** {@code file:line} where {@code method} is declared, or null. */
    public String locationOfMethod(String method) {
        return methodLocations.get(method);
    }
}
