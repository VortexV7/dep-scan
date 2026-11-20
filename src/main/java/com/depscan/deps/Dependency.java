package com.depscan.deps;

/**
 * One direct dependency — from a pom.xml (Maven), a package.json (npm)
 * or a requirements.txt / pyproject.toml (Python / PyPI).
 * Immutable value object. For npm dependencies {@code groupId} is empty and
 * {@code artifactId} holds the npm package name (e.g. {@code lodash} or
 * {@code @babel/core}); {@code scope} is {@code dependencies} or
 * {@code devDependencies}. For Python dependencies {@code groupId} is empty
 * and {@code artifactId} holds the normalised PyPI name (e.g. {@code pyyaml});
 * {@code scope} is {@code requirements} or {@code pyproject}.
 * {@code ecosystem} is {@code "Maven"}, {@code "npm"} or {@code "PyPI"} and
 * is part of the identity: it disambiguates the OSV query, the cache key
 * and the display name.
 */
public record Dependency(String groupId, String artifactId, String version, String scope, String ecosystem) {

    public Dependency {
        ecosystem = ecosystem == null || ecosystem.isBlank() ? "Maven" : ecosystem;
        scope = scope == null || scope.isBlank() ? "compile" : scope;
    }

    public Dependency(String groupId, String artifactId, String version) {
        this(groupId, artifactId, version, "compile", "Maven");
    }

    public Dependency(String groupId, String artifactId, String version, String scope) {
        this(groupId, artifactId, version, scope, "Maven");
    }

    /** Factory for an npm dependency: name is the npm package name. */
    public static Dependency npm(String name, String version, String scope) {
        return new Dependency("", name, version, scope, "npm");
    }

    /** Factory for an npm dependency in {@code dependencies}. */
    public static Dependency npm(String name, String version) {
        return npm(name, version, "dependencies");
    }

    /** Factory for a Python (PyPI) dependency: name is the normalised PyPI name. */
    public static Dependency python(String name, String version, String scope) {
        return new Dependency("", name, version, scope, "PyPI");
    }

    /** Factory for a Python dependency from requirements.txt. */
    public static Dependency python(String name, String version) {
        return python(name, version, "requirements");
    }

    public boolean isNpm() {
        return "npm".equals(ecosystem);
    }

    public boolean isPython() {
        return "PyPI".equals(ecosystem);
    }

    /**
     * Human-readable coordinate, e.g. {@code org.apache.commons:commons-text:1.9},
     * {@code npm:lodash:4.17.20} or {@code pypi:requests:2.28.1}. Also the OSV
     * cache key, so the {@code npm:} / {@code pypi:} prefix keeps the
     * ecosystems from ever colliding.
     */
    public String coordinates() {
        if (isNpm()) return "npm:" + artifactId + ":" + version;
        if (isPython()) return "pypi:" + artifactId + ":" + version;
        return groupId + ":" + artifactId + ":" + version;
    }

    /** OSV.dev package name: {@code groupId:artifactId} for Maven, the npm/PyPI name otherwise. */
    public String osvPackageName() {
        return isNpm() || isPython() ? artifactId : groupId + ":" + artifactId;
    }

    /**
     * Best-guess Java base package for this artifact, derived from the groupId.
     * Used ONLY for the package-level reachability fallback (see
     * {@link com.depscan.reach.ReachabilityAnalyzer}): most Maven artifacts
     * publish code under their groupId, e.g. {@code org.apache.commons:commons-text}
     * &rarr; {@code org.apache.commons.text.*}. This is a heuristic, documented
     * as such — it is never used when function-level data exists. For npm it
     * is just the package name (the JS fallback matches on the package name,
     * not a Java package).
     */
    public String guessedJavaPackage() {
        return isNpm() ? artifactId : groupId;
    }
}
