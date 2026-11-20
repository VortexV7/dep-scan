package com.depscan.osv;

import org.apache.maven.artifact.versioning.DefaultArtifactVersion;

/**
 * Maven version-range check for OSV {@code ranges[].events}:
 * {@code introduced} (inclusive) / {@code fixed} (exclusive) /
 * {@code limit} (exclusive). A version is affected iff it is &ge; the latest
 * introduced event and &lt; the earliest fixed/limit event that follows it.
 * Uses Maven's own version ordering, so {@code 1.10} &gt; {@code 1.9} and
 * {@code 1.9.1} &gt; {@code 1.9} compare correctly.
 */
public final class VersionRange {

    private VersionRange() {}

    public static boolean isAffected(String version, String introduced, String fixed, String limit) {
        DefaultArtifactVersion v = new DefaultArtifactVersion(version);
        if (introduced != null && !introduced.isBlank() && !"0".equals(introduced)) {
            if (v.compareTo(new DefaultArtifactVersion(introduced)) < 0) return false;
        }
        if (fixed != null && !fixed.isBlank()) {
            if (v.compareTo(new DefaultArtifactVersion(fixed)) >= 0) return false;
        }
        if (limit != null && !limit.isBlank()) {
            if (v.compareTo(new DefaultArtifactVersion(limit)) >= 0) return false;
        }
        return true;
    }

    /** Compare two Maven versions: negative if a &lt; b. */
    public static int compare(String a, String b) {
        return new DefaultArtifactVersion(a).compareTo(new DefaultArtifactVersion(b));
    }
}
