package com.depscan.osv;

import com.depscan.deps.Dependency;
import java.io.IOException;
import java.util.List;

/** Queries OSV.dev for advisories affecting a dependency. Implementations must be offline-safe via cache. */
public interface OsvClient {

    /**
     * Returns advisories affecting this exact dependency version.
     * An empty list means OSV knows no vulnerability for it — not an error.
     */
    List<Vulnerability> query(Dependency dependency) throws IOException;
}
