package com.depscan.osv;

import java.io.IOException;

/**
 * OSV.dev could not be reached AND there is no cached response to fall back
 * to (or {@code --offline} was given with an empty cache). Distinct from a
 * generic {@link IOException} (e.g. a missing pom.xml) so the CLI can return
 * exit code 3 for it, per the CLI contract:
 * 0 clean / only unreachable, 1 threshold breached, 2 usage or tool error,
 * 3 network error with no cache.
 */
public class NetworkException extends IOException {

    public NetworkException(String message) {
        super(message);
    }

    public NetworkException(String message, Throwable cause) {
        super(message, cause);
    }
}
