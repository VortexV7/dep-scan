package com.depscan.cli;

/** Progress callback for a scan, used by the hacker TUI progress bars (Stage 4). No-op by default. */
public interface ScanProgress {
    /** A stage started / advanced: name e.g. "parsing pom", done/total work units. */
    void stage(String name, int done, int total);

    ScanProgress NONE = (name, done, total) -> {};
}
