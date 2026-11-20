package com.depscan.config;

import java.util.List;

/** Parsed {@code depscan.yml}: ignore list + optional default threshold. */
public record DepScanConfig(List<IgnoreRule> ignores, String failOn) {

    public DepScanConfig {
        ignores = ignores == null ? List.of() : List.copyOf(ignores);
    }

    public static DepScanConfig empty() {
        return new DepScanConfig(List.of(), null);
    }

    public boolean hasIgnores() {
        return !ignores.isEmpty();
    }
}
