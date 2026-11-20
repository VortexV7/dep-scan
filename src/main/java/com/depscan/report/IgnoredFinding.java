package com.depscan.report;

import com.depscan.config.IgnoreRule;
import com.depscan.reach.Finding;

/** A finding suppressed by a depscan.yml ignore rule, kept visible with its justification and expiry. */
public record IgnoredFinding(Finding finding, IgnoreRule rule) {}
