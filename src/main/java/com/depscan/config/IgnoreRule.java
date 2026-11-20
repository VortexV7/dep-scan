package com.depscan.config;

import com.depscan.reach.Finding;
import java.time.LocalDate;

/**
 * One entry in the {@code ignore} list of {@code depscan.yml}.
 *
 * <p>An ignore is deliberate and time-boxed, never silent:
 * <ul>
 *   <li>{@code id} — advisory id ({@code GHSA-...}) or CVE alias
 *       ({@code CVE-2022-...}); matches the finding's id or any alias.</li>
 *   <li>{@code dependency} — optional scope, {@code group:artifact}
 *       (e.g. {@code org.yaml:snakeyaml}); when set, the finding must be
 *       on that dependency as well as matching the id.</li>
 *   <li>{@code reason} — justification, required. An ignore without a
 *       reason is a config error, not a quiet suppression.</li>
 *   <li>{@code expires} — expiry date ({@code YYYY-MM-DD}), required.
 *       On or after this date the ignore stops applying and the finding
 *       counts normally again.</li>
 * </ul>
 */
public record IgnoreRule(String id, String dependency, String reason, LocalDate expires) {

    public IgnoreRule {
        id = id == null ? "" : id.trim();
        dependency = dependency == null ? "" : dependency.trim();
        reason = reason == null ? "" : reason.trim();
    }

    /** True if the ignore no longer applies on the given date (expiry is inclusive: expires ON that date). */
    public boolean isExpired(LocalDate today) {
        return expires != null && !today.isBefore(expires);
    }

    /** True if this rule suppresses the finding (id + optional dependency scope). */
    public boolean matches(Finding finding) {
        if (id.isBlank()) return false;
        boolean idMatches = id.equalsIgnoreCase(finding.vulnerability().id())
                || finding.vulnerability().aliases().stream().anyMatch(a -> a.equalsIgnoreCase(id));
        if (!idMatches) return false;
        if (dependency.isBlank()) return true;
        String dep = dependency;
        return finding.dependency().osvPackageName().equalsIgnoreCase(dep)
                || finding.dependency().coordinates().equalsIgnoreCase(dep)
                || finding.dependency().coordinates().startsWith(dep + ":");
    }
}
