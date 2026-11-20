package com.depscan.report;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Safe-upgrade suggestion for one finding: what version fixes it, and how
 * risky that upgrade looks. The risk call is mechanical, not a guarantee:
 * a major-version bump is flagged as likely breaking, a minor bump as
 * usually safe, a patch bump as safe. Versions that are not
 * {@code major.minor.patch} numbers (e.g. {@code 1.31}, {@code 2.0}) are
 * compared on their numeric components, missing components counting as 0.
 */
public final class UpgradeSuggestion {

    private static final Pattern NUM = Pattern.compile("(\\d+)");

    private UpgradeSuggestion() {}

    public record Suggestion(String fixedVersion, String text, boolean majorBump, boolean hasFix) {}

    public static Suggestion suggest(String currentVersion, String fixedVersion) {
        if (fixedVersion == null || fixedVersion.isBlank()) {
            return new Suggestion("", "No fixed version published yet - check the advisory for a workaround", false, false);
        }
        String fixed = fixedVersion.trim();
        String current = currentVersion == null ? "" : currentVersion.trim();
        if (current.equals(fixed)) {
            return new Suggestion(fixed, "Already on the fixed version " + fixed, false, true);
        }
        int[] cur = numericParts(current);
        int[] fix = numericParts(fixed);
        if (fix[0] != cur[0]) {
            return new Suggestion(fixed,
                    "Upgrade to " + fixed + " (MAJOR bump from " + current + " - likely breaking, check the changelog and test)",
                    true, true);
        }
        if (fix[1] != cur[1]) {
            return new Suggestion(fixed,
                    "Upgrade to " + fixed + " (minor bump from " + current + " - usually safe, test before shipping)",
                    false, true);
        }
        return new Suggestion(fixed,
                "Upgrade to " + fixed + " (patch bump from " + current + " - safe)",
                false, true);
    }

    /** First three numeric components of a version, missing ones as 0. */
    static int[] numericParts(String version) {
        int[] parts = {0, 0, 0};
        if (version == null) return parts;
        Matcher m = NUM.matcher(version);
        int i = 0;
        while (m.find() && i < 3) {
            try {
                parts[i++] = Integer.parseInt(m.group(1));
            } catch (NumberFormatException ignored) {
                // Very large component: treat as-is by stopping here.
                break;
            }
        }
        return parts;
    }
}
