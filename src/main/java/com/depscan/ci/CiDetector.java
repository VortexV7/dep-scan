package com.depscan.ci;

import java.util.Map;

/**
 * CI auto-detection (Stage 3).
 *
 * <p>A run is CI when any of these holds: {@code CI=true}, {@code GITHUB_ACTIONS},
 * {@code GITLAB_CI}, {@code JENKINS_URL}, or stdout is not a TTY
 * ({@code System.console() == null}). In CI mode DepScan switches to plain,
 * colour-free, animation-free logs — no ANSI codes, no spinner, no TUI boot
 * sequence — so logs stay readable in GitHub/GitLab/Jenkins.
 *
 * <p>{@code NO_COLOR} (any non-empty value) disables colour even on a TTY,
 * per the NO_COLOR convention. {@code --no-color} / {@code --no-animation}
 * flags override the same way.
 */
public final class CiDetector {

    private CiDetector() {}

    public static boolean isCi() {
        return isCi(System.getenv()) || System.console() == null;
    }

    /** Env-var check only (no console check) — so tests can pass an empty env and get false. */
    public static boolean isCi(Map<String, String> env) {
        return isTruthy(env.get("CI"))
                || env.containsKey("GITHUB_ACTIONS")
                || env.containsKey("GITLAB_CI")
                || env.containsKey("JENKINS_URL")
                || env.containsKey("TF_BUILD")
                || env.containsKey("CIRCLECI");
    }

    public static boolean isGitHubActions() {
        return isGitHubActions(System.getenv());
    }

    public static boolean isGitHubActions(Map<String, String> env) {
        return env.containsKey("GITHUB_ACTIONS");
    }

    public static boolean isGitLabCi(Map<String, String> env) {
        return env.containsKey("GITLAB_CI");
    }

    public static boolean isJenkins(Map<String, String> env) {
        return env.containsKey("JENKINS_URL");
    }

    /** Human-readable CI name for logs, or "" when not CI. */
    public static String ciName(Map<String, String> env) {
        if (env.containsKey("GITHUB_ACTIONS")) return "GitHub Actions";
        if (env.containsKey("GITLAB_CI")) return "GitLab CI";
        if (env.containsKey("JENKINS_URL")) return "Jenkins";
        if (env.containsKey("TF_BUILD")) return "Azure DevOps";
        if (env.containsKey("CIRCLECI")) return "CircleCI";
        if (isTruthy(env.get("CI"))) return "CI";
        return "";
    }

    public static boolean noColorEnv() {
        return noColorEnv(System.getenv());
    }

    public static boolean noColorEnv(Map<String, String> env) {
        String v = env.get("NO_COLOR");
        return v != null && !v.isBlank();
    }

    /** Colour is allowed only on a TTY, outside CI, without NO_COLOR / --no-color. */
    public static boolean shouldUseColor(boolean noColorFlag) {
        if (noColorFlag || noColorEnv()) return false;
        if (isCi()) return false;
        return System.console() != null;
    }

    /** Animation is allowed only on a TTY, outside CI, without --no-animation. */
    public static boolean shouldAnimate(boolean noAnimationFlag) {
        if (noAnimationFlag) return false;
        if (isCi()) return false;
        return System.console() != null;
    }

    private static boolean isTruthy(String v) {
        return v != null && !v.isBlank() && !"false".equalsIgnoreCase(v.trim()) && !"0".equals(v.trim());
    }
}
