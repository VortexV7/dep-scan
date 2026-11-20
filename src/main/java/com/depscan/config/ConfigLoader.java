package com.depscan.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Loads {@code depscan.yml}. Shape:
 *
 * <pre>
 * failOn: critical            # optional: critical | reachable | high | none
 * ignore:                     # or "ignores:"
 *   - id: CVE-2022-1471
 *     package: org.yaml:snakeyaml   # optional scope ("dependency:" also accepted)
 *     reason: Only used in tests, never on untrusted input
 *     expires: 2026-12-31           # required, YYYY-MM-DD ("expiry:" also accepted)
 * </pre>
 *
 * Rules without a {@code reason} or an {@code expires} date are config
 * errors (exit 2) — an ignore must be justified and time-boxed. A bad
 * date, an unknown top-level shape, or unreadable YAML is also exit 2.
 * A missing file is an error only when the caller explicitly asked for
 * that file; auto-discovery callers check existence first.
 */
public final class ConfigLoader {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private ConfigLoader() {}

    public static DepScanConfig load(Path configFile) throws ConfigException {
        if (!Files.isRegularFile(configFile)) {
            throw new ConfigException("Config file not found: " + configFile);
        }
        Map<String, Object> root;
        try {
            String text = Files.readString(configFile);
            if (text.isBlank()) return DepScanConfig.empty();
            Object parsed = YAML.readValue(text, Object.class);
            if (!(parsed instanceof Map)) {
                throw new ConfigException("Config " + configFile + " must be a YAML mapping (failOn / ignore)");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) parsed;
            root = map;
        } catch (IOException e) {
            throw new ConfigException("Cannot read config " + configFile + ": " + e.getMessage(), e);
        }

        String failOn = stringValue(root.get("failOn"));
        if (failOn == null) failOn = stringValue(root.get("fail-on"));
        if (failOn != null) {
            String f = failOn.trim().toLowerCase();
            if (!List.of("critical", "reachable", "high", "none").contains(f)) {
                throw new ConfigException("Config " + configFile + ": invalid failOn '" + failOn
                        + "' (use critical, reachable, high or none)");
            }
            failOn = f;
        }

        Object ignoreNode = root.get("ignore");
        if (ignoreNode == null) ignoreNode = root.get("ignores");
        List<IgnoreRule> ignores = new ArrayList<>();
        if (ignoreNode != null) {
            if (!(ignoreNode instanceof List)) {
                throw new ConfigException("Config " + configFile + ": 'ignore' must be a list of rules");
            }
            int i = 0;
            for (Object entry : (List<?>) ignoreNode) {
                i++;
                if (!(entry instanceof Map)) {
                    throw new ConfigException("Config " + configFile + ": ignore entry #" + i + " must be a mapping");
                }
                @SuppressWarnings("unchecked")
                Map<String, Object> rule = (Map<String, Object>) entry;
                String id = stringValue(rule.get("id"));
                if (id == null) id = stringValue(rule.get("advisory"));
                String dep = stringValue(rule.get("package"));
                if (dep == null) dep = stringValue(rule.get("dependency"));
                String reason = stringValue(rule.get("reason"));
                if (reason == null) reason = stringValue(rule.get("justification"));
                String expiresRaw = stringValue(rule.get("expires"));
                if (expiresRaw == null) expiresRaw = stringValue(rule.get("expiry"));
                if (expiresRaw == null) expiresRaw = stringValue(rule.get("until"));
                if (id == null || id.isBlank()) {
                    throw new ConfigException("Config " + configFile + ": ignore entry #" + i + " has no 'id'");
                }
                if (reason == null || reason.isBlank()) {
                    throw new ConfigException("Config " + configFile + ": ignore for '" + id
                            + "' has no 'reason' - every ignore needs a justification");
                }
                if (expiresRaw == null || expiresRaw.isBlank()) {
                    throw new ConfigException("Config " + configFile + ": ignore for '" + id
                            + "' has no 'expires' date - every ignore needs an expiry (YYYY-MM-DD)");
                }
                LocalDate expires;
                try {
                    expires = LocalDate.parse(expiresRaw.trim());
                } catch (DateTimeParseException e) {
                    throw new ConfigException("Config " + configFile + ": ignore for '" + id
                            + "' has an invalid 'expires' date '" + expiresRaw + "' (use YYYY-MM-DD)");
                }
                ignores.add(new IgnoreRule(id, dep, reason, expires));
            }
        }
        return new DepScanConfig(ignores, failOn);
    }

    /** Auto-discover: {@code depscan.yml} (or {@code depscan.yaml}) in the project dir, else empty config. */
    public static DepScanConfig discover(Path projectDir) throws ConfigException {
        Path yml = projectDir.resolve("depscan.yml");
        if (Files.isRegularFile(yml)) return load(yml);
        Path yaml = projectDir.resolve("depscan.yaml");
        if (Files.isRegularFile(yaml)) return load(yaml);
        return DepScanConfig.empty();
    }

    private static String stringValue(Object v) {
        if (v == null) return null;
        return String.valueOf(v).trim();
    }
}
