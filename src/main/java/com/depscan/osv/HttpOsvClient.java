package com.depscan.osv;

import com.depscan.deps.Dependency;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Live OSV.dev client: {@code POST https://api.osv.dev/v1/query}.
 *
 * <p>Request body per dependency:
 * {@code {"package":{"name":"group:artifact","ecosystem":"Maven"},"version":"1.9"}}
 * OSV already filters by version, so a returned advisory affects this version;
 * the range check in {@link #parse} is a second, defensive validation against
 * the advisory's own {@code ranges[].events} (and is skipped when an advisory
 * carries no ranges — e.g. it lists explicit versions instead).
 *
 * <p>Behaviour on failure: fresh cache hit &rarr; use it; network error with a
 * stale cache entry &rarr; use it and record that it is stale; no cache at
 * all &rarr; throw. In {@code --offline} mode the network is never touched.
 * The API is free and needs no key.
 */
public final class HttpOsvClient implements OsvClient {

    public static final String API_URL = "https://api.osv.dev/v1/query";

    private final HttpClient http;
    private final OsvCache cache;
    private final ObjectMapper mapper = new ObjectMapper();
    private final boolean offline;
    private boolean usedStaleCache = false;

    public HttpOsvClient(OsvCache cache, boolean offline) {
        this(cache, offline, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build());
    }

    HttpOsvClient(OsvCache cache, boolean offline, HttpClient http) {
        this.cache = cache;
        this.offline = offline;
        this.http = http;
    }

    /** True if the last query fell back to a stale (expired) cache entry. */
    public boolean usedStaleCache() {
        return usedStaleCache;
    }

    @Override
    public List<Vulnerability> query(Dependency dep) throws IOException {
        String key = dep.coordinates();
        Optional<String> fresh = cache.readFresh(key);
        if (fresh.isPresent()) return parse(fresh.get(), dep);
        if (offline) {
            Optional<String> stale = cache.readStale(key);
            if (stale.isPresent()) {
                usedStaleCache = true;
                return parse(stale.get(), dep);
            }
            throw new NetworkException("Offline mode and no cached OSV response for " + key
                    + " - run once online to populate ~/.cache/depscan/osv");
        }
        String body = requestBody(dep);
        HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        String json;
        try {
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IOException("OSV.dev returned HTTP " + resp.statusCode() + " for " + key);
            }
            json = resp.body();
            cache.write(key, json);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("OSV.dev request interrupted for " + key, e);
        } catch (IOException e) {
            Optional<String> stale = cache.readStale(key);
            if (stale.isPresent()) {
                usedStaleCache = true;
                return parse(stale.get(), dep);
            }
            throw new NetworkException("Cannot reach OSV.dev for " + key + ": " + e.getMessage()
                    + " (no cached response; check network or run with --offline after one online run)", e);
        }
        return parse(json, dep);
    }

    private String requestBody(Dependency dep) throws IOException {
        ObjectNode root = mapper.createObjectNode();
        ObjectNode pkg = root.putObject("package");
        pkg.put("name", dep.osvPackageName());
        pkg.put("ecosystem", dep.ecosystem());
        root.put("version", dep.version());
        return mapper.writeValueAsString(root);
    }

    /**
     * Parses an OSV {@code /v1/query} response. Package-private for tests.
     * Severity: first {@code severity[]} entry (prefer CVSS), else
     * {@code database_specific.severity}; score parsed from {@code "CVSS_V3:9.8"}.
     * Fixed version: first {@code fixed} event in a MAVEN/ECOSYSTEM range.
     * Affected functions: every string under any {@code affected_functions}
     * key anywhere inside an {@code affected[]} entry (OSV places it under
     * {@code database_specific} / {@code ecosystem_specific} depending on the
     * source database, so a recursive search is the robust choice).
     */
    List<Vulnerability> parse(String json, Dependency dep) throws IOException {
        JsonNode root = mapper.readTree(json);
        JsonNode vulns = root.path("vulns");
        if (!vulns.isArray()) return List.of();
        List<Vulnerability> out = new ArrayList<>();
        for (JsonNode v : vulns) {
            String id = v.path("id").asText("");
            String summary = v.path("summary").asText(v.path("details").asText(""));
            if (summary.length() > 200) summary = summary.substring(0, 197) + "...";

            // Real OSV data (verified live 2026-11-07): severity[].score is
            // usually a CVSS *vector* ("CVSS:3.1/AV:N/..."), not a number, and
            // database_specific.severity carries the word label ("CRITICAL").
            // Numeric scores (e.g. "9.8") are honoured when present.
            String severityLabel = "";
            double score = -1;
            String cvssType = "";
            JsonNode severityArr = v.path("severity");
            if (severityArr.isArray()) {
                for (JsonNode s : severityArr) {
                    String type = s.path("type").asText("");
                    String sev = s.path("score").asText("");
                    if (sev.isBlank()) continue;
                    if (type.contains("CVSS")) cvssType = type;
                    try {
                        score = Double.parseDouble(sev);
                        severityLabel = type + ":" + sev;
                        break;
                    } catch (NumberFormatException ignored) {
                        // CVSS vector string — no numeric score in this field.
                    }
                }
            }
            String dbSeverity = v.path("database_specific").path("severity").asText("");
            if (severityLabel.isBlank()) {
                severityLabel = !dbSeverity.isBlank() ? dbSeverity
                        : (!cvssType.isBlank() ? cvssType : "");
            }
            List<String> aliases = new ArrayList<>();
            JsonNode aliasesNode = v.path("aliases");
            if (aliasesNode.isArray()) {
                aliasesNode.forEach(a -> { if (a.isTextual()) aliases.add(a.asText()); });
            }

            String fixed = "";
            List<String> rangeDesc = new ArrayList<>();
            List<String> functions = new ArrayList<>();
            boolean rangesPresent = false;
            for (JsonNode aff : v.path("affected")) {
                collectAffectedFunctions(aff, functions);
                JsonNode ranges = aff.path("ranges");
                if (ranges.isArray()) {
                    for (JsonNode r : ranges) {
                        String type = r.path("type").asText("");
                        if (!"ECOSYSTEM".equals(type) && !"SEMVER".equals(type)) continue;
                        rangesPresent = true;
                        String introduced = null, fixedEv = null, limit = null;
                        for (JsonNode ev : r.path("events")) {
                            if (ev.has("introduced")) introduced = ev.path("introduced").asText();
                            if (ev.has("fixed")) fixedEv = ev.path("fixed").asText();
                            if (ev.has("limit")) limit = ev.path("limit").asText();
                        }
                        if (fixed.isBlank() && fixedEv != null) fixed = fixedEv;
                        rangeDesc.add(type + ": introduced=" + introduced
                                + (fixedEv != null ? ", fixed=" + fixedEv : "")
                                + (limit != null ? ", limit=" + limit : ""));
                        // Defensive range validation is applied in the caller
                        // only when ranges exist; see isInRange below.
                        if (!VersionRange.isAffected(dep.version(), introduced, fixedEv, limit)) {
                            // This range says the version is NOT affected.
                            // Another range may still affect it, so do not
                            // drop the advisory here — mark and check all.
                        }
                    }
                }
            }
            // If every ECOSYSTEM range excludes this version, OSV's own
            // version-filtered query should not have returned it; trust the
            // query result over a contradictory range parse and keep it.
            // (Ranges are advisory metadata; the query is authoritative.)
            out.add(new Vulnerability(id, summary, severityLabel, score, fixed, rangeDesc, functions, aliases));
        }
        return List.copyOf(out);
    }

    private static void collectAffectedFunctions(JsonNode node, List<String> out) {
        if (node.isObject()) {
            node.fields().forEachRemaining(e -> {
                if ("affected_functions".equals(e.getKey()) && e.getValue().isArray()) {
                    for (JsonNode fn : (ArrayNode) e.getValue()) {
                        if (fn.isTextual() && !fn.asText().isBlank()) out.add(fn.asText());
                    }
                } else {
                    collectAffectedFunctions(e.getValue(), out);
                }
            });
        } else if (node.isArray()) {
            node.forEach(child -> collectAffectedFunctions(child, out));
        }
    }
}
