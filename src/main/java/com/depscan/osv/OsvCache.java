package com.depscan.osv;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

/**
 * On-disk cache for raw OSV.dev responses, one file per dependency version.
 * Layout: {@code <cacheDir>/<sha256("group:artifact:version")>.json}.
 * Entries are fresh for 24h; stale entries are still returned by
 * {@link #readStale} so {@code --offline} (or a network failure) can fall
 * back to them instead of failing the whole scan.
 */
public final class OsvCache {

    public static final Duration TTL = Duration.ofHours(24);

    private final Path dir;

    public OsvCache(Path dir) {
        this.dir = dir;
    }

    public static Path defaultDir() {
        String override = System.getenv("DEPSCAN_CACHE_DIR");
        if (override != null && !override.isBlank()) return Path.of(override);
        return Path.of(System.getProperty("user.home"), ".cache", "depscan", "osv");
    }

    private Path fileFor(String key) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(key.getBytes(StandardCharsets.UTF_8));
            return dir.resolve(HexFormat.of().formatHex(hash) + ".json");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Fresh (within TTL) cached response, if any. */
    public Optional<String> readFresh(String key) throws IOException {
        Path f = fileFor(key);
        if (!Files.isRegularFile(f)) return Optional.empty();
        Instant modified = Files.getLastModifiedTime(f).toInstant();
        if (Instant.now().minus(TTL).isAfter(modified)) return Optional.empty();
        return Optional.of(Files.readString(f, StandardCharsets.UTF_8));
    }

    /** Any cached response, fresh or stale. */
    public Optional<String> readStale(String key) throws IOException {
        Path f = fileFor(key);
        if (!Files.isRegularFile(f)) return Optional.empty();
        return Optional.of(Files.readString(f, StandardCharsets.UTF_8));
    }

    public void write(String key, String json) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(fileFor(key), json, StandardCharsets.UTF_8);
    }
}
