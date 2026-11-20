package com.depscan.config;

/** A {@code depscan.yml} problem: missing file, bad YAML, or a rule without justification/expiry. */
public class ConfigException extends Exception {

    public ConfigException(String message) {
        super(message);
    }

    public ConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
