package com.example.app;

import org.yaml.snakeyaml.Yaml;

/**
 * Dead code on purpose: loadYaml is private and nothing in this project
 * calls it, so the SnakeYAML vulnerability must come back LOW (unreachable),
 * not CRITICAL — even though the dependency is declared in the pom.
 */
class UnusedHelper {
    @SuppressWarnings("unused")
    private Object loadYaml(String text) {
        return new Yaml().load(text);
    }
}
