package com.ellan.mcace.velocity;

import com.ellan.mcace.core.session.InventoryAdmissionPolicy;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/** Optional startup-only configuration; absence never enables disconnection. */
final class VelocityInventoryAdmissionConfig {
    private VelocityInventoryAdmissionConfig() { }

    static InventoryAdmissionPolicy load(Path path) throws IOException {
        if (!Files.exists(path)) return InventoryAdmissionPolicy.disabled();
        if (Files.size(path) > 131072) throw new IOException("inventory admission configuration is too large");
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        String enabled = properties.getProperty("enabled", "false").trim();
        if (!enabled.equals("true") && !enabled.equals("false")) {
            throw new IOException("inventory admission enabled must be true or false");
        }
        try {
            return new InventoryAdmissionPolicy(Boolean.parseBoolean(enabled),
                    selectors(properties.getProperty("denied-mod-ids", "")),
                    selectors(properties.getProperty("denied-selected-resource-packs", "")));
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid inventory admission selectors", exception);
        }
    }

    private static Set<String> selectors(String input) {
        if (input.isBlank()) return Set.of();
        Set<String> values = new HashSet<>();
        for (String value : input.split(",", -1)) {
            if (!values.add(value.trim())) throw new IllegalArgumentException("duplicate selector");
        }
        return values;
    }
}
