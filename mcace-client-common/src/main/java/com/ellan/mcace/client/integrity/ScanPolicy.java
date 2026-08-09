package com.ellan.mcace.client.integrity;

import java.util.Locale;
import java.util.Set;

public record ScanPolicy(int maxEntries, long maxFileBytes, Set<String> allowedExtensions) {
    public ScanPolicy {
        if (maxEntries <= 0 || maxFileBytes <= 0) {
            throw new IllegalArgumentException("scan ceilings must be positive");
        }
        allowedExtensions = allowedExtensions.stream()
                .map(extension -> extension.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public static ScanPolicy mods() {
        return new ScanPolicy(4096, 512L * 1024 * 1024, Set.of(".jar", ".disabled"));
    }

    public static ScanPolicy resourcePacks() {
        return new ScanPolicy(4096, 1024L * 1024 * 1024, Set.of(".zip", ".jar", ".json", ".png", ".mcmeta"));
    }
}
