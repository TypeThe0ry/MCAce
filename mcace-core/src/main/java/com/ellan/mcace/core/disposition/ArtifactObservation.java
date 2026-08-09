package com.ellan.mcace.core.disposition;

import java.util.Map;
import java.util.Objects;

public record ArtifactObservation(ArtifactType type, String identifier, String version, String sha256,
                                  Map<String, String> metadata, ObservationOrigin origin, Confidence confidence,
                                  boolean foundationSecurity) {
    public ArtifactObservation {
        Objects.requireNonNull(type, "type"); Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(version, "version"); Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(origin, "origin"); Objects.requireNonNull(confidence, "confidence");
        if (identifier.isBlank() || version.isBlank()) throw new IllegalArgumentException("identifier and version are required");
        if (sha256 != null && !sha256.matches("[A-Fa-f0-9]{64}")) throw new IllegalArgumentException("sha256 must be 64 hexadecimal characters");
        if (foundationSecurity && type != ArtifactType.PROTOCOL) {
            throw new IllegalArgumentException("foundation observations must describe protocol artifacts");
        }
        metadata = Map.copyOf(metadata);
    }
}
