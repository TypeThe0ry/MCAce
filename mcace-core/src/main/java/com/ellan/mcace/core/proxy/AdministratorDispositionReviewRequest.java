package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.util.Map;
import java.util.Objects;

/** Bounded operator input; the active signed policy, never the command, selects the action. */
public record AdministratorDispositionReviewRequest(
        String reviewTicket,
        ArtifactType artifactType,
        String identifier,
        String version,
        String sha256) {
    private static final int MAX_VALUE_CHARS = 128;

    public AdministratorDispositionReviewRequest {
        Objects.requireNonNull(reviewTicket, "reviewTicket");
        Objects.requireNonNull(artifactType, "artifactType");
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(sha256, "sha256");
        validateToken(reviewTicket, "reviewTicket");
        validateToken(identifier, "identifier");
        validateToken(version, "version");
        if (!sha256.matches("[A-Fa-f0-9]{64}")) {
            throw new IllegalArgumentException("sha256 must be 64 hexadecimal characters");
        }
        if (artifactType != ArtifactType.MOD
                && artifactType != ArtifactType.RESOURCE_PACK
                && artifactType != ArtifactType.SHADER_PACK
                && artifactType != ArtifactType.CONFIG) {
            throw new IllegalArgumentException("administrator artifact review type is unsupported");
        }
        sha256 = sha256.toLowerCase(java.util.Locale.ROOT);
    }

    public ArtifactObservation observation() {
        return new ArtifactObservation(
                artifactType, identifier, version, sha256, Map.of(),
                ObservationOrigin.ADMIN_REVIEWED, Confidence.CONFIRMED, false);
    }

    public static ArtifactType parseArtifactType(String value) {
        Objects.requireNonNull(value, "value");
        return switch (value.toLowerCase(java.util.Locale.ROOT)) {
            case "mod" -> ArtifactType.MOD;
            case "resource-pack", "resource_pack", "resourcepack" -> ArtifactType.RESOURCE_PACK;
            case "shader-pack", "shader_pack", "shaderpack" -> ArtifactType.SHADER_PACK;
            case "config" -> ArtifactType.CONFIG;
            default -> throw new IllegalArgumentException("unsupported administrator artifact review type");
        };
    }

    private static void validateToken(String value, String field) {
        if (value.isBlank() || value.length() > MAX_VALUE_CHARS
                || value.chars().anyMatch(character -> Character.isISOControl(character)
                || Character.isWhitespace(character))) {
            throw new IllegalArgumentException(field + " must be one bounded token");
        }
    }
}