package com.ellan.mcace.client.observation;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityEntry;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Converts an already policy-scoped integrity manifest into neutral artifact observations.
 *
 * <p>This class deliberately does not classify an artifact as cheating. Its output has
 * {@link ObservationOrigin#CLIENT_REPORTED} provenance and {@link Confidence#LOW} confidence;
 * a signed server disposition policy decides whether an observation has operational meaning.
 * The only extra read for a Fabric mod is its bounded {@code fabric.mod.json} metadata file.
 */
public final class ArtifactObservationCollector {
    private static final Map<String, ArtifactType> ARTIFACT_TYPES = Map.of(
            "mods", ArtifactType.MOD,
            "resourcepacks", ArtifactType.RESOURCE_PACK,
            "shaderpacks", ArtifactType.SHADER_PACK);

    /**
     * Builds observations only for directory scopes explicitly granted in {@code policy}.
     * The supplied bundle must have been produced from that same policy.
     */
    public List<ArtifactObservation> collect(
            Path minecraftRoot, SecurityPolicy policy, ClientIntegrityBundle bundle) throws IntegrityScanException {
        Objects.requireNonNull(minecraftRoot, "minecraftRoot");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(bundle, "bundle");

        Map<String, IntegrityScopeRule> rulesByScope = rulesByScope(policy);
        List<ArtifactObservation> observations = new ArrayList<>();
        for (ScopeIntegrityManifest scope : bundle.scopes()) {
            IntegrityScopeRule rule = rulesByScope.get(scope.scope());
            if (rule == null) {
                throw new IntegrityScanException("integrity bundle contains a scope not granted by policy: " + scope.scope());
            }
            ArtifactType type = ARTIFACT_TYPES.get(rule.getRelativeRoot());
            if (type == null || rule.getExplicitRelativeFilesCount() != 0) {
                continue;
            }
            if (!scope.present()) {
                continue;
            }
            for (IntegrityEntry entry : scope.entries()) {
                observations.add(observationFor(minecraftRoot, rule, type, entry));
            }
        }
        return observations.stream().sorted(Comparator
                        .comparing((ArtifactObservation observation) -> observation.type().name())
                        .thenComparing(ArtifactObservation::identifier)
                        .thenComparing(ArtifactObservation::version)
                        .thenComparing(observation -> observation.sha256() == null ? "" : observation.sha256()))
                .toList();
    }

    private static Map<String, IntegrityScopeRule> rulesByScope(SecurityPolicy policy) throws IntegrityScanException {
        Map<String, IntegrityScopeRule> byScope = new HashMap<>();
        for (IntegrityScopeRule rule : policy.getIntegrityScopesList()) {
            String scope = rule.getScope().toLowerCase(Locale.ROOT);
            if (scope.isBlank() || byScope.putIfAbsent(scope, rule) != null) {
                throw new IntegrityScanException("artifact observation policy contains duplicate or invalid scope");
            }
        }
        return Map.copyOf(byScope);
    }

    private static ArtifactObservation observationFor(
            Path minecraftRoot, IntegrityScopeRule rule, ArtifactType type, IntegrityEntry entry)
            throws IntegrityScanException {
        String identifier = "unknown";
        String version = "unknown";
        String metadataStatus = "not-applicable";
        if (type == ArtifactType.MOD) {
            FabricModMetadata metadata = FabricModMetadata.read(resolveScannedFile(minecraftRoot, rule, entry));
            identifier = metadata.identifier();
            version = metadata.version();
            metadataStatus = metadata.status();
        }
        Map<String, String> metadata = new java.util.TreeMap<>();
        metadata.put("artifact_path", entry.relativePath());
        metadata.put("classification_input", classificationInput(type));
        metadata.put("metadata_status", metadataStatus);
        metadata.put("scope", rule.getScope().toLowerCase(Locale.ROOT));
        return new ArtifactObservation(
                type,
                identifier,
                version,
                entry.sha256Hex(),
                metadata,
                ObservationOrigin.CLIENT_REPORTED,
                Confidence.LOW,
                false);
    }

    private static Path resolveScannedFile(Path minecraftRoot, IntegrityScopeRule rule, IntegrityEntry entry)
            throws IntegrityScanException {
        Path root = minecraftRoot.toAbsolutePath().normalize();
        Path scope = root.resolve(rule.getRelativeRoot()).normalize();
        Path relative = Path.of(entry.relativePath());
        if (relative.isAbsolute()) {
            throw new IntegrityScanException("manifest artifact path must be relative");
        }
        Path file = scope.resolve(relative).normalize();
        if (!scope.startsWith(root) || !file.startsWith(scope)) {
            throw new IntegrityScanException("manifest artifact path escapes its policy scope");
        }
        rejectSymlinkSegments(root, file);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IntegrityScanException("manifest artifact is no longer a regular file");
        }
        return file;
    }

    private static void rejectSymlinkSegments(Path root, Path file) throws IntegrityScanException {
        Path current = root;
        for (Path segment : root.relativize(file)) {
            current = current.resolve(segment);
            if (Files.isSymbolicLink(current)) {
                throw new IntegrityScanException("symbolic links are not allowed in artifact scopes");
            }
        }
    }

    private static String classificationInput(ArtifactType type) {
        return switch (type) {
            case MOD -> "fabric-mod-manifest";
            case RESOURCE_PACK -> "resource-pack-manifest";
            case SHADER_PACK -> "shader-pack-manifest";
            default -> throw new IllegalArgumentException("unsupported client artifact type: " + type);
        };
    }
}
