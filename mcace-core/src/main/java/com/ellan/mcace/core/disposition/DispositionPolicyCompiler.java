package com.ellan.mcace.core.disposition;

import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionRuleScope;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Converts a document which the caller has already signature-verified into the deterministic core
 * representation. It repeats structural validation and rejects any field that cannot be mapped
 * without changing its security meaning; it does not verify a signature itself.
 */
public final class DispositionPolicyCompiler {
    private static final int MAX_COMPILED_RULES = 4_096;
    private static final String CONTENT_ROOT_METADATA = "content_root_sha256";
    private static final String SIGNER_METADATA = "signer";
    private static final String ADMIN_CLASSIFICATION_METADATA = "admin_classification";

    private DispositionPolicyCompiler() { }

    public static DispositionPolicy compileVerified(DispositionPolicyDocument document) {
        try {
            DispositionPolicyDocuments.validateStructure(document);
        } catch (PolicyException exception) {
            throw new DispositionPolicyCompileException("invalid verified disposition policy", exception);
        }
        List<DispositionRule> compiled = new ArrayList<>();
        Set<String> compiledIds = new HashSet<>();
        for (DetectionRule rule : document.getRulesList()) {
            validateSourceProvenance(rule);
            ArtifactSelector selector = selector(rule.getSelector());
            List<RuleScope> scopes = scopes(rule.getScope());
            if (compiled.size() > MAX_COMPILED_RULES - scopes.size()) {
                throw new DispositionPolicyCompileException("compiled disposition policy exceeds rule budget");
            }
            for (int index = 0; index < scopes.size(); index++) {
                String id = scopes.size() == 1 ? rule.getRuleId() : rule.getRuleId() + "~scope~" + index;
                if (!compiledIds.add(id)) {
                    throw new DispositionPolicyCompileException("scope-expanded rule id collision: " + id);
                }
                compiled.add(new DispositionRule(
                        id, selector, scopes.get(index), action(rule.getDefaultAction()), confidence(rule.getConfidence()),
                        Instant.ofEpochMilli(rule.getEffectiveFromEpochMs()), Instant.ofEpochMilli(rule.getExpiresAtEpochMs()),
                        unsignedPriority(rule), rule.getFoundationSecurity(),
                        new RuleExplanation(rule.getRuleId(), rule.getPlayerMessageKey(), rule.getFalsePositiveNotes(),
                                rule.getOperatorReason(), Integer.toUnsignedLong(rule.getRevision()),
                                rule.getIntroducedAtEpochMs(), rule.getException(), rule.getSourceUri(),
                                rule.getSourceRevision(), rule.getSourceManifestPath(),
                                rule.getSourceRetrievedAtEpochMs()),
                        rule.getDisabled()));
            }
        }
        return new DispositionPolicy(document.getVersion(), compiled, new DispositionPolicyMetadata(
                document.getPolicyId(), Integer.toUnsignedLong(document.getSchemaVersion()), document.getSequence(),
                Instant.ofEpochMilli(document.getIssuedAtEpochMs()), Instant.ofEpochMilli(document.getEffectiveFromEpochMs()),
                Instant.ofEpochMilli(document.getExpiresAtEpochMs()), document.getRolloutStage(), hex(document.getSignerKeyIdSha256())));
    }

    private static void validateSourceProvenance(DetectionRule rule) {
        try {
            CatalogSourceProvenance provenance = CatalogSourceProvenance.from(rule);
            provenance.validate();
            if (rule.getCatalogEntryId().isEmpty() && !provenance.isEmpty()) {
                throw new IllegalArgumentException("manual rule carries catalog source provenance");
            }
        } catch (IllegalArgumentException exception) {
            throw new DispositionPolicyCompileException(
                    "invalid source provenance for disposition rule: " + rule.getRuleId(), exception);
        }
    }

    /** Strict mapping helper for protocol observations accepted by callers outside this compiler. */
    public static ObservationOrigin observationOrigin(com.ellan.mcace.protocol.generated.ObservationOrigin origin) {
        return switch (origin) {
            case OBSERVATION_ORIGIN_SERVER_CONFIRMED -> ObservationOrigin.SERVER_CONFIRMED;
            case OBSERVATION_ORIGIN_CLIENT_REPORTED -> ObservationOrigin.CLIENT_REPORTED;
            case OBSERVATION_ORIGIN_INFERRED -> ObservationOrigin.INFERRED;
            case OBSERVATION_ORIGIN_ADMIN_REVIEWED -> ObservationOrigin.ADMIN_REVIEWED;
            case OBSERVATION_ORIGIN_UNAVAILABLE -> ObservationOrigin.UNAVAILABLE;
            case OBSERVATION_ORIGIN_UNSPECIFIED, UNRECOGNIZED -> throw unsupported("observation origin", origin);
        };
    }

    static ArtifactType artifactType(DetectionArtifactType type) {
        return switch (type) {
            case DETECTION_ARTIFACT_MOD -> ArtifactType.MOD;
            case DETECTION_ARTIFACT_RESOURCE_PACK -> ArtifactType.RESOURCE_PACK;
            case DETECTION_ARTIFACT_SHADER_PACK -> ArtifactType.SHADER_PACK;
            case DETECTION_ARTIFACT_CONFIG -> ArtifactType.CONFIG;
            case DETECTION_ARTIFACT_BEHAVIOR -> ArtifactType.BEHAVIOR;
            case DETECTION_ARTIFACT_PROTOCOL -> ArtifactType.PROTOCOL;
            case DETECTION_ARTIFACT_TYPE_UNSPECIFIED, UNRECOGNIZED -> throw unsupported("artifact type", type);
        };
    }

    static Confidence confidence(DetectionConfidence confidence) {
        return switch (confidence) {
            case DETECTION_CONFIDENCE_LOW -> Confidence.LOW;
            case DETECTION_CONFIDENCE_MEDIUM -> Confidence.MEDIUM;
            case DETECTION_CONFIDENCE_HIGH -> Confidence.HIGH;
            case DETECTION_CONFIDENCE_CONFIRMED -> Confidence.CONFIRMED;
            case DETECTION_CONFIDENCE_UNSPECIFIED, UNRECOGNIZED -> throw unsupported("confidence", confidence);
        };
    }

    static DispositionAction action(com.ellan.mcace.protocol.generated.DispositionAction action) {
        return switch (action) {
            case DISPOSITION_ALLOW -> DispositionAction.ALLOW;
            case DISPOSITION_OBSERVE -> DispositionAction.OBSERVE;
            case DISPOSITION_NOTICE -> DispositionAction.NOTICE;
            case DISPOSITION_WARN -> DispositionAction.WARN;
            case DISPOSITION_CHALLENGE -> DispositionAction.CHALLENGE;
            case DISPOSITION_LIMIT -> DispositionAction.LIMIT;
            case DISPOSITION_QUARANTINE -> DispositionAction.QUARANTINE;
            case DISPOSITION_DENY -> DispositionAction.DENY;
            case DISPOSITION_ACTION_UNSPECIFIED, UNRECOGNIZED -> throw unsupported("disposition action", action);
        };
    }

    /**
     * Strict protocol-to-core selector mapping shared by local configuration validation.
     * Callers must have already canonicalized administrator hash helpers before using it.
     */
    static ArtifactSelector selector(DetectionSelector source) {
        ArtifactType type = artifactType(source.getArtifactType());
        VersionBounds versions = versionBounds(source.getVersionConstraint());
        return switch (source.getMatchType()) {
            case DETECTION_MATCH_EXACT_SHA256 -> new ArtifactSelector(type, MatchType.EXACT_HASH, hex(source.getSha256()), versions.minimum(), versions.maximum(), Map.of());
            case DETECTION_MATCH_MOD_ID_VERSION -> new ArtifactSelector(type, MatchType.EXACT_ID, source.getArtifactId(), versions.minimum(), versions.maximum(), Map.of());
            case DETECTION_MATCH_SIGNER -> new ArtifactSelector(type, MatchType.METADATA, "signer", versions.minimum(), versions.maximum(), Map.of(SIGNER_METADATA, source.getSigner()));
            case DETECTION_MATCH_CONTENT_ROOT -> new ArtifactSelector(type, MatchType.METADATA, "content-root", versions.minimum(), versions.maximum(), Map.of(CONTENT_ROOT_METADATA, hex(source.getContentRootSha256())));
            case DETECTION_MATCH_METADATA -> new ArtifactSelector(type, MatchType.METADATA, "metadata", versions.minimum(), versions.maximum(), canonicalMetadata(source.getMetadataMap()));
            case DETECTION_MATCH_BEHAVIOR_CORRELATION -> new ArtifactSelector(type, MatchType.EXACT_ID, source.getBehaviorRuleId(), versions.minimum(), versions.maximum(), Map.of());
            case DETECTION_MATCH_ADMIN_CLASSIFICATION -> new ArtifactSelector(type, MatchType.METADATA, "admin-classification", versions.minimum(), versions.maximum(), Map.of(ADMIN_CLASSIFICATION_METADATA, source.getArtifactId()));
            case DETECTION_MATCH_TYPE_UNSPECIFIED, UNRECOGNIZED -> throw unsupported("selector match type", source.getMatchType());
        };
    }

    private static List<RuleScope> scopes(DetectionRuleScope source) {
        List<String> proxies = scopeValues(source.getProxyIdsList(), "proxy");
        List<String> backends = scopeValues(source.getBackendIdsList(), "backend");
        List<String> gameModes = scopeValues(source.getGameModesList(), "game mode");
        List<String> groups = scopeValues(source.getPermissionGroupsList(), "permission group");
        List<String> worlds = scopeValues(source.getWorldIdsList(), "world");
        List<UUID> players = playerScopeValues(source.getPlayerIdsList());
        long variants = 1;
        for (List<?> values : List.of(proxies, backends, gameModes, groups, worlds, players)) {
            if (variants > MAX_COMPILED_RULES / values.size()) {
                throw new DispositionPolicyCompileException("rule scope expansion exceeds rule budget");
            }
            variants *= values.size();
        }
        List<RuleScope> result = new ArrayList<>((int) variants);
        for (String proxy : proxies) for (String backend : backends) for (String gameMode : gameModes)
            for (String group : groups) for (String world : worlds)
                for (UUID player : players)
                    result.add(new RuleScope(proxy, backend, world, gameMode, group, player));
        return List.copyOf(result);
    }

    private static List<String> scopeValues(List<String> values, String name) {
        if (values.isEmpty()) return Collections.singletonList(null);
        Set<String> unique = new HashSet<>(values);
        if (unique.size() != values.size()) throw new DispositionPolicyCompileException("duplicate " + name + " scope value");
        return unique.stream().sorted(Comparator.naturalOrder()).toList();
    }

    private static List<UUID> playerScopeValues(List<String> values) {
        if (values.isEmpty()) return Collections.singletonList(null);
        Set<UUID> unique = new HashSet<>();
        for (String value : values) {
            try {
                UUID parsed = UUID.fromString(value);
                if (!parsed.toString().equals(value.toLowerCase(java.util.Locale.ROOT)) || !unique.add(parsed)) {
                    throw new DispositionPolicyCompileException("duplicate or non-canonical player scope value");
                }
            } catch (IllegalArgumentException exception) {
                throw new DispositionPolicyCompileException("invalid player scope UUID", exception);
            }
        }
        return unique.stream().sorted(Comparator.comparing(UUID::toString)).toList();
    }

    private static Map<String, String> canonicalMetadata(Map<String, String> metadata) {
        if (metadata.isEmpty()) throw new DispositionPolicyCompileException("metadata selector must not be empty");
        return metadata.entrySet().stream().sorted(Map.Entry.comparingByKey()).collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static int unsignedPriority(DetectionRule rule) {
        long priority = Integer.toUnsignedLong(rule.getPriority());
        if (priority > Integer.MAX_VALUE) throw new DispositionPolicyCompileException("rule priority exceeds core range: " + rule.getRuleId());
        return (int) priority;
    }

    private static VersionBounds versionBounds(String source) {
        if (source.isEmpty()) return new VersionBounds(null, null);
        if (source.startsWith("=")) source = source.substring(1);
        if (source.isBlank() || source.startsWith(">") || source.startsWith("<") || source.contains(",") || source.contains("[") || source.contains("(") || source.contains(" ")) {
            throw new DispositionPolicyCompileException("unsupported version constraint; use an exact version or no constraint");
        }
        return new VersionBounds(source, source);
    }

    private static String hex(ByteString bytes) {
        if (bytes.size() != 32) throw new DispositionPolicyCompileException("expected SHA-256 bytes");
        StringBuilder result = new StringBuilder(64);
        for (byte value : bytes.toByteArray()) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }

    private static DispositionPolicyCompileException unsupported(String field, Object value) {
        return new DispositionPolicyCompileException("unsupported " + field + ": " + value);
    }

    private record VersionBounds(String minimum, String maximum) { }
}
