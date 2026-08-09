package com.ellan.mcace.protocol.policy;

import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionRuleScope;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionAction;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Signs and validates independently versioned detection/disposition policy documents. */
public final class DispositionPolicyDocuments {
    private static final byte[] SIGNATURE_DOMAIN =
            "mcace-disposition-policy-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final int SCHEMA_VERSION = 1;
    private static final int MAX_RULES = 4096;
    private static final int MAX_SCOPE_VALUES = 64;
    private static final int MAX_IDENTIFIER_CHARS = 128;
    private static final int MAX_NOTES_CHARS = 2048;
    private static final Duration MAX_LIFETIME = Duration.ofDays(30);
    private static final Set<String> ROLLOUT_STAGES = Set.of("OBSERVE", "CANARY", "BROAD", "FULL");

    private DispositionPolicyDocuments() {
    }

    public static SignedDispositionPolicyDocument sign(
            DispositionPolicyDocument document, PrivateKey privateKey, PublicKey publicKey)
            throws PolicyException {
        Objects.requireNonNull(document, "document");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        byte[] keyId = PolicyDocuments.keyId(publicKey);
        if (!MessageDigest.isEqual(keyId, document.getSignerKeyIdSha256().toByteArray())) {
            throw new PolicyException("disposition policy signer key id does not match signing key");
        }
        validateStructure(document);
        byte[] body = document.toByteArray();
        return SignedDispositionPolicyDocument.newBuilder()
                .setDocument(ByteString.copyFrom(body))
                .setSignerKeyIdSha256(ByteString.copyFrom(keyId))
                .setSignature(ByteString.copyFrom(sign(signingBytes(body), privateKey)))
                .build();
    }

    public static DispositionPolicyDocument verify(
            SignedDispositionPolicyDocument signed,
            PublicKey trustedKey,
            Clock clock,
            Duration allowedClockSkew) throws PolicyException {
        DispositionPolicyDocument document = verifySignatureAndStructure(signed, trustedKey);
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(allowedClockSkew, "allowedClockSkew");
        if (allowedClockSkew.isNegative()) {
            throw new PolicyException("allowed clock skew must not be negative");
        }
        long now = clock.millis();
        long skew = allowedClockSkew.toMillis();
        if (document.getIssuedAtEpochMs() > safeAdd(now, skew)) {
            throw new PolicyException("disposition policy was issued in the future");
        }
        if (document.getEffectiveFromEpochMs() > safeAdd(now, skew)) {
            throw new PolicyException("disposition policy is not effective yet");
        }
        if (document.getExpiresAtEpochMs() <= safeSubtract(now, skew)) {
            throw new PolicyException("disposition policy has expired");
        }
        return document;
    }

    public static DispositionPolicyDocument verifySignatureAndStructure(
            SignedDispositionPolicyDocument signed, PublicKey trustedKey) throws PolicyException {
        Objects.requireNonNull(signed, "signed");
        Objects.requireNonNull(trustedKey, "trustedKey");
        if (signed.getDocument().isEmpty() || signed.getSignature().isEmpty()
                || signed.getSignerKeyIdSha256().size() != 32) {
            throw new PolicyException("signed disposition policy fields are missing");
        }
        byte[] trustedKeyId = PolicyDocuments.keyId(trustedKey);
        if (!MessageDigest.isEqual(trustedKeyId, signed.getSignerKeyIdSha256().toByteArray())) {
            throw new PolicyException("disposition policy is not signed by the trusted key");
        }
        if (!verifySignature(signingBytes(signed.getDocument().toByteArray()),
                signed.getSignature().toByteArray(), trustedKey)) {
            throw new PolicyException("invalid disposition policy signature");
        }
        DispositionPolicyDocument document;
        try {
            document = DispositionPolicyDocument.parseFrom(signed.getDocument());
        } catch (InvalidProtocolBufferException exception) {
            throw new PolicyException("cannot parse disposition policy", exception);
        }
        if (!MessageDigest.isEqual(
                signed.getSignerKeyIdSha256().toByteArray(),
                document.getSignerKeyIdSha256().toByteArray())) {
            throw new PolicyException("disposition document signer does not match wrapper");
        }
        validateStructure(document);
        return document;
    }

    public static byte[] documentSha256(DispositionPolicyDocument document) throws PolicyException {
        Objects.requireNonNull(document, "document");
        validateStructure(document);
        try {
            return MessageDigest.getInstance("SHA-256").digest(document.toByteArray());
        } catch (NoSuchAlgorithmException exception) {
            throw new PolicyException("SHA-256 is unavailable", exception);
        }
    }

    public static void validateStructure(DispositionPolicyDocument document) throws PolicyException {
        Objects.requireNonNull(document, "document");
        requireIdentifier(document.getPolicyId(), "policy id");
        requireIdentifier(document.getVersion(), "policy version");
        if (document.getSchemaVersion() != SCHEMA_VERSION || document.getSequence() <= 0
                || document.getSignerKeyIdSha256().size() != 32) {
            throw new PolicyException("invalid disposition policy identity fields");
        }
        long issued = document.getIssuedAtEpochMs();
        long effective = document.getEffectiveFromEpochMs();
        long expires = document.getExpiresAtEpochMs();
        if (issued <= 0 || effective < issued || expires <= effective
                || expires - issued > MAX_LIFETIME.toMillis()) {
            throw new PolicyException("invalid disposition policy validity window");
        }
        if (!ROLLOUT_STAGES.contains(document.getRolloutStage())) {
            throw new PolicyException("unsupported disposition policy rollout stage");
        }
        int previousSize = document.getPreviousDocumentSha256().size();
        if ((document.getSequence() == 1 && previousSize != 0)
                || (document.getSequence() > 1 && previousSize != 32)) {
            throw new PolicyException("invalid disposition policy predecessor hash");
        }
        if (document.getRulesCount() > MAX_RULES) {
            throw new PolicyException("disposition policy contains too many rules");
        }
        Set<String> ids = new HashSet<>();
        for (DetectionRule rule : document.getRulesList()) {
            validateRule(rule, effective, expires);
            if (!ids.add(rule.getRuleId())) {
                throw new PolicyException("duplicate disposition rule id: " + rule.getRuleId());
            }
        }
    }

    private static void validateRule(DetectionRule rule, long policyEffective, long policyExpires)
            throws PolicyException {
        requireIdentifier(rule.getRuleId(), "rule id");
        if (rule.getRevision() <= 0
                || rule.getConfidence() == DetectionConfidence.DETECTION_CONFIDENCE_UNSPECIFIED
                || rule.getConfidence() == DetectionConfidence.UNRECOGNIZED
                || rule.getDefaultAction() == DispositionAction.DISPOSITION_ACTION_UNSPECIFIED
                || rule.getDefaultAction() == DispositionAction.UNRECOGNIZED) {
            throw new PolicyException("disposition rule fields are missing: " + rule.getRuleId());
        }
        long effective = rule.getEffectiveFromEpochMs();
        if (effective < policyEffective || rule.getIntroducedAtEpochMs() <= 0
                || rule.getExpiresAtEpochMs() <= effective || rule.getExpiresAtEpochMs() > policyExpires) {
            throw new PolicyException("disposition rule validity is outside its policy");
        }
        if (rule.getPlayerMessageKey().length() > MAX_IDENTIFIER_CHARS
                || rule.getFalsePositiveNotes().length() > MAX_NOTES_CHARS
                || rule.getOperatorReason().length() > MAX_NOTES_CHARS
                || rule.getSourceId().length() > MAX_IDENTIFIER_CHARS
                || rule.getCatalogEntryId().length() > MAX_IDENTIFIER_CHARS
                || rule.getSourceRevision().length() > MAX_IDENTIFIER_CHARS
                || rule.getSourceSummary().length() > MAX_NOTES_CHARS
                || rule.getSourceUri().length() > MAX_NOTES_CHARS
                || rule.getSourceManifestPath().length() > MAX_NOTES_CHARS
                || rule.getLimitJustification().length() > MAX_NOTES_CHARS
                || containsControl(rule.getPlayerMessageKey())
                || containsControl(rule.getFalsePositiveNotes())
                || containsControl(rule.getOperatorReason())
                || containsControl(rule.getSourceId())
                || containsControl(rule.getSourceRevision())
                || containsControl(rule.getSourceSummary())
                || containsControl(rule.getSourceUri())
                || containsControl(rule.getSourceManifestPath())
                || containsControl(rule.getCatalogEntryId())
                || containsControl(rule.getLimitJustification())) {
            throw new PolicyException("disposition rule text exceeds bounds");
        }
        if (rule.getException() && (rule.getFoundationSecurity()
                || rule.getDefaultAction() != DispositionAction.DISPOSITION_ALLOW
                || rule.getScope().getPlayerIdsCount() == 0)) {
            throw new PolicyException("exceptions must be non-foundation ALLOW rules scoped to player ids");
        }
        if (rule.getFoundationSecurity()
                && (rule.getDefaultAction() == DispositionAction.DISPOSITION_ALLOW
                || rule.getSelector().getArtifactType()
                != DetectionArtifactType.DETECTION_ARTIFACT_PROTOCOL)) {
            throw new PolicyException("foundation rules must protect protocol artifacts and cannot ALLOW");
        }
        validateSelector(rule.getSelector(), rule);
        validateScope(rule.getScope());
        validateCatalogProvenance(rule);
    }

    private static void validateSelector(DetectionSelector selector, DetectionRule rule) throws PolicyException {
        if (selector.getArtifactType() == DetectionArtifactType.DETECTION_ARTIFACT_TYPE_UNSPECIFIED
                || selector.getArtifactType() == DetectionArtifactType.UNRECOGNIZED
                || selector.getMatchType() == DetectionMatchType.DETECTION_MATCH_TYPE_UNSPECIFIED
                || selector.getMatchType() == DetectionMatchType.UNRECOGNIZED) {
            throw new PolicyException("disposition selector fields are missing");
        }
        switch (selector.getMatchType()) {
            case DETECTION_MATCH_EXACT_SHA256 -> requireHash(selector.getSha256(), "artifact hash");
            case DETECTION_MATCH_MOD_ID_VERSION -> requireIdentifier(selector.getArtifactId(), "artifact id");
            case DETECTION_MATCH_SIGNER -> requireIdentifier(selector.getSigner(), "artifact signer");
            case DETECTION_MATCH_CONTENT_ROOT -> requireHash(selector.getContentRootSha256(), "content root");
            case DETECTION_MATCH_METADATA -> {
                if (selector.getMetadataCount() == 0 || selector.getMetadataCount() > 64) {
                    throw new PolicyException("metadata selector must be non-empty and bounded");
                }
            }
            case DETECTION_MATCH_BEHAVIOR_CORRELATION ->
                    requireIdentifier(selector.getBehaviorRuleId(), "behavior rule id");
            case DETECTION_MATCH_ADMIN_CLASSIFICATION ->
                    requireIdentifier(selector.getArtifactId(), "admin classification id");
            default -> throw new PolicyException("unsupported disposition selector");
        }
        if (!rule.getFoundationSecurity()) {
            validateSelectorActionGuard(selector.getMatchType(), rule.getDefaultAction());
        }
    }

    /**
     * Operational-rule action ceiling, intentionally enforced before catalog provenance so a
     * valid signature can never elevate a weak selector through a non-catalog rule. Foundation
     * protocol-integrity rules are separately constrained above and retain their existing
     * verified-protocol contract.
     */
    private static void validateSelectorActionGuard(
            DetectionMatchType matchType, DispositionAction action) throws PolicyException {
        switch (matchType) {
            case DETECTION_MATCH_EXACT_SHA256 -> {
                // An independently identified artifact may use the full disposition range.
            }
            case DETECTION_MATCH_CONTENT_ROOT -> {
                if (action.getNumber() > DispositionAction.DISPOSITION_QUARANTINE.getNumber()) {
                    throw new PolicyException("content-root matching may not DENY");
                }
            }
            case DETECTION_MATCH_MOD_ID_VERSION, DETECTION_MATCH_SIGNER, DETECTION_MATCH_METADATA,
                    DETECTION_MATCH_BEHAVIOR_CORRELATION, DETECTION_MATCH_ADMIN_CLASSIFICATION -> {
                if (action.getNumber() > DispositionAction.DISPOSITION_WARN.getNumber()) {
                    throw new PolicyException("non-exact selector may not exceed WARN");
                }
            }
            case DETECTION_MATCH_TYPE_UNSPECIFIED, UNRECOGNIZED ->
                    throw new PolicyException("unsupported disposition selector");
        }
    }

    private static void validateCatalogProvenance(DetectionRule rule) throws PolicyException {
        boolean catalog = !rule.getCatalogEntryId().isEmpty();
        if (!catalog) {
            if (rule.getCatalogCategory() != DetectionCatalogCategory.DETECTION_CATALOG_CATEGORY_UNSPECIFIED
                    || !rule.getSourceId().isEmpty() || !rule.getSourceSummary().isEmpty()
                    || !rule.getLimitJustification().isEmpty() || !rule.getSourceUri().isEmpty()
                    || !rule.getSourceRevision().isEmpty() || !rule.getSourceManifestPath().isEmpty()
                    || rule.getSourceRetrievedAtEpochMs() != 0) {
                throw new PolicyException("catalog provenance is incomplete");
            }
            return;
        }
        if (rule.getCatalogCategory() == DetectionCatalogCategory.DETECTION_CATALOG_CATEGORY_UNSPECIFIED
                || rule.getCatalogCategory() == DetectionCatalogCategory.UNRECOGNIZED
                || rule.getSourceId().isBlank() || rule.getSourceSummary().isBlank()
                || rule.getOperatorReason().isBlank() || rule.getFalsePositiveNotes().isBlank()
                || rule.getException() || rule.getFoundationSecurity()
                || rule.getScope().getPlayerIdsCount() != 0) {
            throw new PolicyException("catalog provenance or scope is invalid");
        }
        validateStructuredCatalogProvenance(rule);
        if ((rule.getCatalogCategory() == DetectionCatalogCategory.ACCESSIBILITY
                || rule.getCatalogCategory() == DetectionCatalogCategory.UTILITY)
                && rule.getDefaultAction().getNumber() > DispositionAction.DISPOSITION_OBSERVE.getNumber()) {
            throw new PolicyException("accessibility and utility catalog rules may only ALLOW or OBSERVE");
        }
        DetectionMatchType matchType = rule.getSelector().getMatchType();
        boolean exact = matchType == DetectionMatchType.DETECTION_MATCH_EXACT_SHA256
                || matchType == DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT;
        if (!exact && rule.getDefaultAction().getNumber() > DispositionAction.DISPOSITION_WARN.getNumber()) {
            throw new PolicyException("catalog non-exact rules may not exceed WARN");
        }
        if ((rule.getDefaultAction() == DispositionAction.DISPOSITION_LIMIT
                || rule.getDefaultAction() == DispositionAction.DISPOSITION_QUARANTINE
                || rule.getDefaultAction() == DispositionAction.DISPOSITION_DENY) && !exact) {
            throw new PolicyException("catalog high-impact rules require exact matching");
        }
    }

    /**
     * Legacy catalog documents have no structured source fields. New documents must either keep
     * all four absent or provide a complete, bounded and non-ambiguous upstream reference.
     */
    private static void validateStructuredCatalogProvenance(DetectionRule rule) throws PolicyException {
        boolean uriPresent = !rule.getSourceUri().isEmpty();
        boolean revisionPresent = !rule.getSourceRevision().isEmpty();
        boolean pathPresent = !rule.getSourceManifestPath().isEmpty();
        boolean retrievedPresent = rule.getSourceRetrievedAtEpochMs() != 0;
        if (!uriPresent && !revisionPresent && !pathPresent && !retrievedPresent) {
            return;
        }
        if (!uriPresent || !revisionPresent || !pathPresent || !retrievedPresent) {
            throw new PolicyException("catalog structured provenance is incomplete");
        }
        validateSourceRevision(rule.getSourceRevision());
        validateSourceUri(rule.getSourceUri());
        validateRelativeManifestPath(rule.getSourceManifestPath());
        long retrieved = rule.getSourceRetrievedAtEpochMs();
        if (retrieved <= 0 || (rule.getIntroducedAtEpochMs() > 0 && retrieved > rule.getIntroducedAtEpochMs())) {
            throw new PolicyException("catalog source retrieval time is invalid");
        }
    }

    private static void validateSourceUri(String value) throws PolicyException {
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getHost().isBlank() || uri.getUserInfo() != null || uri.getFragment() != null) {
                throw new PolicyException("catalog source URI must be absolute HTTPS without userinfo or fragment");
            }
        } catch (URISyntaxException exception) {
            throw new PolicyException("catalog source URI is invalid", exception);
        }
    }

    private static void validateSourceRevision(String value) throws PolicyException {
        if (value.isEmpty() || value.length() > MAX_IDENTIFIER_CHARS
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) {
            throw new PolicyException("catalog source revision is outside safe bounds");
        }
    }

    private static void validateRelativeManifestPath(String value) throws PolicyException {
        if (value.isBlank() || value.startsWith("/") || value.contains("\\")) {
            throw new PolicyException("catalog source manifest path must be relative and slash-separated");
        }
        for (String segment : value.split("/", -1)) {
            if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)
                    || !segment.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) {
                throw new PolicyException("catalog source manifest path contains an unsafe segment");
            }
        }
    }

    private static void validateScope(DetectionRuleScope scope) throws PolicyException {
        validateScopeValues(scope.getProxyIdsList(), "proxy scope");
        validateScopeValues(scope.getBackendIdsList(), "backend scope");
        validateScopeValues(scope.getGameModesList(), "game-mode scope");
        validateScopeValues(scope.getPermissionGroupsList(), "permission scope");
        validateScopeValues(scope.getWorldIdsList(), "world scope");
        validatePlayerIds(scope.getPlayerIdsList());
    }

    private static void validateScopeValues(java.util.List<String> values, String name) throws PolicyException {
        if (values.size() > MAX_SCOPE_VALUES) {
            throw new PolicyException(name + " contains too many values");
        }
        for (String value : values) {
            requireIdentifier(value, name);
        }
    }

    private static void validatePlayerIds(java.util.List<String> values) throws PolicyException {
        if (values.size() > MAX_SCOPE_VALUES) {
            throw new PolicyException("player scope contains too many values");
        }
        Set<UUID> unique = new HashSet<>();
        for (String value : values) {
            UUID playerId;
            try {
                playerId = UUID.fromString(value);
            } catch (IllegalArgumentException exception) {
                throw new PolicyException("player scope contains an invalid UUID", exception);
            }
            if (!playerId.toString().equals(value.toLowerCase(java.util.Locale.ROOT)) || !unique.add(playerId)) {
                throw new PolicyException("player scope contains a non-canonical or duplicate UUID");
            }
        }
    }

    private static void requireIdentifier(String value, String name) throws PolicyException {
        if (value == null || value.isBlank() || value.length() > MAX_IDENTIFIER_CHARS
                || containsControl(value)) {
            throw new PolicyException(name + " is missing or too long");
        }
    }

    private static boolean containsControl(String value) {
        return value != null && value.chars().anyMatch(Character::isISOControl);
    }

    private static void requireHash(ByteString value, String name) throws PolicyException {
        if (value.size() != 32) {
            throw new PolicyException(name + " must contain 32 bytes");
        }
    }

    private static byte[] signingBytes(byte[] body) {
        return ByteBuffer.allocate(SIGNATURE_DOMAIN.length + Integer.BYTES + body.length)
                .put(SIGNATURE_DOMAIN).putInt(body.length).put(body).array();
    }

    private static byte[] sign(byte[] content, PrivateKey key) throws PolicyException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(content);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new PolicyException("cannot sign disposition policy", exception);
        }
    }

    private static boolean verifySignature(byte[] content, byte[] signed, PublicKey key) throws PolicyException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(key);
            signature.update(content);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new PolicyException("cannot verify disposition policy", exception);
        }
    }

    private static long safeAdd(long left, long right) throws PolicyException {
        try {
            return Math.addExact(left, right);
        } catch (ArithmeticException exception) {
            throw new PolicyException("time calculation overflow", exception);
        }
    }

    private static long safeSubtract(long left, long right) throws PolicyException {
        try {
            return Math.subtractExact(left, right);
        } catch (ArithmeticException exception) {
            throw new PolicyException("time calculation overflow", exception);
        }
    }
}
