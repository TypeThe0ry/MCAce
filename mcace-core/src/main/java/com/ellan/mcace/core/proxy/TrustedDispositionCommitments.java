package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.EvaluationContext;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/** Domain-separated, content-free commitments binding an authorization to its exact inputs. */
public final class TrustedDispositionCommitments {
    private static final HexFormat HEX = HexFormat.of();

    private TrustedDispositionCommitments() {
    }

    static String session(UUID authorizationId, String sessionId) {
        Objects.requireNonNull(authorizationId, "authorizationId");
        Objects.requireNonNull(sessionId, "sessionId");
        MessageDigest digest = sha256();
        field(digest, "mcace/trusted-disposition/session/v1");
        field(digest, authorizationId.toString());
        field(digest, sessionId);
        return HEX.formatHex(digest.digest());
    }

    static String reviewInput(
            UUID authorizationId,
            EvaluationContext context,
            ArtifactObservation observation) {
        Objects.requireNonNull(authorizationId, "authorizationId");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(observation, "observation");
        MessageDigest digest = sha256();
        field(digest, "mcace/trusted-disposition/review-input/v1");
        field(digest, authorizationId.toString());
        field(digest, context.playerId().toString());
        nullableField(digest, context.proxy());
        nullableField(digest, context.backend());
        nullableField(digest, context.world());
        nullableField(digest, context.gameMode());
        field(digest, context.evaluatedAt().toString());
        field(digest, Integer.toString(context.permissionGroups().size()));
        context.permissionGroups().stream().sorted().forEach(value -> field(digest, value));
        field(digest, observation.type().name());
        field(digest, observation.identifier());
        field(digest, observation.version());
        nullableField(digest, observation.sha256());
        field(digest, observation.origin().name());
        field(digest, observation.confidence().name());
        field(digest, Boolean.toString(observation.foundationSecurity()));
        field(digest, Integer.toString(observation.metadata().size()));
        observation.metadata().entrySet().stream()
                .sorted(java.util.Map.Entry.comparingByKey())
                .forEach(entry -> {
                    field(digest, entry.getKey());
                    field(digest, entry.getValue());
                });
        return HEX.formatHex(digest.digest());
    }

    static String serverInput(
            UUID authorizationId,
            EvaluationContext context,
            ServerConfirmedDispositionInput input) {
        Objects.requireNonNull(input, "input");
        MessageDigest digest = sha256();
        field(digest, "mcace/trusted-disposition/server-input/v1");
        field(digest, authorizationId.toString());
        field(digest, input.serverObservation().provider());
        field(digest, input.serverObservation().signal());
        field(digest, input.serverObservation().observedAt().toString());
        field(digest, reviewInput(authorizationId, context, input.correlatedObservation()));
        return HEX.formatHex(digest.digest());
    }

    /**
     * Commits to the mutable execution scope without binding the review timestamp.
     *
     * <p>Adapters recompute this value while holding their physical-login lifecycle boundary.
     * A backend, proxy, world, game-mode, group, or player change therefore invalidates a queued
     * authorization instead of allowing it to execute in a different scope.</p>
     */
    public static String executionContext(UUID authorizationId, EvaluationContext context) {
        Objects.requireNonNull(authorizationId, "authorizationId");
        Objects.requireNonNull(context, "context");
        MessageDigest digest = sha256();
        field(digest, "mcace/trusted-disposition/execution-context/v1");
        field(digest, authorizationId.toString());
        field(digest, context.playerId().toString());
        nullableField(digest, context.proxy());
        nullableField(digest, context.backend());
        nullableField(digest, context.world());
        nullableField(digest, context.gameMode());
        field(digest, Integer.toString(context.permissionGroups().size()));
        context.permissionGroups().stream().sorted().forEach(value -> field(digest, value));
        return HEX.formatHex(digest.digest());
    }

    /** Constant-time comparison for a previously validated lowercase SHA-256 commitment. */
    public static boolean executionContextMatches(
            UUID authorizationId, EvaluationContext context, String expectedSha256) {
        Objects.requireNonNull(expectedSha256, "expectedSha256");
        if (!expectedSha256.matches("[0-9a-f]{64}")) {
            return false;
        }
        return MessageDigest.isEqual(
                HEX.parseHex(executionContext(authorizationId, context)),
                HEX.parseHex(expectedSha256));
    }

    private static void nullableField(MessageDigest digest, String value) {
        digest.update((byte) (value == null ? 0 : 1));
        if (value != null) {
            field(digest, value);
        }
    }

    private static void field(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK SHA-256 is unavailable", exception);
        }
    }
}
