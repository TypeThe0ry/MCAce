package com.ellan.mcace.bungeecord;

import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.core.proxy.SharedProxyDispositionPolicyRuntime;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.ShadowBackendContextRuntime;
import com.ellan.mcace.core.session.HeartbeatTransition;
import com.ellan.mcace.core.session.HeartbeatMissingPolicy;
import com.ellan.mcace.core.session.HeartbeatMissingTransition;
import com.ellan.mcace.core.evidence.EvidenceIngressResult;
import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import com.ellan.mcace.core.evidence.EvidenceRequestSpec;
import com.ellan.mcace.core.evidence.EvidenceAdminService;
import com.ellan.mcace.core.evidence.LoopbackEvidenceReviewService;
import com.ellan.mcace.core.federation.FederationRuntime;
import com.ellan.mcace.core.federation.FederationSubject;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.security.PrivateKey;
import java.util.function.Consumer;
import com.ellan.mcace.protocol.crypto.EnvelopeException;

/**
 * Boundary between BungeeCord transport and the shared MCAce security/session implementation.
 *
 * <p>Implementations must use the shared core coordinator or a cloud-authoritative equivalent.
 * They must not turn a single client signal into a ban or kick decision.</p>
 */
public interface BungeeSessionBridge extends AutoCloseable {
    Optional<byte[]> begin(UUID playerId);

    BungeeBridgeAction receive(UUID playerId, byte[] encodedFrame);

    default Optional<EvidenceRequestRuntime.IssuedRequest> issueEvidenceRequest(
            UUID playerId, EvidenceRequestSpec spec, String operatorId) throws EnvelopeException {
        return Optional.empty();
    }

    /** Cancels the bridge's single outstanding evidence request for this player, when supported. */
    default boolean cancelEvidenceRequest(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return false;
    }

    default EvidenceRequestSpec evidenceRequestSpec(EvidenceCaptureScope scope, String caseId) {
        return EvidenceRequestSpec.screenshot(scope, caseId);
    }

    default Optional<EvidenceAdminService> evidenceAdmin() {
        return Optional.empty();
    }

    /** Optional local-only review endpoint owned by the bridge lifecycle. */
    default Optional<LoopbackEvidenceReviewService> evidenceReviewService() {
        return Optional.empty();
    }

    default EvidenceIngressResult receiveEvidence(UUID playerId, byte[] encodedFrame) {
        return new EvidenceIngressResult(EvidenceIngressResult.Status.REJECTED, List.of(), "evidence unavailable");
    }

    List<PlayerSecuritySnapshot> expireTimedOut();

    /** Monitor-only heartbeat transitions; implementations must not change admission here. */
    default List<HeartbeatTransition> pollHeartbeatTransitions() {
        return List.of();
    }

    default List<HeartbeatMissingTransition> pollHeartbeatMissingTransitions() { return List.of(); }
    default HeartbeatMissingPolicy heartbeatMissingPolicy() { return HeartbeatMissingPolicy.disabled(); }

    void remove(UUID playerId);

    MCAceApi api();

    default Optional<FederationRuntime> federationRuntime() {
        return Optional.empty();
    }

    default Optional<FederationSubject> federationSubject(UUID playerId) {
        return Optional.empty();
    }

    /**
     * Signing key for backend admission snapshots, if this bridge is active.
     *
     * <p>Backend plugins must independently pin the corresponding public key; a client plugin
     * message is never an admission authority.</p>
     */
    default Optional<PrivateKey> admissionSigningKey() {
        return Optional.empty();
    }

    /**
     * Optional shared disposition-policy runtime owned by this bridge.
     *
     * <p>The runtime only evaluates signed policy. The adapter may execute the resulting
     * content-free event through its bounded, session-bound executor; it never changes the
     * admission snapshot or creates a permanent punishment.</p>
     */
    default Optional<SharedProxyDispositionPolicyRuntime> dispositionPolicyRuntime() {
        return Optional.empty();
    }

    /** Optional audit-only backend/world/game-mode context runtime. */
    default Optional<ShadowBackendContextRuntime> shadowBackendContextRuntime() {
        return Optional.empty();
    }

    /**
     * Optional administrative publisher. The bridge owns any signing material and returns only a
     * bounded publication summary to the adapter.
     */
    default Optional<BungeeDispositionPolicyPublisher> dispositionPolicyPublisher() {
        return Optional.empty();
    }

    /** Re-checks the session binding before a proxy-side action touches a player. */
    default boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) {
        return false;
    }

    /**
     * Returns the currently authenticated session for one player, when this bridge can expose it.
     *
     * <p>The Bungee adapter uses this only to bind proxy-side frames to a physical login. It is
     * deliberately optional so third-party bridges retain the previous fail-closed behavior.</p>
     */
    default Optional<String> currentAuthenticatedSessionId(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return Optional.empty();
    }

    /** Installs a content-free event sink; the default bridge remains fail-closed and inert. */
    default void setDispositionEventHandler(Consumer<AuthenticatedManifestDispositionEvent> handler) {
        java.util.Objects.requireNonNull(handler, "handler");
    }

    default BungeeDispositionExecutionMode dispositionExecutionMode() {
        return BungeeDispositionExecutionMode.MONITOR;
    }

    default Optional<String> dispositionRestrictedServer() {
        return Optional.empty();
    }

    /**
     * Explicit target for LIMIT. The old restricted-server bridge method is retained only as a
     * one-way LIMIT migration path for third-party bridge implementations.
     */
    default Optional<String> dispositionLimitedServer() {
        return dispositionRestrictedServer();
    }

    /** Explicit target for QUARANTINE; it intentionally has no legacy fallback. */
    default Optional<String> dispositionQuarantineServer() {
        return Optional.empty();
    }

    @Override
    default void close() {
        // Most bridges have no external resources. Implementations can override when needed.
    }
}
