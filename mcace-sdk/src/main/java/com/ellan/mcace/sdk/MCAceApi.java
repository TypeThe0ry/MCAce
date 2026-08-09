package com.ellan.mcace.sdk;

import com.ellan.mcace.protocol.generated.TrustLevel;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Stable, read-only integration surface for third-party server plugins.
 *
 * <p>Implementations publish immutable observations. This interface deliberately has no method that
 * changes admission, applies a punishment, requests raw evidence, or exposes evidence content. Client
 * integrity and client-reported evidence are useful review signals, but are not an authority for a
 * third-party plugin to punish a player. Servers must combine them with their own authoritative
 * observations and an operator-reviewed policy.</p>
 *
 * <p>New methods on this interface are default methods so integrations compiled against an earlier SDK
 * continue to load. Consumers should call {@link #negotiate(MCAceSdkNegotiationRequest)} before relying
 * on an optional capability.</p>
 *
 * @since 1.0
 */
public interface MCAceApi {
    /**
     * Returns the latest immutable security snapshot for a player, if the implementation has one.
     *
     * @param playerId player UUID
     * @return the latest snapshot, or empty when no session is known
     */
    Optional<PlayerSecuritySnapshot> snapshot(UUID playerId);

    /**
     * Describes the SDK revision and read-only features offered by this implementation.
     *
     * <p>An implementation that only implemented the original {@link #snapshot(UUID)} method receives
     * the baseline descriptor automatically.</p>
     *
     * @return immutable descriptor for this API instance
     */
    default MCAceSdkDescriptor descriptor() {
        return MCAceSdk.baselineDescriptor();
    }

    /**
     * Negotiates an optional feature set without changing server or player state.
     *
     * @param request consumer's minimum compatible version and required capabilities
     * @return the offered descriptor and a deterministic compatibility result
     */
    default MCAceSdkNegotiationResult negotiate(MCAceSdkNegotiationRequest request) {
        return Objects.requireNonNull(request, "request").evaluate(descriptor());
    }

    /**
     * Returns a read-only trust view derived from the latest snapshot.
     *
     * @param playerId player UUID
     * @return trust view, or empty when no session is known
     */
    default Optional<TrustSummary> trust(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return snapshot(playerId).map(TrustSummary::fromSnapshot);
    }

    /**
     * Returns a read-only risk view derived from the latest snapshot.
     *
     * <p>Risk is an explainable signal for review and server-owned policy; it is not a command to punish
     * a player.</p>
     *
     * @param playerId player UUID
     * @return risk view, or empty when no session is known
     */
    default Optional<RiskSummary> risk(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return snapshot(playerId).map(RiskSummary::fromSnapshot);
    }

    /**
     * Returns non-sensitive lifecycle metadata for the active session when this optional capability is
     * supported. The baseline implementation returns empty.
     *
     * @param playerId player UUID
     * @return session metadata, or empty when unavailable
     */
    default Optional<SessionSecuritySummary> session(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return Optional.empty();
    }

    /**
     * Returns content-free evidence metadata for review when this optional capability is supported.
     *
     * <p>The result never contains evidence bytes, files, storage locations, decryption material, or a
     * punishment recommendation. The baseline implementation explicitly reports that summaries are not
     * supported.</p>
     *
     * @param playerId player UUID
     * @return immutable evidence-summary page
     */
    default EvidenceSummaryPage evidence(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return EvidenceSummaryPage.notSupported();
    }

    /**
     * Reports whether the latest snapshot is verified.
     *
     * @param playerId player UUID
     * @return {@code true} only for a verified admission state
     */
    default boolean isVerified(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return snapshot(playerId).map(PlayerSecuritySnapshot::verified).orElse(false);
    }

    /**
     * Returns the latest trust level, or {@link TrustLevel#UNKNOWN} when no snapshot is available.
     *
     * @param playerId player UUID
     * @return published trust level or unknown
     */
    default TrustLevel trustLevel(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return snapshot(playerId).map(PlayerSecuritySnapshot::trustLevel).orElse(TrustLevel.UNKNOWN);
    }

    /**
     * Returns the latest non-negative risk score, or zero when no snapshot is available.
     *
     * @param playerId player UUID
     * @return published risk score or zero
     */
    default int riskScore(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        return snapshot(playerId).map(PlayerSecuritySnapshot::riskScore).orElse(0);
    }
}
