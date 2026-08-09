package com.ellan.mcace.sdk;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * Consumer-side, read-only wrapper around the JDK-only MCAce interop wire contract.
 *
 * <p>This class belongs to the consumer's own SDK copy. No MCAce type crosses the provider boundary.</p>
 *
 * @since 1.0
 */
public final class MCAceInteropBridge {
    private final Function<?, ?> provider;

    MCAceInteropBridge(Function<?, ?> provider) {
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    /**
     * Reads the provider's version and capabilities.
     *
     * @return immutable provider descriptor
     */
    public MCAceSdkDescriptor descriptor() {
        Map<String, Object> response = call(Map.of(MCAceInterop.OPERATION, MCAceInterop.DESCRIPTOR_OPERATION));
        return MCAceInteropPayload.readDescriptor(response);
    }

    /**
     * Negotiates a read-only capability set with the provider.
     *
     * @param request consumer requirements
     * @return deterministic compatibility result
     */
    public MCAceSdkNegotiationResult negotiate(MCAceSdkNegotiationRequest request) {
        return Objects.requireNonNull(request, "request").evaluate(descriptor());
    }

    /**
     * Reads a player's immutable interoperability snapshot.
     *
     * @param playerId player UUID
     * @return snapshot, or empty when no player/session snapshot is known
     */
    public Optional<MCAceInteropSnapshot> snapshot(UUID playerId) {
        return optionalSnapshot(MCAceInterop.SNAPSHOT_OPERATION, playerId, MCAceInteropPayload::readSnapshot);
    }

    /**
     * Reads non-sensitive session metadata when offered.
     *
     * @param playerId player UUID
     * @return metadata, or empty when the player is unknown or the capability is unavailable
     */
    public Optional<MCAceInteropSessionSummary> session(UUID playerId) {
        return optionalSnapshot(MCAceInterop.SESSION_OPERATION, playerId, MCAceInteropPayload::readSession);
    }

    /**
     * Reads content-free evidence metadata when offered.
     *
     * @param playerId player UUID
     * @return immutable summary page; never raw evidence content
     */
    public EvidenceSummaryPage evidence(UUID playerId) {
        Map<String, Object> response = call(playerRequest(MCAceInterop.EVIDENCE_OPERATION, playerId));
        return MCAceInteropPayload.readEvidence(response);
    }

    private <T> Optional<T> optionalSnapshot(
            String operation, UUID playerId, java.util.function.Function<Map<String, Object>, T> mapper) {
        Map<String, Object> response = call(playerRequest(operation, playerId));
        String status = MCAceInteropPayload.status(response);
        if (MCAceInterop.STATUS_NOT_FOUND.equals(status) || MCAceInterop.STATUS_NOT_SUPPORTED.equals(status)) {
            return Optional.empty();
        }
        return Optional.of(mapper.apply(response));
    }

    private static Map<String, Object> playerRequest(String operation, UUID playerId) {
        return Map.of(
                MCAceInterop.OPERATION, operation,
                MCAceInterop.PLAYER_ID, Objects.requireNonNull(playerId, "playerId"));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> call(Map<String, Object> request) {
        final Object raw;
        try {
            raw = ((Function<Object, Object>) provider).apply(Map.copyOf(request));
        } catch (ClassCastException exception) {
            throw new MCAceInteropException("interop provider rejected the JDK-only request contract", exception);
        } catch (RuntimeException exception) {
            throw new MCAceInteropException("interop provider failed", exception);
        }
        return MCAceInteropPayload.requireSafeResponse(raw);
    }
}
