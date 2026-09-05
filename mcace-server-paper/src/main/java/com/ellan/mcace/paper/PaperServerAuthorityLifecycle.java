package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.BackendAuthorityGrantCodec;
import com.ellan.mcace.core.authority.DurablyIssuedServerAuthorityObservation;
import com.ellan.mcace.core.authority.RecoveredServerAuthoritySequence;
import com.ellan.mcace.core.authority.ServerAuthorityObservationCodec;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default-disabled Paper/Folia lifecycle seam for the configured authority producer.
 *
 * <p>This class itself registers no plugin channel, signs or sends no frame, and has no
 * disposition/executor dependency. When its owning runtime is enabled by a complete
 * configuration, it only retains already-verified grants and prepares one sequence lease under a
 * lifecycle lock. A lease advances in-memory state only after an exact commit; abort makes it
 * reusable. The durable journal remains the source of the recovered sequence, and the actual
 * grant receiver and sender remain a later release gate.</p>
 */
final class PaperServerAuthorityLifecycle {
    private final boolean enabled;
    private final Clock clock;
    private final Map<UUID, State> states = new HashMap<>();

    private PaperServerAuthorityLifecycle(boolean enabled, Clock clock) {
        this.enabled = enabled;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    static PaperServerAuthorityLifecycle disabled(Clock clock) {
        return new PaperServerAuthorityLifecycle(false, clock);
    }

    static PaperServerAuthorityLifecycle enabledForTests(Clock clock) {
        return new PaperServerAuthorityLifecycle(true, clock);
    }

    static PaperServerAuthorityLifecycle enabled(Clock clock) {
        return new PaperServerAuthorityLifecycle(true, clock);
    }

    boolean enabled() {
        return enabled;
    }

    synchronized boolean acceptVerifiedGrant(
            UUID carryingPlayerId,
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            RecoveredServerAuthoritySequence recoveredSequence) {
        Objects.requireNonNull(carryingPlayerId, "carryingPlayerId");
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(recoveredSequence, "recoveredSequence");
        if (!enabled || !carryingPlayerId.equals(grant.playerId())
                || !clock.instant().isBefore(grant.expiresAt())
                || !recoveredSequence.matches(grant)) {
            return false;
        }
        long recoveredObservationSequence = recoveredSequence.lastSequence();
        State previous = states.get(carryingPlayerId);
        if (previous != null) {
            if (previous.pendingLease() != null
                    || !grant.authenticatedSessionId().equals(
                    previous.grant().authenticatedSessionId())
                    || !java.security.MessageDigest.isEqual(
                    grant.physicalLoginBinding(),
                    previous.grant().physicalLoginBinding())
                    || grant.grantSequence() <= previous.grant().grantSequence()
                    || grant.admissionTransportSequence()
                    < previous.grant().admissionTransportSequence()
                    || !recoveredSequence.backendKeyIdSha256().equals(
                    previous.backendKeyIdSha256())
                    || recoveredObservationSequence
                    < previous.lastObservationSequence()) {
                return false;
            }
        }
        states.put(carryingPlayerId,
                new State(grant, recoveredSequence.backendKeyIdSha256(),
                        recoveredObservationSequence, null));
        return true;
    }

    synchronized Optional<IssuanceLease> nextIssuance(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        if (!enabled) {
            return Optional.empty();
        }
        State state = states.get(playerId);
        if (state == null || state.pendingLease() != null) {
            return Optional.empty();
        }
        if (!clock.instant().isBefore(state.grant().expiresAt())) {
            states.remove(playerId);
            return Optional.empty();
        }
        long next;
        try {
            next = Math.incrementExact(state.lastObservationSequence());
        } catch (ArithmeticException exception) {
            states.remove(playerId);
            return Optional.empty();
        }
        IssuanceLease lease = IssuanceLease.create(
                state.grant(), state.backendKeyIdSha256(), next);
        states.put(playerId,
                new State(state.grant(), state.backendKeyIdSha256(),
                        state.lastObservationSequence(), lease));
        return Optional.of(lease);
    }

    synchronized boolean commitIssuance(
            UUID playerId,
            IssuanceLease lease,
            DurablyIssuedServerAuthorityObservation durableObservation) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(lease, "lease");
        Objects.requireNonNull(durableObservation, "durableObservation");
        State state = states.get(playerId);
        if (!currentPendingLease(state, lease)
                || durableObservation.observationSequence() != lease.observationSequence()
                || !state.backendKeyIdSha256().equals(
                durableObservation.backendKeyIdSha256())
                || !durableObservation.matches(lease.grant())) {
            return false;
        }
        Instant now = clock.instant();
        if (!now.isBefore(state.grant().expiresAt())) {
            states.remove(playerId);
            return false;
        }
        if (durableObservation.issuedAt().isAfter(now)
                || !now.isBefore(durableObservation.expiresAt())) {
            return false;
        }
        states.put(playerId,
                new State(state.grant(), state.backendKeyIdSha256(),
                        lease.observationSequence(), null));
        return true;
    }

    synchronized boolean abortIssuance(UUID playerId, IssuanceLease lease) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(lease, "lease");
        State state = states.get(playerId);
        if (!currentPendingLease(state, lease)) {
            return false;
        }
        states.put(playerId,
                new State(state.grant(), state.backendKeyIdSha256(),
                        state.lastObservationSequence(), null));
        return true;
    }

    synchronized void expire() {
        if (!enabled) {
            states.clear();
            return;
        }
        Iterator<Map.Entry<UUID, State>> iterator = states.entrySet().iterator();
        while (iterator.hasNext()) {
            if (!clock.instant().isBefore(iterator.next().getValue().grant().expiresAt())) {
                iterator.remove();
            }
        }
    }

    synchronized void remove(UUID playerId) {
        states.remove(Objects.requireNonNull(playerId, "playerId"));
    }

    synchronized void clear() {
        states.clear();
    }

    synchronized int trackedPlayers() {
        return states.size();
    }

    private static boolean currentPendingLease(State state, IssuanceLease lease) {
        return state != null && state.pendingLease() != null
                && state.pendingLease().matchesExactCapability(lease);
    }

    static final class IssuanceLease {
        private final BackendAuthorityGrantCodec.VerifiedGrant grant;
        private final String backendKeyIdSha256;
        private final long observationSequence;
        private final UUID capabilityId;

        private IssuanceLease(
                BackendAuthorityGrantCodec.VerifiedGrant grant,
                String backendKeyIdSha256,
                long observationSequence,
                UUID capabilityId) {
            this.grant = Objects.requireNonNull(grant, "grant");
            this.backendKeyIdSha256 = Objects.requireNonNull(
                    backendKeyIdSha256, "backendKeyIdSha256");
            if (observationSequence <= 0) {
                throw new IllegalArgumentException("observationSequence must be positive");
            }
            this.observationSequence = observationSequence;
            this.capabilityId = Objects.requireNonNull(capabilityId, "capabilityId");
        }

        private static IssuanceLease create(
                BackendAuthorityGrantCodec.VerifiedGrant grant,
                String backendKeyIdSha256,
                long observationSequence) {
            return new IssuanceLease(
                    grant, backendKeyIdSha256, observationSequence, UUID.randomUUID());
        }

        BackendAuthorityGrantCodec.VerifiedGrant grant() {
            return grant;
        }

        long observationSequence() {
            return observationSequence;
        }

        /**
         * Checks that a caller-supplied observation request is for this exact grant and lease.
         * Provider/profile semantics remain the responsibility of the authority codec and profile;
         * this method binds only the already-verified physical lifecycle.
         */
        boolean matchesRequest(
                UUID carryingPlayerId,
                ServerAuthorityObservationCodec.ObservationRequest request) {
            if (carryingPlayerId == null || request == null) {
                return false;
            }
            return carryingPlayerId.equals(grant.playerId())
                    && carryingPlayerId.equals(request.playerId())
                    && backendKeyIdSha256.equals(request.backendKeyIdSha256())
                    && grant.backendInstanceId().equals(request.backendInstanceId())
                    && grant.authenticatedSessionId().equals(request.authenticatedSessionId())
                    && grant.grantId().equals(request.grantId())
                    && grant.commitmentSha256().equals(request.grantCommitmentSha256())
                    && MessageDigest.isEqual(
                    grant.physicalLoginBinding(), request.physicalLoginBinding())
                    && grant.admissionTransportSequence()
                    == request.admissionTransportSequence()
                    && observationSequence == request.observationSequence()
                    && !request.observedAt().isBefore(grant.issuedAt())
                    && request.observedAt().isBefore(grant.expiresAt());
        }

        private boolean matchesExactCapability(IssuanceLease candidate) {
            return this == candidate && capabilityId.equals(candidate.capabilityId);
        }
    }

    private record State(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            String backendKeyIdSha256,
            long lastObservationSequence,
            IssuanceLease pendingLease) {
        private State {
            Objects.requireNonNull(grant, "grant");
            Objects.requireNonNull(backendKeyIdSha256, "backendKeyIdSha256");
            if (lastObservationSequence < 0) {
                throw new IllegalArgumentException("lastObservationSequence cannot be negative");
            }
        }
    }
}
