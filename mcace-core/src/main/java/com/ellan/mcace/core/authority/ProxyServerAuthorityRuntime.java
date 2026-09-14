package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Monitor-only proxy lifecycle for signed Paper/Folia authority grants and observations.
 *
 * <p>The caller must hold its platform physical-login lock around every call. This runtime never
 * selects or executes a disposition. It commits a verified prior-observation snapshot only after
 * the complete signed frame passes the core verifier.</p>
 */
public final class ProxyServerAuthorityRuntime {
    private final ProxyServerAuthorityConfiguration configuration;
    private final KeyPair proxyIdentity;
    private final Clock clock;
    private final SecureRandom secureRandom;
    private final BackendAuthorityGrantCodec grantCodec;
    private final ServerAuthorityObservationCodec observationCodec;
    private final NonceReplayGuard localGrantReplay;
    private final NonceReplayGuard observationReplay;
    private final Map<UUID, State> states = new HashMap<>();

    public ProxyServerAuthorityRuntime(
            ProxyServerAuthorityConfiguration configuration,
            KeyPair proxyIdentity,
            Clock clock,
            SecureRandom secureRandom) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        if (!configuration.enabled() || !configuration.registry().enabled()) {
            throw new IllegalArgumentException("backend authority configuration is disabled");
        }
        this.proxyIdentity = requireMatchingEd25519KeyPair(proxyIdentity);
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.grantCodec = new BackendAuthorityGrantCodec(clock, secureRandom);
        this.observationCodec = new ServerAuthorityObservationCodec(clock, secureRandom);
        this.localGrantReplay = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
        this.observationReplay = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
    }

    public synchronized IssuedGrant issueGrant(
            String registeredBackend,
            UUID playerId,
            String authenticatedSessionId,
            long admissionTransportSequence) throws AuthorityProtocolException {
        BackendAuthorityPin pin = configuration.registry()
                .pinForRegisteredBackend(registeredBackend)
                .orElseThrow(() -> new AuthorityProtocolException(
                        "registered backend has no authority pin"));
        Objects.requireNonNull(playerId, "playerId");
        BackendAuthorityPin.bounded(authenticatedSessionId, "authenticatedSessionId");
        if (admissionTransportSequence <= 0L) {
            throw new IllegalArgumentException("admissionTransportSequence must be positive");
        }

        State previous = states.get(playerId);
        boolean samePhysicalBinding = previous != null
                && previous.registeredBackend().equals(registeredBackend)
                && previous.authenticatedSessionId().equals(authenticatedSessionId);
        if (samePhysicalBinding
                && admissionTransportSequence <= previous.latestAdmissionTransportSequence()) {
            throw new AuthorityProtocolException("authority grant admission sequence did not increase");
        }
        if (samePhysicalBinding && clock.instant().isBefore(previous.grant().expiresAt())) {
            states.put(playerId, previous.withLatestAdmissionTransportSequence(
                    admissionTransportSequence));
            return issuedGrantFromState(previous, false);
        }
        byte[] binding = samePhysicalBinding
                ? previous.physicalLoginBinding() : randomBinding();
        long grantSequence;
        try {
            grantSequence = samePhysicalBinding
                    ? Math.incrementExact(previous.grantSequence()) : 1L;
        } catch (ArithmeticException exception) {
            states.remove(playerId);
            throw new AuthorityProtocolException("authority grant sequence is exhausted", exception);
        }
        BackendAuthorityGrantCodec.GrantRequest request =
                new BackendAuthorityGrantCodec.GrantRequest(
                        configuration.proxyInstanceId(), pin.backendInstanceId(), playerId,
                        authenticatedSessionId, binding, admissionTransportSequence,
                        grantSequence, configuration.grantLifetime());
        BackendAuthorityGrantCodec.IssuedGrant issued =
                grantCodec.issue(request, proxyIdentity.getPrivate());
        BackendAuthorityGrantCodec.VerifiedGrant verified = grantCodec.verify(
                issued.frame(), configuration.proxyInstanceId(), pin.backendInstanceId(), playerId,
                authenticatedSessionId, binding, admissionTransportSequence,
                samePhysicalBinding ? previous.grantSequence() : 0L,
                proxyIdentity.getPublic(), localGrantReplay);
        Optional<ServerAuthorityObservationCodec.PriorAcceptedObservation> prior =
                samePhysicalBinding ? previous.priorAccepted() : Optional.empty();
        states.put(playerId, new State(
                registeredBackend, authenticatedSessionId, binding,
                admissionTransportSequence, grantSequence, verified, prior, issued.frame()));
        return new IssuedGrant(
                registeredBackend, pin.backendInstanceId(), playerId, authenticatedSessionId,
                issued.grantId(), issued.commitmentSha256(), binding,
                admissionTransportSequence, grantSequence, issued.expiresAt(), true, issued.frame());
    }

    public synchronized VerifiedServerAuthorityObservation acceptObservation(
            String registeredBackend,
            UUID playerId,
            String authenticatedSessionId,
            long admissionTransportSequence,
            byte[] encodedFrame) throws AuthorityProtocolException {
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        State state = states.get(Objects.requireNonNull(playerId, "playerId"));
        if (state == null
                || !state.registeredBackend().equals(registeredBackend)
                || !state.authenticatedSessionId().equals(authenticatedSessionId)
                || state.grant().admissionTransportSequence() != admissionTransportSequence
                || !clock.instant().isBefore(state.grant().expiresAt())) {
            throw new AuthorityProtocolException(
                    "no current backend authority grant matches the platform lifecycle");
        }
        VerifiedServerAuthorityObservation verified = observationCodec.verify(
                encodedFrame, registeredBackend, playerId, authenticatedSessionId,
                state.physicalLoginBinding(), admissionTransportSequence, state.grant(),
                state.priorAccepted(), configuration.registry(), observationReplay);
        states.put(playerId, state.withPrior(
                Optional.of(ServerAuthorityObservationCodec.PriorAcceptedObservation.from(verified))));
        return verified;
    }

    public synchronized Optional<CurrentGrant> currentGrant(UUID playerId) {
        State state = states.get(Objects.requireNonNull(playerId, "playerId"));
        if (state == null || !clock.instant().isBefore(state.grant().expiresAt())) {
            states.remove(playerId);
            return Optional.empty();
        }
        return Optional.of(new CurrentGrant(
                state.registeredBackend(), state.authenticatedSessionId(),
                state.physicalLoginBinding(), state.grant().admissionTransportSequence(),
                state.grantSequence(), state.grant().expiresAt()));
    }

    public synchronized void invalidate(UUID playerId) {
        states.remove(Objects.requireNonNull(playerId, "playerId"));
    }

    public synchronized void clear() {
        states.clear();
    }

    public synchronized int trackedPlayers() {
        return states.size();
    }

    private byte[] randomBinding() {
        byte[] binding = new byte[AuthorityProtocolSupport.BINDING_BYTES];
        secureRandom.nextBytes(binding);
        return binding;
    }

    private static IssuedGrant issuedGrantFromState(State state, boolean newlyIssued) {
        BackendAuthorityGrantCodec.VerifiedGrant grant = state.grant();
        return new IssuedGrant(
                state.registeredBackend(), grant.backendInstanceId(), grant.playerId(),
                state.authenticatedSessionId(), grant.grantId(), grant.commitmentSha256(),
                state.physicalLoginBinding(), grant.admissionTransportSequence(),
                grant.grantSequence(), grant.expiresAt(), newlyIssued, state.frame());
    }

    private static KeyPair requireMatchingEd25519KeyPair(KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "proxyIdentity");
        if (keyPair.getPrivate() == null || keyPair.getPublic() == null) {
            throw new IllegalArgumentException("proxy authority identity is incomplete");
        }
        try {
            byte[] probe = "mcace/proxy-authority/key-pair-check/v1"
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(probe);
            byte[] signed = signature.sign();
            signature.initVerify(keyPair.getPublic());
            signature.update(probe);
            if (!signature.verify(signed)) {
                throw new IllegalArgumentException("proxy authority identity does not match");
            }
            return keyPair;
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("invalid proxy Ed25519 authority identity", exception);
        }
    }

    public record IssuedGrant(
            String registeredBackend,
            String backendInstanceId,
            UUID playerId,
            String authenticatedSessionId,
            UUID grantId,
            String grantCommitmentSha256,
            byte[] physicalLoginBinding,
            long admissionTransportSequence,
            long grantSequence,
            Instant expiresAt,
            boolean newlyIssued,
            byte[] frame) {
        public IssuedGrant {
            registeredBackend = BackendAuthorityPin.bounded(registeredBackend, "registeredBackend");
            backendInstanceId = BackendAuthorityPin.bounded(backendInstanceId, "backendInstanceId");
            Objects.requireNonNull(playerId, "playerId");
            authenticatedSessionId = BackendAuthorityPin.bounded(
                    authenticatedSessionId, "authenticatedSessionId");
            Objects.requireNonNull(grantId, "grantId");
            grantCommitmentSha256 = BackendAuthorityPin.sha256(
                    grantCommitmentSha256, "grantCommitmentSha256");
            physicalLoginBinding = Objects.requireNonNull(
                    physicalLoginBinding, "physicalLoginBinding").clone();
            frame = Objects.requireNonNull(frame, "frame").clone();
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (physicalLoginBinding.length != AuthorityProtocolSupport.BINDING_BYTES
                    || admissionTransportSequence <= 0L || grantSequence <= 0L
                    || frame.length == 0
                    || frame.length > ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES) {
                throw new IllegalArgumentException("issued authority grant is outside bounds");
            }
        }
        @Override public byte[] physicalLoginBinding() { return physicalLoginBinding.clone(); }
        @Override public byte[] frame() { return frame.clone(); }
    }

    public record CurrentGrant(
            String registeredBackend,
            String authenticatedSessionId,
            byte[] physicalLoginBinding,
            long admissionTransportSequence,
            long grantSequence,
            Instant expiresAt) {
        public CurrentGrant {
            Objects.requireNonNull(registeredBackend, "registeredBackend");
            Objects.requireNonNull(authenticatedSessionId, "authenticatedSessionId");
            physicalLoginBinding = Objects.requireNonNull(
                    physicalLoginBinding, "physicalLoginBinding").clone();
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
        @Override public byte[] physicalLoginBinding() { return physicalLoginBinding.clone(); }
    }

    private record State(
            String registeredBackend,
            String authenticatedSessionId,
            byte[] physicalLoginBinding,
            long latestAdmissionTransportSequence,
            long grantSequence,
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            Optional<ServerAuthorityObservationCodec.PriorAcceptedObservation> priorAccepted,
            byte[] frame) {
        private State {
            physicalLoginBinding = physicalLoginBinding.clone();
            frame = frame.clone();
            Objects.requireNonNull(grant, "grant");
            Objects.requireNonNull(priorAccepted, "priorAccepted");
            if (latestAdmissionTransportSequence < grant.admissionTransportSequence()) {
                throw new IllegalArgumentException("latest admission sequence predates the grant");
            }
        }
        @Override public byte[] physicalLoginBinding() { return physicalLoginBinding.clone(); }
        @Override public byte[] frame() { return frame.clone(); }
        private State withPrior(
                Optional<ServerAuthorityObservationCodec.PriorAcceptedObservation> value) {
            return new State(registeredBackend, authenticatedSessionId, physicalLoginBinding,
                    latestAdmissionTransportSequence, grantSequence, grant, value, frame);
        }
        private State withLatestAdmissionTransportSequence(long value) {
            return new State(registeredBackend, authenticatedSessionId, physicalLoginBinding,
                    value, grantSequence, grant, priorAccepted, frame);
        }
    }
}
