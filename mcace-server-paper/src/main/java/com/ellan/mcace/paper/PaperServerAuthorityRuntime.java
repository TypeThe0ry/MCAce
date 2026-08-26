package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.AuthorityProtocolException;
import com.ellan.mcace.core.authority.BackendAuthorityGrantCodec;
import com.ellan.mcace.core.authority.DurableServerAuthorityIssuer;
import com.ellan.mcace.core.authority.DurablyIssuedServerAuthorityObservation;
import com.ellan.mcace.core.authority.RecoveredServerAuthoritySequence;
import com.ellan.mcace.core.authority.ServerAuthorityObservationCodec;
import com.ellan.mcace.paper.behavior.BehaviorAlert;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.BackendAuthorityGrant;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.Closeable;
import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.jetbrains.annotations.NotNull;

/** Default-disabled Paper/Folia grant receiver, provider correlator, durable signer and sender. */
final class PaperServerAuthorityRuntime
        implements PluginMessageListener, Closeable {
    private final Plugin plugin;
    private final PaperServerAuthorityConfiguration configuration;
    private final PublicKey proxyPublicKey;
    private final Clock clock;
    private final MCAceRuntimeScheduler scheduler;
    private final Logger logger;
    private final BackendAuthorityGrantCodec grantCodec;
    private final NonceReplayGuard grantReplay;
    private final PaperServerAuthorityLifecycle lifecycle;
    private final DurableServerAuthorityIssuer issuer;
    private final PaperServerAuthorityIssueCoordinator coordinator;
    private final PaperAuthorityProviderCorrelator correlator;
    private final PaperServerAuthorityJournalWriter journalWriter;
    private final Map<UUID, AdmissionBinding> admissions = new HashMap<>();
    private final Map<UUID, GrantBinding> grants = new HashMap<>();
    private final Map<UUID, PendingGrantRecovery> pendingGrantRecoveries = new HashMap<>();
    private final Map<UUID, PendingIssuance> pendingIssuances = new HashMap<>();
    private boolean closed;

    PaperServerAuthorityRuntime(
            Plugin plugin,
            PaperServerAuthorityConfiguration configuration,
            PublicKey proxyPublicKey,
            Clock clock,
            MCAceRuntimeScheduler scheduler,
            Logger logger) throws IOException {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.proxyPublicKey = Objects.requireNonNull(proxyPublicKey, "proxyPublicKey");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.grantCodec = new BackendAuthorityGrantCodec(clock, new SecureRandom());
        this.grantReplay = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
        this.lifecycle = PaperServerAuthorityLifecycle.enabled(clock);
        this.issuer = new DurableServerAuthorityIssuer(
                new ServerAuthorityObservationCodec(clock, new SecureRandom()),
                configuration.backendIdentity(), configuration.issuanceJournal(),
                configuration.journalQuotaBytes());
        this.coordinator = new PaperServerAuthorityIssueCoordinator(lifecycle, issuer);
        this.correlator = new PaperAuthorityProviderCorrelator(configuration.profile(), clock);
        this.journalWriter = new PaperServerAuthorityJournalWriter();
    }

    synchronized void acceptAdmission(
            Player player, PaperAdmissionReceiver.AcceptedAdmission admission) {
        Objects.requireNonNull(player, "player");
        Objects.requireNonNull(admission, "admission");
        if (closed || !player.getUniqueId().equals(admission.playerId())
                || !admission.snapshot().verified()
                || admission.snapshot().admissionStatus() != AdmissionStatus.VERIFIED) {
            remove(admission.playerId());
            return;
        }
        AdmissionBinding previous = admissions.put(admission.playerId(), new AdmissionBinding(
                admission.transportSequence(), admission.expiresAt(), player));
        if (previous != null && admission.transportSequence() <= previous.transportSequence()) {
            admissions.put(admission.playerId(), previous);
        }
    }

    @Override
    public void onPluginMessageReceived(
            @NotNull String channel,
            @NotNull Player player,
            byte @NotNull [] message) {
        if (!ProtocolConstants.BACKEND_AUTHORITY_CHANNEL.equals(channel)
                || message.length == 0
                || message.length > ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES) {
            return;
        }
        byte[] frame = message.clone();
        scheduler.executeForPlayer(player,
                () -> receiveGrant(player, frame), () -> remove(player.getUniqueId()));
    }

    public void accept(Player carrier, BehaviorAlert alert) {
        try {
            Objects.requireNonNull(carrier, "carrier");
            Objects.requireNonNull(alert, "alert");
            if (!carrier.getUniqueId().equals(alert.playerId())) return;
            scheduler.executeForPlayer(carrier,
                    () -> acceptCurrent(carrier, alert), () -> remove(alert.playerId()));
        } catch (RuntimeException exception) {
            // Provider adapters are external plugin surfaces. No malformed callback, server API
            // failure or scheduler rejection may escape back into their event dispatch path.
            logger.log(Level.WARNING,
                    "Ignored MCAce authority provider callback failure (MONITOR)", exception);
        }
    }

    synchronized void expire() {
        if (closed) return;
        lifecycle.expire();
        Instant now = clock.instant();
        Iterator<Map.Entry<UUID, AdmissionBinding>> admissionsIterator =
                admissions.entrySet().iterator();
        while (admissionsIterator.hasNext()) {
            Map.Entry<UUID, AdmissionBinding> entry = admissionsIterator.next();
            if (!now.isBefore(entry.getValue().expiresAt())) {
                UUID playerId = entry.getKey();
                admissionsIterator.remove();
                grants.remove(playerId);
                pendingGrantRecoveries.remove(playerId);
                pendingIssuances.remove(playerId);
                lifecycle.remove(playerId);
                correlator.remove(playerId);
            }
        }
        Iterator<Map.Entry<UUID, GrantBinding>> iterator = grants.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<UUID, GrantBinding> entry = iterator.next();
            AdmissionBinding admission = admissions.get(entry.getKey());
            if (!now.isBefore(entry.getValue().grant().expiresAt())
                    || admission == null || !now.isBefore(admission.expiresAt())) {
                lifecycle.remove(entry.getKey());
                correlator.remove(entry.getKey());
                pendingGrantRecoveries.remove(entry.getKey());
                pendingIssuances.remove(entry.getKey());
                iterator.remove();
            }
        }
    }

    synchronized void remove(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        admissions.remove(playerId);
        grants.remove(playerId);
        pendingGrantRecoveries.remove(playerId);
        pendingIssuances.remove(playerId);
        lifecycle.remove(playerId);
        correlator.remove(playerId);
    }

    synchronized int trackedGrants() {
        return grants.size();
    }

    @Override
    public void close() throws IOException {
        synchronized (this) {
            if (closed) return;
            closed = true;
        }
        IOException failure = null;
        try {
            journalWriter.close();
        } catch (IOException exception) {
            failure = exception;
        }
        synchronized (this) {
            admissions.clear();
            grants.clear();
            pendingGrantRecoveries.clear();
            pendingIssuances.clear();
            lifecycle.clear();
            correlator.clear();
        }
        if (journalWriter.isTerminated()) {
            try {
                issuer.close();
            } catch (IOException exception) {
                if (failure == null) failure = exception;
                else failure.addSuppressed(exception);
            }
        } else {
            journalWriter.closeAfterTermination(issuer, exception -> logger.log(
                    Level.SEVERE,
                    "MCAce authority journal close failed after writer termination", exception));
            IOException deferred = new IOException(
                    "authority issuer close deferred until the journal writer terminates");
            if (failure == null) failure = deferred;
            else failure.addSuppressed(deferred);
        }
        if (failure != null) throw failure;
    }

    void awaitAuthorityWriterForTests(Duration timeout)
            throws InterruptedException, ExecutionException, TimeoutException {
        journalWriter.awaitIdleForTests(timeout);
    }

    void executeAuthorityWriterForTests(Runnable task) {
        journalWriter.execute(task);
    }

    synchronized long currentGrantSequenceForTests(UUID playerId) {
        GrantBinding binding = grants.get(Objects.requireNonNull(playerId, "playerId"));
        return binding == null ? 0L : binding.grant().grantSequence();
    }

    private synchronized void receiveGrant(Player player, byte[] frame) {
        if (closed || !player.isOnline()) return;
        UUID playerId = player.getUniqueId();
        AdmissionBinding admission = admissions.get(playerId);
        if (admission == null || admission.player() != player
                || !clock.instant().isBefore(admission.expiresAt())) {
            return;
        }
        if (pendingGrantRecoveries.containsKey(playerId)) {
            // Do not consume a signed grant nonce while the preceding grant for this player is
            // already waiting for durable recovery. The one bounded writer preserves ordering;
            // the current verified grant remains authoritative until that recovery completes.
            return;
        }
        GrantCandidate candidate;
        GrantBinding previous = grants.get(playerId);
        boolean sameBinding;
        BackendAuthorityGrantCodec.VerifiedGrant verified;
        try {
            candidate = inspectCandidate(frame);
            sameBinding = previous != null
                    && previous.grant().authenticatedSessionId().equals(
                    candidate.authenticatedSessionId())
                    && java.security.MessageDigest.isEqual(
                    previous.grant().physicalLoginBinding(), candidate.physicalLoginBinding());
            long previousGrantSequence = sameBinding ? previous.grant().grantSequence() : 0L;
            verified = grantCodec.verify(
                    frame, configuration.proxyInstanceId(), configuration.backendInstanceId(),
                    playerId, candidate.authenticatedSessionId(), candidate.physicalLoginBinding(),
                    admission.transportSequence(), previousGrantSequence,
                    proxyPublicKey, grantReplay);
        } catch (AuthorityProtocolException | RuntimeException exception) {
            // This channel is carried by a Player, so client-originated garbage reaches the same
            // listener as a proxy frame. An unauthenticated, malformed, replayed or stale frame
            // must never revoke the last valid signed grant and suppress SERVER_CONFIRMED output.
            logger.log(Level.WARNING,
                    "Ignored invalid MCAce backend authority grant for " + playerId
                            + "; the current verified grant was preserved (MONITOR)", exception);
            return;
        }

        PendingGrantRecovery pending = new PendingGrantRecovery(
                UUID.randomUUID(), player, verified);
        pendingGrantRecoveries.put(playerId, pending);
        try {
            journalWriter.execute(() -> recoverGrantOnJournalWriter(pending));
        } catch (RejectedExecutionException exception) {
            if (pendingGrantRecoveries.get(playerId) == pending) {
                pendingGrantRecoveries.remove(playerId);
            }
            logger.log(Level.WARNING,
                    !sameBinding
                            ? "MCAce authority journal queue rejected recovery for a new physical "
                                    + "binding; the old grant was retired for " + playerId
                                    + " (MONITOR)"
                            : "MCAce authority journal queue rejected grant recovery for "
                                    + playerId + "; the current verified grant was preserved "
                                    + "(MONITOR)",
                    exception);
            if (!sameBinding) {
                disableGrantState(playerId);
            }
        }
    }

    private void recoverGrantOnJournalWriter(PendingGrantRecovery pending) {
        UUID playerId = pending.grant().playerId();
        synchronized (this) {
            if (closed || pendingGrantRecoveries.get(playerId) != pending) return;
        }

        RecoveredServerAuthoritySequence recovered = null;
        Throwable failure = null;
        try {
            recovered = issuer.recover(pending.grant());
        } catch (IOException | RuntimeException exception) {
            failure = exception;
        }
        RecoveredServerAuthoritySequence result = recovered;
        Throwable resultFailure = failure;
        try {
            scheduler.executeForPlayer(pending.player(),
                    () -> completeGrantRecoveryOnPlayer(pending, result, resultFailure),
                    () -> retirePendingGrantRecovery(pending));
        } catch (RuntimeException exception) {
            synchronized (this) {
                if (pendingGrantRecoveries.get(playerId) == pending) {
                    pendingGrantRecoveries.remove(playerId);
                    disableGrantState(playerId);
                }
            }
            if (resultFailure != null) exception.addSuppressed(resultFailure);
            logger.log(Level.WARNING,
                    "MCAce authority grant recovery result scheduling failed for " + playerId
                            + " after the journal writer completed (MONITOR)", exception);
        }
    }

    private synchronized void completeGrantRecoveryOnPlayer(
            PendingGrantRecovery pending,
            RecoveredServerAuthoritySequence recovered,
            Throwable failure) {
        UUID playerId = pending.grant().playerId();
        if (pendingGrantRecoveries.get(playerId) != pending) return;
        pendingGrantRecoveries.remove(playerId);
        if (closed) return;
        if (failure != null || recovered == null) {
            // A verified grant supersedes the sender's previous authority boundary. An
            // unavailable durable journal cannot safely allocate for either boundary.
            disableGrantState(playerId);
            logger.log(Level.WARNING,
                    "Disabled MCAce backend authority grant for " + playerId
                            + " because durable recovery failed (MONITOR)", failure);
            return;
        }

        AdmissionBinding admission = admissions.get(playerId);
        Instant now = clock.instant();
        if (admission == null || admission.player() != pending.player()
                || !pending.player().isOnline()
                || admission.transportSequence() < pending.grant().admissionTransportSequence()
                || !now.isBefore(admission.expiresAt())
                || !now.isBefore(pending.grant().expiresAt())) {
            disableGrantState(playerId);
            logger.warning("Suppressed an MCAce authority grant after durable recovery because "
                    + "its exact player/admission capability retired: " + playerId
                    + " (MONITOR)");
            return;
        }

        GrantBinding previous = grants.get(playerId);
        boolean sameBinding = previous != null && samePhysicalLifecycle(
                previous.grant(), pending.grant());
        if (!sameBinding) {
            lifecycle.remove(playerId);
        }
        if (!lifecycle.acceptVerifiedGrant(playerId, pending.grant(), recovered)) {
            if (!sameBinding) {
                disableGrantState(playerId);
            }
            logger.warning("Rejected a verified MCAce backend authority grant that did not match "
                    + "the current lifecycle for " + playerId + " (MONITOR)");
            return;
        }

        // The writer serialized any older durable issuance before this recovery. If its player
        // callback is still queued, the recovered sequence/timestamps already include it; cancel
        // the obsolete transport capability rather than sending under the retired grant.
        pendingIssuances.remove(playerId);
        if (!sameBinding) {
            correlator.remove(playerId);
        } else {
            // A refreshed grant has a later issuance boundary. Retain cooldown state but
            // discard provider events that the durable issuer would reject as pre-grant.
            correlator.grantAdvanced(playerId, pending.grant().issuedAt());
        }
        correlator.recovered(
                playerId, recovered.lastObservedAt(), recovered.lastIssuedAt());
        grants.put(playerId,
                new GrantBinding(pending.grant(), recovered.lastSequence(), pending.player()));
        logger.log(Level.INFO,
                "Accepted MCAce authority grant for {0}: backend={1}, sequence={2} (MONITOR)",
                new Object[] {playerId, configuration.backendInstanceId(),
                        pending.grant().grantSequence()});
    }

    private synchronized void retirePendingGrantRecovery(PendingGrantRecovery pending) {
        UUID playerId = pending.grant().playerId();
        if (pendingGrantRecoveries.get(playerId) == pending) {
            pendingGrantRecoveries.remove(playerId);
            disableGrantState(playerId);
        }
    }

    private synchronized void acceptCurrent(Player player, BehaviorAlert alert) {
        try {
            acceptCurrentChecked(player, alert);
        } catch (RuntimeException exception) {
            if (coordinator.poisoned()) remove(alert.playerId());
            logger.log(Level.WARNING,
                    "Ignored MCAce authority provider processing failure for "
                            + alert.playerId() + " (MONITOR)", exception);
        }
    }

    private void acceptCurrentChecked(Player player, BehaviorAlert alert) {
        if (closed || !player.isOnline() || !player.getUniqueId().equals(alert.playerId())) return;
        UUID playerId = player.getUniqueId();
        if (pendingGrantRecoveries.containsKey(playerId)
                || pendingIssuances.containsKey(playerId)) return;
        AdmissionBinding admission = admissions.get(playerId);
        GrantBinding grantBinding = grants.get(playerId);
        Instant now = clock.instant();
        if (admission == null || grantBinding == null
                || admission.player() != player || grantBinding.player() != player
                || admission.transportSequence() < grantBinding.grant().admissionTransportSequence()
                || !now.isBefore(admission.expiresAt())
                || !now.isBefore(grantBinding.grant().expiresAt())
                || !player.getListeningPluginChannels().contains(
                ProtocolConstants.BACKEND_AUTHORITY_CHANNEL)) {
            return;
        }
        Optional<PaperAuthorityProviderCorrelator.CorrelatedProviders> correlated =
                correlator.accept(alert);
        if (correlated.isEmpty()) return;
        PaperAuthorityProviderCorrelator.CorrelatedProviders evidence = correlated.orElseThrow();
        logger.info("MCAce authority provider quorum reached in MONITOR mode: player="
                + playerId + " profile=" + configuration.profile().sha256()
                + " providers=" + evidence.providers().stream()
                .map(ServerAuthorityObservationCodec.ProviderInput::providerId)
                .sorted().toList());
        long observationSequence;
        try {
            observationSequence = Math.incrementExact(grantBinding.lastObservationSequence());
        } catch (ArithmeticException exception) {
            remove(playerId);
            return;
        }
        Duration remaining = Duration.between(now, grantBinding.grant().expiresAt());
        Duration lifetime = remaining.compareTo(configuration.observationLifetime()) < 0
                ? remaining : configuration.observationLifetime();
        if (lifetime.isZero() || lifetime.isNegative()) return;
        lifetime = Duration.ofMillis(lifetime.toMillis());
        if (lifetime.isZero()) return;
        ServerAuthorityObservationCodec.ObservationRequest request =
                new ServerAuthorityObservationCodec.ObservationRequest(
                        configuration.backendInstanceId(), configuration.backendKeyIdSha256(),
                        playerId, grantBinding.grant().authenticatedSessionId(),
                        grantBinding.grant().grantId(), grantBinding.grant().commitmentSha256(),
                        grantBinding.grant().physicalLoginBinding(),
                        grantBinding.grant().admissionTransportSequence(), observationSequence,
                        evidence.observedAt(), lifetime, configuration.profile().sha256(),
                        evidence.providers());
        PendingIssuance pending = new PendingIssuance(
                UUID.randomUUID(), player, grantBinding.grant(), evidence, request);
        pendingIssuances.put(playerId, pending);
        try {
            journalWriter.execute(() -> issueOnJournalWriter(pending));
        } catch (RejectedExecutionException exception) {
            if (pendingIssuances.get(playerId) == pending) {
                pendingIssuances.remove(playerId);
            }
            logger.log(Level.WARNING,
                    "MCAce authority journal queue rejected issuance for " + playerId
                            + " (MONITOR)", exception);
        }
    }

    private void issueOnJournalWriter(PendingIssuance pending) {
        UUID playerId = pending.request().playerId();
        synchronized (this) {
            if (closed || pendingIssuances.get(playerId) != pending) return;
        }

        Optional<DurablyIssuedServerAuthorityObservation> issued = Optional.empty();
        Throwable failure = null;
        try {
            issued = coordinator.issue(playerId, pending.request());
        } catch (AuthorityProtocolException | IOException | RuntimeException exception) {
            failure = exception;
        }
        Optional<DurablyIssuedServerAuthorityObservation> result = issued;
        Throwable resultFailure = failure;
        try {
            scheduler.executeForPlayer(pending.player(),
                    () -> completeIssuanceOnPlayer(pending, result, resultFailure),
                    () -> retirePendingIssuance(pending));
        } catch (RuntimeException exception) {
            synchronized (this) {
                if (pendingIssuances.get(playerId) == pending) {
                    remove(playerId);
                }
            }
            if (resultFailure != null) exception.addSuppressed(resultFailure);
            logger.log(Level.WARNING,
                    "MCAce authority result scheduling failed for " + playerId
                            + " after the journal writer completed (MONITOR)", exception);
        }
    }

    private synchronized void completeIssuanceOnPlayer(
            PendingIssuance pending,
            Optional<DurablyIssuedServerAuthorityObservation> issued,
            Throwable failure) {
        UUID playerId = pending.request().playerId();
        if (pendingIssuances.get(playerId) != pending) return;
        pendingIssuances.remove(playerId);
        if (closed) return;
        if (failure != null) {
            if (coordinator.poisoned()) remove(playerId);
            logger.log(Level.WARNING,
                    "MCAce authority durable issuance failed for " + playerId
                            + " before any send attempt (MONITOR)", failure);
            return;
        }
        if (issued.isEmpty()) return;

        DurablyIssuedServerAuthorityObservation durable = issued.orElseThrow();
        GrantBinding currentGrant = grants.get(playerId);
        AdmissionBinding currentAdmission = admissions.get(playerId);
        Instant now = clock.instant();
        if (currentGrant == null || currentAdmission == null
                || currentGrant.player() != pending.player()
                || currentAdmission.player() != pending.player()
                || !pending.player().isOnline()
                || !durable.matches(currentGrant.grant())
                || !durable.matches(pending.grant())
                || durable.observationSequence() != pending.request().observationSequence()
                || currentAdmission.transportSequence()
                < currentGrant.grant().admissionTransportSequence()
                || !now.isBefore(currentAdmission.expiresAt())
                || !now.isBefore(currentGrant.grant().expiresAt())
                || !now.isBefore(durable.expiresAt())
                || !pending.player().getListeningPluginChannels().contains(
                ProtocolConstants.BACKEND_AUTHORITY_CHANNEL)) {
            // The append is durable but this Player/grant capability is no longer current. Force
            // the next physical lifecycle to recover the sequence instead of retrying this frame.
            remove(playerId);
            logger.warning("Suppressed a durable MCAce authority send attempt because its exact "
                    + "player/grant capability retired before publication: " + playerId
                    + " (MONITOR)");
            return;
        }

        try {
            grants.put(playerId, new GrantBinding(
                    currentGrant.grant(), durable.observationSequence(), pending.player()));
            correlator.committed(playerId, pending.evidence().observedAt(),
                    pending.request().observedAt(), durable.issuedAt());
        } catch (RuntimeException exception) {
            remove(playerId);
            logger.log(Level.WARNING,
                    "MCAce authority durable state commit failed before any send attempt for "
                            + playerId + " (MONITOR)", exception);
            return;
        }

        try {
            pending.player().sendPluginMessage(plugin,
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, durable.frameForTransport());
            logger.info("MCAce durable SERVER_CONFIRMED authority observation send attempted in MONITOR mode: "
                    + "player=" + playerId + " attestation=" + durable.attestationId()
                    + " sequence=" + durable.observationSequence()
                    + " frame=" + durable.signedFrameSha256()
                    + " profile=" + durable.authorityProfileSha256()
                    + " provider_commitment="
                    + durable.providerEvidenceCommitmentSha256()
                    + " lifecycle_commitment="
                    + durable.lifecycleCommitmentSha256()
                    + " backend_key=" + durable.backendKeyIdSha256());
        } catch (RuntimeException exception) {
            // State remains committed. This at-most-once sender never retries an uncertain call.
            logger.log(Level.WARNING,
                    "MCAce authority observation send attempt failed for " + playerId, exception);
        }
    }

    private synchronized void retirePendingIssuance(PendingIssuance pending) {
        UUID playerId = pending.request().playerId();
        if (pendingIssuances.get(playerId) == pending) remove(playerId);
    }

    private synchronized void disableGrantState(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        grants.remove(playerId);
        pendingGrantRecoveries.remove(playerId);
        pendingIssuances.remove(playerId);
        lifecycle.remove(playerId);
        correlator.remove(playerId);
    }

    private static boolean samePhysicalLifecycle(
            BackendAuthorityGrantCodec.VerifiedGrant left,
            BackendAuthorityGrantCodec.VerifiedGrant right) {
        return left.playerId().equals(right.playerId())
                && left.backendInstanceId().equals(right.backendInstanceId())
                && left.authenticatedSessionId().equals(right.authenticatedSessionId())
                && java.security.MessageDigest.isEqual(
                left.physicalLoginBinding(), right.physicalLoginBinding());
    }

    private static GrantCandidate inspectCandidate(byte[] frame) throws AuthorityProtocolException {
        try {
            SignedEnvelope envelope = SignedEnvelope.parseFrom(frame);
            if (envelope.getHeader().getPacketType() != PacketType.BACKEND_AUTHORITY_GRANT) {
                throw new AuthorityProtocolException("unexpected backend authority packet type");
            }
            BackendAuthorityGrant grant = BackendAuthorityGrant.parseFrom(envelope.getPayload());
            return new GrantCandidate(
                    grant.getAuthenticatedSessionId(), grant.getPhysicalLoginBinding().toByteArray());
        } catch (InvalidProtocolBufferException exception) {
            throw new AuthorityProtocolException("malformed backend authority grant", exception);
        }
    }

    private record AdmissionBinding(long transportSequence, Instant expiresAt, Player player) {
        private AdmissionBinding {
            if (transportSequence <= 0L) throw new IllegalArgumentException("invalid transport sequence");
            Objects.requireNonNull(expiresAt, "expiresAt");
            Objects.requireNonNull(player, "player");
        }
    }

    private record GrantBinding(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            long lastObservationSequence,
            Player player) {
        private GrantBinding {
            Objects.requireNonNull(grant, "grant");
            if (lastObservationSequence < 0L) {
                throw new IllegalArgumentException("lastObservationSequence cannot be negative");
            }
            Objects.requireNonNull(player, "player");
        }
    }

    private record PendingIssuance(
            UUID capabilityId,
            Player player,
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            PaperAuthorityProviderCorrelator.CorrelatedProviders evidence,
            ServerAuthorityObservationCodec.ObservationRequest request) {
        private PendingIssuance {
            Objects.requireNonNull(capabilityId, "capabilityId");
            Objects.requireNonNull(player, "player");
            Objects.requireNonNull(grant, "grant");
            Objects.requireNonNull(evidence, "evidence");
            Objects.requireNonNull(request, "request");
            if (!player.getUniqueId().equals(request.playerId())
                    || !request.playerId().equals(grant.playerId())) {
                throw new IllegalArgumentException("pending authority player binding mismatch");
            }
        }
    }

    private record PendingGrantRecovery(
            UUID capabilityId,
            Player player,
            BackendAuthorityGrantCodec.VerifiedGrant grant) {
        private PendingGrantRecovery {
            Objects.requireNonNull(capabilityId, "capabilityId");
            Objects.requireNonNull(player, "player");
            Objects.requireNonNull(grant, "grant");
            if (!player.getUniqueId().equals(grant.playerId())) {
                throw new IllegalArgumentException("pending grant recovery player mismatch");
            }
        }
    }

    private record GrantCandidate(String authenticatedSessionId, byte[] physicalLoginBinding) {
        private GrantCandidate {
            Objects.requireNonNull(authenticatedSessionId, "authenticatedSessionId");
            physicalLoginBinding = Objects.requireNonNull(
                    physicalLoginBinding, "physicalLoginBinding").clone();
        }
        @Override public byte[] physicalLoginBinding() { return physicalLoginBinding.clone(); }
    }
}
