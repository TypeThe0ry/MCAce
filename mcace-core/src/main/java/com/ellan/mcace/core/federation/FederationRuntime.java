package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.federation.FederationDocuments;
import com.ellan.mcace.protocol.federation.FederationException;
import com.ellan.mcace.protocol.federation.FederationVerification;
import com.ellan.mcace.protocol.generated.ClientFederationConsent;
import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.FederationPresentation;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Isolated runtime for the four-step, client-carried federation flow.
 *
 * <p>This class opens no network transport. It never references or publishes
 * {@code InMemoryMCAceApi}, {@code RiskEngine}, admission, or disposition state. Source grants are
 * short-lived bearer material only after explicit client consent; targets additionally require a
 * current locally authenticated outer envelope and fresh presentation proof.</p>
 */
public final class FederationRuntime {
    public static final int DEFAULT_MAX_PENDING = 1024;
    public static final int DEFAULT_MAX_OBSERVATIONS = 10_000;
    private static final int MAX_ADMIN_QUERY = 100;
    private static final int DEFAULT_SWEEP_LIMIT = 256;

    private final Clock clock;
    private final SecureRandom secureRandom;
    private final KeyPair localIdentity;
    private final FederationAuditSink auditSink;
    private final AtomicReference<FederationConfiguration> configuration;
    private final EnvelopeCodec envelopeCodec;
    private final NonceReplayGuard outerReplayGuard;
    private final NonceReplayGuard presentationReplayGuard;
    private final int maxPending;
    private final int maxObservations;
    private final Map<UUID, PendingConsent> pendingByPlayer = new LinkedHashMap<>();
    private final Map<ObservationKey, FederationObservation> observations = new LinkedHashMap<>();

    public FederationRuntime(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair localIdentity,
            FederationConfiguration configuration,
            FederationAuditSink auditSink) {
        this(clock, secureRandom, localIdentity, configuration, auditSink,
                DEFAULT_MAX_PENDING, DEFAULT_MAX_OBSERVATIONS);
    }

    public FederationRuntime(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair localIdentity,
            FederationConfiguration configuration,
            FederationAuditSink auditSink,
            int maxPending,
            int maxObservations) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.localIdentity = Objects.requireNonNull(localIdentity, "localIdentity");
        Objects.requireNonNull(localIdentity.getPrivate(), "local identity private key");
        Objects.requireNonNull(localIdentity.getPublic(), "local identity public key");
        this.configuration = new AtomicReference<>(Objects.requireNonNull(configuration, "configuration"));
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        if (maxPending <= 0 || maxPending > ProtocolConstants.MAX_FEDERATION_REPLAY_ENTRIES
                || maxObservations <= 0 || maxObservations > ProtocolConstants.MAX_FEDERATION_REPLAY_ENTRIES) {
            throw new IllegalArgumentException("invalid federation runtime capacity");
        }
        this.maxPending = maxPending;
        this.maxObservations = maxObservations;
        this.envelopeCodec = new EnvelopeCodec(
                clock, secureRandom, ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        this.outerReplayGuard = new NonceReplayGuard(
                clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW,
                ProtocolConstants.MAX_FEDERATION_REPLAY_ENTRIES,
                ProtocolConstants.MAX_NONCE_REPLAY_ENTRIES_PER_SESSION);
        this.presentationReplayGuard = FederationDocuments.newReplayGuard(
                clock, ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    /** Atomically replaces a fully validated immutable configuration; replay state is preserved. */
    public void reload(FederationConfiguration next) {
        configuration.set(Objects.requireNonNull(next, "next"));
    }

    public FederationConfiguration configuration() {
        return configuration.get();
    }

    public synchronized FederationRuntimeState status() {
        expireInternal(DEFAULT_SWEEP_LIMIT);
        FederationConfiguration current = configuration.get();
        return new FederationRuntimeState(
                current.enabled(), current.localNetworkId(), current.peers().size(),
                pendingByPlayer.size(), observations.size());
    }

    /** Offline pin summaries suitable for bounded operator status output. */
    public List<FederationPeerSummary> peerSummaries() {
        return configuration.get().peers().values().stream()
                .sorted(Comparator.comparing(FederationPeerPin::networkId))
                .map(pin -> new FederationPeerSummary(
                        pin.networkId(), pin.keyIdHex(), pin.capabilities()))
                .toList();
    }

    /**
     * Source step 1: create a signed consent request only for a live local subject and an explicitly
     * pinned target. One player may have one outstanding request at a time.
     */
    public synchronized FederationIssueResult issueConsent(
            FederationSubject sourceSubject,
            String targetNetworkId,
            String operatorId) {
        Objects.requireNonNull(sourceSubject, "sourceSubject");
        if (!validOperator(operatorId)) {
            return FederationIssueResult.rejected(FederationRuntimeStatus.INTERNAL_ERROR);
        }
        expireInternal(DEFAULT_SWEEP_LIMIT);
        FederationConfiguration current = configuration.get();
        if (!current.enabled()) {
            auditRejection(FederationAuditEvent.CONSENT_ISSUED, FederationAuditOutcome.DISABLED,
                    operatorId, sourceSubject.playerId(), current.localNetworkId(), targetNetworkId,
                    Optional.empty(), Optional.empty());
            return FederationIssueResult.rejected(FederationRuntimeStatus.DISABLED);
        }
        if (!sourceSubject.localNetworkId().equals(current.localNetworkId())) {
            return FederationIssueResult.rejected(FederationRuntimeStatus.NO_CURRENT_SUBJECT);
        }
        FederationPeerPin targetPin = current.peers().get(targetNetworkId);
        if (targetPin == null || !targetPin.allows(FederationPeerCapability.ISSUE_TO)) {
            auditRejection(FederationAuditEvent.CONSENT_ISSUED, FederationAuditOutcome.NOT_PINNED,
                    operatorId, sourceSubject.playerId(), current.localNetworkId(), targetNetworkId,
                    Optional.empty(), Optional.empty());
            return FederationIssueResult.rejected(FederationRuntimeStatus.NOT_PINNED);
        }
        if (pendingByPlayer.containsKey(sourceSubject.playerId())) {
            return FederationIssueResult.rejected(FederationRuntimeStatus.PENDING_EXISTS);
        }
        if (pendingByPlayer.size() >= maxPending) {
            return FederationIssueResult.rejected(FederationRuntimeStatus.CAPACITY_REACHED);
        }
        try {
            FederationConsentRequest request = FederationDocuments.issueConsentRequest(
                    current.localNetworkId(), targetNetworkId, sourceSubject.playerId().toString(),
                    sourceSubject.clientPublicKey(), localIdentity.getPublic(), targetPin.publicKey(),
                    sourceSubject.authenticatedSessionId(), sourceSubject.policyVersion(),
                    sourceSubject.policySha256(), clock, current.assertionLifetime(), secureRandom);
            UUID assertionId = canonicalUuid(request.getAssertionId());
            byte[] frame = signOuter(PacketType.FEDERATION_CONSENT_REQUEST,
                    sourceSubject.authenticatedSessionId(), request.toByteArray());
            FederationAuditRecord audit = auditRecord(
                    FederationAuditEvent.CONSENT_ISSUED, FederationAuditOutcome.SUCCEEDED,
                    operatorId, sourceSubject.playerId(), current.localNetworkId(), targetNetworkId,
                    Optional.of(assertionId), Optional.of(auditKeyFingerprint(targetPin)));
            if (!appendAudit(audit)) {
                return FederationIssueResult.rejected(FederationRuntimeStatus.AUDIT_FAILED);
            }
            pendingByPlayer.put(sourceSubject.playerId(), new PendingConsent(
                    sourceSubject, request, operatorId, targetPin.keyIdSha256()));
            return new FederationIssueResult(
                    FederationRuntimeStatus.CONSENT_ISSUED, Optional.of(request), Optional.of(frame));
        } catch (FederationException | EnvelopeException | BoundedPayloadException | RuntimeException exception) {
            return FederationIssueResult.rejected(FederationRuntimeStatus.INTERNAL_ERROR);
        }
    }

    /**
     * Source steps 2-3: verify the current client's outer envelope and signed consent, then return a
     * source-signed grant frame. Invalid responses do not consume the pending request.
     */
    public synchronized FederationGrantResult receiveConsentResponse(
            FederationSubject currentSourceSubject,
            byte[] encodedOuterFrame) {
        Objects.requireNonNull(currentSourceSubject, "currentSourceSubject");
        Objects.requireNonNull(encodedOuterFrame, "encodedOuterFrame");
        expireInternal(DEFAULT_SWEEP_LIMIT);
        PendingConsent pending = pendingByPlayer.get(currentSourceSubject.playerId());
        if (pending == null) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.NO_PENDING_REQUEST);
        }
        FederationConfiguration current = configuration.get();
        if (!current.enabled()) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.DISABLED);
        }
        if (!currentSourceSubject.localNetworkId().equals(current.localNetworkId())) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.NO_CURRENT_SUBJECT);
        }
        FederationPeerPin targetPin = current.peers().get(pending.request().getTargetNetworkId());
        if (targetPin == null || !targetPin.allows(FederationPeerCapability.ISSUE_TO)
                || !MessageDigest.isEqual(targetPin.keyIdSha256(), pending.targetKeyIdSha256())) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.NOT_PINNED);
        }
        if (!sameSubject(currentSourceSubject, pending.subject())) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.NO_CURRENT_SUBJECT);
        }
        try {
            byte[] payload = verifyOuter(
                    currentSourceSubject, encodedOuterFrame, PacketType.FEDERATION_CONSENT_RESPONSE);
            ClientFederationConsent consent = FederationDocuments.parseConsentResponse(payload);
            FederationDocuments.validateConsentRequestBindings(
                    pending.request(), current.localNetworkId(), targetPin.networkId(),
                    currentSourceSubject.playerId().toString(), currentSourceSubject.clientPublicKey(),
                    localIdentity.getPublic(), targetPin.publicKey(),
                    currentSourceSubject.authenticatedSessionId());
            var signedAssertion = FederationDocuments.signAssertion(
                    pending.request(), consent, currentSourceSubject.clientPublicKey(),
                    localIdentity.getPrivate(), localIdentity.getPublic(), clock,
                    ProtocolConstants.DEFAULT_CLOCK_SKEW);
            FederationGrant grant = FederationDocuments.grant(
                    consent, signedAssertion, currentSourceSubject.clientPublicKey());
            byte[] frame = signOuter(PacketType.FEDERATION_GRANT,
                    currentSourceSubject.authenticatedSessionId(), FederationDocuments.encodeGrant(grant));
            FederationAuditRecord audit = auditRecord(
                    FederationAuditEvent.GRANT_SIGNED, FederationAuditOutcome.SUCCEEDED,
                    pending.operatorId(), currentSourceSubject.playerId(), current.localNetworkId(),
                    targetPin.networkId(), Optional.of(canonicalUuid(pending.request().getAssertionId())),
                    Optional.of(auditKeyFingerprint(targetPin)));
            if (!appendAudit(audit)) {
                return FederationGrantResult.rejected(FederationRuntimeStatus.AUDIT_FAILED);
            }
            pendingByPlayer.remove(currentSourceSubject.playerId());
            return new FederationGrantResult(
                    FederationRuntimeStatus.GRANT_READY, Optional.of(grant), Optional.of(frame));
        } catch (FederationException exception) {
            auditRejection(FederationAuditEvent.GRANT_SIGNED, FederationAuditOutcome.INVALID_CONSENT,
                    pending.operatorId(), currentSourceSubject.playerId(), current.localNetworkId(),
                    pending.request().getTargetNetworkId(),
                    uuidOptional(pending.request().getAssertionId()), Optional.of(auditKeyFingerprint(targetPin)));
            return FederationGrantResult.rejected(FederationRuntimeStatus.INVALID_CONSENT);
        } catch (EnvelopeException | BoundedPayloadException exception) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.INVALID_FRAME);
        } catch (RuntimeException exception) {
            return FederationGrantResult.rejected(FederationRuntimeStatus.INTERNAL_ERROR);
        }
    }

    /**
     * Target step 4: verify the current client's signed outer envelope, peer pin, target identity,
     * session/challenge/player PoP, freshness, and one-time replay. Success stores only an advisory
     * in-memory observation bound to the target session and assertion expiry.
     */
    public synchronized FederationPresentationResult receivePresentation(
            FederationSubject targetSubject,
            byte[] encodedOuterFrame,
            String operatorId) {
        Objects.requireNonNull(targetSubject, "targetSubject");
        Objects.requireNonNull(encodedOuterFrame, "encodedOuterFrame");
        if (!validOperator(operatorId)) {
            return FederationPresentationResult.rejected(FederationRuntimeStatus.INTERNAL_ERROR);
        }
        expireInternal(DEFAULT_SWEEP_LIMIT);
        FederationConfiguration current = configuration.get();
        if (!current.enabled()) {
            auditRejection(FederationAuditEvent.PRESENTATION_REJECTED, FederationAuditOutcome.DISABLED,
                    operatorId, targetSubject.playerId(), "unknown", current.localNetworkId(),
                    Optional.empty(), Optional.empty());
            return FederationPresentationResult.rejected(FederationRuntimeStatus.DISABLED);
        }
        if (!targetSubject.localNetworkId().equals(current.localNetworkId())) {
            return FederationPresentationResult.rejected(FederationRuntimeStatus.NO_CURRENT_SUBJECT);
        }

        String sourceNetworkId = "unknown";
        FederationPeerPin sourcePin = null;
        try {
            // Authenticate the current target carrier before using the bounded inner source id as
            // a peer-pin lookup selector. The selector is never accepted as an assertion by itself.
            byte[] presentation = verifyOuter(
                    targetSubject, encodedOuterFrame, PacketType.FEDERATION_PRESENTATION);
            sourceNetworkId = presentationSourceNetworkId(presentation);
            sourcePin = current.peers().get(sourceNetworkId);
            if (sourcePin == null || !sourcePin.allows(FederationPeerCapability.ACCEPT_FROM)) {
                auditRejection(FederationAuditEvent.PRESENTATION_REJECTED,
                        FederationAuditOutcome.NOT_PINNED, operatorId, targetSubject.playerId(),
                        sourceNetworkId, current.localNetworkId(), Optional.empty(), Optional.empty());
                return FederationPresentationResult.rejected(FederationRuntimeStatus.NOT_PINNED);
            }
            ObservationKey observationKey = new ObservationKey(
                    targetSubject.playerId(), targetSubject.authenticatedSessionId(), sourceNetworkId);
            if (!observations.containsKey(observationKey) && observations.size() >= maxObservations) {
                return FederationPresentationResult.rejected(FederationRuntimeStatus.CAPACITY_REACHED);
            }
            FederationVerification verified = FederationDocuments.verify(
                    presentation, sourcePin.publicKey(), localIdentity.getPublic(),
                    sha256(targetSubject.clientPublicKey().getEncoded()), sourceNetworkId,
                    current.localNetworkId(), targetSubject.playerId().toString(),
                    targetSubject.authenticatedSessionId(), targetSubject.serverChallengeNonce(),
                    clock, ProtocolConstants.DEFAULT_CLOCK_SKEW, presentationReplayGuard);
            UUID assertionId = canonicalUuid(verified.assertionId());
            Instant issuedAt = Instant.ofEpochMilli(verified.issuedAtEpochMs());
            Instant expiresAt = Instant.ofEpochMilli(verified.expiresAtEpochMs());
            FederationObservation observation = new FederationObservation(
                    targetSubject.playerId(), targetSubject.authenticatedSessionId(),
                    verified.sourceNetworkId(), verified.targetNetworkId(), assertionId,
                    verified.policyVersion(), verified.remoteClaim(), issuedAt, expiresAt, clock.instant());
            FederationAuditRecord audit = auditRecord(
                    FederationAuditEvent.PRESENTATION_ACCEPTED, FederationAuditOutcome.SUCCEEDED,
                    operatorId, targetSubject.playerId(), verified.sourceNetworkId(),
                    verified.targetNetworkId(), Optional.of(assertionId), Optional.of(auditKeyFingerprint(sourcePin)));
            if (!appendAudit(audit)) {
                return FederationPresentationResult.rejected(FederationRuntimeStatus.AUDIT_FAILED);
            }
            observations.put(observationKey, observation);
            return new FederationPresentationResult(
                    FederationRuntimeStatus.OBSERVED, Optional.of(observation));
        } catch (FederationException exception) {
            FederationRuntimeStatus status = exception.getMessage() != null
                    && exception.getMessage().contains("replayed federation")
                    ? FederationRuntimeStatus.REPLAYED : FederationRuntimeStatus.INVALID_PRESENTATION;
            FederationAuditOutcome outcome = status == FederationRuntimeStatus.REPLAYED
                    ? FederationAuditOutcome.REPLAYED : FederationAuditOutcome.INVALID_PRESENTATION;
            auditRejection(FederationAuditEvent.PRESENTATION_REJECTED, outcome, operatorId,
                    targetSubject.playerId(), sourceNetworkId, current.localNetworkId(),
                    Optional.empty(), sourcePin == null
                            ? Optional.empty() : Optional.of(auditKeyFingerprint(sourcePin)));
            return FederationPresentationResult.rejected(status);
        } catch (EnvelopeException | BoundedPayloadException exception) {
            auditRejection(FederationAuditEvent.PRESENTATION_REJECTED,
                    FederationAuditOutcome.INVALID_PRESENTATION, operatorId, targetSubject.playerId(),
                    sourceNetworkId, current.localNetworkId(), Optional.empty(),
                    sourcePin == null ? Optional.empty() : Optional.of(auditKeyFingerprint(sourcePin)));
            return FederationPresentationResult.rejected(FederationRuntimeStatus.INVALID_FRAME);
        } catch (RuntimeException exception) {
            return FederationPresentationResult.rejected(FederationRuntimeStatus.INTERNAL_ERROR);
        }
    }

    /** Read-only advisory observations for an operator; never returns raw grants or presentations. */
    public synchronized List<FederationObservation> observations(UUID playerId, int limit) {
        Objects.requireNonNull(playerId, "playerId");
        if (limit <= 0 || limit > MAX_ADMIN_QUERY) {
            throw new IllegalArgumentException("federation observation query is outside bounds");
        }
        expireInternal(DEFAULT_SWEEP_LIMIT);
        return observations.values().stream()
                .filter(observation -> observation.playerId().equals(playerId))
                .sorted(Comparator.comparing(FederationObservation::observedAt).reversed())
                .limit(limit)
                .toList();
    }

    /** Disconnect cleanup. Previously issued grants remain independently valid until their signed expiry. */
    public synchronized void removeForSession(UUID playerId, String authenticatedSessionId) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(authenticatedSessionId, "authenticatedSessionId");
        PendingConsent pending = pendingByPlayer.get(playerId);
        if (pending != null && pending.subject().authenticatedSessionId().equals(authenticatedSessionId)) {
            pendingByPlayer.remove(playerId);
        }
        observations.keySet().removeIf(key -> key.playerId().equals(playerId)
                && key.targetSessionId().equals(authenticatedSessionId));
    }

    /** Cancels only an outstanding request; a grant already returned to the client is independent. */
    public synchronized boolean cancelPending(UUID playerId) {
        return pendingByPlayer.remove(Objects.requireNonNull(playerId, "playerId")) != null;
    }

    /** Session-specific cancellation prevents a delayed send failure from cancelling a newer request. */
    public synchronized boolean cancelPending(UUID playerId, String authenticatedSessionId) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(authenticatedSessionId, "authenticatedSessionId");
        PendingConsent pending = pendingByPlayer.get(playerId);
        if (pending == null
                || !pending.subject().authenticatedSessionId().equals(authenticatedSessionId)) {
            return false;
        }
        pendingByPlayer.remove(playerId);
        return true;
    }

    /** Disconnect fallback for adapters that no longer retain the previous session id. */
    public synchronized void removeForPlayer(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        pendingByPlayer.remove(playerId);
        observations.keySet().removeIf(key -> key.playerId().equals(playerId));
    }

    /** Performs a bounded expiry sweep and returns the number of entries removed. */
    public synchronized int expire(int maximumEntries) {
        if (maximumEntries <= 0 || maximumEntries > ProtocolConstants.MAX_FEDERATION_REPLAY_ENTRIES) {
            throw new IllegalArgumentException("federation expiry sweep is outside bounds");
        }
        return expireInternal(maximumEntries);
    }

    private byte[] verifyOuter(
            FederationSubject subject,
            byte[] encodedFrame,
            PacketType expectedType) throws EnvelopeException, BoundedPayloadException {
        BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
        if (envelope.getHeader().getPacketType() != expectedType
                || !envelope.getHeader().getSessionId().equals(subject.authenticatedSessionId())) {
            throw new EnvelopeException("federation outer envelope binding mismatch");
        }
        envelopeCodec.verify(envelope, subject.clientPublicKey(), outerReplayGuard);
        return envelope.getPayload().toByteArray();
    }

    private byte[] signOuter(PacketType type, String sessionId, byte[] payload)
            throws EnvelopeException, BoundedPayloadException {
        byte[] frame = envelopeCodec.sign(type, sessionId, payload, localIdentity.getPrivate()).toByteArray();
        BoundedPayloadTransferLimits.validateFrameBytes(frame.length);
        return frame;
    }

    private int expireInternal(int maximumEntries) {
        int removed = 0;
        long now = clock.millis();
        int pendingInspected = 0;
        Iterator<Map.Entry<UUID, PendingConsent>> pendingIterator = pendingByPlayer.entrySet().iterator();
        while (pendingIterator.hasNext() && pendingInspected < maximumEntries) {
            Map.Entry<UUID, PendingConsent> entry = pendingIterator.next();
            pendingInspected++;
            if (entry.getValue().request().getExpiresAtEpochMs() <= now) {
                pendingIterator.remove();
                removed++;
            }
        }
        // Give the independent target-observation collection its own bounded budget. Sharing one
        // counter lets a full source-pending collection indefinitely starve target expiry cleanup.
        int observationInspected = 0;
        Iterator<Map.Entry<ObservationKey, FederationObservation>> observationIterator =
                observations.entrySet().iterator();
        while (observationIterator.hasNext() && observationInspected < maximumEntries) {
            Map.Entry<ObservationKey, FederationObservation> entry = observationIterator.next();
            observationInspected++;
            if (!clock.instant().isBefore(entry.getValue().expiresAt())) {
                observationIterator.remove();
                removed++;
            }
        }
        return removed;
    }

    private boolean sameSubject(FederationSubject current, FederationSubject issued) {
        return current.playerId().equals(issued.playerId())
                && current.localNetworkId().equals(issued.localNetworkId())
                && current.authenticatedSessionId().equals(issued.authenticatedSessionId())
                && MessageDigest.isEqual(current.clientPublicKey().getEncoded(), issued.clientPublicKey().getEncoded())
                && current.policyVersion().equals(issued.policyVersion())
                && MessageDigest.isEqual(current.policySha256(), issued.policySha256());
    }

    private void auditRejection(
            FederationAuditEvent event,
            FederationAuditOutcome outcome,
            String operatorId,
            UUID playerId,
            String sourceNetworkId,
            String targetNetworkId,
            Optional<UUID> assertionId,
            Optional<String> peerKeyId) {
        try {
            appendAudit(auditRecord(event, outcome, operatorId, playerId, sourceNetworkId,
                    targetNetworkId, assertionId, peerKeyId));
        } catch (RuntimeException ignored) {
            // The operation is already rejected. Audit failure cannot make it less restrictive.
        }
    }

    private FederationAuditRecord auditRecord(
            FederationAuditEvent event,
            FederationAuditOutcome outcome,
            String operatorId,
            UUID playerId,
            String sourceNetworkId,
            String targetNetworkId,
            Optional<UUID> assertionId,
            Optional<String> peerKeyId) {
        return new FederationAuditRecord(clock.instant(), event, outcome, operatorId, playerId,
                sourceNetworkId, targetNetworkId, assertionId, peerKeyId);
    }

    private boolean appendAudit(FederationAuditRecord record) {
        try {
            return auditSink.offer(record);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    private static UUID canonicalUuid(String value) {
        UUID parsed = UUID.fromString(value);
        if (!parsed.toString().equals(value)) {
            throw new IllegalArgumentException("non-canonical federation assertion id");
        }
        return parsed;
    }

    private static Optional<UUID> uuidOptional(String value) {
        try {
            return Optional.of(canonicalUuid(value));
        } catch (RuntimeException ignored) {
            return Optional.empty();
        }
    }

    /**
     * Keeps the on-disk audit within the documented short-fingerprint disclosure budget. The full
     * SHA-256 pin remains only in the operator-controlled federation configuration and is never
     * written to an audit record.
     */
    private static String auditKeyFingerprint(FederationPeerPin pin) {
        String fullPin = Objects.requireNonNull(pin, "pin").keyIdHex();
        return fullPin.substring(0, FederationAuditRecord.PEER_KEY_FINGERPRINT_HEX_CHARS);
    }

    private static boolean validOperator(String value) {
        return value != null && !value.isBlank()
                && value.length() <= ProtocolConstants.MAX_FEDERATION_ID_CHARS
                && value.codePoints().noneMatch(Character::isISOControl);
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /**
     * Extracts only the bounded source selector after the target outer envelope is authenticated.
     * Full trust comes solely from the subsequent pinned {@link FederationDocuments#verify} call.
     */
    private static String presentationSourceNetworkId(byte[] payload) throws FederationException {
        if (payload.length == 0 || payload.length > ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES) {
            throw new FederationException("federation presentation exceeds encoded budget");
        }
        try {
            FederationPresentation presentation = FederationPresentation.parseFrom(payload);
            if (!presentation.hasGrant() || !presentation.getGrant().hasClientConsent()) {
                throw new FederationException("federation presentation source binding is missing");
            }
            String source = presentation.getGrant().getClientConsent().getSourceNetworkId();
            FederationPeerPin.requireNetworkId(source);
            return source;
        } catch (com.google.protobuf.InvalidProtocolBufferException | IllegalArgumentException exception) {
            throw new FederationException("malformed federation presentation source binding", exception);
        }
    }

    private record PendingConsent(
            FederationSubject subject,
            FederationConsentRequest request,
            String operatorId,
            byte[] targetKeyIdSha256) {
        private PendingConsent {
            Objects.requireNonNull(subject, "subject");
            Objects.requireNonNull(request, "request");
            Objects.requireNonNull(operatorId, "operatorId");
            targetKeyIdSha256 = targetKeyIdSha256.clone();
        }

        @Override
        public byte[] targetKeyIdSha256() {
            return targetKeyIdSha256.clone();
        }
    }

    private record ObservationKey(UUID playerId, String targetSessionId, String sourceNetworkId) { }
}
