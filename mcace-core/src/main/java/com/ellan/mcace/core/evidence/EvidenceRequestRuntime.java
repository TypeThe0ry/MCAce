package com.ellan.mcace.core.evidence;

import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.evidence.EvidenceTransferLimits;
import com.ellan.mcace.protocol.generated.EvidenceAck;
import com.ellan.mcace.protocol.generated.EvidenceAckStatus;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceError;
import com.ellan.mcace.protocol.generated.EvidenceErrorCode;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceResponse;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.core.session.AuthenticatedObservationSession;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Shared server-side evidence request and receive runtime.
 *
 * <p>This class deliberately has no risk, admission, routing, logging-content, or ban callback.
 * A completed transfer is handed to the explicitly supplied bounded content and audit sinks only.
 * One request and one transfer may be outstanding for a session; the evidence nonce budget is
 * independent from the handshake replay guard so a legal 1,024-chunk upload remains possible.</p>
 */
public final class EvidenceRequestRuntime {
    public record IssuedRequest(EvidenceRequest request, byte[] encodedFrame) {
        public IssuedRequest {
            Objects.requireNonNull(request, "request");
            Objects.requireNonNull(encodedFrame, "encodedFrame");
            encodedFrame = encodedFrame.clone();
        }
        @Override public byte[] encodedFrame() { return encodedFrame.clone(); }
    }

    private final Clock clock;
    private final SecureRandom secureRandom;
    private final PrivateKey serverSigningKey;
    private final EnvelopeCodec envelopeCodec;
    private final SecurityAuditSink auditSink;
    private final EvidenceAuditSink evidenceAuditSink;
    private final EvidenceContentStore contentStore;
    private final int maxOutstandingRequests;
    private final Map<String, ActiveRequest> requests = new HashMap<>();
    private final Map<UUID, String> requestByPlayer = new HashMap<>();

    public EvidenceRequestRuntime(
            Clock clock,
            SecureRandom secureRandom,
            PrivateKey serverSigningKey,
            SecurityAuditSink auditSink,
            EvidenceContentStore contentStore,
            int maxOutstandingRequests) {
        this(clock, secureRandom, serverSigningKey, auditSink, EvidenceAuditSink.noop(), contentStore,
                maxOutstandingRequests);
    }

    public EvidenceRequestRuntime(
            Clock clock,
            SecureRandom secureRandom,
            PrivateKey serverSigningKey,
            SecurityAuditSink auditSink,
            EvidenceAuditSink evidenceAuditSink,
            EvidenceContentStore contentStore,
            int maxOutstandingRequests) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.serverSigningKey = Objects.requireNonNull(serverSigningKey, "serverSigningKey");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.evidenceAuditSink = Objects.requireNonNull(evidenceAuditSink, "evidenceAuditSink");
        this.contentStore = Objects.requireNonNull(contentStore, "contentStore");
        if (maxOutstandingRequests < 1 || maxOutstandingRequests > 65_536) {
            throw new IllegalArgumentException("invalid evidence request capacity");
        }
        this.maxOutstandingRequests = maxOutstandingRequests;
        this.envelopeCodec = new EnvelopeCodec(
                clock, secureRandom, ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    public EvidenceRequestRuntime(
            Clock clock, SecureRandom secureRandom, PrivateKey serverSigningKey, SecurityAuditSink auditSink) {
        this(clock, secureRandom, serverSigningKey, auditSink, EvidenceContentStore.discard(), 4096);
    }

    public synchronized Optional<IssuedRequest> issue(
            AuthenticatedObservationSession session, EvidenceRequestSpec spec, String operatorId)
            throws EnvelopeException {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(spec, "spec");
        operatorId = requireOperator(operatorId);
        Instant now = clock.instant();
        if (!now.isBefore(session.expiresAt())) return Optional.empty();
        if (requestByPlayer.containsKey(session.playerId()) || requests.size() >= maxOutstandingRequests) {
            return Optional.empty();
        }
        long expiry = Math.min(
                safeEpochMillis(now.plus(spec.ttl())), safeEpochMillis(session.expiresAt()));
        if (expiry <= clock.millis()) return Optional.empty();
        if (!spec.retentionDisclosure().equals(contentStore.retentionDisclosure())) {
            throw new IllegalArgumentException("request retention disclosure does not match configured store");
        }
        EvidenceRequest.Builder requestBuilder = EvidenceRequest.newBuilder()
                .setEvidenceId(UUID.randomUUID().toString())
                .setType(spec.type())
                .addAllAllowedRelativePaths(spec.allowedRelativePaths())
                .setExpiresAtEpochMs(expiry)
                .setCaptureScope(spec.captureScope())
                .setCaseId(spec.caseId())
                .setRequestId(randomId())
                .setPlayerId(session.playerId().toString());
        EvidenceContentStore.RetentionDisclosure disclosure = spec.retentionDisclosure();
        if (disclosure.rawContentRetained()) {
            requestBuilder.setRawContentRetained(true)
                    .setRetentionSeconds(Math.toIntExact(disclosure.retentionSeconds()))
                    .setRetentionPolicyId(disclosure.retentionPolicyId())
                    .setRetentionPurpose(disclosure.retentionPurpose());
        }
        EvidenceRequest request = requestBuilder.build();
        EvidenceTransferLimits.validateRequest(request, clock.millis());
        byte[] frame = envelopeCodec.sign(
                PacketType.EVIDENCE_REQUEST, session.sessionId(), request.toByteArray(), serverSigningKey).toByteArray();
        if (frame.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
            throw new EnvelopeException("evidence request exceeds proxy frame budget");
        }
        ActiveRequest active = new ActiveRequest(
                session, request, operatorId, EvidenceTransferLimits.newRequestReplayGuard(clock, request));
        requests.put(request.getRequestId(), active);
        requestByPlayer.put(session.playerId(), request.getRequestId());
        return Optional.of(new IssuedRequest(request, frame));
    }

    /** Receives one raw client frame. The raw 30KiB budget is checked before protobuf parsing. */
    public synchronized EvidenceIngressResult receive(
            AuthenticatedObservationSession session, byte[] encodedFrame) {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        String requestId = requestByPlayer.get(session.playerId());
        ActiveRequest active = requestId == null ? null : requests.get(requestId);
        if (active == null || !active.session.sessionId().equals(session.sessionId())) {
            return new EvidenceIngressResult(EvidenceIngressResult.Status.REJECTED, List.of(), "no outstanding request");
        }
        if (clock.millis() >= active.request.getExpiresAtEpochMs()) {
            remove(active);
            return error(active, PacketType.EVIDENCE_RESPONSE, EvidenceErrorCode.EVIDENCE_ERROR_EXPIRED, 1L,
                    EvidenceIngressResult.Status.EXPIRED, "evidence request expired");
        }
        PacketType packetType = PacketType.PACKET_TYPE_UNSPECIFIED;
        try {
            if (encodedFrame.length <= 0 || encodedFrame.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
                throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, 0L,
                        "signed frame exceeds 30 KiB budget");
            }
            SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
            if (!envelope.hasHeader() || !session.sessionId().equals(envelope.getHeader().getSessionId())) {
                throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_UNAUTHORIZED, 0L,
                        "evidence session binding mismatch");
            }
            packetType = envelope.getHeader().getPacketType();
            if (packetType != PacketType.EVIDENCE_RESPONSE && packetType != PacketType.EVIDENCE_BEGIN
                    && packetType != PacketType.EVIDENCE_CHUNK && packetType != PacketType.EVIDENCE_COMMIT) {
                throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, 0L,
                        "unexpected evidence packet");
            }
            envelopeCodec.verify(envelope, session.clientPublicKey(), active.replayGuard);
            return switch (packetType) {
                case EVIDENCE_RESPONSE -> response(active, EvidenceResponse.parseFrom(envelope.getPayload()));
                case EVIDENCE_BEGIN -> begin(active, EvidenceBegin.parseFrom(envelope.getPayload()));
                case EVIDENCE_CHUNK -> chunk(active, EvidenceChunk.parseFrom(envelope.getPayload()));
                case EVIDENCE_COMMIT -> commit(active, EvidenceCommit.parseFrom(envelope.getPayload()));
                default -> throw new AssertionError(packetType);
            };
        } catch (ProtocolFailure failure) {
            return reject(active, packetType, failure.code, failure.sequence, failure.getMessage());
        } catch (InvalidProtocolBufferException | EnvelopeException | IllegalArgumentException exception) {
            EvidenceErrorCode code = exception.getMessage() != null && exception.getMessage().contains("replayed nonce")
                    ? EvidenceErrorCode.EVIDENCE_ERROR_REPLAYED
                    : EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER;
            return reject(active, packetType, code, active.nextSequence, "evidence frame rejected");
        }
    }

    public synchronized void removeForSession(String sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        requests.values().stream()
                .filter(active -> active.session.sessionId().equals(sessionId))
                .toList().forEach(this::remove);
    }

    /** Cancels an issued request when transport delivery fails; this does not create risk. */
    public synchronized boolean cancelForPlayer(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        String requestId = requestByPlayer.get(playerId);
        ActiveRequest active = requestId == null ? null : requests.get(requestId);
        if (active == null) return false;
        remove(active);
        return true;
    }

    public synchronized int outstandingCount() {
        return requests.size();
    }

    private EvidenceIngressResult response(ActiveRequest active, EvidenceResponse response) {
        if (response.getCollectionStatusCode() == EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            return reject(active, PacketType.EVIDENCE_RESPONSE, EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, 1L,
                    "collected evidence must use begin/chunk/commit");
        }
        validateUnavailableResponse(active, response);
        finishUnavailable(active, response.getCollectionStatusCode(), response.getCapturedAtEpochMs());
        return ack(active, PacketType.EVIDENCE_RESPONSE, EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, 1L,
                EvidenceIngressResult.Status.COMPLETE);
    }

    private void validateUnavailableResponse(ActiveRequest active, EvidenceResponse response) {
        if (!active.request.getEvidenceId().equals(response.getEvidenceId())
                || !active.request.getRequestId().equals(response.getRequestId())
                || !active.request.getPlayerId().equals(response.getPlayerId())
                || active.request.getType() != response.getType()
                || active.request.getCaptureScope() != response.getCaptureScope()
                || response.getCollectionStatusCode() == EvidenceCollectionStatus.EVIDENCE_COLLECTION_STATUS_UNSPECIFIED
                || response.getCollectionStatusCode() == EvidenceCollectionStatus.UNRECOGNIZED
                || !response.getContent().isEmpty() || !response.getContentSha256().isEmpty()
                || response.getCapturedAtEpochMs() > clock.millis()) {
            throw new IllegalArgumentException("evidence response is not a zero-content unavailable result");
        }
    }

    private EvidenceIngressResult begin(ActiveRequest active, EvidenceBegin begin) {
        EvidenceTransferLimits.validateBegin(begin, clock.millis());
        bind(active, begin.getEvidenceId(), begin.getRequestId(), begin.getPlayerId(), begin.getType(),
                begin.getCaptureScope(), begin.getTransportSequence(), 1L);
        if (begin.getCollectionStatus() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            finishUnavailable(active, begin.getCollectionStatus(), begin.getCapturedAtEpochMs());
            return ack(active, PacketType.EVIDENCE_BEGIN, EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, 1L,
                    EvidenceIngressResult.Status.COMPLETE);
        }
        if (active.transfer != null) throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, 1L,
                "evidence transfer already started");
        active.transfer = new ActiveTransfer(begin);
        active.nextSequence = 2L;
        return ack(active, PacketType.EVIDENCE_BEGIN, EvidenceAckStatus.EVIDENCE_ACK_ACCEPTED, 1L,
                EvidenceIngressResult.Status.ACCEPTED);
    }

    private EvidenceIngressResult chunk(ActiveRequest active, EvidenceChunk chunk) {
        ActiveTransfer transfer = active.transfer;
        if (transfer == null) throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER,
                active.nextSequence, "evidence begin is required");
        EvidenceTransferLimits.validateChunk(chunk, transfer.begin);
        bind(active, chunk.getEvidenceId(), chunk.getRequestId(), chunk.getPlayerId(),
                transfer.begin.getType(), transfer.begin.getCaptureScope(), chunk.getTransportSequence(), active.nextSequence);
        if (chunk.getChunkIndex() != transfer.chunks.size()) {
            throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, active.nextSequence,
                    "evidence chunks must be ordered");
        }
        byte[] content = chunk.getContent().toByteArray();
        if (transfer.bytes > transfer.begin.getTotalBytes() - content.length) {
            throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, active.nextSequence,
                    "evidence total bytes exceeded");
        }
        transfer.chunks.add(content);
        transfer.hashes.add(chunk.getChunkSha256().toByteArray());
        transfer.bytes += content.length;
        active.nextSequence++;
        return new EvidenceIngressResult(EvidenceIngressResult.Status.ACCEPTED, List.of(), "");
    }

    private EvidenceIngressResult commit(ActiveRequest active, EvidenceCommit commit) {
        ActiveTransfer transfer = active.transfer;
        if (transfer == null) throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER,
                active.nextSequence, "evidence begin is required");
        EvidenceTransferLimits.validateCommit(commit, transfer.begin);
        bind(active, commit.getEvidenceId(), commit.getRequestId(), commit.getPlayerId(),
                transfer.begin.getType(), transfer.begin.getCaptureScope(), commit.getTransportSequence(), active.nextSequence);
        long expectedSequence = (long) transfer.begin.getTotalChunks() + 2L;
        if (commit.getTransportSequence() != expectedSequence || active.nextSequence != expectedSequence
                || transfer.chunks.size() != transfer.begin.getTotalChunks()
                || transfer.bytes != transfer.begin.getTotalBytes()) {
            throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, expectedSequence,
                    "evidence commit is incomplete or out of order");
        }
        byte[] content = join(transfer.chunks, (int) transfer.bytes);
        try {
            if (!MessageDigest.isEqual(
                    com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits.sha256(content),
                    transfer.begin.getContentSha256().toByteArray())
                    || !MessageDigest.isEqual(
                    com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits.merkleRoot(transfer.hashes),
                    transfer.begin.getMerkleRootSha256().toByteArray())) {
                throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, expectedSequence,
                        "evidence content integrity mismatch");
            }
        } catch (com.ellan.mcace.protocol.transport.BoundedPayloadException exception) {
            throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, expectedSequence,
                    "evidence content integrity unavailable");
        }
        UUID evidenceId = uuid(active.request.getEvidenceId());
        byte[] sha256 = transfer.begin.getContentSha256().toByteArray();
        String storageUri;
        if (!active.request.getRawContentRetained()) {
            // The signed no-retention disclosure is an enforcement boundary, not just UI text.
            storageUri = "memory://mcace/evidence/discarded/" + active.request.getEvidenceId();
            appendAudit(active, ObservationOrigin.CLIENT_REPORTED, transfer.begin.getCapturedAtEpochMs(),
                    content.length, sha256, storageUri, EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED,
                    transfer.begin);
            remove(active);
            return ack(active, PacketType.EVIDENCE_COMMIT, EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, expectedSequence,
                    EvidenceIngressResult.Status.COMPLETE);
        }
        try {
            EvidenceStorageMetadata storageMetadata = new EvidenceStorageMetadata(
                    evidenceId, active.session.playerId(), active.session.sessionId(), active.request.getRequestId(),
                    active.request.getCaseId(), active.request.getType(), active.request.getCaptureScope(),
                    EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED,
                    Instant.ofEpochMilli(transfer.begin.getCapturedAtEpochMs()), transfer.begin.getWidthPixels(),
                    transfer.begin.getHeightPixels(), transfer.begin.getTotalChunks(), sha256,
                    transfer.begin.getMerkleRootSha256().toByteArray(),
                    active.request.getRetentionSeconds(), active.request.getRetentionPolicyId(),
                    active.request.getRetentionPurpose());
            storageUri = contentStore.store(new EvidenceContentStore.EvidenceContent(
                    evidenceId, active.session.playerId(), active.session.sessionId(), active.request.getRequestId(),
                    Instant.ofEpochMilli(transfer.begin.getCapturedAtEpochMs()), content, sha256), storageMetadata).storageUri();
        } catch (Exception exception) {
            finishUnavailable(active, EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED,
                    transfer.begin.getCapturedAtEpochMs());
            return error(active, PacketType.EVIDENCE_COMMIT, EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER,
                    expectedSequence, EvidenceIngressResult.Status.REJECTED, "evidence storage failed");
        }
        appendAudit(active, ObservationOrigin.CLIENT_REPORTED, transfer.begin.getCapturedAtEpochMs(), content.length,
                sha256, storageUri, EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, transfer.begin);
        remove(active);
        return ack(active, PacketType.EVIDENCE_COMMIT, EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, expectedSequence,
                EvidenceIngressResult.Status.COMPLETE);
    }

    private void bind(ActiveRequest active, String evidenceId, String requestId, String playerId,
                      com.ellan.mcace.protocol.generated.EvidenceType type, EvidenceCaptureScope scope,
                      long sequence, long expectedSequence) {
        if (!active.request.getEvidenceId().equals(evidenceId) || !active.request.getRequestId().equals(requestId)
                || !active.request.getPlayerId().equals(playerId) || active.request.getType() != type
                || active.request.getCaptureScope() != scope || sequence != expectedSequence) {
            throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_UNAUTHORIZED, expectedSequence,
                    "evidence request binding or sequence mismatch");
        }
    }

    private void finishUnavailable(ActiveRequest active, EvidenceCollectionStatus status, long capturedAt) {
        if (status == EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            throw new ProtocolFailure(EvidenceErrorCode.EVIDENCE_ERROR_INVALID_TRANSFER, 1L,
                    "collected evidence requires a transfer");
        }
        appendAudit(active, ObservationOrigin.CLIENT_REPORTED, capturedAt, 0L, sha256Empty(),
                "memory://mcace/evidence/unavailable/" + active.request.getEvidenceId(), status, null);
        remove(active);
    }

    private void appendAudit(ActiveRequest active, ObservationOrigin origin, long capturedAt, long size,
                             byte[] sha256, String storageUri, EvidenceCollectionStatus status,
                             EvidenceBegin transferBegin) {
        int totalChunks = transferBegin == null ? 0 : transferBegin.getTotalChunks();
        int width = transferBegin == null ? 0 : transferBegin.getWidthPixels();
        int height = transferBegin == null ? 0 : transferBegin.getHeightPixels();
        byte[] merkle = transferBegin == null ? new byte[0] : transferBegin.getMerkleRootSha256().toByteArray();
        Instant captured = Instant.ofEpochMilli(Math.max(0L, capturedAt));
        try {
            auditSink.appendEvidence(new EvidenceMetadataDraft(
                    uuid(active.request.getEvidenceId()), active.session.playerId(), active.session.sessionId(),
                    active.request.getType(), origin, captured, size,
                    sha256, storageUri, active.operatorId));
        } catch (Exception ignored) {
            // Audit failure is never a risk, admission, or transport authority.
        }
        try {
            evidenceAuditSink.append(new EvidenceAuditRecord(
                    uuid(active.request.getEvidenceId()), active.session.playerId(), active.session.sessionId(),
                    active.request.getRequestId(), active.request.getCaseId(), active.request.getType(),
                    active.request.getCaptureScope(), status, captured, size, totalChunks, width, height,
                    sha256, merkle, storageUri, active.operatorId));
        } catch (RuntimeException ignored) {
            // A diagnostic sink cannot change transport, risk, or admission.
        }
    }

    private EvidenceIngressResult ack(
            ActiveRequest active, PacketType acknowledgedPacketType, EvidenceAckStatus status, long sequence,
            EvidenceIngressResult.Status result) {
        Optional<byte[]> frame = sign(PacketType.EVIDENCE_ACK, EvidenceAck.newBuilder()
                .setRequestId(active.request.getRequestId())
                .setEvidenceId(active.request.getEvidenceId())
                .setAcknowledgedPacketType(acknowledgedPacketType)
                .setStatus(status)
                .setTransportSequence(sequence)
                .build(), active.session.sessionId());
        return new EvidenceIngressResult(result, frame.map(List::of).orElseGet(List::of),
                frame.isEmpty() ? "evidence acknowledgement unavailable" : "");
    }

    private EvidenceIngressResult error(ActiveRequest active, PacketType packetType, EvidenceErrorCode code,
                                        long sequence, EvidenceIngressResult.Status status, String detail) {
        sequence = Math.max(1L, sequence);
        Optional<byte[]> frame = sign(PacketType.EVIDENCE_ERROR, EvidenceError.newBuilder()
                .setRequestId(active.request.getRequestId()).setEvidenceId(active.request.getEvidenceId())
                .setRejectedPacketType(packetType).setCode(code).setTransportSequence(sequence).build(),
                active.session.sessionId());
        return new EvidenceIngressResult(status, frame.map(List::of).orElseGet(List::of),
                frame.isEmpty() ? detail + "; response unavailable" : detail);
    }

    private EvidenceIngressResult reject(ActiveRequest active, PacketType packetType,
                                         EvidenceErrorCode code, long sequence, String detail) {
        EvidenceIngressResult result = error(active, packetType, code, sequence,
                switch (code) {
                    case EVIDENCE_ERROR_CODE_UNSPECIFIED, EVIDENCE_ERROR_INVALID_TRANSFER, EVIDENCE_ERROR_UNAUTHORIZED ->
                            EvidenceIngressResult.Status.REJECTED;
                    case EVIDENCE_ERROR_EXPIRED -> EvidenceIngressResult.Status.EXPIRED;
                    case EVIDENCE_ERROR_REPLAYED -> EvidenceIngressResult.Status.REPLAYED;
                    case EVIDENCE_ERROR_UNSUPPORTED_SCOPE -> EvidenceIngressResult.Status.UNSUPPORTED;
                    case EVIDENCE_ERROR_DECLINED -> EvidenceIngressResult.Status.COMPLETE;
                    default -> EvidenceIngressResult.Status.REJECTED;
                }, detail);
        remove(active);
        return result;
    }

    private Optional<byte[]> sign(PacketType packetType, com.google.protobuf.Message message, String sessionId) {
        try {
            return Optional.of(envelopeCodec.sign(packetType, sessionId, message.toByteArray(), serverSigningKey).toByteArray());
        } catch (EnvelopeException exception) {
            return Optional.empty();
        }
    }

    private void remove(ActiveRequest active) {
        requests.remove(active.request.getRequestId());
        requestByPlayer.remove(active.session.playerId(), active.request.getRequestId());
    }

    private String randomId() {
        byte[] bytes = new byte[18];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String requireOperator(String operatorId) {
        Objects.requireNonNull(operatorId, "operatorId");
        if (operatorId.isBlank() || operatorId.length() > 128) throw new IllegalArgumentException("invalid operator id");
        return operatorId;
    }

    private static long safeEpochMillis(Instant instant) {
        try { return instant.toEpochMilli(); }
        catch (ArithmeticException exception) { return Long.MAX_VALUE; }
    }

    private static UUID uuid(String value) {
        try { return UUID.fromString(value); }
        catch (IllegalArgumentException exception) { throw new IllegalStateException("evidence id is not UUID", exception); }
    }

    private static byte[] sha256Empty() {
        try { return MessageDigest.getInstance("SHA-256").digest(); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }

    private static byte[] join(List<byte[]> chunks, int length) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(length);
        for (byte[] chunk : chunks) output.writeBytes(chunk);
        return output.toByteArray();
    }

    private static final class ActiveRequest {
        private final AuthenticatedObservationSession session;
        private final EvidenceRequest request;
        private final String operatorId;
        private final NonceReplayGuard replayGuard;
        private ActiveTransfer transfer;
        private long nextSequence;

        private ActiveRequest(AuthenticatedObservationSession session, EvidenceRequest request,
                              String operatorId, NonceReplayGuard replayGuard) {
            this.session = session;
            this.request = request;
            this.operatorId = operatorId;
            this.replayGuard = replayGuard;
            this.nextSequence = 1L;
        }
    }

    private static final class ActiveTransfer {
        private final EvidenceBegin begin;
        private final List<byte[]> chunks = new ArrayList<>();
        private final List<byte[]> hashes = new ArrayList<>();
        private long bytes;

        private ActiveTransfer(EvidenceBegin begin) { this.begin = begin; }
    }

    private static final class ProtocolFailure extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        private final EvidenceErrorCode code;
        private final long sequence;

        private ProtocolFailure(EvidenceErrorCode code, long sequence, String message) {
            super(message);
            this.code = code;
            this.sequence = sequence;
        }
    }
}
