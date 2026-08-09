package com.ellan.mcace.protocol;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.evidence.EvidenceRequestVerifier;
import com.ellan.mcace.protocol.evidence.EvidenceTransferReceiver;
import com.ellan.mcace.protocol.evidence.EvidenceTransferLimits;
import com.ellan.mcace.protocol.generated.BoundedPayloadBegin;
import com.ellan.mcace.protocol.generated.BoundedPayloadChunk;
import com.ellan.mcace.protocol.generated.BoundedPayloadCommit;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceAck;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceError;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceResponse;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferReceiver;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.Descriptors.Descriptor;
import com.google.protobuf.UnknownFieldSet;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.SplittableRandom;
import org.junit.jupiter.api.Test;

/** Fixed, finite wire corpus for v1 migration and fail-closed parser behavior. */
final class ProtocolCompatibilityCorpusTest {
    private static final long CORPUS_SEED = 0x4D434143455F4556L;
    private static final long NOW = 1_800_000_000_000L;
    private static final String SESSION_ID = "compat-session-1";
    private static final String PLAYER_ID = "00000000-0000-0000-0000-000000000001";

    @Test
    void packetTypeNumbersOneThroughSixteenAreWireLocked() {
        PacketType[] types = {
                PacketType.SERVER_HELLO, PacketType.CLIENT_HELLO, PacketType.AUTH_REQUEST,
                PacketType.AUTH_RESULT, PacketType.HEARTBEAT, PacketType.EVIDENCE_REQUEST,
                PacketType.EVIDENCE_RESPONSE, PacketType.ADMISSION_UPDATE, PacketType.EVIDENCE_BEGIN,
                PacketType.EVIDENCE_CHUNK, PacketType.EVIDENCE_COMMIT, PacketType.PAYLOAD_BEGIN,
                PacketType.PAYLOAD_CHUNK, PacketType.PAYLOAD_COMMIT, PacketType.EVIDENCE_ACK,
                PacketType.EVIDENCE_ERROR
        };
        for (int index = 0; index < types.length; index++) {
            assertEquals(index + 1, types[index].getNumber(), "PacketType wire value changed at index " + index);
        }
        assertEquals(PacketType.PACKET_TYPE_UNSPECIFIED, PacketType.forNumber(0));
        assertEquals(PacketType.FEDERATION_CONSENT_REQUEST, PacketType.forNumber(17));
        assertEquals(PacketType.FEDERATION_CONSENT_RESPONSE, PacketType.forNumber(18));
        assertEquals(PacketType.FEDERATION_GRANT, PacketType.forNumber(19));
        assertEquals(PacketType.FEDERATION_PRESENTATION, PacketType.forNumber(20));
        assertEquals(null, PacketType.forNumber(21));
    }

    @Test
    void envelopeAndEvidenceFieldNumbersAreWireLocked() {
        assertFields(EnvelopeHeader.getDescriptor(),
                "protocol_version", 1, "packet_type", 2, "session_id", 3,
                "timestamp_epoch_ms", 4, "nonce", 5, "payload_length", 6,
                "checksum_crc32c", 7);
        assertFields(SignedEnvelope.getDescriptor(), "header", 1, "payload", 2, "signature", 3);
        assertFields(EvidenceRequest.getDescriptor(),
                "evidence_id", 1, "type", 2, "allowed_relative_paths", 3, "expires_at_epoch_ms", 4,
                "capture_scope", 5, "case_id", 6, "request_id", 7, "player_id", 8,
                "raw_content_retained", 9, "retention_seconds", 10, "retention_policy_id", 11,
                "retention_purpose", 12);
        assertFields(EvidenceResponse.getDescriptor(),
                "evidence_id", 1, "type", 2, "captured_at_epoch_ms", 3, "content_sha256", 4,
                "content", 5, "collection_status", 6, "capture_scope", 7,
                "collection_status_code", 8, "request_id", 9, "player_id", 10);
        assertFields(EvidenceBegin.getDescriptor(),
                "evidence_id", 1, "type", 2, "capture_scope", 3, "collection_status", 4,
                "captured_at_epoch_ms", 5, "total_bytes", 6, "total_chunks", 7,
                "width_pixels", 8, "height_pixels", 9, "content_sha256", 10,
                "merkle_root_sha256", 11, "request_id", 12, "player_id", 13,
                "transport_sequence", 14);
        assertFields(EvidenceChunk.getDescriptor(),
                "evidence_id", 1, "chunk_index", 2, "content", 3, "chunk_sha256", 4,
                "request_id", 5, "player_id", 6, "transport_sequence", 7);
        assertFields(EvidenceCommit.getDescriptor(),
                "evidence_id", 1, "total_bytes", 2, "total_chunks", 3, "content_sha256", 4,
                "merkle_root_sha256", 5, "collection_status", 6, "request_id", 7,
                "player_id", 8, "transport_sequence", 9);
        assertFields(EvidenceAck.getDescriptor(),
                "request_id", 1, "evidence_id", 2, "acknowledged_packet_type", 3,
                "status", 4, "transport_sequence", 5);
        assertFields(EvidenceError.getDescriptor(),
                "request_id", 1, "evidence_id", 2, "rejected_packet_type", 3,
                "code", 4, "transport_sequence", 5);
        assertFields(BoundedPayloadBegin.getDescriptor(),
                "transfer_id", 1, "payload_kind", 2, "transport_sequence", 3,
                "manifest_root_sha256", 4, "total_bytes", 5, "total_chunks", 6,
                "content_sha256", 7, "merkle_root_sha256", 8);
        assertFields(BoundedPayloadChunk.getDescriptor(),
                "transfer_id", 1, "payload_kind", 2, "transport_sequence", 3,
                "chunk_index", 4, "content", 5, "chunk_sha256", 6);
        assertFields(BoundedPayloadCommit.getDescriptor(),
                "transfer_id", 1, "payload_kind", 2, "transport_sequence", 3,
                "total_bytes", 4, "total_chunks", 5, "content_sha256", 6,
                "merkle_root_sha256", 7);
    }

    @Test
    void legacyEvidenceRequestWithoutFieldsNineThroughTwelveIsNoRetentionAndVerifiable() throws Exception {
        Fixture fixture = fixture();
        EvidenceRequest legacy = request("legacy-request");
        byte[] frame = fixture.codec().sign(PacketType.EVIDENCE_REQUEST, SESSION_ID,
                legacy.toByteArray(), fixture.server().getPrivate()).toByteArray();

        EvidenceRequestVerifier.VerifiedRequest verified = assertDoesNotThrow(() ->
                new EvidenceRequestVerifier(fixture.clock()).accept(
                        frame, fixture.codec(), fixture.server().getPublic(), replay(fixture),
                        SESSION_ID, PLAYER_ID));
        assertFalse(verified.request().getRawContentRetained());
        assertEquals(0, verified.request().getRetentionSeconds());
        assertTrue(verified.request().getRetentionPolicyId().isEmpty());
        assertTrue(verified.request().getRetentionPurpose().isEmpty());
        EvidenceTransferLimits.validateRequest(verified.request(), NOW);
    }

    @Test
    void strippingRetentionFieldsCannotUpgradeARequestOrPreserveOldSignedAuthorization() throws Exception {
        Fixture fixture = fixture();
        EvidenceRequest retained = request("retained-request").toBuilder()
                .setRawContentRetained(true)
                .setRetentionSeconds(3600)
                .setRetentionPolicyId("case-review-v1")
                .setRetentionPurpose("review consented game-render evidence")
                .build();
        EvidenceRequest stripped = retained.toBuilder()
                .clearRawContentRetained()
                .clearRetentionSeconds()
                .clearRetentionPolicyId()
                .clearRetentionPurpose()
                .build();

        assertTrue(retained.getRawContentRetained());
        assertFalse(stripped.getRawContentRetained());
        assertEquals(0, stripped.getRetentionSeconds());
        EvidenceTransferLimits.validateRequest(stripped, NOW);

        SignedEnvelope original = fixture.codec().sign(PacketType.EVIDENCE_REQUEST, SESSION_ID,
                retained.toByteArray(), fixture.server().getPrivate());
        SignedEnvelope forwardedWithOldSignature = original.toBuilder()
                .setPayload(ByteString.copyFrom(stripped.toByteArray())).build();
        assertThrows(EnvelopeException.class, () -> new EvidenceRequestVerifier(fixture.clock()).accept(
                forwardedWithOldSignature.toByteArray(), fixture.codec(), fixture.server().getPublic(),
                replay(fixture), SESSION_ID, PLAYER_ID));
    }

    @Test
    void finiteMalformedCorpusRejectsAndLeavesAFollowingLegalRequestUsable() throws Exception {
        Fixture fixture = fixture();
        EvidenceRequest badRequest = request("corpus-bad");
        byte[] validFrame = fixture.codec().sign(PacketType.EVIDENCE_REQUEST, SESSION_ID,
                badRequest.toByteArray(), fixture.server().getPrivate()).toByteArray();
        SplittableRandom random = new SplittableRandom(CORPUS_SEED);
        byte[] varintBomb = new byte[32];
        varintBomb[0] = 0x0A;
        Arrays.fill(varintBomb, 1, varintBomb.length, (byte) 0x80);
        varintBomb[varintBomb.length - 1] = 0;

        List<byte[]> corpus = List.of(
                new byte[] {0x01},
                Arrays.copyOf(validFrame, validFrame.length - 1),
                new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1],
                varintBomb,
                withHeader(validFrame, header -> header.setProtocolVersion(0)),
                withHeader(validFrame, header -> header.setProtocolVersion(2)),
                withHeader(validFrame, header -> header.setProtocolVersion(Integer.MIN_VALUE)),
                withHeader(validFrame, header -> header.setPacketTypeValue(99)),
                withHeader(validFrame, header -> header.setTimestampEpochMs(Long.MIN_VALUE)),
                withHeader(validFrame, header -> header.setTimestampEpochMs(Long.MAX_VALUE)),
                withHeader(validFrame, header -> header.clearNonce()),
                withHeader(validFrame, header -> header.setNonce(ByteString.copyFrom(new byte[33]))),
                signedUnknownPayload(fixture, badRequest, random.nextLong()),
                signedSemanticallyInvalidPayload(fixture));

        for (int index = 0; index < corpus.size(); index++) {
            assertRejectedThenLegalRequest(fixture, corpus.get(index), index);
        }
    }

    @Test
    void unknownPacketEnumIsRejectedBeforeItCanBeTreatedAsAuthenticated() throws Exception {
        Fixture fixture = fixture();
        byte[] valid = fixture.codec().sign(PacketType.HEARTBEAT, SESSION_ID,
                new byte[] {1}, fixture.server().getPrivate()).toByteArray();
        byte[] unknown = withHeader(valid, header -> header.setPacketTypeValue(0x7FFF));
        SignedEnvelope parsed = fixture.codec().parse(unknown);
        assertEquals(PacketType.UNRECOGNIZED, parsed.getHeader().getPacketType());
        assertThrows(EnvelopeException.class, () -> fixture.codec().verify(parsed,
                fixture.server().getPublic(), replay(fixture)));
    }

    @Test
    void unknownSignedEnvelopeAndHeaderFieldsAreRejected() throws Exception {
        Fixture fixture = fixture();
        SignedEnvelope valid = fixture.codec().sign(PacketType.HEARTBEAT, SESSION_ID,
                new byte[] {1}, fixture.server().getPrivate());
        UnknownFieldSet unknown = UnknownFieldSet.newBuilder()
                .addField(1000, UnknownFieldSet.Field.newBuilder().addVarint(1).build())
                .build();
        SignedEnvelope outerUnknown = valid.toBuilder().setUnknownFields(unknown).build();
        SignedEnvelope headerUnknown = valid.toBuilder().setHeader(
                valid.getHeader().toBuilder().setUnknownFields(unknown).build()).build();
        assertThrows(EnvelopeException.class, () -> fixture.codec().verify(
                outerUnknown, fixture.server().getPublic(), replay(fixture)));
        assertThrows(EnvelopeException.class, () -> fixture.codec().verify(
                headerUnknown, fixture.server().getPublic(), replay(fixture)));
    }

    @Test
    void duplicateOrReorderedFragmentsAreRejectedAndReleaseTheirTransferSlots() throws Exception {
        Clock clock = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
        byte[] content = {7};
        byte[] hash = sha256(content);

        BoundedPayloadTransferReceiver bounded = new BoundedPayloadTransferReceiver(
                SESSION_ID, clock, Duration.ofMinutes(1));
        bounded.acceptVerified(unsignedEnvelope(PacketType.PAYLOAD_BEGIN,
                BoundedPayloadBegin.newBuilder().setTransferId("bounded-a")
                        .setPayloadKind(BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION)
                        .setTransportSequence(1).setManifestRootSha256(ByteString.copyFrom(hash))
                        .setTotalBytes(1).setTotalChunks(1).setContentSha256(ByteString.copyFrom(hash))
                        .setMerkleRootSha256(ByteString.copyFrom(hash)).build(), SESSION_ID));
        assertThrows(BoundedPayloadException.class, () -> bounded.acceptVerified(unsignedEnvelope(
                PacketType.PAYLOAD_CHUNK,
                BoundedPayloadChunk.newBuilder().setTransferId("bounded-a")
                        .setPayloadKind(BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION)
                        .setTransportSequence(1).setChunkIndex(0).setContent(ByteString.copyFrom(content))
                        .setChunkSha256(ByteString.copyFrom(hash)).build(), SESSION_ID)));
        assertDoesNotThrow(() -> bounded.acceptVerified(unsignedEnvelope(PacketType.PAYLOAD_BEGIN,
                BoundedPayloadBegin.newBuilder().setTransferId("bounded-b")
                        .setPayloadKind(BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION)
                        .setTransportSequence(1).setManifestRootSha256(ByteString.copyFrom(hash))
                        .setTotalBytes(1).setTotalChunks(1).setContentSha256(ByteString.copyFrom(hash))
                        .setMerkleRootSha256(ByteString.copyFrom(hash)).build(), SESSION_ID)));

        EvidenceRequest request = request("duplicate-evidence");
        EvidenceTransferReceiver evidence = new EvidenceTransferReceiver(SESSION_ID, request, clock);
        EvidenceBegin begin = EvidenceBegin.newBuilder().setEvidenceId(request.getEvidenceId())
                .setType(EvidenceType.SCREENSHOT).setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setCapturedAtEpochMs(NOW).setTotalBytes(1).setTotalChunks(1)
                .setWidthPixels(1).setHeightPixels(1).setContentSha256(ByteString.copyFrom(hash))
                .setMerkleRootSha256(ByteString.copyFrom(hash)).setRequestId(request.getRequestId())
                .setPlayerId(PLAYER_ID).setTransportSequence(1).build();
        evidence.acceptVerified(unsignedEnvelope(PacketType.EVIDENCE_BEGIN, begin, SESSION_ID));
        EvidenceChunk duplicateSequence = EvidenceChunk.newBuilder().setEvidenceId(request.getEvidenceId())
                .setChunkIndex(0).setContent(ByteString.copyFrom(content)).setChunkSha256(ByteString.copyFrom(hash))
                .setRequestId(request.getRequestId()).setPlayerId(PLAYER_ID).setTransportSequence(1).build();
        assertThrows(BoundedPayloadException.class, () -> evidence.acceptVerified(
                unsignedEnvelope(PacketType.EVIDENCE_CHUNK, duplicateSequence, SESSION_ID)));
        assertDoesNotThrow(() -> evidence.acceptVerified(unsignedEnvelope(
                PacketType.EVIDENCE_BEGIN, begin, SESSION_ID)));
    }

    private static void assertRejectedThenLegalRequest(Fixture fixture, byte[] rejected, int index)
            throws Exception {
        EvidenceRequestVerifier verifier = new EvidenceRequestVerifier(fixture.clock());
        // Capacity one makes semantic rejection observable: an invalid signed payload must not
        // consume the only shared replay slot needed by the following legal request.
        NonceReplayGuard replay = new NonceReplayGuard(fixture.clock(), Duration.ofMinutes(5), 1, 1);
        assertThrows(EnvelopeException.class, () -> verifier.accept(
                rejected, fixture.codec(), fixture.server().getPublic(), replay,
                SESSION_ID, PLAYER_ID), "corpus case " + index + " unexpectedly accepted");

        EvidenceRequest legal = request("recovered-" + index);
        byte[] legalFrame = fixture.codec().sign(PacketType.EVIDENCE_REQUEST, SESSION_ID,
                legal.toByteArray(), fixture.server().getPrivate()).toByteArray();
        assertDoesNotThrow(() -> verifier.accept(legalFrame, fixture.codec(), fixture.server().getPublic(),
                replay, SESSION_ID, PLAYER_ID), "legal request did not recover after corpus case " + index);
    }

    private static byte[] signedUnknownPayload(Fixture fixture, EvidenceRequest request, long seed)
            throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(request.toByteArray());
        CodedOutputStream coded = CodedOutputStream.newInstance(output);
        coded.writeUInt64(1000, seed & Long.MAX_VALUE);
        coded.writeBytes(1001, ByteString.copyFrom(new byte[] {0x11, 0x22, 0x33}));
        coded.flush();
        return fixture.codec().sign(PacketType.EVIDENCE_REQUEST, SESSION_ID,
                output.toByteArray(), fixture.server().getPrivate()).toByteArray();
    }

    private static byte[] signedSemanticallyInvalidPayload(Fixture fixture) throws Exception {
        EvidenceRequest invalid = request("invalid-retention").toBuilder().setRetentionSeconds(1).build();
        return fixture.codec().sign(PacketType.EVIDENCE_REQUEST, SESSION_ID,
                invalid.toByteArray(), fixture.server().getPrivate()).toByteArray();
    }

    private static SignedEnvelope unsignedEnvelope(PacketType type, com.google.protobuf.Message payload,
            String sessionId) {
        return SignedEnvelope.newBuilder().setHeader(EnvelopeHeader.newBuilder()
                .setProtocolVersion(ProtocolConstants.CURRENT_VERSION).setPacketType(type)
                .setSessionId(sessionId)).setPayload(ByteString.copyFrom(payload.toByteArray())).build();
    }

    private static byte[] sha256(byte[] content) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(content);
    }

    private static byte[] withHeader(byte[] encoded, java.util.function.UnaryOperator<EnvelopeHeader.Builder> change)
            throws Exception {
        SignedEnvelope envelope = SignedEnvelope.parseFrom(encoded);
        EnvelopeHeader.Builder header = envelope.getHeader().toBuilder();
        return envelope.toBuilder().setHeader(change.apply(header).build()).build().toByteArray();
    }

    private static EvidenceRequest request(String requestId) {
        return EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-" + requestId)
                .setType(EvidenceType.SCREENSHOT)
                .setExpiresAtEpochMs(NOW + 60_000L)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setCaseId("case-compat")
                .setRequestId(requestId)
                .setPlayerId(PLAYER_ID)
                .build();
    }

    private static NonceReplayGuard replay(Fixture fixture) {
        return new NonceReplayGuard(fixture.clock(), Duration.ofMinutes(5));
    }

    private static Fixture fixture() throws Exception {
        Clock clock = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(CORPUS_SEED);
        KeyPair keys = Ed25519Keys.generate(random);
        EnvelopeCodec codec = new EnvelopeCodec(clock, random,
                ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        return new Fixture(clock, codec, keys);
    }

    private static void assertFields(Descriptor descriptor, Object... pairs) {
        assertEquals(0, pairs.length % 2, "field lock must contain name/number pairs");
        for (int index = 0; index < pairs.length; index += 2) {
            String name = (String) pairs[index];
            int expected = (Integer) pairs[index + 1];
            assertNotNull(descriptor.findFieldByName(name), descriptor.getFullName() + "." + name);
            assertEquals(expected, descriptor.findFieldByName(name).getNumber(),
                    descriptor.getFullName() + "." + name);
        }
    }

    private record Fixture(Clock clock, EnvelopeCodec codec, KeyPair server) { }
}
