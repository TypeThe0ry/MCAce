package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.BackendAuthorityGrant;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.UnknownFieldSet;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class BackendAuthorityGrantCodecTest {
    @Test
    void issuesAndVerifiesAnExactlyBoundGrantWithDefensiveCopies() throws Exception {
        KeyPair proxyKeys = AuthorityTestFixtures.keyPair();
        BackendAuthorityGrantCodec codec = codec(AuthorityTestFixtures.CLOCK);
        byte[] sourceBinding = AuthorityTestFixtures.binding();
        BackendAuthorityGrantCodec.GrantRequest request =
                new BackendAuthorityGrantCodec.GrantRequest(
                        AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        sourceBinding,
                        AuthorityTestFixtures.ADMISSION_SEQUENCE,
                        1L,
                        Duration.ofSeconds(20));

        BackendAuthorityGrantCodec.IssuedGrant issued =
                codec.issue(request, proxyKeys.getPrivate());
        byte[] expectedFrame = issued.frame();
        sourceBinding[0] ^= 0x7f;
        issued.frame()[0] ^= 0x7f;

        BackendAuthorityGrantCodec.VerifiedGrant verified = codec.verify(
                issued.frame(),
                AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                0L,
                proxyKeys.getPublic(),
                AuthorityTestFixtures.replayGuard());

        assertArrayEquals(expectedFrame, issued.frame());
        assertEquals(AuthorityTestFixtures.PROXY_INSTANCE, verified.proxyInstanceId());
        assertEquals(AuthorityTestFixtures.BACKEND_INSTANCE, verified.backendInstanceId());
        assertEquals(AuthorityTestFixtures.PLAYER, verified.playerId());
        assertEquals(AuthorityTestFixtures.SESSION, verified.authenticatedSessionId());
        assertEquals(AuthorityTestFixtures.ADMISSION_SEQUENCE,
                verified.admissionTransportSequence());
        assertEquals(1L, verified.grantSequence());
        assertEquals(64, verified.commitmentSha256().length());
        assertFalse(verified.grantId().equals(new UUID(0L, 0L)));
        assertEquals(32, verified.challenge().length);
        byte[] verifiedBinding = verified.physicalLoginBinding();
        verifiedBinding[0] ^= 0x7f;
        assertArrayEquals(AuthorityTestFixtures.binding(), verified.physicalLoginBinding());
        byte[] challenge = verified.challenge();
        byte originalChallenge = challenge[0];
        challenge[0] ^= 0x7f;
        assertEquals(originalChallenge, verified.challenge()[0]);
    }

    @Test
    void rejectsReplayAndEveryProxyDerivedLifecycleMismatch() throws Exception {
        KeyPair proxyKeys = AuthorityTestFixtures.keyPair();
        BackendAuthorityGrantCodec codec = codec(AuthorityTestFixtures.CLOCK);
        BackendAuthorityGrantCodec.IssuedGrant issued =
                codec.issue(AuthorityTestFixtures.grantRequest(), proxyKeys.getPrivate());
        NonceReplayGuard replay = AuthorityTestFixtures.replayGuard();

        codec.verify(
                issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys.getPublic(), replay);
        assertThrows(AuthorityProtocolException.class, () -> codec.verify(
                issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys.getPublic(), replay));

        assertRejected(codec, issued.frame(), "other-proxy", AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                0L, proxyKeys);
        assertRejected(codec, issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE, "other-backend",
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                0L, proxyKeys);
        assertRejected(codec, issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, UUID.randomUUID(),
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys);
        assertRejected(codec, issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                "other-session", AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys);
        byte[] wrongBinding = AuthorityTestFixtures.binding();
        wrongBinding[0] ^= 1;
        assertRejected(codec, issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, wrongBinding,
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys);
        assertRejected(codec, issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE + 1, 0L, proxyKeys);
        assertRejected(codec, issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 1L, proxyKeys);
    }

    @Test
    void verifiesBothEnvelopeAndPayloadSessionAndRejectsWrongKeyOrExpiry() throws Exception {
        KeyPair proxyKeys = AuthorityTestFixtures.keyPair();
        KeyPair wrongKeys = AuthorityTestFixtures.keyPair();
        BackendAuthorityGrantCodec signer = codec(AuthorityTestFixtures.CLOCK);
        BackendAuthorityGrantCodec.IssuedGrant issued =
                signer.issue(AuthorityTestFixtures.grantRequest(), proxyKeys.getPrivate());

        assertThrows(AuthorityProtocolException.class, () -> signer.verify(
                issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, wrongKeys.getPublic(),
                AuthorityTestFixtures.replayGuard()));

        SignedEnvelope original = SignedEnvelope.parseFrom(issued.frame());
        BackendAuthorityGrant wrongPayloadSession = BackendAuthorityGrant.parseFrom(original.getPayload())
                .toBuilder().setAuthenticatedSessionId("payload-session-mismatch").build();
        byte[] wrongPayloadFrame = AuthorityTestFixtures.signedPayload(
                PacketType.BACKEND_AUTHORITY_GRANT,
                AuthorityTestFixtures.SESSION,
                wrongPayloadSession.toByteArray(),
                proxyKeys,
                AuthorityTestFixtures.CLOCK);
        assertThrows(AuthorityProtocolException.class, () -> signer.verify(
                wrongPayloadFrame, AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys.getPublic(),
                AuthorityTestFixtures.replayGuard()));

        Clock expiredClock = Clock.fixed(
                AuthorityTestFixtures.NOW.plusSeconds(20), ZoneOffset.UTC);
        BackendAuthorityGrantCodec expiredVerifier = codec(expiredClock);
        assertThrows(AuthorityProtocolException.class, () -> expiredVerifier.verify(
                issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L, proxyKeys.getPublic(),
                AuthorityTestFixtures.replayGuard(expiredClock)));
    }

    @Test
    void signedUnknownPayloadFieldsAreRejectedAndConsumeTheirNonce() throws Exception {
        KeyPair proxyKeys = AuthorityTestFixtures.keyPair();
        BackendAuthorityGrantCodec codec = codec(AuthorityTestFixtures.CLOCK);
        BackendAuthorityGrantCodec.IssuedGrant issued =
                codec.issue(AuthorityTestFixtures.grantRequest(), proxyKeys.getPrivate());
        SignedEnvelope original = SignedEnvelope.parseFrom(issued.frame());
        UnknownFieldSet unknown = UnknownFieldSet.newBuilder()
                .addField(1000, UnknownFieldSet.Field.newBuilder().addVarint(1L).build())
                .build();
        BackendAuthorityGrant unknownGrant = BackendAuthorityGrant.parseFrom(original.getPayload())
                .toBuilder().setUnknownFields(unknown).build();
        byte[] frame = AuthorityTestFixtures.signedPayload(
                PacketType.BACKEND_AUTHORITY_GRANT,
                AuthorityTestFixtures.SESSION,
                unknownGrant.toByteArray(),
                proxyKeys,
                AuthorityTestFixtures.CLOCK);
        NonceReplayGuard replay = AuthorityTestFixtures.replayGuard();

        AuthorityProtocolException semantic = assertThrows(AuthorityProtocolException.class,
                () -> codec.verify(
                        frame, AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L,
                        proxyKeys.getPublic(), replay));
        assertEquals("unknown backend authority grant fields", semantic.getMessage());

        AuthorityProtocolException replayed = assertThrows(AuthorityProtocolException.class,
                () -> codec.verify(
                        frame, AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L,
                        proxyKeys.getPublic(), replay));
        assertEquals("invalid backend authority grant envelope", replayed.getMessage());
        assertNotNull(replayed.getCause());
        assertEquals("replayed nonce", replayed.getCause().getMessage());
    }

    @Test
    void rejectsOuterEncodingMalleabilityBeforeNonceAndSignedPayloadMalleabilityAfterNonce()
            throws Exception {
        KeyPair proxyKeys = AuthorityTestFixtures.keyPair();
        BackendAuthorityGrantCodec codec = codec(AuthorityTestFixtures.CLOCK);
        BackendAuthorityGrantCodec.IssuedGrant issued =
                codec.issue(AuthorityTestFixtures.grantRequest(), proxyKeys.getPrivate());
        SignedEnvelope canonicalEnvelope = SignedEnvelope.parseFrom(issued.frame());
        byte[] duplicateOuterSignature = AuthorityTestFixtures.appendBytesField(
                issued.frame(), 3, canonicalEnvelope.getSignature().toByteArray());
        NonceReplayGuard outerReplay = AuthorityTestFixtures.replayGuard();

        AuthorityProtocolException outerFailure = assertThrows(AuthorityProtocolException.class,
                () -> codec.verify(
                        duplicateOuterSignature, AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L,
                        proxyKeys.getPublic(), outerReplay));
        assertEquals("backend authority grant envelope is not canonically encoded",
                outerFailure.getMessage());
        codec.verify(
                issued.frame(), AuthorityTestFixtures.PROXY_INSTANCE,
                AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L,
                proxyKeys.getPublic(), outerReplay);

        byte[] duplicatePayloadSchema = AuthorityTestFixtures.appendUInt32Field(
                canonicalEnvelope.getPayload().toByteArray(), 1,
                ProtocolConstants.BACKEND_AUTHORITY_SCHEMA_VERSION);
        byte[] signedNonCanonicalPayload = AuthorityTestFixtures.signedPayload(
                PacketType.BACKEND_AUTHORITY_GRANT, AuthorityTestFixtures.SESSION,
                duplicatePayloadSchema, proxyKeys, AuthorityTestFixtures.CLOCK);
        NonceReplayGuard payloadReplay = AuthorityTestFixtures.replayGuard();
        AuthorityProtocolException payloadFailure = assertThrows(AuthorityProtocolException.class,
                () -> codec.verify(
                        signedNonCanonicalPayload, AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L,
                        proxyKeys.getPublic(), payloadReplay));
        assertEquals("backend authority grant is not canonically encoded",
                payloadFailure.getMessage());
        AuthorityProtocolException replayedPayload = assertThrows(AuthorityProtocolException.class,
                () -> codec.verify(
                        signedNonCanonicalPayload, AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE, 0L,
                        proxyKeys.getPublic(), payloadReplay));
        assertNotNull(replayedPayload.getCause());
        assertEquals("replayed nonce", replayedPayload.getCause().getMessage());
    }

    @Test
    void grantInputsAreBoundedAndDoNotAliasCallerArrays() {
        assertThrows(AuthorityProtocolException.class,
                () -> AuthorityProtocolSupport.requireFrameSize(new byte[0]));
        assertThrows(AuthorityProtocolException.class,
                () -> AuthorityProtocolSupport.requireFrameSize(
                        new byte[ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES + 1]));
        byte[] binding = AuthorityTestFixtures.binding();
        BackendAuthorityGrantCodec.GrantRequest request =
                new BackendAuthorityGrantCodec.GrantRequest(
                        AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        binding,
                        1L,
                        1L,
                        ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL);
        binding[0] ^= 1;
        assertNotEquals(binding[0], request.physicalLoginBinding()[0]);
        assertThrows(IllegalArgumentException.class, () ->
                new BackendAuthorityGrantCodec.GrantRequest(
                        AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        new byte[31], 1L, 1L, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () ->
                new BackendAuthorityGrantCodec.GrantRequest(
                        AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        AuthorityTestFixtures.binding(), 0L, 1L, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () ->
                new BackendAuthorityGrantCodec.GrantRequest(
                        AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        AuthorityTestFixtures.binding(), 1L, 1L,
                        ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL.plusMillis(1)));
        assertThrows(IllegalArgumentException.class, () ->
                new BackendAuthorityGrantCodec.GrantRequest(
                        AuthorityTestFixtures.PROXY_INSTANCE,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        AuthorityTestFixtures.binding(), 1L, 1L, Duration.ofNanos(1)));
    }

    private static BackendAuthorityGrantCodec codec(Clock clock) {
        return new BackendAuthorityGrantCodec(clock, new SecureRandom());
    }

    private static void assertRejected(
            BackendAuthorityGrantCodec codec,
            byte[] frame,
            String proxy,
            String backend,
            UUID player,
            String session,
            byte[] binding,
            long admissionSequence,
            long previousGrantSequence,
            KeyPair keys) {
        assertThrows(AuthorityProtocolException.class, () -> codec.verify(
                frame, proxy, backend, player, session, binding, admissionSequence,
                previousGrantSequence, keys.getPublic(), AuthorityTestFixtures.replayGuard()));
    }
}
