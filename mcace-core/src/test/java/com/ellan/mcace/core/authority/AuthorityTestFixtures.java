package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.PacketType;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

final class AuthorityTestFixtures {
    static final Instant NOW = Instant.parse("2026-08-13T08:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    static final UUID GRANT = UUID.fromString("00000000-0000-4000-8000-000000000002");
    static final String PROXY_INSTANCE = "proxy-sg-1";
    static final String REGISTERED_BACKEND = "survival";
    static final String BACKEND_INSTANCE = "paper-sg-1";
    static final String SESSION = "authenticated-session-1";
    static final BackendAuthorityProfile AUTHORITY_PROFILE = new BackendAuthorityProfile(
            List.of(
                    new BackendAuthorityProfile.ProviderContract(
                            "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                    new BackendAuthorityProfile.ProviderContract(
                            "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
            2,
            Duration.ofSeconds(15),
            Duration.ofSeconds(30));
    static final String PROFILE = AUTHORITY_PROFILE.sha256();
    static final String OTHER_PROFILE = "cd".repeat(32);
    static final String GRANT_COMMITMENT = "ef".repeat(32);
    static final long ADMISSION_SEQUENCE = 41L;
    static final long OBSERVATION_SEQUENCE = 7L;

    private AuthorityTestFixtures() {
    }

    static KeyPair keyPair() throws Exception {
        return Ed25519Keys.generate(new SecureRandom());
    }

    static String fingerprint(KeyPair keys) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(keys.getPublic().getEncoded()));
    }

    static byte[] binding() {
        byte[] value = new byte[32];
        java.util.Arrays.fill(value, (byte) 0x5a);
        return value;
    }

    static NonceReplayGuard replayGuard() {
        return replayGuard(CLOCK);
    }

    static NonceReplayGuard replayGuard(Clock clock) {
        return new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
    }

    static BackendAuthorityPin pin(KeyPair keys) throws Exception {
        return pin(keys, AUTHORITY_PROFILE);
    }

    static BackendAuthorityPin pin(KeyPair keys, BackendAuthorityProfile... profiles)
            throws Exception {
        java.util.LinkedHashMap<String, BackendAuthorityProfile> byDigest = new java.util.LinkedHashMap<>();
        for (BackendAuthorityProfile profile : profiles) {
            byDigest.put(profile.sha256(), profile);
        }
        return new BackendAuthorityPin(
                REGISTERED_BACKEND,
                BACKEND_INSTANCE,
                fingerprint(keys),
                keys.getPublic(),
                byDigest);
    }

    static BackendAuthorityRegistry registry(KeyPair keys) throws Exception {
        BackendAuthorityPin pin = pin(keys);
        return new BackendAuthorityRegistry(Map.of(pin.registeredBackend(), pin));
    }

    static BackendAuthorityGrantCodec.GrantRequest grantRequest() {
        return new BackendAuthorityGrantCodec.GrantRequest(
                PROXY_INSTANCE,
                BACKEND_INSTANCE,
                PLAYER,
                SESSION,
                binding(),
                ADMISSION_SEQUENCE,
                1L,
                Duration.ofSeconds(20));
    }

    static BackendAuthorityGrantCodec.VerifiedGrant verifiedGrant() {
        return verifiedGrant(
                PLAYER, SESSION, BACKEND_INSTANCE, GRANT, GRANT_COMMITMENT, binding(),
                ADMISSION_SEQUENCE, NOW.minusSeconds(10), NOW.plusSeconds(20));
    }

    static BackendAuthorityGrantCodec.VerifiedGrant verifiedGrant(
            UUID player,
            String session,
            String backendInstance,
            UUID grantId,
            String commitment,
            byte[] physicalBinding,
            long admissionSequence,
            Instant issuedAt,
            Instant expiresAt) {
        return new BackendAuthorityGrantCodec.VerifiedGrant(
                grantId, PROXY_INSTANCE, backendInstance, player, session, physicalBinding,
                admissionSequence, 1L, issuedAt, expiresAt, new byte[32], commitment);
    }

    static ServerAuthorityObservationCodec.ProviderInput provider(
            String domain, String providerId) {
        return new ServerAuthorityObservationCodec.ProviderInput(
                domain,
                providerId,
                "1.0.0",
                "movement-stable",
                2,
                3,
                NOW.minusSeconds(10),
                NOW.minusSeconds(2));
    }

    static List<ServerAuthorityObservationCodec.ProviderInput> providers() {
        return List.of(
                provider("grim-domain", "grim"),
                provider("vulcan-domain", "vulcan"));
    }

    static ServerAuthorityObservationCodec.ObservationRequest observationRequest(KeyPair keys)
            throws Exception {
        return observationRequest(
                keys,
                BACKEND_INSTANCE,
                fingerprint(keys),
                PLAYER,
                SESSION,
                GRANT,
                GRANT_COMMITMENT,
                binding(),
                ADMISSION_SEQUENCE,
                OBSERVATION_SEQUENCE,
                NOW.minusSeconds(1),
                Duration.ofSeconds(20),
                PROFILE,
                providers());
    }

    static ServerAuthorityObservationCodec.ObservationRequest observationRequest(
            KeyPair keys,
            String backendInstance,
            String keyId,
            UUID player,
            String session,
            UUID grant,
            String grantCommitment,
            byte[] physicalBinding,
            long admissionSequence,
            long observationSequence,
            Instant observedAt,
            Duration lifetime,
            String profile,
            List<ServerAuthorityObservationCodec.ProviderInput> providers) {
        return new ServerAuthorityObservationCodec.ObservationRequest(
                backendInstance,
                keyId,
                player,
                session,
                grant,
                grantCommitment,
                physicalBinding,
                admissionSequence,
                observationSequence,
                observedAt,
                lifetime,
                profile,
                providers);
    }

    static byte[] signedPayload(
            PacketType type,
            String session,
            byte[] payload,
            KeyPair keys,
            Clock clock) throws Exception {
        EnvelopeCodec codec = new EnvelopeCodec(
                clock,
                new SecureRandom(),
                ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        return codec.sign(type, session, payload, keys.getPrivate()).toByteArray();
    }

    static byte[] appendBytesField(byte[] encoded, int fieldNumber, byte[] value)
            throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(encoded);
        CodedOutputStream coded = CodedOutputStream.newInstance(output);
        coded.writeByteArray(fieldNumber, value);
        coded.flush();
        return output.toByteArray();
    }

    static byte[] appendUInt32Field(byte[] encoded, int fieldNumber, int value)
            throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(encoded);
        CodedOutputStream coded = CodedOutputStream.newInstance(output);
        coded.writeUInt32(fieldNumber, value);
        coded.flush();
        return output.toByteArray();
    }
}
