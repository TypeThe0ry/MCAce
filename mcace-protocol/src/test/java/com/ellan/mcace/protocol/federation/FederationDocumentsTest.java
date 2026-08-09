package com.ellan.mcace.protocol.federation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.ClientFederationConsent;
import com.ellan.mcace.protocol.generated.FederationAssertion;
import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.FederationLocalClaim;
import com.ellan.mcace.protocol.generated.FederationPresentation;
import com.ellan.mcace.protocol.generated.FederationPresentationProof;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedFederationAssertion;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

final class FederationDocumentsTest {
    private static final long NOW = 1_800_000_000_000L;
    private static final String SOURCE = "network-a";
    private static final String TARGET = "network-b";
    private static final String PLAYER = "123e4567-e89b-12d3-a456-426614174000";
    private static final String SOURCE_SESSION = "source-session-1";
    private static final String TARGET_SESSION = "target-session-1";

    @Test
    void verifiesMinimalFourStepPresentationWithoutCreatingLocalTrustLevel() throws Exception {
        Fixture fixture = fixture();
        FederationDocuments.validateConsentRequestBindings(
                fixture.request(), SOURCE, TARGET, PLAYER, fixture.client().getPublic(),
                fixture.source().getPublic(), fixture.target().getPublic(), SOURCE_SESSION);
        assertEquals(fixture.consent(), FederationDocuments.parseConsentResponse(
                FederationDocuments.encodeConsentResponse(fixture.consent())));
        FederationGrant verifiedGrant = FederationDocuments.verifyGrant(
                FederationDocuments.encodeGrant(fixture.grant()), fixture.request(), fixture.client().getPublic(),
                fixture.source().getPublic(), fixture.clock(), Duration.ZERO);
        assertEquals(fixture.grant(), verifiedGrant);

        FederationVerification verified = verify(fixture, FederationDocuments.newReplayGuard(fixture.clock()));
        assertEquals(FederationLocalClaim.FEDERATION_SOURCE_LOCALLY_VERIFIED, verified.remoteClaim());
        assertEquals(SOURCE_SESSION, verified.sourceAuthenticatedSessionId());
        assertArrayEquals(keyId(fixture.client().getPublic()), verified.clientPublicKeySha256());
        assertArrayEquals(keyId(fixture.source().getPublic()), fixture.request().getSourceKeyIdSha256().toByteArray());
        assertArrayEquals(keyId(fixture.target().getPublic()), fixture.request().getTargetKeyIdSha256().toByteArray());

        for (String forbidden : Arrays.asList("trust_level", "risk_score", "reason_codes", "mods",
                "manifest", "evidence", "device", "ip_address")) {
            assertNull(FederationAssertion.getDescriptor().findFieldByName(forbidden));
        }
    }

    @Test
    void rejectsWrongAudienceWithoutConsumingReplayThenAcceptsValidPresentation() throws Exception {
        Fixture fixture = fixture();
        NonceReplayGuard replay = FederationDocuments.newReplayGuard(fixture.clock());
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, "other-network", PLAYER,
                TARGET_SESSION, fixture.challenge(), fixture.clock(), Duration.ZERO, replay));
        verify(fixture, replay);

        NonceReplayGuard playerReplay = FederationDocuments.newReplayGuard(fixture.clock());
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET,
                "00000000-0000-0000-0000-000000000002", TARGET_SESSION,
                fixture.challenge(), fixture.clock(), Duration.ZERO, playerReplay));
        verify(fixture, playerReplay);
    }

    @Test
    void rejectsCaptureForWrongTargetSessionOrChallengeWithoutConsumingReplay() throws Exception {
        Fixture fixture = fixture();
        NonceReplayGuard sessionReplay = FederationDocuments.newReplayGuard(fixture.clock());
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER,
                "attacker-session", fixture.challenge(), fixture.clock(), Duration.ZERO, sessionReplay));
        verify(fixture, sessionReplay);

        NonceReplayGuard challengeReplay = FederationDocuments.newReplayGuard(fixture.clock());
        byte[] wrongChallenge = fixture.challenge().clone();
        wrongChallenge[0] ^= 1;
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER,
                TARGET_SESSION, wrongChallenge, fixture.clock(), Duration.ZERO, challengeReplay));
        verify(fixture, challengeReplay);
    }

    @Test
    void rejectsReplayAfterFirstSuccessfulUse() throws Exception {
        Fixture fixture = fixture();
        NonceReplayGuard replay = FederationDocuments.newReplayGuard(fixture.clock());
        verify(fixture, replay);
        assertThrows(FederationException.class, () -> verify(fixture, replay));

        byte[] newChallenge = fixture.challenge().clone();
        newChallenge[0] ^= 1;
        FederationPresentation newSessionPresentation = FederationDocuments.presentation(
                fixture.grant(), fixture.client().getPrivate(), "target-session-2",
                newChallenge, fixture.clock());
        byte[] newSessionEncoded = FederationDocuments.encode(newSessionPresentation);
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                newSessionEncoded, fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER, "target-session-2",
                newChallenge, fixture.clock(), Duration.ZERO, replay));
    }

    @Test
    void rejectsExpiredPresentationAndStaleGrant() throws Exception {
        Fixture fixture = fixture();
        Clock expired = fixed(fixture.request().getExpiresAtEpochMs() + 1L);
        assertThrows(FederationException.class, () -> FederationDocuments.verifyGrant(
                FederationDocuments.encodeGrant(fixture.grant()), fixture.request(), fixture.client().getPublic(),
                fixture.source().getPublic(), expired, Duration.ZERO));
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER, TARGET_SESSION,
                fixture.challenge(), expired, Duration.ZERO, FederationDocuments.newReplayGuard(expired)));
    }

    @Test
    void rejectsTamperedProofWithoutConsumingReplay() throws Exception {
        Fixture fixture = fixture();
        byte[] signature = fixture.presentation().getPresentationProof().getClientSignature().toByteArray();
        signature[0] ^= 1;
        FederationPresentation tampered = fixture.presentation().toBuilder().setPresentationProof(
                fixture.presentation().getPresentationProof().toBuilder()
                        .setClientSignature(ByteString.copyFrom(signature))).build();
        NonceReplayGuard replay = FederationDocuments.newReplayGuard(fixture.clock());
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                FederationDocuments.encode(tampered), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER, TARGET_SESSION,
                fixture.challenge(), fixture.clock(), Duration.ZERO, replay));
        verify(fixture, replay);
    }

    @Test
    void rejectsWrongPinnedSourceTargetAndClientSessionKeys() throws Exception {
        Fixture fixture = fixture();
        KeyPair wrong = Ed25519Keys.generate(new SecureRandom());
        assertThrows(FederationException.class, () -> FederationDocuments.verifyGrant(
                FederationDocuments.encodeGrant(fixture.grant()), fixture.request(), fixture.client().getPublic(),
                wrong.getPublic(), fixture.clock(), Duration.ZERO));
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), wrong.getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER, TARGET_SESSION,
                fixture.challenge(), fixture.clock(), Duration.ZERO, FederationDocuments.newReplayGuard(fixture.clock())));
        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(wrong.getPublic()), SOURCE, TARGET, PLAYER, TARGET_SESSION,
                fixture.challenge(), fixture.clock(), Duration.ZERO, FederationDocuments.newReplayGuard(fixture.clock())));
    }

    @Test
    void rejectsMixedConsentAndAssertionUnknownClaimAndOversize() throws Exception {
        Fixture first = fixture();
        Fixture second = fixture();
        assertThrows(FederationException.class, () -> FederationDocuments.grant(
                first.consent(), second.signedAssertion(), first.client().getPublic()));

        FederationAssertion unknown = FederationAssertion.parseFrom(first.signedAssertion().getAssertion())
                .toBuilder().setLocalClaimValue(99).build();
        SignedFederationAssertion unknownSigned = first.signedAssertion().toBuilder()
                .setAssertion(unknown.toByteString()).build();
        assertThrows(FederationException.class, () -> FederationDocuments.grant(
                first.consent(), unknownSigned, first.client().getPublic()));

        assertThrows(FederationException.class, () -> FederationDocuments.verify(
                new byte[ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES + 1],
                first.source().getPublic(), first.target().getPublic(), keyId(first.client().getPublic()),
                SOURCE, TARGET, PLAYER, TARGET_SESSION, first.challenge(), first.clock(), Duration.ZERO,
                FederationDocuments.newReplayGuard(first.clock())));
    }

    @Test
    void consentSignatureAndSourceSignatureBindEveryField() throws Exception {
        Fixture fixture = fixture();
        ClientFederationConsent changedConsent = fixture.consent().toBuilder()
                .setExpiresAtEpochMs(fixture.consent().getExpiresAtEpochMs() - 1L).build();
        assertThrows(FederationException.class, () -> FederationDocuments.grant(
                changedConsent, fixture.signedAssertion(), fixture.client().getPublic()));

        byte[] sourceSignature = fixture.signedAssertion().getSignature().toByteArray();
        sourceSignature[0] ^= 1;
        FederationGrant tampered = fixture.grant().toBuilder().setSignedAssertion(
                fixture.signedAssertion().toBuilder().setSignature(ByteString.copyFrom(sourceSignature))).build();
        assertThrows(FederationException.class, () -> FederationDocuments.verifyGrant(
                FederationDocuments.encodeGrant(tampered), fixture.request(), fixture.client().getPublic(),
                fixture.source().getPublic(), fixture.clock(), Duration.ZERO));
    }

    @Test
    void enforcesFiveMinuteLifetimeBoundAndClockSkewBound() throws Exception {
        Fixture fixture = fixture();
        assertThrows(FederationException.class, () -> FederationDocuments.issueConsentRequest(
                SOURCE, TARGET, PLAYER, fixture.client().getPublic(), fixture.source().getPublic(),
                fixture.target().getPublic(), SOURCE_SESSION, "policy-v1", new byte[32], fixture.clock(),
                Duration.ofMinutes(5).plusMillis(1), new SecureRandom()));
        assertThrows(IllegalArgumentException.class, () -> FederationDocuments.newReplayGuard(
                fixture.clock(), ProtocolConstants.DEFAULT_CLOCK_SKEW.plusMillis(1)));
    }

    @Test
    void enforcesExactPacketDirections() throws Exception {
        FederationPacketDirections.require(PacketType.FEDERATION_CONSENT_REQUEST,
                FederationEndpoint.SOURCE_SERVER, FederationEndpoint.CLIENT);
        FederationPacketDirections.require(PacketType.FEDERATION_CONSENT_RESPONSE,
                FederationEndpoint.CLIENT, FederationEndpoint.SOURCE_SERVER);
        FederationPacketDirections.require(PacketType.FEDERATION_GRANT,
                FederationEndpoint.SOURCE_SERVER, FederationEndpoint.CLIENT);
        FederationPacketDirections.require(PacketType.FEDERATION_PRESENTATION,
                FederationEndpoint.CLIENT, FederationEndpoint.TARGET_SERVER);
        assertThrows(FederationException.class, () -> FederationPacketDirections.require(
                PacketType.FEDERATION_PRESENTATION, FederationEndpoint.SOURCE_SERVER,
                FederationEndpoint.TARGET_SERVER));
        assertThrows(FederationException.class, () -> FederationPacketDirections.require(
                PacketType.FEDERATION_GRANT, FederationEndpoint.CLIENT, FederationEndpoint.TARGET_SERVER));
    }

    private static FederationVerification verify(Fixture fixture, NonceReplayGuard replay) throws Exception {
        return FederationDocuments.verify(
                fixture.encoded(), fixture.source().getPublic(), fixture.target().getPublic(),
                keyId(fixture.client().getPublic()), SOURCE, TARGET, PLAYER, TARGET_SESSION,
                fixture.challenge(), fixture.clock(), Duration.ZERO, replay);
    }

    private static Fixture fixture() throws Exception {
        SecureRandom random = new SecureRandom();
        KeyPair client = Ed25519Keys.generate(random);
        KeyPair source = Ed25519Keys.generate(random);
        KeyPair target = Ed25519Keys.generate(random);
        Clock clock = fixed(NOW);
        FederationConsentRequest request = FederationDocuments.issueConsentRequest(
                SOURCE, TARGET, PLAYER, client.getPublic(), source.getPublic(), target.getPublic(),
                SOURCE_SESSION, "policy-v1", sha256("policy".getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                clock, Duration.ofMinutes(4), random);
        FederationConsentRequest parsed = FederationDocuments.parseConsentRequest(
                request.toByteArray(), clock, Duration.ZERO);
        ClientFederationConsent consent = FederationDocuments.signClientConsent(
                parsed, client.getPrivate(), client.getPublic(), clock, Duration.ZERO);
        SignedFederationAssertion signed = FederationDocuments.signAssertion(
                parsed, consent, client.getPublic(), source.getPrivate(), source.getPublic(), clock, Duration.ZERO);
        FederationGrant grant = FederationDocuments.grant(consent, signed, client.getPublic());
        byte[] challenge = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(challenge);
        FederationPresentation presentation = FederationDocuments.presentation(
                grant, client.getPrivate(), TARGET_SESSION, challenge, clock);
        return new Fixture(clock, client, source, target, parsed, consent, signed, grant, presentation,
                FederationDocuments.encode(presentation), challenge);
    }

    private static Clock fixed(long epochMs) {
        return Clock.fixed(Instant.ofEpochMilli(epochMs), ZoneOffset.UTC);
    }

    private static byte[] keyId(java.security.PublicKey publicKey) throws Exception {
        return sha256(publicKey.getEncoded());
    }

    private static byte[] sha256(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private record Fixture(
            Clock clock, KeyPair client, KeyPair source, KeyPair target, FederationConsentRequest request,
            ClientFederationConsent consent, SignedFederationAssertion signedAssertion, FederationGrant grant,
            FederationPresentation presentation, byte[] encoded, byte[] challenge) {
        private Fixture {
            encoded = encoded.clone();
            challenge = challenge.clone();
        }

        @Override public byte[] encoded() { return encoded.clone(); }
        @Override public byte[] challenge() { return challenge.clone(); }
    }
}
