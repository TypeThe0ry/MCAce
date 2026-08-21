package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.ServerAuthorityObservation;
import com.ellan.mcace.protocol.generated.ServerAuthorityProviderSummary;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class ServerAuthorityObservationCodecTest {
    @Test
    void verifiesAnExactlyPinnedObservationAndDefensivelyCopiesAllMutableValues() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        byte[] sourceBinding = AuthorityTestFixtures.binding();
        ArrayList<ServerAuthorityObservationCodec.ProviderInput> sourceProviders =
                new ArrayList<>(AuthorityTestFixtures.providers());
        ServerAuthorityObservationCodec.ObservationRequest request =
                AuthorityTestFixtures.observationRequest(
                        backendKeys,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.fingerprint(backendKeys),
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        AuthorityTestFixtures.GRANT,
                        AuthorityTestFixtures.GRANT_COMMITMENT,
                        sourceBinding,
                        AuthorityTestFixtures.ADMISSION_SEQUENCE,
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(1),
                        Duration.ofSeconds(20),
                        AuthorityTestFixtures.PROFILE,
                        sourceProviders);
        ServerAuthorityObservationCodec.IssuedObservation issued =
                codec.sign(request, backendKeys.getPrivate());
        byte[] expectedFrame = issued.frame();
        sourceBinding[0] ^= 1;
        sourceProviders.clear();
        issued.frame()[0] ^= 1;

        VerifiedServerAuthorityObservation verified = verify(
                codec, issued.frame(), AuthorityTestFixtures.registry(backendKeys),
                AuthorityTestFixtures.replayGuard());

        assertArrayEquals(expectedFrame, issued.frame());
        assertEquals(issued.attestationId(), verified.attestationId());
        assertEquals(AuthorityTestFixtures.REGISTERED_BACKEND, verified.registeredBackend());
        assertEquals(AuthorityTestFixtures.BACKEND_INSTANCE, verified.backendInstanceId());
        assertEquals(AuthorityTestFixtures.fingerprint(backendKeys),
                verified.backendKeyIdSha256());
        assertEquals(AuthorityTestFixtures.PLAYER, verified.playerId());
        assertEquals(AuthorityTestFixtures.SESSION, verified.authenticatedSessionId());
        assertEquals(AuthorityTestFixtures.GRANT, verified.grantId());
        assertEquals(AuthorityTestFixtures.GRANT_COMMITMENT,
                verified.grantCommitmentSha256());
        assertEquals(AuthorityTestFixtures.ADMISSION_SEQUENCE,
                verified.admissionTransportSequence());
        assertEquals(AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                verified.observationSequence());
        assertEquals(AuthorityTestFixtures.PROFILE, verified.authorityProfileSha256());
        assertEquals(AuthorityProtocolSupport.sha256(issued.frame()), verified.signedFrameSha256());
        assertEquals(2, verified.providers().size());
        assertEquals(Set.of("grim-domain", "vulcan-domain"),
                Set.of(verified.providers().get(0).trustDomainId(),
                        verified.providers().get(1).trustDomainId()));
        byte[] returnedBinding = verified.physicalLoginBinding();
        returnedBinding[0] ^= 1;
        assertArrayEquals(AuthorityTestFixtures.binding(), verified.physicalLoginBinding());
        assertThrows(UnsupportedOperationException.class,
                () -> verified.providers().add(verified.providers().get(0)));
    }

    @Test
    void rejectsSubMillisecondObservationAndProviderTimesAtRequestConstruction()
            throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        assertThrows(IllegalArgumentException.class, () ->
                AuthorityTestFixtures.observationRequest(
                        backendKeys,
                        AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.fingerprint(backendKeys),
                        AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION,
                        AuthorityTestFixtures.GRANT,
                        AuthorityTestFixtures.GRANT_COMMITMENT,
                        AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE,
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(1).plusNanos(1),
                        Duration.ofSeconds(5),
                        AuthorityTestFixtures.PROFILE,
                        AuthorityTestFixtures.providers()));
        assertThrows(IllegalArgumentException.class, () ->
                new ServerAuthorityObservationCodec.ProviderInput(
                        "domain", "provider", "1.0.0", "stable-family", 1, 1,
                        AuthorityTestFixtures.NOW.minusSeconds(2).plusNanos(1),
                        AuthorityTestFixtures.NOW.minusSeconds(1)));
        assertThrows(IllegalArgumentException.class, () ->
                new ServerAuthorityObservationCodec.ProviderInput(
                        "domain", "provider", "1.0.0", "stable-family", 1, 1,
                        AuthorityTestFixtures.NOW.minusSeconds(2),
                        AuthorityTestFixtures.NOW.minusSeconds(1).plusNanos(1)));
    }

    @Test
    void rejectsReplayAndEveryProxyDerivedLifecycleMismatch() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        byte[] frame = codec.sign(
                AuthorityTestFixtures.observationRequest(backendKeys),
                backendKeys.getPrivate()).frame();
        BackendAuthorityRegistry registry = AuthorityTestFixtures.registry(backendKeys);
        NonceReplayGuard replay = AuthorityTestFixtures.replayGuard();

        verify(codec, frame, registry, replay);
        assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, frame, registry, replay));

        assertRejected(codec, frame, "other-backend", AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, Optional.empty(), registry);
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND, UUID.randomUUID(),
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, Optional.empty(), registry);
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, "other-session", AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, Optional.empty(), registry);
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION, UUID.randomUUID(),
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, Optional.empty(), registry);
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.GRANT, "00".repeat(32), AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, Optional.empty(), registry);
        byte[] wrongBinding = AuthorityTestFixtures.binding();
        wrongBinding[0] ^= 1;
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.GRANT, AuthorityTestFixtures.GRANT_COMMITMENT, wrongBinding,
                AuthorityTestFixtures.ADMISSION_SEQUENCE, Optional.empty(), registry);
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.GRANT, AuthorityTestFixtures.GRANT_COMMITMENT,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE + 1,
                Optional.empty(), registry);
        assertRejected(codec, frame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.GRANT, AuthorityTestFixtures.GRANT_COMMITMENT,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                Optional.of(new ServerAuthorityObservationCodec.PriorAcceptedObservation(
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(40),
                        AuthorityTestFixtures.NOW.minusSeconds(40))), registry);
    }

    @Test
    void rejectsWrongSigningKeyKeyIdBackendInstanceProfileAndDisabledRegistry() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        KeyPair attackerKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        ServerAuthorityObservationCodec.ObservationRequest validRequest =
                AuthorityTestFixtures.observationRequest(backendKeys);
        BackendAuthorityRegistry registry = AuthorityTestFixtures.registry(backendKeys);

        byte[] attackerSigned = codec.sign(validRequest, attackerKeys.getPrivate()).frame();
        assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, attackerSigned, registry, AuthorityTestFixtures.replayGuard()));

        byte[] validFrame = codec.sign(validRequest, backendKeys.getPrivate()).frame();
        ServerAuthorityObservation validWire = wire(validFrame);
        byte[] wrongKeyId = resign(validWire.toBuilder()
                .setBackendKeyIdSha256(ByteString.copyFrom(new byte[32])).build(), backendKeys);
        assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, wrongKeyId, registry, AuthorityTestFixtures.replayGuard()));
        byte[] wrongBackend = resign(validWire.toBuilder()
                .setBackendInstanceId("paper-other-instance").build(), backendKeys);
        assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, wrongBackend, registry, AuthorityTestFixtures.replayGuard()));
        byte[] wrongProfile = resign(validWire.toBuilder()
                .setAuthorityProfileSha256(ByteString.copyFrom(
                        HexFormat.of().parseHex(AuthorityTestFixtures.OTHER_PROFILE))).build(), backendKeys);
        assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, wrongProfile, registry, AuthorityTestFixtures.replayGuard()));

        assertThrows(AuthorityProtocolException.class, () -> verify(
                codec, validFrame, BackendAuthorityRegistry.disabled(),
                AuthorityTestFixtures.replayGuard()));
        BackendAuthorityPin unrelatedPin = new BackendAuthorityPin(
                "other-backend", AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(backendKeys), backendKeys.getPublic(),
                java.util.Map.of(
                        AuthorityTestFixtures.PROFILE, AuthorityTestFixtures.AUTHORITY_PROFILE));
        assertThrows(AuthorityProtocolException.class, () -> verify(
                codec, validFrame,
                new BackendAuthorityRegistry(java.util.Map.of("other-backend", unrelatedPin)),
                AuthorityTestFixtures.replayGuard()));
    }

    @Test
    void enforcesPinnedIndependentDomainQuorumAndRejectsDuplicateDomainsOrProviders()
            throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        byte[] validFrame = codec.sign(
                AuthorityTestFixtures.observationRequest(backendKeys),
                backendKeys.getPrivate()).frame();
        ServerAuthorityObservation validWire = wire(validFrame);

        BackendAuthorityProfile threeDomainProfile = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "native-domain", "native", "1.0.0", "movement-stable", 2)),
                3, Duration.ofSeconds(15), Duration.ofSeconds(30));
        BackendAuthorityPin threeDomainPin = AuthorityTestFixtures.pin(
                backendKeys, threeDomainProfile);
        BackendAuthorityRegistry threeDomainRegistry = new BackendAuthorityRegistry(
                java.util.Map.of(AuthorityTestFixtures.REGISTERED_BACKEND, threeDomainPin));
        byte[] twoOfThreeFrame = codec.sign(AuthorityTestFixtures.observationRequest(
                backendKeys, AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(backendKeys), AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                AuthorityTestFixtures.NOW.minusSeconds(1), Duration.ofSeconds(20),
                threeDomainProfile.sha256(), AuthorityTestFixtures.providers()),
                backendKeys.getPrivate()).frame();
        assertThrows(AuthorityProtocolException.class, () -> verify(
                codec, twoOfThreeFrame, threeDomainRegistry, AuthorityTestFixtures.replayGuard()));

        List<ServerAuthorityObservationCodec.ProviderInput> rogueProviders = List.of(
                AuthorityTestFixtures.provider("grim-domain", "grim"),
                AuthorityTestFixtures.provider("rogue-domain", "rogue"));
        byte[] rogueFrame = codec.sign(AuthorityTestFixtures.observationRequest(
                backendKeys, AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(backendKeys), AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                AuthorityTestFixtures.NOW.minusSeconds(1), Duration.ofSeconds(20),
                AuthorityTestFixtures.PROFILE, rogueProviders), backendKeys.getPrivate()).frame();
        assertThrows(AuthorityProtocolException.class, () -> verify(
                codec, rogueFrame, AuthorityTestFixtures.registry(backendKeys),
                AuthorityTestFixtures.replayGuard()));

        ServerAuthorityProviderSummary first = validWire.getProviders(0);
        ServerAuthorityProviderSummary second = validWire.getProviders(1);
        byte[] duplicateDomain = resign(validWire.toBuilder().setProviders(
                1, second.toBuilder().setTrustDomainId(first.getTrustDomainId()).build()).build(),
                backendKeys);
        assertThrows(AuthorityProtocolException.class, () -> verify(
                codec, duplicateDomain, AuthorityTestFixtures.registry(backendKeys),
                AuthorityTestFixtures.replayGuard()));
        byte[] duplicateProvider = resign(validWire.toBuilder().setProviders(
                1, second.toBuilder().setProviderId(first.getProviderId()).build()).build(),
                backendKeys);
        assertThrows(AuthorityProtocolException.class, () -> verify(
                codec, duplicateProvider, AuthorityTestFixtures.registry(backendKeys),
                AuthorityTestFixtures.replayGuard()));
        for (ServerAuthorityProviderSummary changed : List.of(
                first.toBuilder().setProviderVersion("2.0.0").build(),
                first.toBuilder().setStableCheckFamily("experimental").build(),
                first.toBuilder().setThreshold(first.getThreshold() + 1).build())) {
            byte[] driftedProfileContent = resign(
                    validWire.toBuilder().setProviders(0, changed).build(), backendKeys);
            assertThrows(AuthorityProtocolException.class, () -> verify(
                    codec, driftedProfileContent, AuthorityTestFixtures.registry(backendKeys),
                    AuthorityTestFixtures.replayGuard()));
        }

        assertThrows(IllegalArgumentException.class, () ->
                AuthorityTestFixtures.observationRequest(
                        backendKeys, AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.fingerprint(backendKeys), AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                        AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE,
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(1), Duration.ofSeconds(20),
                        AuthorityTestFixtures.PROFILE,
                        List.of(
                                AuthorityTestFixtures.provider("same-domain", "one"),
                                AuthorityTestFixtures.provider("same-domain", "two"))));
        assertThrows(IllegalArgumentException.class, () ->
                AuthorityTestFixtures.observationRequest(
                        backendKeys, AuthorityTestFixtures.BACKEND_INSTANCE,
                        AuthorityTestFixtures.fingerprint(backendKeys), AuthorityTestFixtures.PLAYER,
                        AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                        AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE,
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(1), Duration.ofSeconds(20),
                        AuthorityTestFixtures.PROFILE,
                        List.of(
                                AuthorityTestFixtures.provider("one-domain", "same-provider"),
                                AuthorityTestFixtures.provider("two-domain", "same-provider"))));
    }

    @Test
    void boundsProviderClaimsObservationAgeAndSourceExpiry() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec signer = codec(AuthorityTestFixtures.CLOCK);

        assertThrows(AuthorityProtocolException.class, () -> signer.sign(
                requestAt(backendKeys, AuthorityTestFixtures.NOW.plusMillis(1),
                        AuthorityTestFixtures.providers()),
                backendKeys.getPrivate()));
        java.time.Instant tooOld = AuthorityTestFixtures.NOW
                .minus(ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE)
                .minusMillis(1);
        assertThrows(AuthorityProtocolException.class, () -> signer.sign(
                requestAt(backendKeys, tooOld, providersEndingAt(tooOld)),
                backendKeys.getPrivate()));
        assertThrows(IllegalArgumentException.class, () ->
                new ServerAuthorityObservationCodec.ProviderInput(
                        "grim-domain", "grim", "1.0.0", "movement-stable",
                        3, 2, AuthorityTestFixtures.NOW.minusSeconds(5),
                        AuthorityTestFixtures.NOW.minusSeconds(1)));
        assertThrows(IllegalArgumentException.class, () ->
                new ServerAuthorityObservationCodec.ProviderInput(
                        "grim-domain", "grim", "1.0.0", "movement-stable",
                        1, 1,
                        AuthorityTestFixtures.NOW
                                .minus(ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE)
                                .minusMillis(1),
                        AuthorityTestFixtures.NOW));
        java.time.Instant observedRecently = AuthorityTestFixtures.NOW.minusSeconds(1);
        assertThrows(IllegalArgumentException.class, () -> requestAt(
                backendKeys,
                observedRecently,
                List.of(
                        new ServerAuthorityObservationCodec.ProviderInput(
                                "grim-domain", "grim", "1.0.0", "movement-stable",
                                1, 1, observedRecently.minusSeconds(45), observedRecently.minusSeconds(40)),
                        new ServerAuthorityObservationCodec.ProviderInput(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable",
                                1, 1, observedRecently.minusSeconds(45), observedRecently.minusSeconds(40)))));

        ArrayList<ServerAuthorityObservationCodec.ProviderInput> tooMany = new ArrayList<>();
        for (int index = 0; index <= ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS; index++) {
            tooMany.add(AuthorityTestFixtures.provider("domain-" + index, "provider-" + index));
        }
        assertThrows(IllegalArgumentException.class,
                () -> requestAt(backendKeys, AuthorityTestFixtures.NOW.minusSeconds(1), tooMany));

        byte[] frame = signer.sign(
                AuthorityTestFixtures.observationRequest(backendKeys),
                backendKeys.getPrivate()).frame();
        BackendAuthorityGrantCodec.VerifiedGrant expiredGrant =
                AuthorityTestFixtures.verifiedGrant(
                        AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                        AuthorityTestFixtures.BACKEND_INSTANCE, AuthorityTestFixtures.GRANT,
                        AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                        AuthorityTestFixtures.ADMISSION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(20),
                        AuthorityTestFixtures.NOW.minusMillis(1));
        assertThrows(AuthorityProtocolException.class, () -> signer.verify(
                frame, AuthorityTestFixtures.REGISTERED_BACKEND, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE, expiredGrant, Optional.empty(),
                AuthorityTestFixtures.registry(backendKeys), AuthorityTestFixtures.replayGuard()));
        Clock expiredClock = Clock.fixed(
                AuthorityTestFixtures.NOW.plusSeconds(20), ZoneOffset.UTC);
        ServerAuthorityObservationCodec expiredVerifier = codec(expiredClock);
        assertThrows(AuthorityProtocolException.class, () -> verify(
                expiredVerifier, frame, AuthorityTestFixtures.registry(backendKeys),
                AuthorityTestFixtures.replayGuard(expiredClock)));
    }

    @Test
    void enforcesOneProfileWindowAndCooldownFromAnAtomicPriorSnapshot() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        BackendAuthorityProfile tightWindow = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
                2, Duration.ofSeconds(5), Duration.ofSeconds(3));
        BackendAuthorityRegistry registry = new BackendAuthorityRegistry(java.util.Map.of(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.pin(backendKeys, tightWindow)));
        List<ServerAuthorityObservationCodec.ProviderInput> splitWindows = List.of(
                new ServerAuthorityObservationCodec.ProviderInput(
                        "grim-domain", "grim", "1.0.0", "movement-stable", 2, 3,
                        AuthorityTestFixtures.NOW.minusSeconds(9),
                        AuthorityTestFixtures.NOW.minusSeconds(7)),
                new ServerAuthorityObservationCodec.ProviderInput(
                        "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2, 3,
                        AuthorityTestFixtures.NOW.minusSeconds(4),
                        AuthorityTestFixtures.NOW.minusSeconds(2)));
        byte[] splitFrame = codec.sign(AuthorityTestFixtures.observationRequest(
                backendKeys, AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(backendKeys), AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                AuthorityTestFixtures.NOW.minusSeconds(1), Duration.ofSeconds(20),
                tightWindow.sha256(), splitWindows), backendKeys.getPrivate()).frame();
        assertThrows(AuthorityProtocolException.class, () -> codec.verify(
                splitFrame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.verifiedGrant(), Optional.empty(), registry,
                AuthorityTestFixtures.replayGuard()));

        List<ServerAuthorityObservationCodec.ProviderInput> commonWindow = List.of(
                new ServerAuthorityObservationCodec.ProviderInput(
                        "grim-domain", "grim", "1.0.0", "movement-stable", 2, 3,
                        AuthorityTestFixtures.NOW.minusSeconds(4),
                        AuthorityTestFixtures.NOW.minusSeconds(2)),
                new ServerAuthorityObservationCodec.ProviderInput(
                        "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2, 3,
                        AuthorityTestFixtures.NOW.minusSeconds(3),
                        AuthorityTestFixtures.NOW.minusSeconds(1)));
        byte[] commonFrame = codec.sign(AuthorityTestFixtures.observationRequest(
                backendKeys, AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(backendKeys), AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                AuthorityTestFixtures.NOW.minusSeconds(1), Duration.ofSeconds(20),
                tightWindow.sha256(), commonWindow), backendKeys.getPrivate()).frame();
        VerifiedServerAuthorityObservation first = codec.verify(
                commonFrame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.verifiedGrant(), Optional.empty(), registry,
                AuthorityTestFixtures.replayGuard());
        assertEquals(AuthorityTestFixtures.OBSERVATION_SEQUENCE, first.observationSequence());

        ServerAuthorityObservation commonWire = wire(commonFrame);
        byte[] tooSoon = resign(commonWire.toBuilder()
                .setAttestationId(UUID.randomUUID().toString())
                .setObservationSequence(AuthorityTestFixtures.OBSERVATION_SEQUENCE + 1)
                .build(), backendKeys);
        ServerAuthorityObservationCodec.PriorAcceptedObservation prior =
                new ServerAuthorityObservationCodec.PriorAcceptedObservation(
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                        AuthorityTestFixtures.NOW.minusSeconds(2),
                        AuthorityTestFixtures.NOW.minusSeconds(2));
        assertThrows(AuthorityProtocolException.class, () -> codec.verify(
                tooSoon, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.verifiedGrant(), Optional.of(prior), registry,
                AuthorityTestFixtures.replayGuard()));
        ServerAuthorityObservationCodec.PriorAcceptedObservation cooledDownPrior =
                new ServerAuthorityObservationCodec.PriorAcceptedObservation(
                        AuthorityTestFixtures.OBSERVATION_SEQUENCE - 1,
                        AuthorityTestFixtures.NOW.minusSeconds(5),
                        AuthorityTestFixtures.NOW.minusSeconds(4));
        VerifiedServerAuthorityObservation afterCooldown = codec.verify(
                commonFrame, AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.verifiedGrant(), Optional.of(cooledDownPrior), registry,
                AuthorityTestFixtures.replayGuard());
        assertEquals(AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                afterCooldown.observationSequence());
        assertEquals(afterCooldown.observationSequence(),
                ServerAuthorityObservationCodec.PriorAcceptedObservation.from(afterCooldown)
                        .observationSequence());
        assertThrows(IllegalArgumentException.class, () ->
                new ServerAuthorityObservationCodec.PriorAcceptedObservation(
                        0L, AuthorityTestFixtures.NOW, AuthorityTestFixtures.NOW));
    }

    @Test
    void rejectsOuterEncodingMalleabilityBeforeNonceAndSignedPayloadMalleabilityAfterNonce()
            throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        byte[] canonical = codec.sign(
                AuthorityTestFixtures.observationRequest(backendKeys),
                backendKeys.getPrivate()).frame();
        SignedEnvelope envelope = SignedEnvelope.parseFrom(canonical);
        byte[] duplicateOuterSignature = AuthorityTestFixtures.appendBytesField(
                canonical, 3, envelope.getSignature().toByteArray());
        NonceReplayGuard outerReplay = AuthorityTestFixtures.replayGuard();
        AuthorityProtocolException outerFailure = assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, duplicateOuterSignature,
                        AuthorityTestFixtures.registry(backendKeys), outerReplay));
        assertEquals("server authority observation envelope is not canonically encoded",
                outerFailure.getMessage());
        verify(codec, canonical, AuthorityTestFixtures.registry(backendKeys), outerReplay);

        byte[] duplicatePayloadSchema = AuthorityTestFixtures.appendUInt32Field(
                envelope.getPayload().toByteArray(), 1,
                ProtocolConstants.BACKEND_AUTHORITY_SCHEMA_VERSION);
        byte[] signedNonCanonicalPayload = AuthorityTestFixtures.signedPayload(
                PacketType.SERVER_AUTHORITY_OBSERVATION, AuthorityTestFixtures.SESSION,
                duplicatePayloadSchema, backendKeys, AuthorityTestFixtures.CLOCK);
        NonceReplayGuard payloadReplay = AuthorityTestFixtures.replayGuard();
        AuthorityProtocolException payloadFailure = assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, signedNonCanonicalPayload,
                        AuthorityTestFixtures.registry(backendKeys), payloadReplay));
        assertEquals("server authority observation is not canonically encoded",
                payloadFailure.getMessage());
        AuthorityProtocolException replayedPayload = assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, signedNonCanonicalPayload,
                        AuthorityTestFixtures.registry(backendKeys), payloadReplay));
        assertNotNull(replayedPayload.getCause());
        assertEquals("replayed nonce", replayedPayload.getCause().getMessage());
    }

    @Test
    void signedUnknownObservationAndProviderFieldsAreRejectedAndConsumeNonce() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = codec(AuthorityTestFixtures.CLOCK);
        byte[] validFrame = codec.sign(
                AuthorityTestFixtures.observationRequest(backendKeys),
                backendKeys.getPrivate()).frame();
        ServerAuthorityObservation validWire = wire(validFrame);
        UnknownFieldSet unknown = UnknownFieldSet.newBuilder()
                .addField(1000, UnknownFieldSet.Field.newBuilder().addVarint(1L).build())
                .build();
        byte[] unknownObservation = resign(
                validWire.toBuilder().setUnknownFields(unknown).build(), backendKeys);
        NonceReplayGuard replay = AuthorityTestFixtures.replayGuard();

        AuthorityProtocolException semantic = assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, unknownObservation,
                        AuthorityTestFixtures.registry(backendKeys), replay));
        assertEquals("unknown server authority observation fields", semantic.getMessage());
        AuthorityProtocolException replayed = assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, unknownObservation,
                        AuthorityTestFixtures.registry(backendKeys), replay));
        assertEquals("invalid server authority envelope", replayed.getMessage());
        assertNotNull(replayed.getCause());
        assertEquals("replayed nonce", replayed.getCause().getMessage());

        ServerAuthorityProviderSummary unknownProvider = validWire.getProviders(0).toBuilder()
                .setUnknownFields(unknown).build();
        byte[] nestedUnknown = resign(
                validWire.toBuilder().setProviders(0, unknownProvider).build(), backendKeys);
        AuthorityProtocolException nestedFailure = assertThrows(AuthorityProtocolException.class,
                () -> verify(codec, nestedUnknown,
                        AuthorityTestFixtures.registry(backendKeys),
                        AuthorityTestFixtures.replayGuard()));
        assertEquals("unknown server authority provider fields", nestedFailure.getMessage());
    }

    private static ServerAuthorityObservationCodec codec(Clock clock) {
        return new ServerAuthorityObservationCodec(clock, new SecureRandom());
    }

    private static VerifiedServerAuthorityObservation verify(
            ServerAuthorityObservationCodec codec,
            byte[] frame,
            BackendAuthorityRegistry registry,
            NonceReplayGuard replayGuard) throws AuthorityProtocolException {
        return codec.verify(
                frame,
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.verifiedGrant(),
                Optional.empty(),
                registry,
                replayGuard);
    }

    private static void assertRejected(
            ServerAuthorityObservationCodec codec,
            byte[] frame,
            String backend,
            UUID player,
            String session,
            UUID grant,
            String commitment,
            byte[] binding,
            long admissionSequence,
            Optional<ServerAuthorityObservationCodec.PriorAcceptedObservation> priorAccepted,
            BackendAuthorityRegistry registry) {
        BackendAuthorityGrantCodec.VerifiedGrant currentGrant =
                AuthorityTestFixtures.verifiedGrant(
                        player, session, AuthorityTestFixtures.BACKEND_INSTANCE, grant, commitment,
                        binding, admissionSequence, AuthorityTestFixtures.NOW.minusSeconds(10),
                        AuthorityTestFixtures.NOW.plusSeconds(20));
        assertThrows(AuthorityProtocolException.class, () -> codec.verify(
                frame, backend, player, session, binding, admissionSequence, currentGrant,
                priorAccepted, registry,
                AuthorityTestFixtures.replayGuard()));
    }

    private static ServerAuthorityObservation wire(byte[] frame) throws Exception {
        return ServerAuthorityObservation.parseFrom(SignedEnvelope.parseFrom(frame).getPayload());
    }

    private static byte[] resign(ServerAuthorityObservation observation, KeyPair keys)
            throws Exception {
        return AuthorityTestFixtures.signedPayload(
                PacketType.SERVER_AUTHORITY_OBSERVATION,
                AuthorityTestFixtures.SESSION,
                observation.toByteArray(),
                keys,
                AuthorityTestFixtures.CLOCK);
    }

    private static ServerAuthorityObservationCodec.ObservationRequest requestAt(
            KeyPair keys,
            java.time.Instant observedAt,
            List<ServerAuthorityObservationCodec.ProviderInput> providers) throws Exception {
        return AuthorityTestFixtures.observationRequest(
                keys,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(keys),
                AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.GRANT,
                AuthorityTestFixtures.GRANT_COMMITMENT,
                AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.OBSERVATION_SEQUENCE,
                observedAt,
                Duration.ofSeconds(20),
                AuthorityTestFixtures.PROFILE,
                providers);
    }

    private static List<ServerAuthorityObservationCodec.ProviderInput> providersEndingAt(
            java.time.Instant observedAt) {
        return List.of(
                new ServerAuthorityObservationCodec.ProviderInput(
                        "grim-domain", "grim", "1.0.0", "movement-stable", 1, 1,
                        observedAt.minusSeconds(2), observedAt.minusSeconds(1)),
                new ServerAuthorityObservationCodec.ProviderInput(
                        "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 1, 1,
                        observedAt.minusSeconds(2), observedAt.minusSeconds(1)));
    }
}
