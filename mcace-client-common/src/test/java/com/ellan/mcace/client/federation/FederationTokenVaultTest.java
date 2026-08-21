package com.ellan.mcace.client.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.federation.FederationDocuments;
import com.ellan.mcace.protocol.federation.FederationException;
import com.ellan.mcace.protocol.generated.ClientFederationConsent;
import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.LoaderType;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

final class FederationTokenVaultTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC);
    private static final UUID PLAYER = UUID.fromString("11111111-2222-3333-4444-555555555555");

    @Test
    void preparesOnlyOnceThenBurnsOnSuccessfulSend() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair sourceClient = key();
        KeyPair source = key();
        KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(2, monotonic::get);
        vault.store(grant(sourceClient, source, target), sourceClient, PLAYER, "source-session", CLOCK);

        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.1", "build",
                LoaderType.FABRIC, target.getPublic(), CLOCK, new SecureRandom()).isPresent());
        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation("target", PLAYER,
                "target-session", new byte[32], CLOCK).orElseThrow();
        assertTrue(vault.commit(prepared));
        assertEquals(0, vault.size());
        assertTrue(vault.preparePresentation("target", PLAYER, "target-session", new byte[32], CLOCK).isEmpty());
    }

    @Test
    void localSendFailureReleasesButDoesNotConsume() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.1", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).isPresent());
        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation("target", PLAYER,
                "target-session", new byte[32], CLOCK).orElseThrow();
        vault.sendFailed(prepared);
        assertEquals(1, vault.size());
        assertTrue(vault.preparePresentation("target", PLAYER, "target-session", new byte[32], CLOCK).isPresent());
    }

    @Test
    void preparedCapabilityCarriesExactVisibleBindingsAndUsesObjectIdentity() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.1", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).isPresent());

        FederationTokenVault.PreparedPresentation first = vault.preparePresentation("target", PLAYER,
                "target-session", new byte[32], CLOCK).orElseThrow();
        assertEquals("source", first.sourceNetworkId());
        assertEquals("target", first.targetNetworkId());
        assertEquals(FederationDocuments.MINIMAL_DISCLOSURE, first.disclosure());
        assertEquals(CLOCK.millis(), first.issuedAtEpochMs());
        assertEquals(CLOCK.millis() + Duration.ofMinutes(2).toMillis(), first.expiresAtEpochMs());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(source.getPublic().getEncoded()),
                first.sourceKeyId());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(target.getPublic().getEncoded()),
                first.targetKeyId());
        assertTrue(vault.isReserved(first, CLOCK));

        vault.sendFailed(first);
        FederationTokenVault.PreparedPresentation second = vault.preparePresentation("target", PLAYER,
                "target-session", new byte[32], CLOCK).orElseThrow();
        assertFalse(vault.commit(first), "a stale callback must not burn a newer reservation");
        assertTrue(vault.isReserved(second, CLOCK));
        assertTrue(vault.decline(second));
        assertEquals(0, vault.size());
    }

    @Test
    void declineBurnsExactGrantAndExpiryFailsClosedBeforeSend() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.1", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).isPresent());
        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation("target", PLAYER,
                "target-session", new byte[32], CLOCK).orElseThrow();

        Clock afterExpiry = Clock.offset(CLOCK, Duration.ofMinutes(3));
        assertFalse(vault.isReserved(prepared, afterExpiry));
        assertEquals(0, vault.size());
        assertEquals(0, prepared.encoded().length);
        assertFalse(vault.decline(prepared));
    }

    @Test
    void expiryAndShutdownClearEveryInMemoryGrant() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        monotonic.addAndGet(Duration.ofMinutes(5).toMillis());
        assertEquals(0, vault.size());
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.close();
        assertEquals(0, vault.size());
    }

    @Test
    void sourceGrantSurvivesOneDisconnectAndSeedsOnlyOneExactTargetConnection() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);

        vault.onConnectionClosed();
        assertEquals(1, vault.size(), "one bounded source-to-target disconnect must retain the grant");
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.11", "build",
                LoaderType.FABRIC, target.getPublic(), CLOCK, new SecureRandom()).isPresent());
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.11", "build",
                LoaderType.FABRIC, target.getPublic(), CLOCK, new SecureRandom()).isEmpty(),
                "the same grant must never seed a second or stale target connection");

        vault.onConnectionClosed();
        assertEquals(0, vault.size(), "a claimed target disconnect must clear the retained key");
    }

    @Test
    void secondUnclaimedDisconnectAndPendingTargetPromptDoNotSurvive() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.onConnectionClosed();
        vault.onConnectionClosed();
        assertEquals(0, vault.size(), "an unrelated second disconnect must close the handoff window");

        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.onConnectionClosed();
        vault.newTargetHandshake("target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        FederationTokenVault.PreparedPresentation pending = vault.preparePresentation("target", PLAYER,
                "target-session", new byte[32], CLOCK).orElseThrow();
        vault.onConnectionClosed();
        assertEquals(0, vault.size());
        assertEquals(0, pending.encoded().length,
                "a target-side visible prompt capability must not survive its connection");
    }

    @Test
    void connectionClosePurgesExpiredSourceGrantAndExplicitAbortClearsTargetClaim() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        monotonic.addAndGet(Duration.ofMinutes(5).toMillis());
        vault.onConnectionClosed();
        assertEquals(0, vault.size());

        monotonic.set(1000L);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.onConnectionClosed();
        vault.newTargetHandshake("target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        vault.cancelTargetClaims();
        assertEquals(0, vault.size());
    }

    @Test
    void wallClockExpiryClearsBeforeTargetClaimAndWhileWaitingOnTitle() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        Clock afterExpiry = Clock.offset(CLOCK, Duration.ofMinutes(3));
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.11", "build",
                LoaderType.FABRIC, target.getPublic(), afterExpiry, new SecureRandom()).isEmpty());
        assertEquals(0, vault.size());

        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.discardExpired(afterExpiry);
        assertEquals(0, vault.size());
    }

    @Test
    void sameTargetIdWithDifferentPinnedKeyNeverReusesOrBurnsGrant() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        assertFalse(vault.newTargetHandshake("target", PLAYER, "client", "1.21.1", "build", LoaderType.FABRIC,
                key().getPublic(), CLOCK, new SecureRandom()).isPresent());
        assertEquals(1, vault.size(), "a provisional/wrong-key target must not erase consent");
        assertTrue(vault.newTargetHandshake("target", PLAYER, "client", "1.21.1", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).isPresent());
    }

    @Test
    void rejectsWrongSourceSessionAndNeverWritesFiles() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        assertThrows(FederationException.class, () -> vault.store(
                grant(client, source, target), client, PLAYER, "other-source-session", CLOCK));
        assertEquals(0, vault.size());
    }

    private static FederationGrant grant(KeyPair client, KeyPair source, KeyPair target) throws Exception {
        byte[] policy = new byte[32];
        FederationConsentRequest request = FederationDocuments.issueConsentRequest(
                "source", "target", PLAYER.toString(), client.getPublic(), source.getPublic(), target.getPublic(),
                "source-session", "policy", policy, CLOCK, Duration.ofMinutes(2), new SecureRandom());
        ClientFederationConsent consent = FederationDocuments.signClientConsent(
                request, client.getPrivate(), client.getPublic(), CLOCK, Duration.ZERO);
        return FederationDocuments.grant(consent, FederationDocuments.signAssertion(request, consent,
                client.getPublic(), source.getPrivate(), source.getPublic(), CLOCK, Duration.ZERO), client.getPublic());
    }

    private static KeyPair key() throws Exception { return Ed25519Keys.generate(new SecureRandom()); }
}
