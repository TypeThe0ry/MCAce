package com.ellan.mcace.client.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
