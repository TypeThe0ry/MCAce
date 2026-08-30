package com.ellan.mcace.client.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.session.ClientHandshakeEngine;
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
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
        assertTrue(vault.commit(prepared, CLOCK).isPresent());
        assertEquals(0, vault.size());
        assertTrue(vault.preparePresentation("target", PLAYER, "target-session", new byte[32], CLOCK).isEmpty());
    }

    @Test
    void commitReceiptPromotesOnlyTheExactClaimAndOnlyOnce() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK,
                Set.of("options.txt"));
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.federationInherited(claim.engine(), 7L, claim);
        FederationTokenVault.TargetHandshakeClaim copiedMetadata =
                new FederationTokenVault.TargetHandshakeClaim(
                        claim.engine(), claim.approvedExplicitFiles(), claim.assertionId(),
                        claim.targetNetworkId(), claim.expiresAtEpochMs(),
                        claim.monotonicDeadlineMillis());
        ConnectionEnablementAuthorization copiedAuthorization =
                ConnectionEnablementAuthorization.federationInherited(
                        claim.engine(), 7L, copiedMetadata);
        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation(
                "target", PLAYER, "target-session", new byte[32], CLOCK).orElseThrow();
        FederationTokenVault.PresentationCommitReceipt receipt =
                vault.commit(prepared, CLOCK).orElseThrow();

        assertFalse(copiedAuthorization.promoteAfterPresentationCommit(receipt));
        assertTrue(copiedAuthorization.isInheritedProvisional());
        assertTrue(authorization.promoteAfterPresentationCommit(receipt));
        assertFalse(authorization.isInheritedProvisional());
        assertFalse(authorization.promoteAfterPresentationCommit(receipt));
        assertFalse(authorization.tryBeginEvidenceCapture("legacy-request", "legacy-frame"),
                "a compatibility grant without authenticated source lineage must fail closed");
    }

    @Test
    void negativeMonotonicOriginKeepsAValidClaimLiveUntilItsRelativeDeadline() throws Exception {
        AtomicLong monotonic = new AtomicLong(-1_000_000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);

        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        assertTrue(claim.monotonicDeadlineMillis() < 0L);
        assertTrue(vault.isTargetClaimLive(claim, CLOCK));
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
        assertTrue(vault.commit(first, CLOCK).isEmpty(), "a stale callback must not burn a newer reservation");
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
    void commitAtomicallyRejectsWallClockExpiryAfterReservationCheck() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.newTargetHandshake("target", PLAYER, "client", "1.21.11", "build",
                LoaderType.FABRIC, target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation(
                "target", PLAYER, "target-session", new byte[32], CLOCK).orElseThrow();

        assertTrue(vault.isReserved(prepared, CLOCK));
        Clock exactExpiry = Clock.fixed(
                Instant.ofEpochMilli(prepared.expiresAtEpochMs()), ZoneOffset.UTC);
        assertTrue(vault.commit(prepared, exactExpiry).isEmpty());
        assertEquals(0, vault.size());
        assertEquals(0, prepared.encoded().length);
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
    void approvedFileScopeIsDefensivelyBoundToOneExactTargetClaim() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        Set<String> mutableScope = new HashSet<>(Set.of("options.txt", "config/mcace.properties"));
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK, mutableScope);
        mutableScope.clear();

        vault.onConnectionClosed();
        assertTrue(vault.claimTargetHandshake("target", PLAYER, "client", "1.21.11", "build",
                LoaderType.FABRIC, key().getPublic(), CLOCK, new SecureRandom()).isEmpty(),
                "a wrong pinned target key must not consume the approved scope");
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        assertEquals(Set.of("options.txt", "config/mcace.properties"), claim.approvedExplicitFiles());
        assertThrows(UnsupportedOperationException.class,
                () -> claim.approvedExplicitFiles().add("new-file.txt"));
        assertTrue(vault.claimTargetHandshake("target", PLAYER, "client", "1.21.11", "build",
                LoaderType.FABRIC, target.getPublic(), CLOCK, new SecureRandom()).isEmpty(),
                "one grant must never return its approval scope twice");
    }

    @Test
    void invalidApprovedFileScopeNeverEntersTheVault() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        assertThrows(FederationException.class, () -> vault.store(
                grant(client, source, target), client, PLAYER, "source-session", CLOCK,
                Set.of("bad\npath")));
        for (String unsafe : Set.of("../options.txt", "config/../options.txt", "/options.txt",
                "C:/options.txt", "config\\options.txt", "config//options.txt", "./options.txt")) {
            assertThrows(FederationException.class, () -> vault.store(
                    grant(client, source, target), client, PLAYER, "source-session", CLOCK,
                    Set.of(unsafe)), unsafe);
        }
        assertEquals(0, vault.size());
    }

    @Test
    void targetClaimRemainsProvisionalOnlyWhileExactVaultEntryIsLive() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK,
                Set.of("config/mcace.properties"));
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();

        assertEquals("target", claim.targetNetworkId());
        assertTrue(vault.isTargetClaimLive(claim, CLOCK));
        monotonic.addAndGet(Duration.ofMinutes(3).toMillis());
        assertFalse(vault.isTargetClaimLive(claim, CLOCK));
        assertEquals(0, vault.size());
    }

    @Test
    void legacyTargetHandshakeCannotDiscardAnApprovedExplicitFileScope() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK,
                Set.of("config/mcace.properties"));

        assertTrue(vault.newTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).isEmpty());
        assertEquals(1, vault.size(),
                "a compatibility caller must neither expose nor destroy the scoped approval");
        assertEquals(Set.of("config/mcace.properties"), vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow().approvedExplicitFiles());
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
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        assertTrue(vault.cancelTargetClaim(claim));
        assertEquals(0, vault.size());
    }

    @Test
    void cancelTargetClaimsClearsBoundClaimsButPreservesUnclaimedDisconnectWindow() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(2, monotonic::get);

        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.onConnectionClosed();
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();

        vault.cancelTargetClaims();
        assertEquals(0, vault.size());
        assertFalse(vault.isTargetClaimLive(claim, CLOCK));

        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        vault.cancelTargetClaims();
        assertEquals(1, vault.size(), "an unclaimed source grant remains usable across one disconnect");
        vault.onConnectionClosed();
        assertEquals(1, vault.size(), "the first disconnect opens the one-shot handoff window");
        vault.onConnectionClosed();
        assertEquals(0, vault.size(), "the subsequent disconnect closes the unclaimed window");
    }

    @Test
    void staleTargetClaimCannotCancelANewerGenerationForTheSamePlayerAndTarget() throws Exception {
        AtomicLong monotonic = new AtomicLong(1000L);
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        FederationTokenVault vault = new FederationTokenVault(1, monotonic::get);
        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        FederationTokenVault.TargetHandshakeClaim stale = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "old-build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();

        vault.store(grant(client, source, target), client, PLAYER, "source-session", CLOCK);
        FederationTokenVault.TargetHandshakeClaim current = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "new-build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();

        assertFalse(vault.cancelTargetClaim(stale));
        assertTrue(vault.isTargetClaimLive(current, CLOCK));
        assertEquals(1, vault.size());
        assertTrue(vault.cancelTargetClaim(current));
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
    void capturedSourceFrameBurnsTheSingleEvidenceBudgetInheritedByTarget() throws Exception {
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        ClientHandshakeEngine sourceEngine = sourceEngine(client, source);
        ConnectionEnablementAuthorization sourceAuthorization =
                ConnectionEnablementAuthorization.humanVisible(sourceEngine, 41L);
        FederationGrant federationGrant = grant(client, source, target);
        byte[] sourceExportIdentity = MessageDigest.getInstance("SHA-256")
                .digest(federationGrant.getClientConsent().toByteArray());

        assertTrue(sourceAuthorization.tryBeginEvidenceCapture("source-request", "source-frame"));
        assertTrue(sourceAuthorization.commitEvidenceCapture("source-request", "source-frame"));
        assertTrue(sourceAuthorization.tryBeginSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));
        assertTrue(sourceAuthorization.commitSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));

        FederationTokenVault vault = new FederationTokenVault();
        vault.store(
                federationGrant,
                client,
                PLAYER,
                "source-session",
                CLOCK,
                Set.of("options.txt"),
                sourceEngine,
                sourceAuthorization);
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        ConnectionEnablementAuthorization targetAuthorization =
                ConnectionEnablementAuthorization.federationInherited(claim.engine(), 42L, claim);
        promoteTarget(vault, targetAuthorization);

        assertFalse(targetAuthorization.tryBeginEvidenceCapture("target-request", "target-frame"),
                "the inherited target must observe the source connection's burned frame budget");
    }

    @Test
    void uncapturedSourceFrameLeavesExactlyOneEvidenceBudgetForInheritedTarget() throws Exception {
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        ClientHandshakeEngine sourceEngine = sourceEngine(client, source);
        ConnectionEnablementAuthorization sourceAuthorization =
                ConnectionEnablementAuthorization.humanVisible(sourceEngine, 51L);
        FederationGrant federationGrant = grant(client, source, target);
        byte[] sourceExportIdentity = MessageDigest.getInstance("SHA-256")
                .digest(federationGrant.getClientConsent().toByteArray());
        assertTrue(sourceAuthorization.tryBeginSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));
        assertTrue(sourceAuthorization.commitSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));

        FederationTokenVault vault = new FederationTokenVault();
        vault.store(
                federationGrant,
                client,
                PLAYER,
                "source-session",
                CLOCK,
                Set.of(),
                sourceEngine,
                sourceAuthorization);
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        ConnectionEnablementAuthorization targetAuthorization =
                ConnectionEnablementAuthorization.federationInherited(claim.engine(), 52L, claim);
        promoteTarget(vault, targetAuthorization);

        assertTrue(targetAuthorization.tryBeginEvidenceCapture("target-request", "target-frame"));
        assertTrue(targetAuthorization.commitEvidenceCapture("target-request", "target-frame"));
        assertFalse(targetAuthorization.tryBeginEvidenceCapture("target-request-2", "target-frame-2"));
        assertFalse(sourceAuthorization.tryBeginEvidenceCapture("late-source", "late-frame"),
                "source and target share one lineage-wide frame budget");
    }

    @Test
    void concurrentSourceAndInheritedTargetEvidenceRequestsHaveOneLineageWinner() throws Exception {
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        ClientHandshakeEngine sourceEngine = sourceEngine(client, source);
        ConnectionEnablementAuthorization sourceAuthorization =
                ConnectionEnablementAuthorization.humanVisible(sourceEngine, 71L);
        FederationGrant federationGrant = grant(client, source, target);
        byte[] sourceExportIdentity = MessageDigest.getInstance("SHA-256")
                .digest(federationGrant.getClientConsent().toByteArray());
        assertTrue(sourceAuthorization.tryBeginSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));
        assertTrue(sourceAuthorization.commitSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));

        FederationTokenVault vault = new FederationTokenVault();
        vault.store(
                federationGrant,
                client,
                PLAYER,
                "source-session",
                CLOCK,
                Set.of(),
                sourceEngine,
                sourceAuthorization);
        FederationTokenVault.TargetHandshakeClaim claim = vault.claimTargetHandshake(
                "target", PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                target.getPublic(), CLOCK, new SecureRandom()).orElseThrow();
        ConnectionEnablementAuthorization targetAuthorization =
                ConnectionEnablementAuthorization.federationInherited(claim.engine(), 72L, claim);
        promoteTarget(vault, targetAuthorization);

        AtomicInteger winners = new AtomicInteger();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            executor.submit(() -> {
                ready.countDown();
                start.await();
                if (sourceAuthorization.tryBeginEvidenceCapture("source-race", "source-race-frame")) {
                    winners.incrementAndGet();
                }
                return null;
            });
            executor.submit(() -> {
                ready.countDown();
                start.await();
                if (targetAuthorization.tryBeginEvidenceCapture("target-race", "target-race-frame")) {
                    winners.incrementAndGet();
                }
                return null;
            });
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
        assertEquals(1, winners.get());
    }

    @Test
    void lineageBoundStoreRejectsAnUncommittedOrWrongSourceAuthorization() throws Exception {
        KeyPair client = key(); KeyPair source = key(); KeyPair target = key();
        ClientHandshakeEngine sourceEngine = sourceEngine(client, source);
        ConnectionEnablementAuthorization uncommitted =
                ConnectionEnablementAuthorization.humanVisible(sourceEngine, 61L);
        FederationGrant federationGrant = grant(client, source, target);
        FederationTokenVault vault = new FederationTokenVault();

        assertThrows(FederationException.class, () -> vault.store(
                federationGrant, client, PLAYER, "source-session", CLOCK, Set.of(),
                sourceEngine, uncommitted));
        assertEquals(0, vault.size());

        byte[] sourceExportIdentity = MessageDigest.getInstance("SHA-256")
                .digest(federationGrant.getClientConsent().toByteArray());
        assertTrue(uncommitted.tryBeginSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));
        assertTrue(uncommitted.commitSourceExport(
                federationGrant.getClientConsent().getAssertionId(), sourceExportIdentity));
        ClientHandshakeEngine wrongEngine = sourceEngine(client, source);
        assertThrows(FederationException.class, () -> vault.store(
                federationGrant, client, PLAYER, "source-session", CLOCK, Set.of(),
                wrongEngine, uncommitted));
        assertEquals(0, vault.size());
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

    private static ClientHandshakeEngine sourceEngine(KeyPair client, KeyPair source) throws Exception {
        return new ClientHandshakeEngine(
                PLAYER,
                "client",
                "1.21.11",
                "build",
                LoaderType.FABRIC,
                source.getPublic(),
                CLOCK,
                new SecureRandom(),
                client);
    }

    private static void promoteTarget(
            FederationTokenVault vault,
            ConnectionEnablementAuthorization targetAuthorization) throws Exception {
        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation(
                "target", PLAYER, "target-session", new byte[32], CLOCK).orElseThrow();
        FederationTokenVault.PresentationCommitReceipt receipt =
                vault.commit(prepared, CLOCK).orElseThrow();
        assertTrue(targetAuthorization.promoteAfterPresentationCommit(receipt));
    }

    private static KeyPair key() throws Exception { return Ed25519Keys.generate(new SecureRandom()); }
}
