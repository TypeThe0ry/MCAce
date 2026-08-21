package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.federation.FederationTokenVault;
import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedFederationConsentRequest;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.federation.FederationDocuments;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.ClientFederationConsent;
import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class FederationConsentScreenTest {
    @Test
    void visiblePromptShowsBothPeersDisclosureAndNonPunitiveChoice() {
        List<String> lines = FederationConsentScreen.displayLines(new VerifiedFederationConsentRequest(
                FederationConsentRequest.newBuilder().setSchemaVersion(ProtocolConstants.FEDERATION_SCHEMA_VERSION)
                        .setSourceNetworkId("source-network").setTargetNetworkId("target-network")
                        .setDisclosure("source_locally_verified")
                        .setSourceKeyIdSha256(ByteString.copyFrom(new byte[32]))
                        .setTargetKeyIdSha256(ByteString.copyFrom(new byte[32]))
                        .setIssuedAtEpochMs(1_000L).setExpiresAtEpochMs(121_000L).build()));
        String joined = String.join("\n", lines);
        assertTrue(joined.contains("source-network"));
        assertTrue(joined.contains("target-network"));
        assertTrue(joined.contains("source_locally_verified"));
        assertTrue(joined.contains("observation-only"));
        assertTrue(joined.contains("not a cheat finding"));
        assertTrue(joined.contains("desktop or window capture"));
    }

    @Test
    void pendingConsentUsesIdentityNotValueEqualityForStaleCallbacks() {
        Object active = new Object();
        assertTrue(FederationConsentController.isCurrent(active, active));
        assertFalse(FederationConsentController.isCurrent(active, new Object()));
        assertFalse(FederationConsentController.isCurrent(null, active));
    }

    @Test
    void targetImportPromptShowsExactCapabilityAndLocalAdmissionAlreadyAccepted() throws Exception {
        String joined = String.join("\n", FederationImportConsentScreen.displayLines(preparedPresentation()));
        assertTrue(joined.contains("local authentication to this target was accepted first"));
        assertTrue(joined.contains("source"));
        assertTrue(joined.contains("target"));
        assertTrue(joined.contains("source_locally_verified"));
        assertTrue(joined.contains("exact prepared presentation"));
        assertTrue(joined.contains("current MCAce plugin channel"));
        assertTrue(joined.contains("presentation expires"));
        assertTrue(joined.contains("not a cheat finding"));
        assertTrue(joined.contains("files, storage, screenshots"));
    }

    @Test
    void targetImportPendingCapabilityUsesIdentityForStaleCallbacks() {
        Object active = new Object();
        assertTrue(FederationImportConsentController.isCurrent(active, active));
        assertFalse(FederationImportConsentController.isCurrent(active, new Object()));
        assertFalse(FederationImportConsentController.isCurrent(null, active));
    }

    private static FederationTokenVault.PreparedPresentation preparedPresentation() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC);
        UUID player = UUID.fromString("11111111-2222-3333-4444-555555555555");
        KeyPair client = Ed25519Keys.generate(new SecureRandom());
        KeyPair source = Ed25519Keys.generate(new SecureRandom());
        KeyPair target = Ed25519Keys.generate(new SecureRandom());
        FederationConsentRequest request = FederationDocuments.issueConsentRequest(
                "source", "target", player.toString(), client.getPublic(), source.getPublic(), target.getPublic(),
                "source-session", "policy", new byte[32], clock, Duration.ofMinutes(2), new SecureRandom());
        ClientFederationConsent consent = FederationDocuments.signClientConsent(
                request, client.getPrivate(), client.getPublic(), clock, Duration.ZERO);
        FederationGrant grant = FederationDocuments.grant(consent, FederationDocuments.signAssertion(
                request, consent, client.getPublic(), source.getPrivate(), source.getPublic(),
                clock, Duration.ZERO), client.getPublic());
        FederationTokenVault vault = new FederationTokenVault();
        vault.store(grant, client, player, "source-session", clock);
        vault.newTargetHandshake("target", player, "client", "26.1.2", "build", LoaderType.FABRIC,
                target.getPublic(), clock, new SecureRandom()).orElseThrow();
        return vault.preparePresentation("target", player, "target-session", new byte[32], clock).orElseThrow();
    }
}
