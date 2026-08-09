package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedFederationConsentRequest;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import com.google.protobuf.ByteString;
import java.util.List;
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
}
