package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import java.util.List;
import org.junit.jupiter.api.Test;

final class MCAceEnablementContractTest {
    @Test
    void oneVisibleApprovalDisclosesAllConnectionBoundCapabilities() {
        String text = String.join("\n", ExplicitFileConsentScreen.enablementParagraphs(
                policy(), List.of("options.txt", "config/mcace.properties")));

        assertTrue(text.contains("MCAce enablement"));
        assertTrue(text.contains("options.txt"));
        assertTrue(text.contains("resource-pack"));
        assertTrue(text.contains("in-game render frame"));
        assertTrue(text.contains("federation handoff"));
        assertTrue(text.contains("not persisted"));
        assertTrue(text.contains("keeps MCAce disabled"));
    }

    @Test
    void emptyFilePolicyStillRequiresTheSameSingleDecision() {
        String text = String.join("\n", ExplicitFileConsentScreen.enablementParagraphs(policy(), List.of()));
        assertTrue(text.contains("no explicit-file request"));
        assertTrue(MCAceEnablementController.validDisplayRequest(List.of()));
        assertFalse(MCAceEnablementController.validDisplayRequest(List.of("bad\npath")));
    }

    @Test
    void staleEnablementCallbacksCannotEnableAReplacedConnection() {
        Object current = new Object();
        assertTrue(MCAceEnablementController.isCurrent(current, current));
        assertFalse(MCAceEnablementController.isCurrent(current, new Object()));
        assertFalse(MCAceEnablementController.isCurrent(null, current));
    }

    private static VerifiedPolicy policy() {
        return new VerifiedPolicy(
                SecurityPolicy.newBuilder().setServerId("pinned-network").build(),
                SignedPolicyDocument.getDefaultInstance(), new byte[32], 0L, false);
    }
}
