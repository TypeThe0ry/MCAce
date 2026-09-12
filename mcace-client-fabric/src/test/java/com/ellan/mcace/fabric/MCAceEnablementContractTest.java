package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class MCAceEnablementContractTest {
    @Test
    void oneVisibleApprovalDisclosesAllConnectionBoundCapabilities() {
        String text = String.join("\n", ExplicitFileConsentScreen.enablementParagraphs(
                policy(), List.of("options.txt", "config/mcace.properties")));

        assertTrue(text.contains("MCAce enablement"));
        assertTrue(text.contains("options.txt"));
        assertTrue(text.contains("resource-pack"));
        assertTrue(text.contains("at most one in-game render frame"));
        assertTrue(text.contains("federation handoff"));
        assertTrue(text.contains("same or narrower"));
        assertTrue(text.contains("target is not known at this prompt"));
        assertTrue(text.contains("no second prompt"));
        assertTrue(text.contains("cannot export"));
        assertTrue(text.contains("provisional access"));
        assertTrue(text.contains("not persisted"));
        assertTrue(text.contains("Minecraft exits"));
        assertTrue(text.contains("normal unrelated connection"));
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

    @Test
    void enablementDecisionExpiresAtTheEarlierPolicyOrConfiguredDeadline() {
        long now = 1_800_000_000_000L;
        assertEquals(now + 10_000L,
                MCAceEnablementController.decisionDeadlineEpochMs(
                        policy(now + 10_000L), now));
        assertEquals(now + 30_000L,
                MCAceEnablementController.decisionDeadlineEpochMs(
                        policy(now + 60_000L), now));
        assertFalse(MCAceEnablementController.decisionStillCurrent(now, now));
        assertFalse(MCAceEnablementController.decisionStillCurrent(now + 30_000L, now + 30_000L));
    }

    @Test
    void consentWindowOverrideIsBoundedAndMalformedValuesFailClosedToDefault() {
        assertEquals(30_000L, MCAceEnablementController.decisionAgeMillis(null));
        assertEquals(30_000L, MCAceEnablementController.decisionAgeMillis(""));
        assertEquals(180_000L, MCAceEnablementController.decisionAgeMillis(" 180 "));
        assertEquals(30_000L, MCAceEnablementController.decisionAgeMillis("29"));
        assertEquals(300_000L, MCAceEnablementController.decisionAgeMillis("300"));
        assertEquals(30_000L, MCAceEnablementController.decisionAgeMillis("301"));
        assertEquals(30_000L, MCAceEnablementController.decisionAgeMillis("not-a-number"));
    }

    @Test
    void monotonicDeadlineStillFailsClosedAfterWallClockRollback() {
        long now = 1_800_000_000_000L;
        long monotonicStart = -1_000_000L;
        long monotonicDeadline =
                MCAceEnablementController.decisionMonotonicDeadlineMillis(monotonicStart);
        assertTrue(MCAceEnablementController.decisionStillCurrent(
                now + 60_000L, now, monotonicDeadline, monotonicStart));
        assertFalse(MCAceEnablementController.decisionStillCurrent(
                now + 60_000L, now - 60_000L, monotonicDeadline, monotonicDeadline));
    }

    @Test
    void oneApprovalIsReusableOnlyForAContainedFederationFileScope() {
        Set<String> approved = Set.of("options.txt", "config/mcace.properties");
        assertEquals(Set.of("options.txt"),
                MCAceEnablementController.inheritedFederationFiles(
                        approved, Set.of("options.txt")).orElseThrow());
        assertEquals(Set.of("options.txt", "config/mcace.properties"),
                MCAceEnablementController.inheritedFederationFiles(
                        approved, approved).orElseThrow());
        assertTrue(MCAceEnablementController.inheritedFederationFiles(
                approved, Set.of("new-sensitive-file.txt")).isEmpty());
        assertTrue(MCAceEnablementController.inheritedFederationFiles(
                approved, Set.of("bad\npath")).isEmpty());
        assertEquals(Set.of(), MCAceEnablementController.inheritedFederationFiles(
                approved, Set.of()).orElseThrow());
    }

    @Test
    void synchronousFederationSchedulingFailureRunsExactRollbackOnce() {
        AtomicInteger scheduled = new AtomicInteger();
        AtomicInteger rollbacks = new AtomicInteger();

        assertFalse(MCAceFabricClient.scheduleOrRollbackOnRuntimeFailure(() -> {
            scheduled.incrementAndGet();
            throw new IllegalStateException("executor rejected task");
        }, rollbacks::incrementAndGet));
        assertEquals(1, scheduled.get());
        assertEquals(1, rollbacks.get());

        assertTrue(MCAceFabricClient.scheduleOrRollbackOnRuntimeFailure(
                scheduled::incrementAndGet, rollbacks::incrementAndGet));
        assertEquals(2, scheduled.get());
        assertEquals(1, rollbacks.get());
    }

    @Test
    void federationWorkerRuntimeAndTargetExecutorRejectionEachRollbackExactlyOnce() {
        AtomicInteger workerRollbacks = new AtomicInteger();
        assertFalse(MCAceFabricClient.runFederationWorkerOrRollback(
                () -> {
                    throw new IllegalStateException("consent frame creation failed");
                },
                workerRollbacks::incrementAndGet));
        assertEquals(1, workerRollbacks.get());

        AtomicInteger targetRollbacks = new AtomicInteger();
        assertFalse(MCAceFabricClient.scheduleOrRollbackOnRuntimeFailure(
                () -> {
                    throw new IllegalStateException("target executor rejected presentation");
                },
                targetRollbacks::incrementAndGet));
        assertEquals(1, targetRollbacks.get());
    }

    private static VerifiedPolicy policy() {
        return policy(0L);
    }

    private static VerifiedPolicy policy(long expiresAtEpochMs) {
        return new VerifiedPolicy(
                SecurityPolicy.newBuilder().setServerId("pinned-network")
                        .setExpiresAtEpochMs(expiresAtEpochMs).build(),
                SignedPolicyDocument.getDefaultInstance(), new byte[32], 0L, false);
    }
}
