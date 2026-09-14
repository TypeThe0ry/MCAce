package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AuthenticatedManifestDispositionEventTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");

    @Test
    void highestActionUsesTheCompleteBoundedCountsAndHasStableSessionKey() {
        Map<DispositionAction, Integer> counts = new EnumMap<>(DispositionAction.class);
        counts.put(DispositionAction.WARN, 4);
        counts.put(DispositionAction.DENY, 1);
        AuthenticatedManifestAuditResult audit = new AuthenticatedManifestAuditResult(
                PLAYER, "session-a", NOW,
                new ProxyPolicyBatchEvaluation(
                        ProxyPolicyRefreshStatus.ACTIVE, 5, counts,
                        DispositionAction.DENY, Optional.of("rule-a"),
                        Optional.of("policy-a"), Optional.of(1L), Optional.of(NOW.plusSeconds(60)),
                        0, List.of(), true),
                List.of());

        AuthenticatedManifestDispositionEvent first = audit.dispositionEvent();
        AuthenticatedManifestDispositionEvent second = audit.dispositionEvent();

        assertEquals(DispositionAction.DENY, first.highestAction());
        assertEquals("rule-a", first.winningRuleId().orElseThrow());
        assertEquals("policy-a", first.activePolicyVersion().orElseThrow());
        assertEquals(first.idempotencyKey(), second.idempotencyKey());
        assertTrue(first.policyIsActive());
        assertFalse(first.hasAdmissionEffect());
        AuthenticatedManifestDispositionEvent explainable = new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(1L),
                Optional.of(NOW.plusSeconds(60)), ObservationOrigin.ADMIN_REVIEWED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000002")),
                Optional.of("CASE-42"), Optional.of("11".repeat(32)));
        assertTrue(explainable.hasAdmissionEffect());
        assertTrue(explainable.hasExecutionEvidence());
        AuthenticatedManifestDispositionEvent independentReview = new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(1L),
                Optional.of(NOW.plusSeconds(60)), ObservationOrigin.ADMIN_REVIEWED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000004")),
                Optional.of("CASE-43"), Optional.of("22".repeat(32)));
        assertFalse(explainable.idempotencyKey().equals(independentReview.idempotencyKey()));
        AuthenticatedManifestDispositionEvent clientOnly = new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(1L),
                Optional.of(NOW.plusSeconds(60)));
        assertFalse(clientOnly.hasAdmissionEffect());
        assertFalse(clientOnly.hasExecutionEvidence());
    }

    @Test
    void invalidPolicyAlwaysFallsBackToObservationWithoutAdmissionEffect() {
        AuthenticatedManifestDispositionEvent event = new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY,
                Optional.empty(), Optional.empty(), Optional.empty());

        assertFalse(event.policyIsActive());
        assertFalse(event.hasAdmissionEffect());
    }

    @Test
    void activeStatusWithoutACompleteExpiringPolicyIdentityIsAuditOnly() {
        AuthenticatedManifestDispositionEvent event = new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE,
                Optional.empty(), Optional.empty(), Optional.empty(),
                ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000003")),
                Optional.empty(), Optional.of("33".repeat(32)));

        assertTrue(event.policyIsActive());
        assertFalse(event.hasBoundActivePolicyIdentity());
        assertFalse(event.policyIsActiveAt(NOW));
        assertFalse(event.hasAdmissionEffect());
        assertFalse(event.hasExecutionEvidence());
    }

    @Test
    void trustedAuthorityWithoutExecutionContextCommitmentIsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                new AuthenticatedManifestDispositionEvent(
                        PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                        ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(1L),
                        Optional.of(NOW.plusSeconds(60)), ObservationOrigin.SERVER_CONFIRMED,
                        Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000003")),
                        Optional.empty(), Optional.empty()));
    }
}
