package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
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
                        ProxyPolicyRefreshStatus.ACTIVE, 5, counts, List.of(), true),
                List.of());

        AuthenticatedManifestDispositionEvent first = audit.dispositionEvent();
        AuthenticatedManifestDispositionEvent second = audit.dispositionEvent();

        assertEquals(DispositionAction.DENY, first.highestAction());
        assertEquals(first.idempotencyKey(), second.idempotencyKey());
        assertTrue(first.policyIsActive());
        assertFalse(first.hasAdmissionEffect());
        AuthenticatedManifestDispositionEvent explainable = new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.DENY, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(1L),
                Optional.of(NOW.plusSeconds(60)));
        assertTrue(explainable.hasAdmissionEffect());
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
}
