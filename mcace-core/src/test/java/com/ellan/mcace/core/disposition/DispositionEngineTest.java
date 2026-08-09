package com.ellan.mcace.core.disposition;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DispositionEngineTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-08T00:00:00Z");
    private static ArtifactObservation mod() { return new ArtifactObservation(ArtifactType.MOD, "bad.mod", "1.2.0", null, Map.of(), ObservationOrigin.CLIENT_REPORTED, Confidence.HIGH, false); }
    private static ArtifactObservation protocol() { return new ArtifactObservation(ArtifactType.PROTOCOL, "auth-replay", "1", null, Map.of(), ObservationOrigin.SERVER_CONFIRMED, Confidence.CONFIRMED, true); }
    private static EvaluationContext context() { return new EvaluationContext(PLAYER, "survival", "world", "normal", Set.of("member"), NOW); }
    private static DispositionRule rule(String id, RuleScope scope, DispositionAction action, int priority, boolean foundation) { return new DispositionRule(id, new ArtifactSelector(ArtifactType.MOD, MatchType.EXACT_ID, "bad.mod", null, null, Map.of()), scope, action, Confidence.LOW, null, null, priority, foundation); }
    @Test void resolvesByScopeThenPriorityThenExactExceptionThenSeverity() {
        DispositionPolicy p = new DispositionPolicy("v1", List.of(rule("global", RuleScope.global(), DispositionAction.WARN, 99, false), rule("scoped", new RuleScope("survival", null, null, null, null), DispositionAction.NOTICE, 0, false), rule("exact", new RuleScope("survival", null, null, null, PLAYER), DispositionAction.WARN, 0, false)));
        DispositionDecision d = new DispositionEngine().evaluate(p, context(), mod());
        assertEquals(DispositionAction.WARN, d.action()); assertEquals("exact", d.winningRuleId().orElseThrow()); assertEquals(3, d.explanations().size());
    }
    @Test void foundationSecurityCannotBeAllowedAway() {
        DispositionRule allow = rule("allow", RuleScope.global(), DispositionAction.ALLOW, 100, false);
        DispositionRule replay = new DispositionRule("replay",
                new ArtifactSelector(ArtifactType.PROTOCOL, MatchType.EXACT_ID, "auth-replay", null, null, Map.of()),
                RuleScope.global(), DispositionAction.DENY, Confidence.LOW, null, null, 0, true);
        DispositionPolicy p = new DispositionPolicy("v1", List.of(allow, replay));
        assertEquals(DispositionAction.DENY, new DispositionEngine().evaluate(p, context(), protocol()).action());
    }
    @Test void clientSignalDefaultsToObserveAndNoBanExists() { assertEquals(DispositionAction.OBSERVE, new DispositionEngine().evaluate(new DispositionPolicy("v1", List.of()), context(), mod()).action()); assertThrows(IllegalArgumentException.class, () -> new ArtifactSelector(ArtifactType.MOD, MatchType.EXACT_HASH, "bad", null, null, Map.of())); }
    @Test void rejectsUntrustedPolicyBoundariesAndCopiesCollections() { assertThrows(IllegalArgumentException.class, () -> new DispositionRule("x", new ArtifactSelector(ArtifactType.MOD, MatchType.EXACT_ID, "x", null, null, Map.of()), RuleScope.global(), DispositionAction.WARN, Confidence.LOW, NOW, NOW, 0, false)); Map<String,String> source = new java.util.HashMap<>(); ArtifactObservation o = new ArtifactObservation(ArtifactType.MOD, "x", "1", null, source, ObservationOrigin.INFERRED, Confidence.LOW, false); source.put("changed", "yes"); assertTrue(o.metadata().isEmpty()); }

    @Test void foundationRulesCannotBeAppliedToOrdinaryArtifacts() {
        assertThrows(IllegalArgumentException.class, () -> new DispositionRule(
                "invalid-foundation", new ArtifactSelector(ArtifactType.MOD, MatchType.EXACT_ID,
                "bad.mod", null, null, Map.of()), RuleScope.global(), DispositionAction.DENY,
                Confidence.LOW, null, null, 0, true));
        assertThrows(IllegalArgumentException.class, () -> new ArtifactObservation(
                ArtifactType.MOD, "bad.mod", "1", null, Map.of(), ObservationOrigin.CLIENT_REPORTED,
                Confidence.HIGH, true));
    }
}
