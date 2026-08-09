package com.ellan.mcace.core.disposition;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class DispositionRuleTest {
    private static final Instant NOW = Instant.ofEpochMilli(1_786_118_400_000L);

    @Test
    void directNonExactSelectorsCannotEscalateBeyondWarn() {
        for (ArtifactSelector selector : nonExactSelectors()) {
            for (DispositionAction action : new DispositionAction[] {
                    DispositionAction.CHALLENGE, DispositionAction.LIMIT,
                    DispositionAction.QUARANTINE, DispositionAction.DENY }) {
                assertThrows(IllegalArgumentException.class, () -> rule(selector, action),
                        () -> selector + " must not exceed WARN");
            }
            assertDoesNotThrow(() -> rule(selector, DispositionAction.WARN));
        }
    }

    @Test
    void directContentRootCanQuarantineButCannotDenyAndExactHashCanDeny() {
        ArtifactSelector contentRoot = new ArtifactSelector(ArtifactType.RESOURCE_PACK, MatchType.METADATA,
                "content-root", null, null, Map.of("content_root_sha256", "00".repeat(32)));
        assertDoesNotThrow(() -> rule(contentRoot, DispositionAction.QUARANTINE));
        assertThrows(IllegalArgumentException.class, () -> rule(contentRoot, DispositionAction.DENY));

        ArtifactSelector exactHash = new ArtifactSelector(ArtifactType.MOD, MatchType.EXACT_HASH,
                "00".repeat(32), null, null, Map.of());
        assertDoesNotThrow(() -> rule(exactHash, DispositionAction.DENY));
    }

    @Test
    void directFoundationProtocolRuleRetainsItsSeparateIntegrityException() {
        ArtifactSelector protocolIdentity = new ArtifactSelector(ArtifactType.PROTOCOL, MatchType.EXACT_ID,
                "policy-signature", null, null, Map.of());
        assertDoesNotThrow(() -> new DispositionRule("foundation", protocolIdentity, RuleScope.global(),
                DispositionAction.DENY, Confidence.CONFIRMED, NOW, NOW.plusSeconds(60), 1, true));
    }

    private static DispositionRule rule(ArtifactSelector selector, DispositionAction action) {
        return new DispositionRule("rule", selector, RuleScope.global(), action, Confidence.HIGH,
                NOW, NOW.plusSeconds(60), 1, false);
    }

    private static java.util.List<ArtifactSelector> nonExactSelectors() {
        return java.util.List.of(
                new ArtifactSelector(ArtifactType.MOD, MatchType.EXACT_ID,
                        "public-project-id", null, null, Map.of()),
                new ArtifactSelector(ArtifactType.MOD, MatchType.METADATA,
                        "signer", null, null, Map.of("signer", "reviewed-signer")),
                new ArtifactSelector(ArtifactType.CONFIG, MatchType.METADATA,
                        "metadata", null, null, Map.of("classification", "automation")),
                new ArtifactSelector(ArtifactType.BEHAVIOR, MatchType.EXACT_ID,
                        "reach-correlation", null, null, Map.of()),
                new ArtifactSelector(ArtifactType.MOD, MatchType.METADATA,
                        "admin-classification", null, null, Map.of("admin_classification", "reviewed-aid")));
    }
}
