package com.ellan.mcace.core.disposition;

import java.util.Objects;

/**
 * Shared selector-to-action ceiling for every local disposition construction path.
 *
 * <p>Selectors derived from client-reported names, metadata, signers, classifications, or
 * behaviour identifiers are useful for review, but are not a sufficient enforcement identity.
 * A bounded content-root is stronger, but still not an independently verified single artifact.
 * Keep this check in the core model so a hand-written rule cannot bypass catalog safeguards.</p>
 */
final class DispositionSelectorActionPolicy {
    private static final String CONTENT_ROOT_VALUE = "content-root";
    private static final String CONTENT_ROOT_METADATA = "content_root_sha256";

    private DispositionSelectorActionPolicy() { }

    static void validate(ArtifactSelector selector, DispositionAction action, boolean foundationSecurity) {
        Objects.requireNonNull(selector, "selector");
        Objects.requireNonNull(action, "action");
        // Foundation rules are separately constrained to protocol artifacts and cannot ALLOW.
        // They protect protocol integrity rather than making a client-artifact classification.
        if (foundationSecurity) return;
        if (selector.matchType() == MatchType.EXACT_HASH) return;
        if (isContentRoot(selector)) {
            if (action.severity() > DispositionAction.QUARANTINE.severity()) {
                throw new IllegalArgumentException("content-root selectors cannot DENY");
            }
            return;
        }
        if (action.severity() > DispositionAction.WARN.severity()) {
            throw new IllegalArgumentException("non-exact selectors cannot exceed WARN");
        }
    }

    static boolean isContentRoot(ArtifactSelector selector) {
        return selector.matchType() == MatchType.METADATA
                && CONTENT_ROOT_VALUE.equals(selector.value())
                && selector.requiredMetadata().containsKey(CONTENT_ROOT_METADATA);
    }
}
