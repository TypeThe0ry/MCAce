package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.protocol.policy.PolicyException;

/** Narrow bridge boundary: the Bungee adapter never receives a signing key. */
@FunctionalInterface
public interface BungeeDispositionPolicyPublisher {
    BungeePublishedDispositionPolicy publish() throws PolicyException;

    /** Read-only validation/preview; the default preserves compatibility with custom bridges. */
    default DispositionCatalogPreview preview() throws PolicyException {
        throw new PolicyException("disposition catalog preview is unavailable");
    }
}
