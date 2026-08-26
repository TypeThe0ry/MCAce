package com.ellan.mcace.paper.behavior;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Assigns a stable opaque identity to a provider event object without retaining it. A repeated
 * callback carrying the exact same event object gets the same token; once the provider releases
 * that object, the weak entry can be collected. Identity comparison deliberately ignores any
 * provider-defined equals/hashCode implementation.
 */
final class ProviderEventIdentityCache {
    private final ReferenceQueue<Object> collected = new ReferenceQueue<>();
    private final Map<IdentityReference, String> identities = new HashMap<>();

    synchronized String identityFor(Object event) {
        Objects.requireNonNull(event, "event");
        expungeCollected();
        IdentityReference lookup = new IdentityReference(event, null);
        String existing = identities.get(lookup);
        if (existing != null) {
            return existing;
        }
        String created = UUID.randomUUID().toString();
        identities.put(new IdentityReference(event, collected), created);
        return created;
    }

    private void expungeCollected() {
        IdentityReference reference;
        while ((reference = (IdentityReference) collected.poll()) != null) {
            identities.remove(reference);
        }
    }

    private static final class IdentityReference extends WeakReference<Object> {
        private final int identityHash;

        private IdentityReference(Object referent, ReferenceQueue<Object> queue) {
            super(referent, queue);
            identityHash = System.identityHashCode(referent);
        }

        @Override
        public int hashCode() {
            return identityHash;
        }

        @Override
        public boolean equals(Object candidate) {
            if (this == candidate) return true;
            if (!(candidate instanceof IdentityReference other)) return false;
            Object left = get();
            return left != null && left == other.get();
        }
    }
}
