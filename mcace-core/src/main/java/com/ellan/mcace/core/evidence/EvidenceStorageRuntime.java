package com.ellan.mcace.core.evidence;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

/** Paired content and administrative capabilities used by a proxy runtime. */
public record EvidenceStorageRuntime(EvidenceContentStore contentStore, EvidenceAdminService adminService) {
    public EvidenceStorageRuntime {
        Objects.requireNonNull(contentStore, "contentStore");
        Objects.requireNonNull(adminService, "adminService");
    }

    public static EvidenceStorageRuntime disabled(Clock clock, EvidenceAuditSink auditSink) {
        return new EvidenceStorageRuntime(EvidenceContentStore.discard(), EvidenceAdminService.disabled(clock, auditSink));
    }

    /** Exposes review capability only when the active content store explicitly implements it. */
    public Optional<EvidenceReviewReader> reviewReader() {
        return contentStore instanceof EvidenceReviewReader reader ? Optional.of(reader) : Optional.empty();
    }
}
