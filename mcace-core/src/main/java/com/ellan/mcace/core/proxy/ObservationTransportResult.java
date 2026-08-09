package com.ellan.mcace.core.proxy;

import java.util.Objects;
import java.util.Optional;

/** Bounded receiver result. Rejections are auditable transport facts, not cheat verdicts. */
public record ObservationTransportResult(ObservationReceiveStatus status, Optional<ObservationAuditResult> auditResult) {
    public ObservationTransportResult {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(auditResult, "auditResult");
        if (status != ObservationReceiveStatus.COMPLETED && auditResult.isPresent()) {
            throw new IllegalArgumentException("only completed transfers may contain an audit result");
        }
        if (status == ObservationReceiveStatus.COMPLETED && auditResult.isEmpty()) {
            throw new IllegalArgumentException("completed transfer requires an audit result");
        }
    }

    static ObservationTransportResult status(ObservationReceiveStatus status) {
        return new ObservationTransportResult(status, Optional.empty());
    }
}
