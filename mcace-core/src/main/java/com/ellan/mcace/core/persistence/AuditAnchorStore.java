package com.ellan.mcace.core.persistence;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditAnchorStore {
    Optional<StoredAuditAnchor> createAuditAnchor(Duration minimumInterval)
            throws SecurityPersistenceException;

    List<StoredAuditAnchor> claimPendingAuditAnchors(
            String workerId, Duration leaseDuration, int limit) throws SecurityPersistenceException;

    void recordAuditAnchorPublication(
            UUID anchorId, String workerId, AuditAnchorPublication publication)
            throws SecurityPersistenceException;

    void releaseAuditAnchorClaim(
            UUID anchorId, String workerId, Duration retryDelay, String failure)
            throws SecurityPersistenceException;
}
