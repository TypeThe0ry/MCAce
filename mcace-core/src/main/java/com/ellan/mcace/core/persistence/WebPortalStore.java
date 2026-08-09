package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WebPortalStore {
    void createWebHandoff(WebSessionHandoff handoff) throws SecurityPersistenceException;

    Optional<WebSessionHandoff> consumeWebHandoff(UUID handoffId) throws SecurityPersistenceException;

    void createWebSession(StoredWebSession session) throws SecurityPersistenceException;

    Optional<StoredWebSession> findActiveWebSession(byte[] secretSha256, Instant activeAt)
            throws SecurityPersistenceException;

    void deleteWebSession(UUID sessionId, byte[] secretSha256) throws SecurityPersistenceException;

    List<StoredReviewCase> findReviewQueue(int limit) throws SecurityPersistenceException;

    List<PlayerNotification> findPlayerNotifications(UUID playerId, int limit)
            throws SecurityPersistenceException;

    void markPlayerNotificationRead(UUID playerId, UUID notificationId, Instant readAt)
            throws SecurityPersistenceException;
}
