package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record PlayerNotification(
        UUID notificationId,
        UUID playerId,
        String type,
        String subjectId,
        String title,
        String message,
        String createdBy,
        Instant createdAt,
        Instant readAt) {
    public PlayerNotification {
        Objects.requireNonNull(notificationId, "notificationId");
        Objects.requireNonNull(playerId, "playerId");
        type = WebSessionHandoff.bounded(type, "type", 64);
        subjectId = WebSessionHandoff.bounded(subjectId, "subjectId", 128);
        title = WebSessionHandoff.bounded(title, "title", 160);
        message = WebSessionHandoff.bounded(message, "message", 2000);
        createdBy = WebSessionHandoff.bounded(createdBy, "createdBy", 128);
        Objects.requireNonNull(createdAt, "createdAt");
        if (readAt != null && readAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("notification readAt precedes creation");
        }
    }

    public boolean read() {
        return readAt != null;
    }
}
