package com.ellan.mcace.protocol.crypto;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

public final class NonceReplayGuard {
    private final Map<ReplayKey, Long> seen = new HashMap<>();
    private final Map<String, Integer> sessionEntryCounts = new HashMap<>();
    private final Clock clock;
    private final long windowMillis;
    private final int maxEntries;
    private final int maxEntriesPerSession;

    public NonceReplayGuard(Clock clock, Duration window) {
        this(clock, window, ProtocolConstants.MAX_NONCE_REPLAY_ENTRIES);
    }

    public NonceReplayGuard(Clock clock, Duration window, int maxEntries) {
        this(clock, window, maxEntries, ProtocolConstants.MAX_NONCE_REPLAY_ENTRIES_PER_SESSION);
    }

    public NonceReplayGuard(Clock clock, Duration window, int maxEntries, int maxEntriesPerSession) {
        this.clock = Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(window, "window");
        if (window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be positive");
        }
        this.windowMillis = window.toMillis();
        if (windowMillis <= 0L) {
            throw new IllegalArgumentException("window must be at least one millisecond");
        }
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        if (maxEntriesPerSession <= 0) {
            throw new IllegalArgumentException("maxEntriesPerSession must be positive");
        }
        this.maxEntries = maxEntries;
        this.maxEntriesPerSession = maxEntriesPerSession;
    }

    public synchronized boolean accept(String sessionId, byte[] nonce) {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(nonce, "nonce");
        long now = clock.millis();
        ReplayKey key = new ReplayKey(sessionId,
                Base64.getUrlEncoder().withoutPadding().encodeToString(nonce));
        Long expiresAt = seen.get(key);
        if (expiresAt != null && expiresAt > now) {
            return false;
        }
        if (expiresAt != null) {
            remove(key);
        }
        if (seen.size() >= maxEntries || sessionEntryCounts.getOrDefault(sessionId, 0) >= maxEntriesPerSession) {
            removeExpired(now);
            if (seen.size() >= maxEntries
                    || sessionEntryCounts.getOrDefault(sessionId, 0) >= maxEntriesPerSession) {
                return false;
            }
        }
        seen.put(key, saturatingAdd(now, windowMillis));
        sessionEntryCounts.merge(sessionId, 1, Integer::sum);
        return true;
    }

    private void removeExpired(long now) {
        Iterator<Map.Entry<ReplayKey, Long>> iterator = seen.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<ReplayKey, Long> entry = iterator.next();
            if (entry.getValue() <= now) {
                ReplayKey key = entry.getKey();
                iterator.remove();
                decrementSessionCount(key.sessionId());
            }
        }
    }

    private void remove(ReplayKey key) {
        if (seen.remove(key) != null) {
            decrementSessionCount(key.sessionId());
        }
    }

    private void decrementSessionCount(String sessionId) {
        Integer count = sessionEntryCounts.get(sessionId);
        if (count == null || count <= 1) {
            sessionEntryCounts.remove(sessionId);
        } else {
            sessionEntryCounts.put(sessionId, count - 1);
        }
    }

    private static long saturatingAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }

    private record ReplayKey(String sessionId, String nonce) { }
}
