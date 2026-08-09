package com.ellan.mcace.velocity;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Bounded, in-memory only, one-shot post-connect reevaluation permit for baseline LIMITED admission. */
final class VelocityDeferredAdmissionRoutes {
    private static final int MAX_PENDING = 128;
    private static final Duration MAX_AGE = Duration.ofSeconds(5);
    private final Clock clock;
    private final Map<UUID, Entry> entries = new HashMap<>();

    VelocityDeferredAdmissionRoutes(Clock clock) { this.clock = Objects.requireNonNull(clock, "clock"); }

    synchronized boolean defer(
            UUID playerId,
            String sessionId,
            long generation,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(loginTicket, "loginTicket");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        expire(clock.instant());
        if (!entries.containsKey(playerId) && entries.size() >= MAX_PENDING) return false;
        entries.put(playerId,
                new Entry(sessionId, generation, loginTicket, playerIdentity, clock.instant().plus(MAX_AGE)));
        return true;
    }

    synchronized Optional<Entry> claim(
            UUID playerId,
            long generation,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        expire(clock.instant());
        Entry entry = entries.get(playerId);
        if (entry == null) return Optional.empty();
        if (!entry.loginTicket().equals(loginTicket) || entry.playerIdentity() != playerIdentity) {
            return Optional.empty();
        }
        if (entry.generation() > generation) return Optional.empty();
        entries.remove(playerId);
        return entry.generation() == generation ? Optional.of(entry) : Optional.empty();
    }

    synchronized void clear(UUID playerId) { entries.remove(Objects.requireNonNull(playerId, "playerId")); }

    private void expire(Instant now) {
        Iterator<Map.Entry<UUID, Entry>> iterator = entries.entrySet().iterator();
        while (iterator.hasNext()) if (!iterator.next().getValue().expiresAt().isAfter(now)) iterator.remove();
    }

    record Entry(
            String sessionId,
            long generation,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity,
            Instant expiresAt) {
        Entry {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(loginTicket, "loginTicket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }
}
