package com.ellan.mcace.velocity;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Process-wide, identity-bound physical-login registry.
 *
 * <p>The sequence is deliberately static and never wraps. Recreating the plugin or its registry
 * cannot make a delayed callback's ticket valid for a later physical connection.</p>
 */
final class VelocityLoginLifecycle {
    private static final AtomicLong NEXT_TICKET = new AtomicLong();

    record LoginTicket(long value) {
        LoginTicket {
            if (value <= 0L) throw new IllegalArgumentException("login ticket must be positive");
        }
    }

    record ActiveLogin(LoginTicket ticket, Object playerIdentity) {
        ActiveLogin {
            Objects.requireNonNull(ticket, "ticket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
        }
    }

    private final Map<UUID, ActiveLogin> active = new HashMap<>();

    synchronized LoginTicket beginLogin(UUID playerId, Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        LoginTicket ticket = new LoginTicket(nextTicket());
        active.put(playerId, new ActiveLogin(ticket, playerIdentity));
        return ticket;
    }

    synchronized Optional<ActiveLogin> current(UUID playerId) {
        return Optional.ofNullable(active.get(Objects.requireNonNull(playerId, "playerId")));
    }

    synchronized Optional<LoginTicket> ticketFor(UUID playerId, Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        ActiveLogin login = active.get(playerId);
        return login != null && login.playerIdentity() == playerIdentity
                ? Optional.of(login.ticket()) : Optional.empty();
    }

    synchronized boolean isCurrent(UUID playerId, Object playerIdentity, LoginTicket ticket) {
        Objects.requireNonNull(ticket, "ticket");
        return ticketFor(playerId, playerIdentity).filter(ticket::equals).isPresent();
    }

    /** A stale disconnect can only clear the exact player reference and ticket it captured. */
    synchronized boolean clear(UUID playerId, Object playerIdentity, LoginTicket ticket) {
        if (!isCurrent(playerId, playerIdentity, ticket)) return false;
        active.remove(playerId);
        return true;
    }

    synchronized void clearAll() {
        active.clear();
    }

    private static long nextTicket() {
        while (true) {
            long current = NEXT_TICKET.get();
            if (current == Long.MAX_VALUE) {
                throw new IllegalStateException("Velocity login ticket space exhausted");
            }
            long next = current + 1L;
            if (NEXT_TICKET.compareAndSet(current, next)) return next;
        }
    }
}
