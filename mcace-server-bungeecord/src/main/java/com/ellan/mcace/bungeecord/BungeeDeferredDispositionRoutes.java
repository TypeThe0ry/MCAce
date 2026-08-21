package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Thread-safe, bounded, one-shot holding state for high-impact Bungee routes which arrive while
 * the initial backend connection is still in progress.
 *
 * <p>Bungee's scheduler and event callbacks are not treated as a single serialized lane. Every
 * mutation is synchronized. A pending entry is content-free, tied to one physical player
 * connection/session/backend ticket, expires quickly, and is consumed before its only
 * post-connect dispatch attempt. The ticket is process-global and is deliberately not reset when
 * a player disconnects: a delayed callback from a former login must never be able to match a
 * same-UUID reconnect.</p>
 */
final class BungeeDeferredDispositionRoutes {
    static final int MAX_PENDING = 128;
    static final Duration MAX_AGE = Duration.ofSeconds(5);

    enum Source { DISPOSITION, HEARTBEAT }

    enum DeferResult {
        QUEUED,
        SUPERSEDED,
        ALREADY_STRONGER,
        CAPACITY_REJECTED,
        TERMINAL_REJECTED,
        STALE_SESSION_REJECTED
    }

    /** A non-zero, process-lifetime login token. It is never reused during a normal process life. */
    record LoginTicket(long value) {
        LoginTicket {
            if (value == 0L) {
                throw new IllegalArgumentException("login ticket must be non-zero");
            }
        }
    }

    record Pending(
            UUID playerId,
            String sessionId,
            Source source,
            DispositionAction action,
            String targetName,
            LoginTicket loginTicket,
            Object playerIdentity,
            Optional<AuthenticatedManifestDispositionEvent> dispositionEvent,
            Instant expiresAt) {
        Pending {
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(source, "source");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(targetName, "targetName");
            Objects.requireNonNull(loginTicket, "loginTicket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
            Objects.requireNonNull(dispositionEvent, "dispositionEvent");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (action != DispositionAction.LIMIT && action != DispositionAction.QUARANTINE) {
                throw new IllegalArgumentException("only LIMIT or QUARANTINE may be deferred");
            }
            if (source == Source.DISPOSITION && dispositionEvent.isEmpty()) {
                throw new IllegalArgumentException("disposition pending route requires its signed-policy event");
            }
            if (source == Source.HEARTBEAT && dispositionEvent.isPresent()) {
                throw new IllegalArgumentException("heartbeat pending route must not retain a disposition event");
            }
        }
    }

    private final Clock clock;
    private record ActiveLogin(LoginTicket ticket, Object playerIdentity, boolean backendReady) {
        ActiveLogin {
            Objects.requireNonNull(ticket, "ticket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
        }
    }

    /** Terminal DENY belongs to one physical login, even if its authenticated session id churns. */
    private record DeniedLogin(LoginTicket ticket, Object playerIdentity) {
        DeniedLogin {
            Objects.requireNonNull(ticket, "ticket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
        }
    }

    private final Map<UUID, Pending> pendingByPlayer = new LinkedHashMap<>();
    private final Map<UUID, ActiveLogin> activeLogins = new LinkedHashMap<>();
    private final Map<UUID, DeniedLogin> deniedLogins = new LinkedHashMap<>();
    private long nextLoginTicket;

    BungeeDeferredDispositionRoutes(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Begins a new physical login and invalidates any predecessor route state. */
    synchronized LoginTicket beginLogin(UUID playerId, Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        LoginTicket next = new LoginTicket(increment(nextLoginTicket));
        nextLoginTicket = next.value();
        activeLogins.put(playerId, new ActiveLogin(next, playerIdentity, false));
        pendingByPlayer.remove(playerId);
        deniedLogins.remove(playerId);
        return next;
    }

    /** Bungee emits ServerConnectedEvent only after a backend has connected successfully. */
    synchronized Optional<LoginTicket> markBackendReady(UUID playerId, Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        ActiveLogin active = activeLogins.get(playerId);
        if (active == null || active.playerIdentity() != playerIdentity) {
            return Optional.empty();
        }
        activeLogins.put(playerId, new ActiveLogin(active.ticket(), active.playerIdentity(), true));
        return Optional.of(active.ticket());
    }

    /** Closes the action window before Bungee starts changing this login's backend pointer. */
    synchronized boolean markBackendConnecting(
            UUID playerId, Object playerIdentity, LoginTicket loginTicket) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        Objects.requireNonNull(loginTicket, "loginTicket");
        ActiveLogin active = activeLogins.get(playerId);
        if (active == null || active.playerIdentity() != playerIdentity
                || !active.ticket().equals(loginTicket)) {
            return false;
        }
        activeLogins.put(playerId, new ActiveLogin(active.ticket(), active.playerIdentity(), false));
        return true;
    }

    synchronized Optional<LoginTicket> ticketFor(UUID playerId, Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        ActiveLogin active = activeLogins.get(playerId);
        return active != null && active.playerIdentity() == playerIdentity
                ? Optional.of(active.ticket()) : Optional.empty();
    }

    synchronized boolean isCurrent(UUID playerId, Object playerIdentity, LoginTicket ticket) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        Objects.requireNonNull(ticket, "ticket");
        ActiveLogin active = activeLogins.get(playerId);
        return active != null && active.playerIdentity() == playerIdentity && active.ticket().equals(ticket);
    }

    synchronized boolean isReady(UUID playerId, Object playerIdentity, LoginTicket ticket) {
        if (!isCurrent(playerId, playerIdentity, ticket)) {
            return false;
        }
        return activeLogins.get(playerId).backendReady();
    }

    synchronized DeferResult deferDisposition(
            AuthenticatedManifestDispositionEvent event, String targetName, LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(event, "event");
        return defer(new Pending(event.playerId(), event.sessionId(), Source.DISPOSITION, event.highestAction(),
                targetName, loginTicket, playerIdentity, Optional.of(event), expiresAt()));
    }

    synchronized DeferResult deferHeartbeat(
            UUID playerId, String sessionId, String targetName, LoginTicket loginTicket,
            Object playerIdentity) {
        return defer(new Pending(Objects.requireNonNull(playerId, "playerId"),
                Objects.requireNonNull(sessionId, "sessionId"), Source.HEARTBEAT,
                DispositionAction.LIMIT, targetName, loginTicket, playerIdentity, Optional.empty(), expiresAt()));
    }

    /** Claims and removes the sole retry after the matching successful backend connection. */
    synchronized Optional<Pending> claimForReadyBackend(
            UUID playerId, Object playerIdentity, LoginTicket loginTicket) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        Objects.requireNonNull(loginTicket, "loginTicket");
        expire(clock.instant());
        if (!isReady(playerId, playerIdentity, loginTicket)) {
            return Optional.empty();
        }
        Pending pending = pendingByPlayer.get(playerId);
        if (pending == null || !pending.loginTicket().equals(loginTicket)
                || pending.playerIdentity() != playerIdentity) {
            return Optional.empty();
        }
        pendingByPlayer.remove(playerId);
        return Optional.of(pending);
    }

    synchronized boolean permitRoute(
            UUID playerId, String sessionId, Object playerIdentity, LoginTicket loginTicket) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        DeniedLogin denied = deniedLogins.get(playerId);
        return isCurrent(playerId, playerIdentity, loginTicket)
                && (denied == null || !denied.ticket().equals(loginTicket)
                        || denied.playerIdentity() != playerIdentity);
    }

    /** DENY is terminal for the current session and atomically discards a previously queued route. */
    synchronized boolean markDenied(
            UUID playerId, String sessionId, Object playerIdentity, LoginTicket loginTicket) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        if (!isCurrent(playerId, playerIdentity, loginTicket)) {
            return false;
        }
        pendingByPlayer.remove(playerId);
        deniedLogins.put(playerId, new DeniedLogin(loginTicket, playerIdentity));
        return true;
    }

    synchronized void clearHeartbeat(
            UUID playerId, String sessionId, Object playerIdentity, LoginTicket loginTicket) {
        if (!isCurrent(playerId, playerIdentity, loginTicket)) {
            return;
        }
        Pending pending = pendingByPlayer.get(Objects.requireNonNull(playerId, "playerId"));
        if (pending != null && pending.source() == Source.HEARTBEAT
                && pending.sessionId().equals(Objects.requireNonNull(sessionId, "sessionId"))) {
            pendingByPlayer.remove(playerId);
        }
    }

    /** Clears only the exact physical login. A stale disconnect may not clear a reconnect. */
    synchronized boolean clear(UUID playerId, Object playerIdentity, LoginTicket loginTicket) {
        UUID required = Objects.requireNonNull(playerId, "playerId");
        if (!isCurrent(required, playerIdentity, loginTicket)) {
            return false;
        }
        pendingByPlayer.remove(required);
        activeLogins.remove(required);
        deniedLogins.remove(required);
        return true;
    }

    synchronized int pendingCount() {
        expire(clock.instant());
        return pendingByPlayer.size();
    }

    private DeferResult defer(Pending candidate) {
        if (!isCurrent(candidate.playerId(), candidate.playerIdentity(), candidate.loginTicket())) {
            return DeferResult.STALE_SESSION_REJECTED;
        }
        if (!permitRoute(candidate.playerId(), candidate.sessionId(), candidate.playerIdentity(), candidate.loginTicket())) {
            return DeferResult.TERMINAL_REJECTED;
        }
        Instant now = clock.instant();
        expire(now);
        Pending existing = pendingByPlayer.get(candidate.playerId());
        if (existing != null && existing.sessionId().equals(candidate.sessionId())) {
            if (existing.action().severity() > candidate.action().severity()) {
                return DeferResult.ALREADY_STRONGER;
            }
            if (existing.action() == candidate.action() && existing.targetName().equals(candidate.targetName())
                    && existing.source() == candidate.source()) {
                return DeferResult.ALREADY_STRONGER;
            }
            pendingByPlayer.put(candidate.playerId(), candidate);
            return DeferResult.SUPERSEDED;
        }
        if (existing != null || pendingByPlayer.size() < MAX_PENDING) {
            pendingByPlayer.put(candidate.playerId(), candidate);
            return DeferResult.QUEUED;
        }
        return DeferResult.CAPACITY_REJECTED;
    }

    private Instant expiresAt() {
        return clock.instant().plus(MAX_AGE);
    }

    private void expire(Instant now) {
        Iterator<Map.Entry<UUID, Pending>> iterator = pendingByPlayer.entrySet().iterator();
        while (iterator.hasNext()) {
            Pending pending = iterator.next().getValue();
            if (!pending.expiresAt().isAfter(now)
                    || pending.dispositionEvent().map(event -> !event.policyIsActiveAt(now)).orElse(false)) {
                iterator.remove();
            }
        }
    }

    private static long increment(long previous) {
        if (previous == Long.MAX_VALUE) {
            throw new IllegalStateException("Bungee login ticket space exhausted");
        }
        return previous + 1L;
    }
}
