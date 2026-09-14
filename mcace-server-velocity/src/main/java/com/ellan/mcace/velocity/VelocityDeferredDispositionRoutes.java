package com.ellan.mcace.velocity;

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
import java.util.function.Supplier;

/**
 * A tiny, thread-safe holding area for a disposition route which arrived before
 * Velocity has attached the player to a backend.
 *
 * <p>This deliberately stores only the already content-free disposition event and route name.
 * It is not a retry queue: one player has at most one entry, it is short lived, and it is removed
 * before the single post-connect retry is attempted.</p>
 */
final class VelocityDeferredDispositionRoutes {
    static final int MAX_PENDING = 128;
    static final Duration MAX_AGE = Duration.ofSeconds(5);

    enum DeferResult {
        QUEUED,
        SUPERSEDED,
        ALREADY_STRONGER,
        CAPACITY_REJECTED,
        TERMINAL_REJECTED,
        STALE_SESSION_REJECTED
    }

    record Pending(
            AuthenticatedManifestDispositionEvent event,
            String targetName,
            long backendGeneration,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity,
            Instant expiresAt) {
        Pending {
            Objects.requireNonNull(event, "event");
            Objects.requireNonNull(targetName, "targetName");
            Objects.requireNonNull(loginTicket, "loginTicket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }

    private record DeniedSession(
            String sessionId, VelocityLoginLifecycle.LoginTicket loginTicket, Object playerIdentity) {
        private DeniedSession {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(loginTicket, "loginTicket");
            Objects.requireNonNull(playerIdentity, "playerIdentity");
        }
    }

    private final Clock clock;
    private final Map<UUID, Pending> pendingByPlayer = new LinkedHashMap<>();
    private final Map<UUID, DeniedSession> deniedSessions = new LinkedHashMap<>();

    VelocityDeferredDispositionRoutes(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Thread-safe. LIMIT and QUARANTINE are the only actions which may be retained. */
    synchronized DeferResult defer(
            AuthenticatedManifestDispositionEvent event,
            String targetName,
            long backendGeneration,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(targetName, "targetName");
        if (!isDeferrable(event.highestAction())) {
            throw new IllegalArgumentException("only LIMIT or QUARANTINE may be deferred");
        }
        Objects.requireNonNull(loginTicket, "loginTicket");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        if (!permitRoute(event.playerId(), event.sessionId(), loginTicket, playerIdentity)) {
            return DeferResult.TERMINAL_REJECTED;
        }
        Instant now = clock.instant();
        expire(now);
        Pending existing = pendingByPlayer.get(event.playerId());
        if (existing != null
                && existing.loginTicket().equals(loginTicket)
                && existing.playerIdentity() == playerIdentity
                && existing.event().sessionId().equals(event.sessionId())) {
            if (existing.event().highestAction().severity() > event.highestAction().severity()) {
                return DeferResult.ALREADY_STRONGER;
            }
            if (existing.event().highestAction() == event.highestAction()
                    && existing.targetName().equals(targetName)) {
                return DeferResult.ALREADY_STRONGER;
            }
            pendingByPlayer.remove(event.playerId());
            pendingByPlayer.put(event.playerId(),
                    pending(event, targetName, backendGeneration, loginTicket, playerIdentity, now));
            return DeferResult.SUPERSEDED;
        }
        if (existing != null
                && existing.loginTicket().equals(loginTicket)
                && existing.playerIdentity() == playerIdentity
                && backendGeneration <= existing.backendGeneration()) {
            return DeferResult.STALE_SESSION_REJECTED;
        }
        if (existing == null && pendingByPlayer.size() >= MAX_PENDING) {
            return DeferResult.CAPACITY_REJECTED;
        }
        pendingByPlayer.remove(event.playerId());
        pendingByPlayer.put(event.playerId(),
                pending(event, targetName, backendGeneration, loginTicket, playerIdentity, now));
        return DeferResult.QUEUED;
    }

    /**
     * Claims the one permitted retry. A claimed entry cannot be revived by a later manual switch.
     */
    synchronized Optional<Pending> claimForPostConnect(
            UUID playerId,
            long backendGeneration,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(loginTicket, "loginTicket");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        Instant now = clock.instant();
        expire(now);
        Pending pending = pendingByPlayer.get(playerId);
        if (pending == null || !pending.event().policyIsActiveAt(now)) {
            pendingByPlayer.remove(playerId);
            return Optional.empty();
        }
        if (!pending.loginTicket().equals(loginTicket) || pending.playerIdentity() != playerIdentity) {
            return Optional.empty();
        }
        if (pending.backendGeneration() > backendGeneration) {
            // A delayed post-connect callback belongs to an older connection. It must not consume
            // the current session's later generation permit.
            return Optional.empty();
        }
        if (pending.backendGeneration() < backendGeneration) {
            pendingByPlayer.remove(playerId);
            return Optional.empty();
        }
        pendingByPlayer.remove(playerId);
        return Optional.of(pending);
    }

    synchronized void clear(UUID playerId) {
        UUID requiredPlayerId = Objects.requireNonNull(playerId, "playerId");
        pendingByPlayer.remove(requiredPlayerId);
        deniedSessions.remove(requiredPlayerId);
    }

    synchronized void clearSession(
            UUID playerId,
            String sessionId,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Pending pending = pendingByPlayer.get(playerId);
        if (pending != null && pending.event().sessionId().equals(sessionId)
                && pending.loginTicket().equals(loginTicket) && pending.playerIdentity() == playerIdentity) {
            pendingByPlayer.remove(playerId);
        }
        // DENY is terminal for the physical login, not merely for one coordinator session.
        // Only an exact disconnect or a different physical-login ticket may remove it.
    }

    /** One synchronized route-state boundary for direct, deferred, and baseline route actions. */
    synchronized boolean permitRoute(
            UUID playerId,
            String sessionId,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(loginTicket, "loginTicket");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        DeniedSession denied = deniedSessions.get(playerId);
        return denied == null || !denied.loginTicket().equals(loginTicket)
                || denied.playerIdentity() != playerIdentity;
    }

    /** Clears predecessor state only after the adapter proves this is the current auth session. */
    synchronized void resetForCurrentSession(
            UUID playerId,
            String currentSessionId,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(currentSessionId, "currentSessionId");
        DeniedSession deniedSession = deniedSessions.get(playerId);
        if (deniedSession != null && (!deniedSession.loginTicket().equals(loginTicket)
                || deniedSession.playerIdentity() != playerIdentity)) {
            deniedSessions.remove(playerId);
            pendingByPlayer.remove(playerId);
        }
        Pending pending = pendingByPlayer.get(playerId);
        if (pending != null && (!pending.event().sessionId().equals(currentSessionId)
                || !pending.loginTicket().equals(loginTicket) || pending.playerIdentity() != playerIdentity)) {
            pendingByPlayer.remove(playerId);
        }
    }

    /**
     * Linearizes the terminal-marker check with creation of the Velocity connection request.
     * The supplier must only initiate the request; it must not wait for connection completion.
     */
    synchronized VelocityDispositionExecutor.RouteOutcome executeIfPermitted(
            UUID playerId,
            String sessionId,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity,
            Supplier<VelocityDispositionExecutor.RouteOutcome> operation) {
        Objects.requireNonNull(operation, "operation");
        if (!permitRoute(playerId, sessionId, loginTicket, playerIdentity)) {
            return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        }
        return Objects.requireNonNull(operation.get(), "operation result");
    }

    /** Atomically makes DENY terminal for this session and drops its deferred route. */
    synchronized void markDenied(
            UUID playerId,
            String sessionId,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        markDeniedPhysical(playerId, loginTicket, playerIdentity, sessionId);
    }

    /** Marks the exact physical login denied before a coordinator session exists. */
    synchronized void markDeniedPhysical(
            UUID playerId,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity,
            String markerSessionId) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(loginTicket, "loginTicket");
        Objects.requireNonNull(playerIdentity, "playerIdentity");
        Objects.requireNonNull(markerSessionId, "markerSessionId");
        pendingByPlayer.remove(playerId);
        deniedSessions.put(playerId, new DeniedSession(markerSessionId, loginTicket, playerIdentity));
    }

    synchronized int pendingCount() {
        expire(clock.instant());
        return pendingByPlayer.size();
    }

    private Pending pending(
            AuthenticatedManifestDispositionEvent event,
            String targetName,
            long backendGeneration,
            VelocityLoginLifecycle.LoginTicket loginTicket,
            Object playerIdentity,
            Instant now) {
        return new Pending(event, targetName, backendGeneration, loginTicket, playerIdentity, now.plus(MAX_AGE));
    }

    private void expire(Instant now) {
        Iterator<Map.Entry<UUID, Pending>> iterator = pendingByPlayer.entrySet().iterator();
        while (iterator.hasNext()) {
            Pending pending = iterator.next().getValue();
            if (!pending.expiresAt().isAfter(now) || !pending.event().policyIsActiveAt(now)) {
                iterator.remove();
            }
        }
    }

    private static boolean isDeferrable(DispositionAction action) {
        return action == DispositionAction.LIMIT || action == DispositionAction.QUARANTINE;
    }
}
