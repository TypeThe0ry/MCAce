package com.ellan.mcace.velocity;

import java.util.HashMap;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Concurrency-safe lifecycle barrier between Velocity's configuration connection and a backend
 * that has completed joining.  {@code Player#getCurrentServer()} is intentionally not used as a
 * readiness signal: it can be populated while Velocity still reports CONNECTION_IN_PROGRESS.
 */
final class VelocityBackendReadyBarrier {
    private final Map<UUID, State> states = new HashMap<>();

    synchronized long resetForLogin(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        State previous = states.get(playerId);
        long generation = previous == null ? 1L : Math.incrementExact(previous.generation());
        states.put(playerId, new State(generation, false, new ArrayDeque<>()));
        return generation;
    }

    synchronized long beginConnection(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        State previous = states.get(playerId);
        long generation = previous == null ? 1L : Math.incrementExact(previous.generation());
        Deque<Long> awaitingPostConnect = previous == null
                ? new ArrayDeque<>() : new ArrayDeque<>(previous.awaitingPostConnect());
        awaitingPostConnect.addLast(generation);
        states.put(playerId, new State(generation, false, awaitingPostConnect));
        return generation;
    }

    synchronized long markReady(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        State state = states.get(playerId);
        if (state == null || state.awaitingPostConnect().isEmpty()) {
            return 0L;
        }
        long completedGeneration = state.awaitingPostConnect().removeFirst();
        boolean ready = state.generation() == completedGeneration;
        states.put(playerId, new State(state.generation(), ready, state.awaitingPostConnect()));
        return completedGeneration;
    }

    synchronized long generation(UUID playerId) {
        State state = states.get(Objects.requireNonNull(playerId, "playerId"));
        return state == null ? 0L : state.generation();
    }

    synchronized boolean isReady(UUID playerId) {
        State state = states.get(Objects.requireNonNull(playerId, "playerId"));
        return state != null && state.ready();
    }

    synchronized boolean isReady(UUID playerId, long generation) {
        State state = states.get(Objects.requireNonNull(playerId, "playerId"));
        return state != null && state.generation() == generation && state.ready();
    }

    synchronized void clear(UUID playerId) {
        states.remove(Objects.requireNonNull(playerId, "playerId"));
    }

    private record State(long generation, boolean ready, Deque<Long> awaitingPostConnect) { }
}
