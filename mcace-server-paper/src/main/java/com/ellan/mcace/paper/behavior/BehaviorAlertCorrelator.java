package com.ellan.mcace.paper.behavior;

import com.ellan.mcace.cloudclient.CloudRiskEvent;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.risk.RiskEventType;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public final class BehaviorAlertCorrelator {
    private final int minimumFlags;
    private final Duration window;
    private final Duration cooldown;
    private final int maximumKeys;
    private final int maximumObservationsPerKey;
    private final LinkedHashMap<AlertKey, WindowState> windows = new LinkedHashMap<>();
    private final Map<UUID, Map<String, Instant>> providerEmissions = new HashMap<>();

    public BehaviorAlertCorrelator(int minimumFlags, Duration window, Duration cooldown, int maximumKeys) {
        if (minimumFlags < 1 || minimumFlags > 100) {
            throw new IllegalArgumentException("minimumFlags must be between 1 and 100");
        }
        if (window.isZero() || window.isNegative() || window.compareTo(Duration.ofMinutes(10)) > 0) {
            throw new IllegalArgumentException("window must be between 1 ms and 10 minutes");
        }
        if (cooldown.isNegative() || cooldown.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("cooldown must be between zero and one hour");
        }
        if (maximumKeys < 1 || maximumKeys > 100_000) {
            throw new IllegalArgumentException("maximumKeys must be between 1 and 100000");
        }
        this.minimumFlags = minimumFlags;
        this.window = window;
        this.cooldown = cooldown;
        this.maximumKeys = maximumKeys;
        this.maximumObservationsPerKey = Math.max(minimumFlags, 256);
    }

    public synchronized Optional<CloudRiskEvent> accept(BehaviorAlert alert) {
        Instant cutoff = alert.observedAt().minus(window);
        AlertKey key = new AlertKey(alert.playerId(), alert.provider(), alert.stableCheck());
        WindowState state = windows.computeIfAbsent(key, ignored -> new WindowState());
        while (!state.observations.isEmpty() && state.observations.peekFirst().observedAt().isBefore(cutoff)) {
            state.providerEventIds.remove(state.observations.removeFirst().providerEventIdSha256());
        }
        if (!state.providerEventIds.add(alert.providerEventIdSha256())) {
            return Optional.empty();
        }
        state.observations.addLast(alert);
        while (state.observations.size() > maximumObservationsPerKey) {
            state.providerEventIds.remove(state.observations.removeFirst().providerEventIdSha256());
        }
        trimToMaximumKeys();

        if (state.observations.size() < minimumFlags) {
            return Optional.empty();
        }
        if (state.lastEmission != null && alert.observedAt().isBefore(state.lastEmission.plus(cooldown))) {
            return Optional.empty();
        }
        state.lastEmission = alert.observedAt();
        Map<String, Instant> emissions = providerEmissions.computeIfAbsent(
                alert.playerId(), ignored -> new HashMap<>());
        emissions.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
        emissions.put(alert.provider(), alert.observedAt());
        Set<String> providers = new LinkedHashSet<>(emissions.keySet());
        double maximumViolation = state.observations.stream()
                .mapToDouble(BehaviorAlert::violationLevel).max().orElse(0.0D);
        Instant firstObserved = state.observations.getFirst().observedAt();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("schema", "mcace.behavior-alert.v1");
        details.put("provider", alert.provider());
        details.put("provider_version", alert.providerVersion());
        details.put("check", alert.check());
        details.put("stable_check", alert.stableCheck());
        details.put("provider_event_id_sha256", alert.providerEventIdSha256());
        details.put("flag_count", state.observations.size());
        details.put("window_ms", window.toMillis());
        details.put("first_observed_at", firstObserved.toString());
        details.put("maximum_violation_level", maximumViolation);
        details.put("experimental", alert.experimental());
        details.put("independent_providers", providers.stream().sorted().toList());
        return Optional.of(new CloudRiskEvent(
                UUID.randomUUID(), "", alert.playerId(), RiskEventType.BEHAVIOR_HIGH_RISK,
                alert.provider().toLowerCase(java.util.Locale.ROOT) + "-adapter",
                ObservationOrigin.SERVER_CONFIRMED, providers.size() >= 2,
                alert.observedAt(), details));
    }

    public synchronized void remove(UUID playerId) {
        windows.keySet().removeIf(key -> key.playerId.equals(playerId));
        providerEmissions.remove(playerId);
    }

    public synchronized int trackedKeys() {
        return windows.size();
    }

    private void trimToMaximumKeys() {
        Iterator<AlertKey> iterator = windows.keySet().iterator();
        while (windows.size() > maximumKeys && iterator.hasNext()) {
            iterator.next();
            iterator.remove();
        }
    }

    private record AlertKey(UUID playerId, String provider, String stableCheck) { }

    private static final class WindowState {
        private final ArrayDeque<BehaviorAlert> observations = new ArrayDeque<>();
        private final Set<String> providerEventIds = new LinkedHashSet<>();
        private Instant lastEmission;
    }
}
