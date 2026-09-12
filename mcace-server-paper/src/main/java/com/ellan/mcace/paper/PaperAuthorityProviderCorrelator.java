package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.BackendAuthorityProfile;
import com.ellan.mcace.core.authority.ServerAuthorityObservationCodec;
import com.ellan.mcace.paper.behavior.BehaviorAlert;
import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Exact-profile, two-domain Paper/Folia behavior correlation for signed observations. */
final class PaperAuthorityProviderCorrelator {
    private final BackendAuthorityProfile profile;
    private final Clock clock;
    private final Map<UUID, PlayerWindows> players = new HashMap<>();

    PaperAuthorityProviderCorrelator(BackendAuthorityProfile profile, Clock clock) {
        this.profile = Objects.requireNonNull(profile, "profile");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    synchronized Optional<CorrelatedProviders> accept(BehaviorAlert alert) {
        Objects.requireNonNull(alert, "alert");
        BackendAuthorityProfile.ProviderContract contract =
                profile.provider(alert.provider()).orElse(null);
        // The signed protocol is canonical at epoch-millisecond precision while Paper event
        // clocks commonly expose nanoseconds. Normalize before every window comparison/store so
        // genuine provider events cannot fail only when the durable request is constructed.
        Instant now = Instant.ofEpochMilli(clock.millis());
        Instant eventObservedAt = Instant.ofEpochMilli(alert.observedAt().toEpochMilli());
        if (contract == null || alert.experimental()
                || !contract.providerVersion().equals(alert.providerVersion())
                || !contract.stableCheckFamily().equals(alert.stableCheck())
                || eventObservedAt.isAfter(now)
                || eventObservedAt.isBefore(now.minus(profile.maximumProviderWindow()))) {
            return Optional.empty();
        }
        PlayerWindows player = players.computeIfAbsent(alert.playerId(), ignored -> new PlayerWindows());
        if (player.consumedThroughObservedAt != null
                && !eventObservedAt.isAfter(player.consumedThroughObservedAt)) {
            return Optional.empty();
        }
        ProviderWindow window = player.providers.computeIfAbsent(
                contract.providerId(), ignored -> new ProviderWindow());
        Instant cutoff = now.minus(profile.maximumProviderWindow());
        pruneBefore(window, cutoff);
        if (!window.providerEventIds.add(alert.providerEventIdSha256())) {
            return Optional.empty();
        }
        window.observations.addLast(new ProviderObservation(
                alert.providerEventIdSha256(), eventObservedAt));
        while (window.observations.size()
                > ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATIONS_PER_PROVIDER) {
            window.providerEventIds.remove(window.observations.removeFirst().providerEventIdSha256());
        }

        if (player.lastDurablyIssuedAt != null
                && now.isBefore(player.lastDurablyIssuedAt.plus(profile.cooldown()))) {
            return Optional.empty();
        }
        ArrayList<ServerAuthorityObservationCodec.ProviderInput> inputs = new ArrayList<>();
        Set<String> domains = new HashSet<>();
        Instant observedAt = Instant.EPOCH;
        for (String providerId : profile.providerIds().stream().sorted().toList()) {
            BackendAuthorityProfile.ProviderContract expected =
                    profile.provider(providerId).orElseThrow();
            ProviderWindow candidate = player.providers.get(providerId);
            if (candidate == null) continue;
            pruneBefore(candidate, cutoff);
            if (candidate.observations.size() < expected.threshold()) continue;
            // Providers can deliver genuine events out of order (for example T2 followed by
            // T1 after an async callback). Deque insertion order is not a time ordering.
            Instant start = candidate.observations.stream()
                    .map(ProviderObservation::observedAt)
                    .min(Instant::compareTo).orElseThrow();
            Instant end = candidate.observations.stream()
                    .map(ProviderObservation::observedAt)
                    .max(Instant::compareTo).orElseThrow();
            // The wire contract permits at most one provider summary per independent trust
            // domain. Profiles may list alternative providers in one domain, so select the
            // first exact, thresholded provider in canonical provider-id order.
            if (!domains.add(expected.trustDomainId())) continue;
            inputs.add(new ServerAuthorityObservationCodec.ProviderInput(
                    expected.trustDomainId(), expected.providerId(), expected.providerVersion(),
                    expected.stableCheckFamily(), expected.threshold(),
                    candidate.observations.size(), start, end));
            if (end.isAfter(observedAt)) observedAt = end;
        }
        if (domains.size() < profile.requiredIndependentDomains()) {
            return Optional.empty();
        }
        if (player.lastAcceptedObservedAt != null
                && observedAt.isBefore(
                player.lastAcceptedObservedAt.plus(profile.cooldown()))) {
            return Optional.empty();
        }
        return Optional.of(new CorrelatedProviders(observedAt, inputs));
    }

    synchronized void committed(
            UUID playerId,
            Instant consumedThroughObservedAt,
            Instant acceptedObservedAt,
            Instant durablyIssuedAt) {
        PlayerWindows player = players.get(Objects.requireNonNull(playerId, "playerId"));
        if (player != null) {
            Instant consumed = canonical(Objects.requireNonNull(
                    consumedThroughObservedAt, "consumedThroughObservedAt"));
            Instant accepted = canonical(Objects.requireNonNull(
                    acceptedObservedAt, "acceptedObservedAt"));
            Instant issued = canonical(Objects.requireNonNull(
                    durablyIssuedAt, "durablyIssuedAt"));
            if (accepted.isBefore(consumed) || issued.isBefore(accepted)) {
                throw new IllegalArgumentException("invalid durable authority correlation times");
            }
            player.consumedThroughObservedAt = later(
                    player.consumedThroughObservedAt, consumed);
            player.lastAcceptedObservedAt = later(player.lastAcceptedObservedAt, accepted);
            // Cooldown starts at the signed frame's durable issuedAt, not scheduler entry time or
            // provider time. This exact value survives journal recovery across restarts.
            player.lastDurablyIssuedAt = later(player.lastDurablyIssuedAt, issued);
            // Evidence is single-use. Keeping thresholded events after a durable publication
            // would let the same provider window allocate another journal sequence after the
            // cooldown and would then be rejected by the proxy's prior-observation check.
            player.providers.values().forEach(window ->
                    pruneThrough(window, player.consumedThroughObservedAt));
        }
    }

    synchronized void recovered(
            UUID playerId,
            Optional<Instant> lastAcceptedObservedAt,
            Optional<Instant> lastDurablyIssuedAt) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(lastAcceptedObservedAt, "lastAcceptedObservedAt");
        Objects.requireNonNull(lastDurablyIssuedAt, "lastDurablyIssuedAt");
        if (lastAcceptedObservedAt.isPresent() != lastDurablyIssuedAt.isPresent()) {
            throw new IllegalArgumentException("recovered authority times must be paired");
        }
        if (lastAcceptedObservedAt.isEmpty()) {
            return;
        }
        Instant observed = canonical(lastAcceptedObservedAt.orElseThrow());
        Instant issued = canonical(lastDurablyIssuedAt.orElseThrow());
        if (issued.isBefore(observed)) {
            throw new IllegalArgumentException("recovered issuance predates observation");
        }
        PlayerWindows player = players.computeIfAbsent(playerId, ignored -> new PlayerWindows());
        player.consumedThroughObservedAt = later(player.consumedThroughObservedAt, observed);
        player.lastAcceptedObservedAt = later(player.lastAcceptedObservedAt, observed);
        player.lastDurablyIssuedAt = later(player.lastDurablyIssuedAt, issued);
        player.providers.values().forEach(window ->
                pruneThrough(window, player.consumedThroughObservedAt));
    }

    synchronized void grantAdvanced(UUID playerId, Instant grantIssuedAt) {
        PlayerWindows player = players.get(Objects.requireNonNull(playerId, "playerId"));
        if (player == null) return;
        Instant issuedAt = Objects.requireNonNull(grantIssuedAt, "grantIssuedAt");
        player.providers.values().forEach(window ->
                pruneBefore(window, issuedAt));
    }

    synchronized void remove(UUID playerId) {
        players.remove(Objects.requireNonNull(playerId, "playerId"));
    }

    synchronized void clear() {
        players.clear();
    }

    private static Instant canonical(Instant value) {
        return Instant.ofEpochMilli(value.toEpochMilli());
    }

    private static Instant later(Instant current, Instant candidate) {
        return current == null || candidate.isAfter(current) ? candidate : current;
    }

    private static void pruneBefore(ProviderWindow window, Instant cutoff) {
        window.observations.removeIf(observation -> {
            if (!observation.observedAt().isBefore(cutoff)) return false;
            window.providerEventIds.remove(observation.providerEventIdSha256());
            return true;
        });
    }

    private static void pruneThrough(ProviderWindow window, Instant boundary) {
        window.observations.removeIf(observation -> {
            if (observation.observedAt().isAfter(boundary)) return false;
            window.providerEventIds.remove(observation.providerEventIdSha256());
            return true;
        });
    }

    record CorrelatedProviders(
            Instant observedAt,
            java.util.List<ServerAuthorityObservationCodec.ProviderInput> providers) {
        CorrelatedProviders {
            Objects.requireNonNull(observedAt, "observedAt");
            providers = java.util.List.copyOf(Objects.requireNonNull(providers, "providers"));
        }
    }

    private static final class PlayerWindows {
        private final Map<String, ProviderWindow> providers = new HashMap<>();
        private Instant consumedThroughObservedAt;
        private Instant lastAcceptedObservedAt;
        private Instant lastDurablyIssuedAt;
    }

    private static final class ProviderWindow {
        private final ArrayDeque<ProviderObservation> observations = new ArrayDeque<>();
        private final Set<String> providerEventIds = new HashSet<>();
    }

    private record ProviderObservation(String providerEventIdSha256, Instant observedAt) { }
}
