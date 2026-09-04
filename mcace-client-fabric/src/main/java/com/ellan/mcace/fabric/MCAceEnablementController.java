package com.ellan.mcace.fabric;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import net.minecraft.client.MinecraftClient;

/**
 * Owns the single connection-bound MCAce enablement decision. No decision is persisted and
 * closing the screen is exactly the same as declining it. Federation inheritance is carried by
 * the exact one-time vault grant rather than by this screen controller.
 */
final class MCAceEnablementController {
    private static final String DECISION_AGE_SECONDS_PROPERTY =
            "mcace.client.enablement-decision-timeout-seconds";
    private static final long DEFAULT_DECISION_AGE_MILLIS = Duration.ofSeconds(30).toMillis();
    private static final long MIN_DECISION_AGE_MILLIS = Duration.ofSeconds(30).toMillis();
    private static final long MAX_DECISION_AGE_MILLIS = Duration.ofSeconds(300).toMillis();
    private final Clock clock;
    private final LongSupplier monotonicMillis;
    private Pending pending;

    MCAceEnablementController() {
        this(Clock.systemUTC(), () -> System.nanoTime() / 1_000_000L);
    }

    MCAceEnablementController(Clock clock) {
        this(clock, () -> System.nanoTime() / 1_000_000L);
    }

    MCAceEnablementController(Clock clock, LongSupplier monotonicMillis) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.monotonicMillis = Objects.requireNonNull(monotonicMillis, "monotonicMillis");
    }

    void request(MinecraftClient client, VerifiedPolicy policy, Set<String> requestedFiles,
            Runnable rendered, Consumer<Set<String>> enabled, Runnable declined) {
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(requestedFiles, "requestedFiles");
        Objects.requireNonNull(rendered, "rendered");
        Objects.requireNonNull(enabled, "enabled");
        Objects.requireNonNull(declined, "declined");
        cancel(client);
        List<String> files = requestedFiles.stream().sorted().toList();
        long nowEpochMs = clock.millis();
        long nowMonotonicMillis = monotonicMillis.getAsLong();
        long deadlineEpochMs = decisionDeadlineEpochMs(policy, nowEpochMs);
        long monotonicDeadlineMillis = decisionMonotonicDeadlineMillis(nowMonotonicMillis);
        if (!validDisplayRequest(files)
                || !decisionStillCurrent(
                        deadlineEpochMs, nowEpochMs,
                        monotonicDeadlineMillis, nowMonotonicMillis)) {
            declined.run();
            return;
        }
        Pending next = new Pending(
                files, enabled, declined, client.currentScreen,
                deadlineEpochMs, monotonicDeadlineMillis);
        pending = next;
        next.screen = ExplicitFileConsentScreen.forEnablement(
                next.previous(), policy, files, rendered,
                decision -> decide(client, next, decision));
        client.setScreen(next.screen);
    }

    void tick(MinecraftClient client) {
        Pending current = pending;
        if (current == null) return;
        if (!decisionStillCurrent(
                    current.deadlineEpochMs, clock.millis(),
                    current.monotonicDeadlineMillis, monotonicMillis.getAsLong())
                || client.currentScreen != current.screen) {
            decide(client, current, false);
        }
    }

    void cancel(MinecraftClient client) {
        Pending current = pending;
        pending = null;
        if (current == null) return;
        if (client.currentScreen == current.screen) {
            client.setScreen(current.previous());
        }
        current.declined().run();
    }

    static boolean isCurrent(Object active, Object candidate) {
        return active != null && active == candidate;
    }

    static boolean validDisplayRequest(List<String> files) {
        return files.size() <= 128 && files.stream().allMatch(path -> path != null && !path.isBlank()
                && path.length() <= 512 && path.chars().noneMatch(Character::isISOControl));
    }

    static long decisionDeadlineEpochMs(VerifiedPolicy policy, long nowEpochMs) {
        Objects.requireNonNull(policy, "policy");
        long localDeadline;
        try {
            localDeadline = Math.addExact(nowEpochMs, decisionAgeMillis());
        } catch (ArithmeticException exception) {
            localDeadline = Long.MAX_VALUE;
        }
        return Math.min(policy.policy().getExpiresAtEpochMs(), localDeadline);
    }

    static boolean decisionStillCurrent(long deadlineEpochMs, long nowEpochMs) {
        return deadlineEpochMs > 0L && nowEpochMs < deadlineEpochMs;
    }

    static long decisionMonotonicDeadlineMillis(long nowMonotonicMillis) {
        try {
            return Math.addExact(nowMonotonicMillis, decisionAgeMillis());
        } catch (ArithmeticException exception) {
            return Long.MAX_VALUE;
        }
    }

    static boolean decisionStillCurrent(
            long deadlineEpochMs,
            long nowEpochMs,
            long monotonicDeadlineMillis,
            long nowMonotonicMillis) {
        return decisionStillCurrent(deadlineEpochMs, nowEpochMs)
                && nowMonotonicMillis < monotonicDeadlineMillis;
    }

    /**
     * Returns the bounded, process-local consent window. The smoke runner uses this to leave
     * enough time for a human-visible screenshot and signed attestation; malformed or unsafe
     * values deliberately fall back to the fail-closed 30-second default.
     */
    static long decisionAgeMillis() {
        return decisionAgeMillis(System.getProperty(DECISION_AGE_SECONDS_PROPERTY));
    }

    static long decisionAgeMillis(String configuredSeconds) {
        if (configuredSeconds == null || configuredSeconds.isBlank()) {
            return DEFAULT_DECISION_AGE_MILLIS;
        }
        try {
            long seconds = Long.parseLong(configuredSeconds.trim());
            long millis = Math.multiplyExact(seconds, 1_000L);
            if (millis < MIN_DECISION_AGE_MILLIS || millis > MAX_DECISION_AGE_MILLIS) {
                return DEFAULT_DECISION_AGE_MILLIS;
            }
            return millis;
        } catch (NumberFormatException | ArithmeticException exception) {
            return DEFAULT_DECISION_AGE_MILLIS;
        }
    }

    static Optional<Set<String>> inheritedFederationFiles(
            Set<String> sourceApprovedFiles, Set<String> targetRequestedFiles) {
        Objects.requireNonNull(sourceApprovedFiles, "sourceApprovedFiles");
        Objects.requireNonNull(targetRequestedFiles, "targetRequestedFiles");
        List<String> requested = targetRequestedFiles.stream().sorted().toList();
        if (!validDisplayRequest(requested) || !sourceApprovedFiles.containsAll(requested)) {
            return Optional.empty();
        }
        return Optional.of(Set.copyOf(requested));
    }

    private void decide(MinecraftClient client, Pending current, boolean allow) {
        if (!isCurrent(pending, current)) return;
        pending = null;
        if (client.currentScreen == current.screen) {
            client.setScreen(current.previous());
        }
        if (allow && decisionStillCurrent(
                current.deadlineEpochMs, clock.millis(),
                current.monotonicDeadlineMillis, monotonicMillis.getAsLong())) {
            current.enabled().accept(Set.copyOf(current.files()));
        }
        else current.declined().run();
    }

    private static final class Pending {
        private final List<String> files;
        private final Consumer<Set<String>> enabled;
        private final Runnable declined;
        private final net.minecraft.client.gui.screen.Screen previous;
        private final long deadlineEpochMs;
        private final long monotonicDeadlineMillis;
        private ExplicitFileConsentScreen screen;

        private Pending(List<String> files, Consumer<Set<String>> enabled, Runnable declined,
                net.minecraft.client.gui.screen.Screen previous, long deadlineEpochMs,
                long monotonicDeadlineMillis) {
            this.files = List.copyOf(files);
            this.enabled = enabled;
            this.declined = declined;
            this.previous = previous;
            this.deadlineEpochMs = deadlineEpochMs;
            this.monotonicDeadlineMillis = monotonicDeadlineMillis;
        }

        private List<String> files() { return files; }
        private Consumer<Set<String>> enabled() { return enabled; }
        private Runnable declined() { return declined; }
        private net.minecraft.client.gui.screen.Screen previous() { return previous; }
    }
}
