package com.ellan.mcace.velocity;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Resolves the two operator-configured high-impact routes before any player is handled.
 *
 * <p>A configuration request for {@code LIMITED_ROUTE} is not sufficient authority to route a
 * player.  Both named targets must be explicit, distinct, and already present in Velocity's
 * server registry.  Otherwise this object intentionally exposes {@code MONITOR} as its effective
 * mode, preserving the normal handshake while preventing connection actions.</p>
 */
final class VelocityDispositionRoutes {
    enum ValidationStatus {
        MONITOR_CONFIGURED,
        ACTIVE,
        MISSING_LIMITED_TARGET,
        MISSING_QUARANTINE_TARGET,
        IDENTICAL_TARGETS,
        LIMITED_TARGET_UNREGISTERED,
        QUARANTINE_TARGET_UNREGISTERED
    }

    private final VelocityAdmissionConfig.Mode effectiveMode;
    private final ValidationStatus validationStatus;
    private final Optional<String> limitedServer;
    private final Optional<String> quarantineServer;

    private VelocityDispositionRoutes(
            VelocityAdmissionConfig.Mode effectiveMode,
            ValidationStatus validationStatus,
            Optional<String> limitedServer,
            Optional<String> quarantineServer) {
        this.effectiveMode = Objects.requireNonNull(effectiveMode, "effectiveMode");
        this.validationStatus = Objects.requireNonNull(validationStatus, "validationStatus");
        this.limitedServer = Objects.requireNonNull(limitedServer, "limitedServer");
        this.quarantineServer = Objects.requireNonNull(quarantineServer, "quarantineServer");
    }

    static VelocityDispositionRoutes resolve(
            VelocityAdmissionConfig configuration, Predicate<String> registeredServer) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(registeredServer, "registeredServer");
        if (configuration.mode() != VelocityAdmissionConfig.Mode.LIMITED_ROUTE) {
            return disabled(ValidationStatus.MONITOR_CONFIGURED);
        }
        if (configuration.limitedServer().isEmpty()) {
            return disabled(ValidationStatus.MISSING_LIMITED_TARGET);
        }
        if (configuration.quarantineServer().isEmpty()) {
            return disabled(ValidationStatus.MISSING_QUARANTINE_TARGET);
        }
        String limited = configuration.limitedServer().orElseThrow();
        String quarantine = configuration.quarantineServer().orElseThrow();
        if (limited.equals(quarantine)) {
            return disabled(ValidationStatus.IDENTICAL_TARGETS);
        }
        if (!registeredServer.test(limited)) {
            return disabled(ValidationStatus.LIMITED_TARGET_UNREGISTERED);
        }
        if (!registeredServer.test(quarantine)) {
            return disabled(ValidationStatus.QUARANTINE_TARGET_UNREGISTERED);
        }
        return new VelocityDispositionRoutes(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE,
                ValidationStatus.ACTIVE,
                Optional.of(limited),
                Optional.of(quarantine));
    }

    VelocityAdmissionConfig.Mode effectiveMode() {
        return effectiveMode;
    }

    ValidationStatus validationStatus() {
        return validationStatus;
    }

    Optional<String> targetFor(DispositionAction action) {
        Objects.requireNonNull(action, "action");
        if (effectiveMode != VelocityAdmissionConfig.Mode.LIMITED_ROUTE) {
            return Optional.empty();
        }
        return switch (action) {
            case LIMIT -> limitedServer;
            case QUARANTINE -> quarantineServer;
            default -> Optional.empty();
        };
    }

    private static VelocityDispositionRoutes disabled(ValidationStatus status) {
        return new VelocityDispositionRoutes(
                VelocityAdmissionConfig.Mode.MONITOR, status, Optional.empty(), Optional.empty());
    }
}
