package com.ellan.mcace.bungeecord;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Separates configuration names from proxy registration validation for high-impact routes.
 *
 * <p>Route actions are enabled only when both independently configured targets are present,
 * distinct, and registered by the proxy.  A failed check deliberately has no fallback target.</p>
 */
record BungeeDispositionRouteTargets(String limitedServer, String quarantineServer) {
    enum ValidationStatus {
        MONITOR_CONFIGURED,
        ACTIVE,
        MISSING_LIMITED_TARGET,
        MISSING_QUARANTINE_TARGET,
        IDENTICAL_TARGETS,
        LIMITED_TARGET_UNREGISTERED,
        QUARANTINE_TARGET_UNREGISTERED
    }

    BungeeDispositionRouteTargets {
        requireServerName(limitedServer, "limitedServer");
        requireServerName(quarantineServer, "quarantineServer");
        if (limitedServer.equals(quarantineServer)) {
            throw new IllegalArgumentException("Bungee disposition route targets must differ");
        }
    }

    static Optional<BungeeDispositionRouteTargets> resolve(
            BungeeDispositionExecutionMode mode,
            Optional<String> limitedServer,
            Optional<String> quarantineServer,
            Set<String> registeredServers) {
        ValidationStatus status = validationStatus(mode, limitedServer, quarantineServer, registeredServers);
        if (status != ValidationStatus.ACTIVE) {
            return Optional.empty();
        }
        return Optional.of(new BungeeDispositionRouteTargets(
                limitedServer.orElseThrow(), quarantineServer.orElseThrow()));
    }

    static ValidationStatus validationStatus(
            BungeeDispositionExecutionMode mode,
            Optional<String> limitedServer,
            Optional<String> quarantineServer,
            Set<String> registeredServers) {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(limitedServer, "limitedServer");
        Objects.requireNonNull(quarantineServer, "quarantineServer");
        Objects.requireNonNull(registeredServers, "registeredServers");
        if (mode != BungeeDispositionExecutionMode.LIMITED_ROUTE) {
            return ValidationStatus.MONITOR_CONFIGURED;
        }
        if (limitedServer.isEmpty()) {
            return ValidationStatus.MISSING_LIMITED_TARGET;
        }
        if (quarantineServer.isEmpty()) {
            return ValidationStatus.MISSING_QUARANTINE_TARGET;
        }
        String limited = limitedServer.orElseThrow();
        String quarantine = quarantineServer.orElseThrow();
        if (limited.equals(quarantine)) {
            return ValidationStatus.IDENTICAL_TARGETS;
        }
        if (!isServerName(limited) || !registeredServers.contains(limited)) {
            return ValidationStatus.LIMITED_TARGET_UNREGISTERED;
        }
        if (!isServerName(quarantine) || !registeredServers.contains(quarantine)) {
            return ValidationStatus.QUARANTINE_TARGET_UNREGISTERED;
        }
        return ValidationStatus.ACTIVE;
    }

    private static void requireServerName(String value, String name) {
        Objects.requireNonNull(value, name);
        if (!isServerName(value)) {
            throw new IllegalArgumentException("invalid Bungee disposition " + name);
        }
    }

    private static boolean isServerName(String value) {
        return value.matches("[a-z0-9][a-z0-9._-]{0,63}");
    }
}
