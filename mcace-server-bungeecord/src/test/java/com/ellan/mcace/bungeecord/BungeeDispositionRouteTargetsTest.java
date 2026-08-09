package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class BungeeDispositionRouteTargetsTest {
    @Test
    void limitedRouteRequiresBothExplicitDistinctRegisteredTargets() {
        Set<String> registered = Set.of("limited", "quarantine");

        assertEquals(Optional.empty(), BungeeDispositionRouteTargets.resolve(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.empty(),
                Optional.of("quarantine"), registered));
        assertEquals(Optional.empty(), BungeeDispositionRouteTargets.resolve(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                Optional.of("limited"), registered));
        assertEquals(Optional.empty(), BungeeDispositionRouteTargets.resolve(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                Optional.of("unregistered"), registered));
    }

    @Test
    void validLimitedRoutePreservesIndependentTargetsAndMonitorCannotEnableThem() {
        Optional<BungeeDispositionRouteTargets> resolved = BungeeDispositionRouteTargets.resolve(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                Optional.of("quarantine"), Set.of("limited", "quarantine"));

        assertTrue(resolved.isPresent());
        assertEquals("limited", resolved.orElseThrow().limitedServer());
        assertEquals("quarantine", resolved.orElseThrow().quarantineServer());
        assertEquals(Optional.empty(), BungeeDispositionRouteTargets.resolve(
                BungeeDispositionExecutionMode.MONITOR, Optional.of("limited"),
                Optional.of("quarantine"), Set.of("limited", "quarantine")));
    }

    @Test
    void exposesStableContentFreeValidationReasons() {
        Set<String> registered = Set.of("limited", "quarantine");

        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.MONITOR_CONFIGURED,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.MONITOR, Optional.of("limited"),
                        Optional.of("quarantine"), registered));
        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.MISSING_LIMITED_TARGET,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.empty(),
                        Optional.of("quarantine"), registered));
        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.MISSING_QUARANTINE_TARGET,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                        Optional.empty(), registered));
        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.IDENTICAL_TARGETS,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                        Optional.of("limited"), registered));
        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.LIMITED_TARGET_UNREGISTERED,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("missing"),
                        Optional.of("quarantine"), registered));
        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.QUARANTINE_TARGET_UNREGISTERED,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                        Optional.of("missing"), registered));
        assertEquals(BungeeDispositionRouteTargets.ValidationStatus.ACTIVE,
                BungeeDispositionRouteTargets.validationStatus(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                        Optional.of("quarantine"), registered));
    }
}
