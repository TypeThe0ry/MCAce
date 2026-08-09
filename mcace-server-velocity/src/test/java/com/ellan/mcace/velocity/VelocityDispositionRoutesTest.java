package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the route validation performed by the Velocity plugin at initialization. */
final class VelocityDispositionRoutesTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void activatesOnlyWithTwoExplicitDistinctRegisteredTargets() throws Exception {
        VelocityDispositionRoutes routes = resolve("""
                enforcement.mode=LIMITED_ROUTE
                limited.server=limited-backend
                quarantine.server=quarantine-backend
                """, Set.of("limited-backend", "quarantine-backend"));

        assertEquals(VelocityAdmissionConfig.Mode.LIMITED_ROUTE, routes.effectiveMode());
        assertEquals(VelocityDispositionRoutes.ValidationStatus.ACTIVE, routes.validationStatus());
        assertEquals("limited-backend", routes.targetFor(DispositionAction.LIMIT).orElseThrow());
        assertEquals("quarantine-backend", routes.targetFor(DispositionAction.QUARANTINE).orElseThrow());
        assertEquals(java.util.Optional.empty(), routes.targetFor(DispositionAction.WARN));
    }

    @Test
    void rejectsEqualTargetsAndFallsBackToMonitor() throws Exception {
        VelocityDispositionRoutes routes = resolve("""
                enforcement.mode=LIMITED_ROUTE
                limited.server=restricted-backend
                quarantine.server=restricted-backend
                """, Set.of("restricted-backend"));

        assertEquals(VelocityAdmissionConfig.Mode.MONITOR, routes.effectiveMode());
        assertEquals(VelocityDispositionRoutes.ValidationStatus.IDENTICAL_TARGETS, routes.validationStatus());
    }

    @Test
    void rejectsUnregisteredTargetsAndFallsBackToMonitor() throws Exception {
        VelocityDispositionRoutes limitedMissing = resolve("""
                enforcement.mode=LIMITED_ROUTE
                limited.server=limited-backend
                quarantine.server=quarantine-backend
                """, Set.of("quarantine-backend"));
        VelocityDispositionRoutes quarantineMissing = resolve("""
                enforcement.mode=LIMITED_ROUTE
                limited.server=limited-backend
                quarantine.server=quarantine-backend
                """, Set.of("limited-backend"));

        assertEquals(VelocityDispositionRoutes.ValidationStatus.LIMITED_TARGET_UNREGISTERED,
                limitedMissing.validationStatus());
        assertEquals(VelocityAdmissionConfig.Mode.MONITOR, limitedMissing.effectiveMode());
        assertEquals(VelocityDispositionRoutes.ValidationStatus.QUARANTINE_TARGET_UNREGISTERED,
                quarantineMissing.validationStatus());
        assertEquals(VelocityAdmissionConfig.Mode.MONITOR, quarantineMissing.effectiveMode());
    }

    @Test
    void legacyLimitedTargetCannotEnableQuarantineOrLimitedRoutingByItself() throws Exception {
        VelocityDispositionRoutes routes = resolve("""
                enforcement.mode=LIMITED_ROUTE
                limited.server=legacy-limited
                """, Set.of("legacy-limited"));

        assertEquals(VelocityAdmissionConfig.Mode.MONITOR, routes.effectiveMode());
        assertEquals(VelocityDispositionRoutes.ValidationStatus.MISSING_QUARANTINE_TARGET,
                routes.validationStatus());
        assertEquals(java.util.Optional.empty(), routes.targetFor(DispositionAction.LIMIT));
        assertEquals(java.util.Optional.empty(), routes.targetFor(DispositionAction.QUARANTINE));
    }

    @Test
    void monitorNeverRoutesEvenIfTargetsExist() throws Exception {
        VelocityDispositionRoutes routes = resolve("""
                enforcement.mode=MONITOR
                limited.server=limited-backend
                quarantine.server=quarantine-backend
                """, Set.of("limited-backend", "quarantine-backend"));

        assertEquals(VelocityAdmissionConfig.Mode.MONITOR, routes.effectiveMode());
        assertEquals(VelocityDispositionRoutes.ValidationStatus.MONITOR_CONFIGURED, routes.validationStatus());
        assertEquals(java.util.Optional.empty(), routes.targetFor(DispositionAction.LIMIT));
        assertEquals(java.util.Optional.empty(), routes.targetFor(DispositionAction.QUARANTINE));
    }

    private VelocityDispositionRoutes resolve(String properties, Set<String> registered) throws Exception {
        Path path = temporaryDirectory.resolve("mcace-" + registered.size() + "-" + properties.hashCode() + ".properties");
        Files.writeString(path, properties);
        VelocityAdmissionConfig configuration = VelocityAdmissionConfig.loadOrCreate(path);
        return VelocityDispositionRoutes.resolve(configuration, registered::contains);
    }
}
