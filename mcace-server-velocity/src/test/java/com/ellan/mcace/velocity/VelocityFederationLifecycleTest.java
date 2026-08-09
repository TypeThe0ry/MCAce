package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.core.federation.FederationConfiguration;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class VelocityFederationLifecycleTest {
    @TempDir Path directory;

    @Test
    void createsDisabledEmptyPeerConfigurationAndReusesPersistedIdentity() throws Exception {
        try (VelocityFederationLifecycle lifecycle = VelocityFederationLifecycle.load(
                directory, Clock.systemUTC(), new SecureRandom(), Ed25519Keys.generate(new SecureRandom()))) {
            assertFalse(lifecycle.runtime().status().enabled());
            assertTrue(lifecycle.runtime().configuration().peers().isEmpty());
            assertTrue(Files.isRegularFile(directory.resolve(FederationConfiguration.FILE_NAME)));
        }
    }

    @Test
    void invalidFederationConfigurationFallsBackDisabledWithoutBreakingProxy() throws Exception {
        Files.writeString(directory.resolve(FederationConfiguration.FILE_NAME), "enabled=true\nunknown=value\n");
        java.util.concurrent.atomic.AtomicInteger failures = new java.util.concurrent.atomic.AtomicInteger();
        VelocityFederationLifecycle lifecycle = VelocityFederationLifecycle.loadOrDisabled(
                directory, Clock.systemUTC(), new SecureRandom(), Ed25519Keys.generate(new SecureRandom()),
                "mcace-velocity", ignored -> failures.incrementAndGet());
        assertFalse(lifecycle.runtime().status().enabled());
        assertEquals("mcace-velocity", lifecycle.runtime().status().localNetworkId());
        assertEquals(1, failures.get());
        lifecycle.close();
    }

    @Test
    void invalidAuditPathFallsBackDisabledWithoutBreakingProxy() throws Exception {
        Files.createDirectory(directory.resolve("federation-audit.log"));
        java.util.concurrent.atomic.AtomicInteger failures = new java.util.concurrent.atomic.AtomicInteger();
        VelocityFederationLifecycle lifecycle = VelocityFederationLifecycle.loadOrDisabled(
                directory, Clock.systemUTC(), new SecureRandom(), Ed25519Keys.generate(new SecureRandom()),
                "mcace-velocity", ignored -> failures.incrementAndGet());
        assertFalse(lifecycle.runtime().status().enabled());
        assertEquals("mcace-velocity", lifecycle.runtime().status().localNetworkId());
        assertEquals(1, failures.get());
        lifecycle.close();
    }

    @Test
    void failedReloadRetainsLastGoodConfiguration() throws Exception {
        try (VelocityFederationLifecycle lifecycle = VelocityFederationLifecycle.load(
                directory, Clock.systemUTC(), new SecureRandom(), Ed25519Keys.generate(new SecureRandom()))) {
            FederationConfiguration before = lifecycle.runtime().configuration();
            Files.writeString(directory.resolve(FederationConfiguration.FILE_NAME),
                    "schema.version=1\nenabled=true\nunknown=value\n");
            java.util.concurrent.atomic.AtomicInteger failures = new java.util.concurrent.atomic.AtomicInteger();

            assertFalse(lifecycle.reload(ignored -> failures.incrementAndGet()));
            assertEquals(before, lifecycle.runtime().configuration());
            assertEquals(1, failures.get());
        }
    }
}
