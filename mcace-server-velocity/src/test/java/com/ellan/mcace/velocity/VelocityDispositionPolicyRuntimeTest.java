package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class VelocityDispositionPolicyRuntimeTest {
    @TempDir Path temporaryDirectory;

    @Test
    void initializationCreatesAndLoadsObservationOnlyBootstrapPolicy() throws Exception {
        Path path = temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb");
        VelocityDispositionPolicyRuntime runtime = VelocityDispositionPolicyRuntime.create(
                path, Clock.systemUTC(), identity());

        VelocityDispositionPolicyStatus status = runtime.refresh();

        assertEquals(ProxyPolicyRefreshStatus.ACTIVE, status.refreshStatus());
        assertEquals(1L, status.activeSequence().orElseThrow());
        assertTrue(status.sourceAvailable());
        assertTrue(Files.isRegularFile(path));
        assertEquals(path.toAbsolutePath().normalize(), status.path());
    }

    @Test
    void corruptOnDiskPolicyIsObservationOnlyAndCannotAffectAdmission() throws Exception {
        Path path = temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb");
        Files.createDirectories(path.getParent());
        Files.writeString(path, "not a signed policy", StandardCharsets.UTF_8);
        VelocityDispositionPolicyRuntime runtime = VelocityDispositionPolicyRuntime.create(
                path, Clock.systemUTC(), identity());

        VelocityDispositionPolicyStatus status = runtime.refresh();

        assertEquals(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY, status.refreshStatus());
        assertTrue(status.activeSequence().isEmpty());
        assertTrue(status.sourceAvailable());
        // The adapter has no Player, ProxyServer, or admission dependency.  Its sole output is
        // this status snapshot, so a rejected policy cannot route or disconnect a player.
        assertFalse(status.refreshStatus() == ProxyPolicyRefreshStatus.ACTIVE);
    }

    private static KeyPair identity() throws Exception {
        return Ed25519Keys.generate(new SecureRandom());
    }
}
