package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class VelocityAdmissionConfigTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void createsSafeMonitorDefault() throws Exception {
        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(temporaryDirectory.resolve("mcace.properties"));

        assertEquals(VelocityAdmissionConfig.Mode.MONITOR, config.mode());
        assertEquals(java.util.Optional.empty(), config.limitedServer());
        assertEquals(java.util.Optional.empty(), config.quarantineServer());
        assertEquals(Duration.ofSeconds(5), config.handshakeTimeout());
        assertEquals(false, config.storage().enabled());
        assertEquals("mcace-velocity", config.policy().serverId());
        assertEquals(java.util.List.of("1.21.1"), config.policy().minecraftVersions());
        assertEquals(java.util.List.of("fabric-phase2-dev"), config.policy().clientBuildIds());
        assertEquals(false, config.heartbeatMissing().enabled());
    }

    @Test
    void loadsExplicitIndependentLimitedAndQuarantineTargets() throws Exception {
        Path path = temporaryDirectory.resolve("mcace.properties");
        Files.writeString(path, """
                enforcement.mode=LIMITED_ROUTE
                disposition.limited.server=limited-backend
                disposition.quarantine.server=quarantine-backend
                handshake.timeout.seconds=8
                """);

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(VelocityAdmissionConfig.Mode.LIMITED_ROUTE, config.mode());
        assertEquals(java.util.Optional.of("limited-backend"), config.limitedServer());
        assertEquals(java.util.Optional.of("quarantine-backend"), config.quarantineServer());
        assertEquals(Duration.ofSeconds(8), config.handshakeTimeout());
    }

    @Test
    void legacyLimitedTargetIsReadOnlyForLimitAndNeverCopiedToQuarantine() throws Exception {
        Path path = temporaryDirectory.resolve("legacy.properties");
        Files.writeString(path, "enforcement.mode=LIMITED_ROUTE\nlimited.server=legacy-limited\n");

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(java.util.Optional.of("legacy-limited"), config.limitedServer());
        assertEquals(java.util.Optional.empty(), config.quarantineServer());
    }

    @Test
    void legacyUnprefixedQuarantineAliasDoesNotAffectLimitedTarget() throws Exception {
        Path path = temporaryDirectory.resolve("legacy-quarantine.properties");
        Files.writeString(path, "enforcement.mode=LIMITED_ROUTE\nquarantine.server=legacy-quarantine\n");

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(java.util.Optional.empty(), config.limitedServer());
        assertEquals(java.util.Optional.of("legacy-quarantine"), config.quarantineServer());
    }

    @Test
    void rejectsConflictingCanonicalAndLegacyRouteAliases() throws Exception {
        Path path = temporaryDirectory.resolve("conflicting-route.properties");
        Files.writeString(path, """
                disposition.limited.server=canonical-limited
                limited.server=legacy-limited
                """);

        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(path));
    }

    @Test
    void rejectsBlankExplicitRouteTarget() throws Exception {
        Path path = temporaryDirectory.resolve("blank-route.properties");
        Files.writeString(path, "limited.server=   \n");

        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(path));
    }

    @Test
    void rejectsUnsafeTimeout() throws Exception {
        Path path = temporaryDirectory.resolve("mcace.properties");
        Files.writeString(path, "handshake.timeout.seconds=0\n");

        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(path));
    }

    @Test
    void loadsBoundedOptInHeartbeatMissingControl() throws Exception {
        Path path = temporaryDirectory.resolve("heartbeat.properties");
        Files.writeString(path, """
                enforcement.mode=LIMITED_ROUTE
                heartbeat.missing.enabled=true
                heartbeat.missing.consecutive-polls=5
                heartbeat.missing.action=LIMITED_ROUTE
                """);

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(true, config.heartbeatMissing().enabled());
        assertEquals(5, config.heartbeatMissing().consecutivePolls());
        assertEquals(com.ellan.mcace.core.session.HeartbeatMissingPolicy.Action.LIMITED_ROUTE,
                config.heartbeatMissing().action());
    }

    @Test
    void rejectsUnsafeHeartbeatMissingConfiguration() throws Exception {
        Path threshold = temporaryDirectory.resolve("heartbeat-threshold.properties");
        Files.writeString(threshold, "heartbeat.missing.enabled=true\nheartbeat.missing.consecutive-polls=1\n");
        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(threshold));

        Path action = temporaryDirectory.resolve("heartbeat-action.properties");
        Files.writeString(action, "heartbeat.missing.enabled=true\nheartbeat.missing.action=DENY\n");
        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(action));
    }

    @Test
    void loadsBoundedSignedPolicyReleaseMetadata() throws Exception {
        Path path = temporaryDirectory.resolve("mcace.properties");
        Files.writeString(path, """
                policy.server-id=network-east
                policy.minecraft-versions=1.21.1, 1.21.4
                policy.client-build-ids=fabric-release-17, fabric-release-18
                """);

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals("network-east", config.policy().serverId());
        assertEquals(java.util.List.of("1.21.1", "1.21.4"), config.policy().minecraftVersions());
        assertEquals(java.util.List.of("fabric-release-17", "fabric-release-18"),
                config.policy().clientBuildIds());
    }

    @Test
    void rejectsDuplicateOrBlankReleaseMetadata() throws Exception {
        Path duplicate = temporaryDirectory.resolve("duplicate.properties");
        Files.writeString(duplicate, "policy.minecraft-versions=1.21.1,1.21.1\n");
        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(duplicate));

        Path blank = temporaryDirectory.resolve("blank.properties");
        Files.writeString(blank, "policy.client-build-ids=fabric-release-17,\n");
        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(blank));
    }

    @Test
    void loadsPostgresSettingsWithoutPersistingPassword() throws Exception {
        Path path = temporaryDirectory.resolve("mcace.properties");
        Files.writeString(path, """
                storage.enabled=true
                storage.jdbc-url=jdbc:postgresql://db.internal:5432/mcace
                storage.username=mcace_writer
                storage.password-env=MCACE_DB_PASSWORD
                """);

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(true, config.storage().enabled());
        assertEquals("mcace_writer", config.storage().username());
        assertEquals("MCACE_DB_PASSWORD", config.storage().passwordEnvironmentVariable());
        assertEquals(true, config.storage().migrateOnStart());
    }

    @Test
    void rejectsEnabledStorageWithUnsafePasswordVariableName() throws Exception {
        Path path = temporaryDirectory.resolve("mcace.properties");
        Files.writeString(path, "storage.enabled=true\nstorage.password-env=contains-lowercase\n");

        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(path));
    }
}
