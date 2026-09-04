package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import com.ellan.mcace.sdk.RiskReason;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
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
        assertEquals(VelocityAdmissionConfig.ClientRequirement.REQUIRE_CLIENT, config.clientRequirement());
        assertEquals(true, config.requireClient());
        assertEquals(false, config.storage().enabled());
        assertEquals("mcace-velocity", config.policy().serverId());
        assertEquals(java.util.List.of("1.21.11"), config.policy().minecraftVersions());
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
    void existingConfigurationWithoutClientRequirementRetainsLegacyOptionalProfile() throws Exception {
        Path path = temporaryDirectory.resolve("legacy-client-profile.properties");
        Files.writeString(path, "enforcement.mode=MONITOR\n");

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(VelocityAdmissionConfig.ClientRequirement.OPTIONAL, config.clientRequirement());
        assertEquals(false, config.requireClient());
    }

    @Test
    void parsesExplicitOptionalAndStrictClientRequirementProfiles() throws Exception {
        Path optionalPath = temporaryDirectory.resolve("optional-client-profile.properties");
        Files.writeString(optionalPath, "client.requirement=OPTIONAL\n");
        assertEquals(VelocityAdmissionConfig.ClientRequirement.OPTIONAL,
                VelocityAdmissionConfig.loadOrCreate(optionalPath).clientRequirement());

        Path strictPath = temporaryDirectory.resolve("strict-client-profile.properties");
        Files.writeString(strictPath, "client.requirement=STRICT\n");
        VelocityAdmissionConfig strict = VelocityAdmissionConfig.loadOrCreate(strictPath);
        assertEquals(VelocityAdmissionConfig.ClientRequirement.REQUIRE_CLIENT, strict.clientRequirement());
        assertEquals(true, strict.requireClient());
    }

    @Test
    void rejectsInvalidClientRequirementProfile() throws Exception {
        Path blank = temporaryDirectory.resolve("blank-client-profile.properties");
        Files.writeString(blank, "client.requirement=   \n");
        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(blank));

        Path unknown = temporaryDirectory.resolve("unknown-client-profile.properties");
        Files.writeString(unknown, "client.requirement=ENFORCE_EVERYTHING\n");
        assertThrows(IOException.class, () -> VelocityAdmissionConfig.loadOrCreate(unknown));
    }

    @Test
    void missingClientSignalIsRecognizedWithoutTreatingOtherLimitedStatesAsMissingClient() {
        PlayerSecuritySnapshot missing = new PlayerSecuritySnapshot(
                UUID.randomUUID(), TrustLevel.UNKNOWN, AdmissionStatus.LIMITED, 20, RiskBand.WATCH,
                "test-policy", Instant.EPOCH,
                List.of(new RiskReason("MISSING_MCACE", 20, "timeout", Instant.EPOCH, true)));
        PlayerSecuritySnapshot otherLimited = new PlayerSecuritySnapshot(
                UUID.randomUUID(), TrustLevel.UNKNOWN, AdmissionStatus.LIMITED, 20, RiskBand.WATCH,
                "test-policy", Instant.EPOCH,
                List.of(new RiskReason("PROTOCOL_VIOLATION", 20, "protocol", Instant.EPOCH, true)));

        assertTrue(MCAceVelocityPlugin.isMissingClientSnapshot(missing));
        assertFalse(MCAceVelocityPlugin.isMissingClientSnapshot(otherLimited));
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
    void acceptsSupervisedHumanReviewTimeoutWithinBound() throws Exception {
        Path path = temporaryDirectory.resolve("extended-timeout.properties");
        Files.writeString(path, "handshake.timeout.seconds=300\n");

        VelocityAdmissionConfig config = VelocityAdmissionConfig.loadOrCreate(path);

        assertEquals(Duration.ofSeconds(300), config.handshakeTimeout());
    }

    @Test
    void rejectsTimeoutBeyondSupervisedHumanReviewBound() throws Exception {
        Path path = temporaryDirectory.resolve("too-long-timeout.properties");
        Files.writeString(path, "handshake.timeout.seconds=301\n");

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
