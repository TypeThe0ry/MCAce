package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BungeeBridgeConfigurationTest {
    @Test
    void createsFabricFirstDefaults(@TempDir Path directory) throws Exception {
        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(
                directory.resolve("mcace.properties"));

        assertEquals("mcace-bungeecord", configuration.serverId());
        assertEquals("1.21.11", configuration.minecraftVersion());
        assertEquals(Duration.ofSeconds(5), configuration.handshakeTimeout());
        assertEquals(BungeeBridgeConfiguration.ClientRequirement.REQUIRE_CLIENT,
                configuration.clientRequirement());
        assertEquals(true, configuration.requireClient());
        assertEquals(false, configuration.heartbeatMissingPolicy().enabled());
        assertEquals(java.util.Optional.empty(), configuration.limitedServer());
        assertEquals(java.util.Optional.empty(), configuration.quarantineServer());
        assertEquals(BungeeBridgeConfiguration.DEFAULT_CONTENT,
                Files.readString(directory.resolve("mcace.properties")));
    }

    @Test
    void rejectsOutOfRangeHandshakeTimeout() {
        assertThrows(IllegalArgumentException.class, () -> new BungeeBridgeConfiguration(
                "bungee", "1.21.1", "fabric-build", Duration.ofSeconds(31)));
    }

    @Test
    void explicitLimitedRouteConfigurationIsParsedAndBounded(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("mcace.properties");
        Files.writeString(path, """
                server.id=bungee
                minecraft.version=1.21.1
                client.build-id=fabric-build
                handshake.timeout.seconds=5
                disposition.enforcement.mode=LIMITED_ROUTE
                disposition.limited.server=limited-eu
                disposition.quarantine.server=quarantine-eu
                """);

        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(path);

        assertEquals(BungeeDispositionExecutionMode.LIMITED_ROUTE, configuration.dispositionExecutionMode());
        assertEquals(java.util.Optional.of("limited-eu"), configuration.limitedServer());
        assertEquals(java.util.Optional.of("quarantine-eu"), configuration.quarantineServer());
    }

    @Test
    void existingConfigurationWithoutClientRequirementRetainsLegacyOptionalProfile(@TempDir Path directory)
            throws Exception {
        Path path = directory.resolve("legacy-client-profile.properties");
        Files.writeString(path, "disposition.enforcement.mode=MONITOR\n");

        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(path);

        assertEquals(BungeeBridgeConfiguration.ClientRequirement.OPTIONAL,
                configuration.clientRequirement());
        assertEquals(false, configuration.requireClient());
    }

    @Test
    void parsesExplicitOptionalAndStrictClientRequirementProfiles(@TempDir Path directory) throws Exception {
        Path optionalPath = directory.resolve("optional-client-profile.properties");
        Files.writeString(optionalPath, "client.requirement=OPTIONAL\n");
        assertEquals(BungeeBridgeConfiguration.ClientRequirement.OPTIONAL,
                BungeeBridgeConfiguration.loadOrCreate(optionalPath).clientRequirement());

        Path strictPath = directory.resolve("strict-client-profile.properties");
        Files.writeString(strictPath, "client.requirement=STRICT\n");
        BungeeBridgeConfiguration strict = BungeeBridgeConfiguration.loadOrCreate(strictPath);
        assertEquals(BungeeBridgeConfiguration.ClientRequirement.REQUIRE_CLIENT, strict.clientRequirement());
        assertEquals(true, strict.requireClient());
    }

    @Test
    void rejectsInvalidClientRequirementProfile(@TempDir Path directory) throws Exception {
        Path blank = directory.resolve("blank-client-profile.properties");
        Files.writeString(blank, "client.requirement=   \n");
        assertThrows(java.io.IOException.class, () -> BungeeBridgeConfiguration.loadOrCreate(blank));

        Path unknown = directory.resolve("unknown-client-profile.properties");
        Files.writeString(unknown, "client.requirement=ENFORCE_EVERYTHING\n");
        assertThrows(java.io.IOException.class, () -> BungeeBridgeConfiguration.loadOrCreate(unknown));
    }

    @Test
    void legacyRestrictedServerMigratesOnlyTheLimitTarget(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("mcace.properties");
        Files.writeString(path, """
                disposition.enforcement.mode=LIMITED_ROUTE
                disposition.restricted.server=restricted-eu
                disposition.quarantine.server=quarantine-eu
                """);

        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(path);

        assertEquals(java.util.Optional.of("restricted-eu"), configuration.limitedServer());
        assertEquals(java.util.Optional.of("quarantine-eu"), configuration.quarantineServer());
    }

    @Test
    void legacyRestrictedServerNeverSuppliesTheQuarantineTarget(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("mcace.properties");
        Files.writeString(path, """
                disposition.enforcement.mode=LIMITED_ROUTE
                disposition.restricted.server=restricted-eu
                """);

        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(path);

        assertEquals(java.util.Optional.of("restricted-eu"), configuration.limitedServer());
        assertEquals(java.util.Optional.empty(), configuration.quarantineServer());
    }

    @Test
    void rejectsUnknownDispositionMode(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("mcace.properties");
        Files.writeString(path, "disposition.enforcement.mode=execute-everything\n");

        assertThrows(java.io.IOException.class, () -> BungeeBridgeConfiguration.loadOrCreate(path));
    }

    @Test
    void loadsBoundedOptInHeartbeatMissingControl(@TempDir Path directory) throws Exception {
        Path path = directory.resolve("heartbeat.properties");
        Files.writeString(path, """
                disposition.enforcement.mode=LIMITED_ROUTE
                heartbeat.missing.enabled=true
                heartbeat.missing.consecutive-polls=5
                heartbeat.missing.action=LIMITED_ROUTE
                """);

        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(path);

        assertEquals(true, configuration.heartbeatMissingPolicy().enabled());
        assertEquals(5, configuration.heartbeatMissingPolicy().consecutiveMissingPolls());
        assertEquals(com.ellan.mcace.core.session.HeartbeatMissingPolicy.Action.LIMITED_ROUTE,
                configuration.heartbeatMissingPolicy().action());
    }

    @Test
    void rejectsUnsafeHeartbeatMissingConfiguration(@TempDir Path directory) throws Exception {
        Path threshold = directory.resolve("heartbeat-threshold.properties");
        Files.writeString(threshold, "heartbeat.missing.enabled=true\nheartbeat.missing.consecutive-polls=301\n");
        assertThrows(java.io.IOException.class, () -> BungeeBridgeConfiguration.loadOrCreate(threshold));

        Path action = directory.resolve("heartbeat-action.properties");
        Files.writeString(action, "heartbeat.missing.enabled=true\nheartbeat.missing.action=DENY\n");
        assertThrows(java.io.IOException.class, () -> BungeeBridgeConfiguration.loadOrCreate(action));
    }
}
