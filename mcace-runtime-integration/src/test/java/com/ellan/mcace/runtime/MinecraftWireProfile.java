package com.ellan.mcace.runtime;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Exact packet layout used by the test-only raw Minecraft peers.
 *
 * <p>Packet identifiers are protocol data, not an ordering relationship. A new protocol must be
 * added as a complete profile after its packet registration order has been verified; callers must
 * never infer packet identifiers from a {@code protocol >= ...} threshold.
 */
record MinecraftWireProfile(
        String minecraftVersion,
        int protocolVersion,
        int requiredServerJavaFeature,
        boolean clientInformationIncludesParticleStatus,
        ConfigurationPackets configuration,
        PlayPackets play) {

    private static final ConfigurationPackets CONFIGURATION_1_21_1_TO_26_2 =
            new ConfigurationPackets(
                    0x00, // clientbound cookie request
                    0x01, // serverbound cookie response
                    0x01, // clientbound custom payload
                    0x02, // serverbound custom payload
                    0x02, // clientbound disconnect
                    0x03, // clientbound finish configuration
                    0x03, // serverbound finish configuration
                    0x04, // clientbound keep alive
                    0x04, // serverbound keep alive
                    0x05, // clientbound ping
                    0x05, // serverbound pong
                    0x0E, // clientbound select known packs
                    0x07, // serverbound select known packs
                    0x00  // serverbound client information
            );

    private static final MinecraftWireProfile LEGACY_1_21_1 = new MinecraftWireProfile(
            "1.21.1",
            767,
            21,
            false,
            CONFIGURATION_1_21_1_TO_26_2,
            new PlayPackets(0x19, 0x26, 0x2B, 0x69, 0x12, 0x18, 0x0C));

    private static final MinecraftWireProfile MINECRAFT_1_21_11 = new MinecraftWireProfile(
            "1.21.11",
            774,
            21,
            true,
            CONFIGURATION_1_21_1_TO_26_2,
            new PlayPackets(0x18, 0x2B, 0x30, 0x74, 0x15, 0x1B, 0x0F));

    private static final MinecraftWireProfile MINECRAFT_26_1_2 = new MinecraftWireProfile(
            "26.1.2",
            775,
            25,
            true,
            CONFIGURATION_1_21_1_TO_26_2,
            new PlayPackets(0x18, 0x2C, 0x31, 0x76, 0x16, 0x1C, 0x10));

    private static final MinecraftWireProfile MINECRAFT_26_2 = new MinecraftWireProfile(
            "26.2",
            776,
            25,
            true,
            CONFIGURATION_1_21_1_TO_26_2,
            new PlayPackets(0x18, 0x2C, 0x31, 0x76, 0x16, 0x1C, 0x10));

    private static final List<MinecraftWireProfile> RELEASE_PROFILES = List.of(
            MINECRAFT_1_21_11,
            MINECRAFT_26_1_2,
            MINECRAFT_26_2);

    private static final Map<String, MinecraftWireProfile> BY_MINECRAFT_VERSION = Map.of(
            LEGACY_1_21_1.minecraftVersion(), LEGACY_1_21_1,
            MINECRAFT_1_21_11.minecraftVersion(), MINECRAFT_1_21_11,
            MINECRAFT_26_1_2.minecraftVersion(), MINECRAFT_26_1_2,
            MINECRAFT_26_2.minecraftVersion(), MINECRAFT_26_2);

    private static final Map<Integer, MinecraftWireProfile> BY_PROTOCOL_VERSION = Map.of(
            LEGACY_1_21_1.protocolVersion(), LEGACY_1_21_1,
            MINECRAFT_1_21_11.protocolVersion(), MINECRAFT_1_21_11,
            MINECRAFT_26_1_2.protocolVersion(), MINECRAFT_26_1_2,
            MINECRAFT_26_2.protocolVersion(), MINECRAFT_26_2);

    MinecraftWireProfile {
        minecraftVersion = Objects.requireNonNull(minecraftVersion, "minecraftVersion").trim();
        if (minecraftVersion.isEmpty()) throw new IllegalArgumentException("minecraftVersion is blank");
        if (protocolVersion <= 0) throw new IllegalArgumentException("protocolVersion must be positive");
        if (requiredServerJavaFeature <= 0) {
            throw new IllegalArgumentException("requiredServerJavaFeature must be positive");
        }
        configuration = Objects.requireNonNull(configuration, "configuration");
        play = Objects.requireNonNull(play, "play");
    }

    static MinecraftWireProfile forMinecraftVersion(String minecraftVersion) {
        String exactVersion = Objects.requireNonNull(minecraftVersion, "minecraftVersion").trim();
        MinecraftWireProfile profile = BY_MINECRAFT_VERSION.get(exactVersion);
        if (profile == null) {
            throw new IllegalArgumentException(
                    "MINECRAFT_WIRE_PROFILE_UNSUPPORTED_VERSION|no exact raw-peer profile for "
                            + exactVersion);
        }
        return profile;
    }

    static MinecraftWireProfile forProtocolVersion(int protocolVersion) {
        MinecraftWireProfile profile = BY_PROTOCOL_VERSION.get(protocolVersion);
        if (profile == null) {
            throw new IllegalArgumentException(
                    "MINECRAFT_WIRE_PROFILE_UNSUPPORTED_PROTOCOL|no exact raw-peer profile for "
                            + protocolVersion);
        }
        return profile;
    }

    static List<MinecraftWireProfile> releaseProfiles() {
        return RELEASE_PROFILES;
    }

    record ConfigurationPackets(
            int clientboundCookieRequest,
            int serverboundCookieResponse,
            int clientboundCustomPayload,
            int serverboundCustomPayload,
            int clientboundDisconnect,
            int clientboundFinish,
            int serverboundFinish,
            int clientboundKeepAlive,
            int serverboundKeepAlive,
            int clientboundPing,
            int serverboundPong,
            int clientboundSelectKnownPacks,
            int serverboundSelectKnownPacks,
            int serverboundClientInformation) { }

    record PlayPackets(
            int clientboundCustomPayload,
            int clientboundKeepAlive,
            int clientboundLogin,
            int clientboundStartConfiguration,
            int serverboundCustomPayload,
            int serverboundKeepAlive,
            int serverboundConfigurationAcknowledged) { }
}
