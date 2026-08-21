package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

final class MinecraftWireProfileTest {
    @Test
    void releaseProfilesPinExactVersionProtocolAndPlayPacketLayouts() {
        assertProfile("1.21.11", 774, 21, 0x18, 0x2B, 0x30, 0x74, 0x15, 0x1B, 0x0F);
        assertProfile("26.1.2", 775, 25, 0x18, 0x2C, 0x31, 0x76, 0x16, 0x1C, 0x10);
        assertProfile("26.2", 776, 25, 0x18, 0x2C, 0x31, 0x76, 0x16, 0x1C, 0x10);

        assertEquals(
                List.of("1.21.11", "26.1.2", "26.2"),
                MinecraftWireProfile.releaseProfiles().stream()
                        .map(MinecraftWireProfile::minecraftVersion)
                        .toList());
    }

    @Test
    void releaseProfilesPinConfigurationPacketLayoutAndClientInformationShape() {
        for (MinecraftWireProfile profile : MinecraftWireProfile.releaseProfiles()) {
            MinecraftWireProfile.ConfigurationPackets packets = profile.configuration();
            assertEquals(0x00, packets.clientboundCookieRequest());
            assertEquals(0x01, packets.serverboundCookieResponse());
            assertEquals(0x01, packets.clientboundCustomPayload());
            assertEquals(0x02, packets.serverboundCustomPayload());
            assertEquals(0x02, packets.clientboundDisconnect());
            assertEquals(0x03, packets.clientboundFinish());
            assertEquals(0x03, packets.serverboundFinish());
            assertEquals(0x04, packets.clientboundKeepAlive());
            assertEquals(0x04, packets.serverboundKeepAlive());
            assertEquals(0x05, packets.clientboundPing());
            assertEquals(0x05, packets.serverboundPong());
            assertEquals(0x0E, packets.clientboundSelectKnownPacks());
            assertEquals(0x07, packets.serverboundSelectKnownPacks());
            assertEquals(0x00, packets.serverboundClientInformation());
            assertTrue(profile.clientInformationIncludesParticleStatus());
        }
    }

    @Test
    void versionAndProtocolResolutionAreExactRatherThanThresholdBased() {
        for (MinecraftWireProfile release : MinecraftWireProfile.releaseProfiles()) {
            assertSame(release, MinecraftWireProfile.forMinecraftVersion(release.minecraftVersion()));
            assertSame(release, MinecraftWireProfile.forProtocolVersion(release.protocolVersion()));
        }

        IllegalArgumentException versionFailure = assertThrows(
                IllegalArgumentException.class,
                () -> MinecraftWireProfile.forMinecraftVersion("1.21.12"));
        assertTrue(versionFailure.getMessage().startsWith(
                "MINECRAFT_WIRE_PROFILE_UNSUPPORTED_VERSION|"));

        IllegalArgumentException protocolFailure = assertThrows(
                IllegalArgumentException.class,
                () -> MinecraftWireProfile.forProtocolVersion(777));
        assertTrue(protocolFailure.getMessage().startsWith(
                "MINECRAFT_WIRE_PROFILE_UNSUPPORTED_PROTOCOL|"));
    }

    @Test
    void legacyPaperProfileRemainsExactWithoutEnteringReleaseMatrix() {
        MinecraftWireProfile profile = MinecraftWireProfile.forMinecraftVersion("1.21.1");
        assertEquals(767, profile.protocolVersion());
        assertEquals(21, profile.requiredServerJavaFeature());
        assertFalse(profile.clientInformationIncludesParticleStatus());
        assertEquals(0x19, profile.play().clientboundCustomPayload());
        assertEquals(0x26, profile.play().clientboundKeepAlive());
        assertEquals(0x2B, profile.play().clientboundLogin());
        assertEquals(0x69, profile.play().clientboundStartConfiguration());
        assertEquals(0x12, profile.play().serverboundCustomPayload());
        assertEquals(0x18, profile.play().serverboundKeepAlive());
        assertEquals(0x0C, profile.play().serverboundConfigurationAcknowledged());
        assertFalse(MinecraftWireProfile.releaseProfiles().contains(profile));
    }

    private static void assertProfile(
            String minecraftVersion,
            int protocolVersion,
            int requiredServerJavaFeature,
            int clientboundCustomPayload,
            int clientboundKeepAlive,
            int clientboundLogin,
            int clientboundStartConfiguration,
            int serverboundCustomPayload,
            int serverboundKeepAlive,
            int serverboundConfigurationAcknowledged) {
        MinecraftWireProfile profile = MinecraftWireProfile.forMinecraftVersion(minecraftVersion);
        assertEquals(protocolVersion, profile.protocolVersion());
        assertEquals(requiredServerJavaFeature, profile.requiredServerJavaFeature());
        MinecraftWireProfile.PlayPackets packets = profile.play();
        assertEquals(clientboundCustomPayload, packets.clientboundCustomPayload());
        assertEquals(clientboundKeepAlive, packets.clientboundKeepAlive());
        assertEquals(clientboundLogin, packets.clientboundLogin());
        assertEquals(clientboundStartConfiguration, packets.clientboundStartConfiguration());
        assertEquals(serverboundCustomPayload, packets.serverboundCustomPayload());
        assertEquals(serverboundKeepAlive, packets.serverboundKeepAlive());
        assertEquals(
                serverboundConfigurationAcknowledged,
                packets.serverboundConfigurationAcknowledged());
    }
}
