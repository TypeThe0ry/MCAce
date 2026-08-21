package com.ellan.mcace.core.context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.BackendContextUpdate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class BackendContextCodecTest {
    private static final Instant NOW = Instant.parse("2026-08-12T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void roundTripsAContextWithoutAnyBackendIdentityField() throws Exception {
        BackendContextCodec codec = new BackendContextCodec(CLOCK);
        BackendContextReport report = new BackendContextReport(
                PLAYER, 41L, 7L, "minecraft:overworld", "survival", NOW);

        byte[] encoded = codec.encode(report);

        assertEquals(report, codec.decode(encoded));
        BackendContextUpdate wire = BackendContextUpdate.parseFrom(encoded);
        assertEquals(7, wire.getDescriptorForType().getFields().size());
        assertEquals(null, wire.getDescriptorForType().findFieldByName("backend_id"));
    }

    @Test
    void rejectsOversizedStaleUnknownModeAndNonCanonicalUuidFrames() {
        BackendContextCodec codec = new BackendContextCodec(CLOCK);
        assertThrows(BackendContextException.class,
                () -> codec.decode(new byte[ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES + 1]));
        assertThrows(BackendContextException.class, () -> codec.encode(new BackendContextReport(
                PLAYER, 1L, 1L, "minecraft:overworld", "survival",
                NOW.minus(BackendContextCodec.MAX_REPORT_AGE).minus(Duration.ofMillis(1)))));
        assertThrows(BackendContextException.class, () -> codec.encode(new BackendContextReport(
                PLAYER, 1L, 1L, "minecraft:overworld", "unknown", NOW)));

        UUID alphabeticPlayer = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        byte[] nonCanonical = BackendContextUpdate.newBuilder()
                .setSchemaVersion(BackendContextCodec.SCHEMA_VERSION)
                .setPlayerUuid(alphabeticPlayer.toString().toUpperCase())
                .setAdmissionTransportSequence(1L)
                .setReportSequence(1L)
                .setWorldId("minecraft:overworld")
                .setGameMode("survival")
                .setObservedAtEpochMs(NOW.toEpochMilli())
                .build().toByteArray();
        assertThrows(BackendContextException.class, () -> codec.decode(nonCanonical));
    }
}
