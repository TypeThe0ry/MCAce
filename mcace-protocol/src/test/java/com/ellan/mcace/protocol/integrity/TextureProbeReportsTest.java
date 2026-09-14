package com.ellan.mcace.protocol.integrity;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.protocol.generated.ResourcePackTextureProbe;
import org.junit.jupiter.api.Test;

final class TextureProbeReportsTest {
    @Test
    void enforcesFixedCountersAndDoesNotAcceptPartialFailedReports() {
        var valid = ResourcePackTextureProbe.newBuilder().setStatus("complete")
                .setOpaqueTexturesChecked(3).setOpaqueTexturesTransparent(3).build();
        assertTrue(TextureProbeReports.valid(valid));
        assertEquals(valid, TextureProbeReports.fromMetadata(TextureProbeReports.metadata(valid)));
        assertEquals("opaque-block-transparency", TextureProbeReports.metadata(valid).get("xray_heuristic"));
        for (var invalid : java.util.List.of(
                valid.toBuilder().setStatus("server-confirmed").build(),
                valid.toBuilder().setStatus("invalid").build(),
                valid.toBuilder().setOpaqueTexturesChecked(7).build(),
                valid.toBuilder().setOpaqueTexturesChecked(-1).build(),
                valid.toBuilder().setOpaqueTexturesTransparent(4).build(),
                valid.toBuilder().setOpaqueTexturesTransparent(-1).build())) {
            assertFalse(TextureProbeReports.valid(invalid));
            assertThrows(IllegalArgumentException.class, () -> TextureProbeReports.metadata(invalid));
        }
    }
}
