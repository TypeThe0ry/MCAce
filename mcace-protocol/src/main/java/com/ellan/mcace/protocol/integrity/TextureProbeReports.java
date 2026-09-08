package com.ellan.mcace.protocol.integrity;

import com.ellan.mcace.protocol.generated.ResourcePackTextureProbe;
import java.util.Map;
import java.util.Set;

/** Wire bounds shared by sender and receiver; reported content is not trusted execution. */
public final class TextureProbeReports {
    private TextureProbeReports() { }

    public static boolean valid(ResourcePackTextureProbe report) {
        int checked = report.getOpaqueTexturesChecked();
        int transparent = report.getOpaqueTexturesTransparent();
        return report.getUnknownFields().asMap().isEmpty()
                && Set.of("complete", "invalid", "limit-exceeded").contains(report.getStatus())
                && checked >= 0 && checked <= 6 && transparent >= 0 && transparent <= checked
                && (report.getStatus().equals("complete") || (checked == 0 && transparent == 0));
    }

    public static ResourcePackTextureProbe fromMetadata(Map<String, String> metadata) {
        var report = ResourcePackTextureProbe.newBuilder()
                .setStatus(metadata.get("texture_probe_status"))
                .setOpaqueTexturesChecked(Integer.parseInt(metadata.get("opaque_textures_checked")))
                .setOpaqueTexturesTransparent(Integer.parseInt(metadata.get("opaque_textures_transparent")))
                .build();
        if (!valid(report)) throw new IllegalArgumentException("invalid texture probe report");
        return report;
    }

    public static Map<String, String> metadata(ResourcePackTextureProbe report) {
        if (!valid(report)) throw new IllegalArgumentException("invalid texture probe report");
        return Map.of("texture_probe_status", report.getStatus(),
                "opaque_textures_checked", Integer.toString(report.getOpaqueTexturesChecked()),
                "opaque_textures_transparent", Integer.toString(report.getOpaqueTexturesTransparent()),
                "xray_heuristic", report.getOpaqueTexturesTransparent() >= 3
                        ? "opaque-block-transparency" : "none");
    }
}
