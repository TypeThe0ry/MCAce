package com.ellan.mcace.client.observation;

import static org.junit.jupiter.api.Assertions.*;

import com.ellan.mcace.client.integrity.IntegrityScanCancellation;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ResourcePackTextureProbeTest {
    @TempDir Path root;

    @Test
    void transparentOpaqueBlocksProduceContentFeatureRegardlessOfArchiveName() throws Exception {
        Path file = pack("ordinary-name.zip", Map.of(
                texture("stone"), png(16, 16, 0x00ffffff),
                texture("dirt"), png(16, 16, 0x00ffffff),
                texture("deepslate"), png(16, 16, 0x00ffffff)));
        var result = inspect(file);
        assertEquals("complete", result.get("texture_probe_status"));
        assertEquals("3", result.get("opaque_textures_checked"));
        assertEquals("3", result.get("opaque_textures_transparent"));
        assertEquals("opaque-block-transparency", result.get("xray_heuristic"));
    }

    @Test
    void nameGlassAndOpaqueRecolorsDoNotTrigger() throws Exception {
        Path file = pack("xray-cheat.zip", Map.of(
                texture("stone"), png(16, 16, 0xffff00ff),
                texture("dirt"), png(16, 16, 0xffff00ff),
                texture("glass"), png(16, 16, 0x00ffffff)));
        assertEquals("none", inspect(file).get("xray_heuristic"));
        assertEquals("2", inspect(file).get("opaque_textures_checked"));
    }

    @Test
    void oneTransparentOverrideDoesNotMeetMultiBlockThreshold() throws Exception {
        Path file = pack("one.zip", Map.of(texture("stone"), png(16, 16, 0)));
        assertEquals("1", inspect(file).get("opaque_textures_transparent"));
        assertEquals("none", inspect(file).get("xray_heuristic"));
    }

    @Test
    void malformedAndOversizedImagesDiscardPartialFindings() throws Exception {
        for (byte[] bytes : new byte[][]{new byte[]{1, 2, 3}, png(513, 1, 0)}) {
            Path file = pack("invalid-" + bytes.length + ".zip", Map.of(texture("stone"), bytes));
            assertEquals("invalid", inspect(file).get("texture_probe_status"));
            assertEquals("none", inspect(file).get("xray_heuristic"));
        }
    }

    @Test
    void decompressionBudgetIsEnforcedEvenForUnrelatedEntries() throws Exception {
        Path file = pack("bomb.zip", Map.of("unused.bin", new byte[9 * 1024 * 1024]));
        assertEquals("limit-exceeded", inspect(file).get("texture_probe_status"));
        assertEquals("none", inspect(file).get("xray_heuristic"));
    }

    @Test
    void changedBytesCannotBeAttributedToScannedHash() throws Exception {
        Path file = pack("changed.zip", Map.of(texture("stone"), png(16, 16, 0)));
        assertThrows(IntegrityScanException.class, () -> ResourcePackTextureProbe.inspect(
                file, "0".repeat(64), IntegrityScanCancellation.NONE));
    }

    @Test
    void cancelledProbeDoesNotReadEvenMissingFile() {
        assertThrows(IntegrityScanException.class, () -> ResourcePackTextureProbe.inspect(
                root.resolve("missing.zip"), "0".repeat(64), () -> true));
    }

    private Map<String, String> inspect(Path file) throws Exception {
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        return ResourcePackTextureProbe.inspect(file, sha, IntegrityScanCancellation.NONE);
    }

    private Path pack(String name, Map<String, byte[]> entries) throws Exception {
        Path file = root.resolve(name);
        try (var zip = new ZipOutputStream(Files.newOutputStream(file))) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return file;
    }

    private static String texture(String name) {
        return "assets/minecraft/textures/block/" + name + ".png";
    }

    private static byte[] png(int width, int height, int argb) throws Exception {
        var image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < height; y++) for (int x = 0; x < width; x++) image.setRGB(x, y, argb);
        var output = new ByteArrayOutputStream();
        assertTrue(ImageIO.write(image, "png", output));
        return output.toByteArray();
    }
}
