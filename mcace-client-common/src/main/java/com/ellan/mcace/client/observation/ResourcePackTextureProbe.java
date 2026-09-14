package com.ellan.mcace.client.observation;

import com.ellan.mcace.client.integrity.IntegrityScanCancellation;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipInputStream;
import javax.imageio.ImageIO;
import javax.imageio.stream.MemoryCacheImageInputStream;

/** Bounded content observations, never a cheat verdict or authorization. */
final class ResourcePackTextureProbe {
    private static final int MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;
    private static final int MAX_EXPANDED_BYTES = 8 * 1024 * 1024;
    private static final int MAX_PNG_BYTES = 1024 * 1024;
    private static final int MAX_ENTRIES = 4096;
    private static final Set<String> OPAQUE_TEXTURES = Set.of(
            "assets/minecraft/textures/block/stone.png",
            "assets/minecraft/textures/block/deepslate.png",
            "assets/minecraft/textures/block/dirt.png",
            "assets/minecraft/textures/block/gravel.png",
            "assets/minecraft/textures/block/sand.png",
            "assets/minecraft/textures/block/netherrack.png");

    private ResourcePackTextureProbe() { }

    static Map<String, String> inspect(Path file, String expectedSha256,
            IntegrityScanCancellation cancellation) throws IntegrityScanException {
        cancellation.check();
        try {
            if (Files.size(file) > MAX_ARCHIVE_BYTES) return result("limit-exceeded", 0, 0);
            byte[] archive;
            try (var input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
                archive = input.readNBytes(MAX_ARCHIVE_BYTES + 1);
            }
            cancellation.check();
            if (archive.length > MAX_ARCHIVE_BYTES) return result("limit-exceeded", 0, 0);
            if (!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(archive))
                    .equalsIgnoreCase(expectedSha256)) {
                throw new IntegrityScanException("resource pack changed after its integrity scan");
            }
            if (archive.length < 4 || archive[0] != 'P' || archive[1] != 'K') {
                return result("invalid", 0, 0);
            }
            int expanded = 0;
            int entries = 0;
            int checked = 0;
            int transparent = 0;
            Set<String> seen = new HashSet<>();
            try (var zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
                for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                    cancellation.check();
                    if (++entries > MAX_ENTRIES) return result("limit-exceeded", 0, 0);
                    boolean target = OPAQUE_TEXTURES.contains(entry.getName());
                    if (target && !seen.add(entry.getName())) return result("invalid", 0, 0);
                    var png = target ? new java.io.ByteArrayOutputStream() : null;
                    byte[] buffer = new byte[8192];
                    int count;
                    while ((count = zip.read(buffer)) != -1) {
                        cancellation.check();
                        expanded += count;
                        if (expanded > MAX_EXPANDED_BYTES) return result("limit-exceeded", 0, 0);
                        if (png != null) {
                            if (png.size() + count > MAX_PNG_BYTES) return result("limit-exceeded", 0, 0);
                            png.write(buffer, 0, count);
                        }
                    }
                    if (target) {
                        boolean hidden = mostlyTransparentPng(png.toByteArray());
                        checked++;
                        if (hidden) transparent++;
                    }
                }
            }
            return result("complete", checked, transparent);
        } catch (IOException | IllegalArgumentException exception) {
            return result("invalid", 0, 0);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean mostlyTransparentPng(byte[] bytes) throws IOException {
        try (var input = new MemoryCacheImageInputStream(new ByteArrayInputStream(bytes))) {
            var readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) throw new IOException("unsupported texture");
            var reader = readers.next();
            try {
                if (!reader.getFormatName().equalsIgnoreCase("png")) throw new IOException("not PNG");
                reader.setInput(input, true, true);
                int width = reader.getWidth(0);
                int height = reader.getHeight(0);
                if (width < 1 || height < 1 || width > 512 || height > 512) {
                    throw new IOException("texture dimensions outside probe budget");
                }
                var image = reader.read(0);
                int transparent = 0;
                for (int y = 0; y < height; y++) {
                    for (int x = 0; x < width; x++) {
                        if ((image.getRGB(x, y) >>> 24) < 32) transparent++;
                    }
                }
                return transparent * 10L >= (long) width * height * 9;
            } finally { reader.dispose(); }
        }
    }

    private static Map<String, String> result(String status, int checked, int transparent) {
        return Map.of("texture_probe_status", status,
                "opaque_textures_checked", Integer.toString(checked),
                "opaque_textures_transparent", Integer.toString(transparent),
                "xray_heuristic", transparent >= 3 ? "opaque-block-transparency" : "none");
    }
}
