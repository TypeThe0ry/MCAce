package com.ellan.mcace.client.observation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import com.ellan.mcace.client.integrity.PolicyDrivenIntegrityCollector;
import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.DispositionEngine;
import com.ellan.mcace.core.disposition.DispositionPolicy;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ArtifactObservationCollectorTest {
    @TempDir Path root;

    @Test
    void convertsOnlyPolicyGrantedArtifactsIntoNeutralDeterministicObservations() throws Exception {
        Path mods = Files.createDirectories(root.resolve("mods"));
        writeZip(mods.resolve("z-accessibility.jar"), "{\"id\":\"accessibilityplus\",\"version\":\"1.4.2\"}");
        writeZip(mods.resolve("a-helper.jar"), "{\"id\":\"legitimatehelper\",\"version\":\"2.0.0\"}");
        Path resourcePacks = Files.createDirectories(root.resolve("resourcepacks"));
        Files.writeString(resourcePacks.resolve("ore-highlight.zip"), "opaque resource-pack fixture");
        Files.writeString(Files.createDirectories(root.resolve("shaderpacks")).resolve("cinematic.zip"), "shader fixture");

        SecurityPolicy policy = policy(
                directory("mods", "mods", ".jar"),
                directory("resourcepacks", "resourcepacks", ".zip"),
                directory("shaderpacks", "shaderpacks", ".zip"));
        ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC()).collect(root, policy);

        List<ArtifactObservation> observations = new ArtifactObservationCollector().collect(root, policy, bundle);

        assertEquals(4, observations.size());
        assertEquals("accessibilityplus", observations.getFirst().identifier());
        ArtifactObservation accessibility = observations.stream()
                .filter(observation -> observation.identifier().equals("accessibilityplus"))
                .findFirst().orElseThrow();
        assertEquals("1.4.2", accessibility.version());
        assertEquals(ObservationOrigin.CLIENT_REPORTED, accessibility.origin());
        assertEquals(Confidence.LOW, accessibility.confidence());
        assertFalse(accessibility.foundationSecurity());
        assertEquals(DispositionAction.OBSERVE, new DispositionEngine().evaluate(
                new DispositionPolicy("empty", List.of()),
                new EvaluationContext(UUID.randomUUID(), "proxy", "backend", "world", "survival", Set.of("member"), Instant.EPOCH),
                accessibility).action());

        ArtifactObservation pack = observations.stream()
                .filter(observation -> observation.metadata().get("artifact_path").equals("ore-highlight.zip"))
                .findFirst().orElseThrow();
        assertEquals("resource-pack-manifest", pack.metadata().get("classification_input"));
        assertEquals("not-applicable", pack.metadata().get("metadata_status"));
        assertEquals("unknown", pack.identifier());
    }

    @Test
    void untrustedOrMaliciousFabricMetadataIsNeutralInsteadOfACheatFinding() throws Exception {
        Path mods = Files.createDirectories(root.resolve("mods"));
        writeZip(mods.resolve("malformed.jar"), "{\"id\":\"bad id\",\"version\":\"1\"}");
        writeZip(mods.resolve("oversized.jar"), "{\"id\":\"x\",\"version\":\"1\",\"padding\":\"" + "x".repeat(70_000) + "\"}");
        SecurityPolicy policy = policy(directory("mods", "mods", ".jar"));
        ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC()).collect(root, policy);

        List<ArtifactObservation> observations = new ArtifactObservationCollector().collect(root, policy, bundle);

        assertEquals(2, observations.size());
        assertTrue(observations.stream().allMatch(observation -> observation.identifier().equals("unknown")));
        assertTrue(observations.stream().allMatch(observation -> observation.version().equals("unknown")));
        assertTrue(observations.stream().allMatch(observation -> observation.confidence() == Confidence.LOW));
        assertTrue(observations.stream().allMatch(observation -> observation.metadata().get("metadata_status").equals("invalid")));
    }

    @Test
    void rejectsBundleScopeThatWasNotGrantedByThePolicy() throws Exception {
        Files.writeString(Files.createDirectories(root.resolve("mods")).resolve("client.jar"), "fixture");
        SecurityPolicy sourcePolicy = policy(directory("mods", "mods", ".jar"));
        ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC()).collect(root, sourcePolicy);

        assertThrows(IntegrityScanException.class, () -> new ArtifactObservationCollector().collect(
                root, policy(directory("resourcepacks", "resourcepacks", ".zip")), bundle));
    }

    @Test
    void textureFeatureIsHashBoundPolicyScopedAndRemainsClientReported() throws Exception {
        Path file = Files.createDirectories(root.resolve("resourcepacks")).resolve("ordinary.zip");
        var image = new java.awt.image.BufferedImage(16, 16, java.awt.image.BufferedImage.TYPE_INT_ARGB);
        var png = new java.io.ByteArrayOutputStream();
        assertTrue(javax.imageio.ImageIO.write(image, "png", png));
        try (var zip = new ZipOutputStream(Files.newOutputStream(file))) {
            for (String block : List.of("stone", "dirt", "deepslate")) {
                zip.putNextEntry(new ZipEntry("assets/minecraft/textures/block/" + block + ".png"));
                zip.write(png.toByteArray());
                zip.closeEntry();
            }
        }
        SecurityPolicy granted = policy(directory("resourcepacks", "resourcepacks", ".zip"));
        var integrity = new PolicyDrivenIntegrityCollector(Clock.systemUTC());
        var bundle = integrity.collect(root, granted);
        var collector = new ArtifactObservationCollector();
        var observation = collector.collect(root, granted, bundle).getFirst();
        assertEquals("opaque-block-transparency", observation.metadata().get("xray_heuristic"));
        assertEquals("3", observation.metadata().get("opaque_textures_checked"));
        assertEquals(ObservationOrigin.CLIENT_REPORTED, observation.origin());
        assertEquals(Confidence.LOW, observation.confidence());
        assertFalse(observation.foundationSecurity());
        assertEquals("unknown", observation.identifier());
        SecurityPolicy withoutPacks = policy(directory("mods", "mods", ".jar"));
        assertTrue(collector.collect(root, withoutPacks, integrity.collect(root, withoutPacks)).isEmpty());
        Files.writeString(file, "changed after scan");
        assertThrows(IntegrityScanException.class, () -> collector.collect(root, granted, bundle));
    }

    @Test
    void directoryPackFilesRemainOrdinaryManifestEntries() throws Exception {
        Path file = Files.createDirectories(root.resolve("resourcepacks/folder/assets/minecraft/textures/block"))
                .resolve("stone.png");
        Files.write(file, new byte[]{1, 2, 3});
        SecurityPolicy granted = policy(directory("resourcepacks", "resourcepacks", ".png"));
        var bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC()).collect(root, granted);
        var observations = new ArtifactObservationCollector().collect(root, granted, bundle);
        assertEquals(1, observations.size());
        assertFalse(observations.getFirst().metadata().containsKey("texture_probe_status"));
    }

    private static SecurityPolicy policy(IntegrityScopeRule... rules) {
        return SecurityPolicy.newBuilder().addAllIntegrityScopes(List.of(rules)).build();
    }

    private static IntegrityScopeRule directory(String scope, String root, String extension) {
        return IntegrityScopeRule.newBuilder()
                .setScope(scope)
                .setRelativeRoot(root)
                .setMaxEntries(32)
                .setMaxFileBytes(1024 * 1024)
                .addAllowedExtensions(extension)
                .build();
    }

    private static void writeZip(Path file, String fabricMetadata) throws IOException {
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(file))) {
            output.putNextEntry(new ZipEntry("fabric.mod.json"));
            output.write(fabricMetadata.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.closeEntry();
        }
    }
}
