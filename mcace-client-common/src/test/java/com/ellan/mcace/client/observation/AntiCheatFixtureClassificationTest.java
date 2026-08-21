package com.ellan.mcace.client.observation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Controlled fixture regression for a public Meteor build and an Xray resource pack.
 * The artifacts are never loaded as executable game code; only bounded metadata and
 * policy-scoped bytes are inspected. A client artifact remains a low-confidence,
 * CLIENT_REPORTED observation and cannot independently select enforcement.
 */
final class AntiCheatFixtureClassificationTest {
    private static final UUID PLAYER = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @TempDir
    Path root;

    @Test
    void classifiesMeteorAndXrayFixturesWithoutCallingEitherCheat() throws Exception {
        String meteorProperty = fixtureValue("mcace.test.meteor.jar", "MCACE_TEST_METEOR_JAR");
        String xrayProperty = fixtureValue("mcace.test.xray.pack", "MCACE_TEST_XRAY_PACK");
        assumeTrue(!meteorProperty.isBlank() && !xrayProperty.isBlank(),
                "fixture paths were not supplied; this test is opt-in");

        Path meteorSource = Path.of(meteorProperty).toAbsolutePath().normalize();
        Path xraySource = Path.of(xrayProperty).toAbsolutePath().normalize();
        assumeTrue(Files.isRegularFile(meteorSource), "Meteor fixture is missing");
        assumeTrue(Files.isRegularFile(xraySource), "Xray resource-pack fixture is missing");

        Path mods = Files.createDirectories(root.resolve("mods"));
        Path resourcePacks = Files.createDirectories(root.resolve("resourcepacks"));
        Path meteor = Files.copy(meteorSource, mods.resolve("meteor-client-1.21.11-86.jar"));
        Path xray = Files.copy(xraySource, resourcePacks.resolve("xray-fixture.zip"));

        String metadata;
        try (ZipFile archive = new ZipFile(meteor.toFile())) {
            var entry = archive.getEntry("fabric.mod.json");
            assertTrue(entry != null, "Meteor fixture must expose Fabric metadata");
            metadata = new String(archive.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
        }
        assertTrue(metadata.contains("\"id\": \"meteor-client\""));
        assertTrue(metadata.contains("\"version\": \"1.21.11-86\""));

        try (ZipFile archive = new ZipFile(xray.toFile())) {
            var entry = archive.getEntry("pack.mcmeta");
            assertTrue(entry != null, "Xray fixture must expose pack metadata");
            String packMetadata = new String(
                    archive.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(packMetadata.contains("\"pack\""));
        }

        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .addIntegrityScopes(directory("mods", "mods", ".jar"))
                .addIntegrityScopes(directory("resourcepacks", "resourcepacks", ".zip"))
                .build();
        ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC())
                .collect(root, policy);
        List<ArtifactObservation> observations = new ArtifactObservationCollector()
                .collect(root, policy, bundle);

        ArtifactObservation meteorObservation = observations.stream()
                .filter(observation -> observation.identifier().equals("meteor-client"))
                .findFirst()
                .orElseThrow();
        assertEquals(ObservationOrigin.CLIENT_REPORTED, meteorObservation.origin());
        assertEquals(Confidence.LOW, meteorObservation.confidence());
        assertFalse(meteorObservation.foundationSecurity());
        assertEquals(DispositionAction.OBSERVE, new DispositionEngine().evaluate(
                new DispositionPolicy("empty", List.of()),
                new EvaluationContext(PLAYER, "proxy", "backend", "world", "survival",
                        Set.of("member"), Instant.EPOCH),
                meteorObservation).action());

        ArtifactObservation xrayObservation = observations.stream()
                .filter(observation -> observation.metadata().get("scope").equals("resourcepacks"))
                .findFirst()
                .orElseThrow();
        assertEquals("unknown", xrayObservation.identifier());
        assertEquals("not-applicable", xrayObservation.metadata().get("metadata_status"));
        assertEquals(ObservationOrigin.CLIENT_REPORTED, xrayObservation.origin());
        assertEquals(Confidence.LOW, xrayObservation.confidence());
        assertEquals(DispositionAction.OBSERVE, new DispositionEngine().evaluate(
                new DispositionPolicy("empty", List.of()),
                new EvaluationContext(PLAYER, "proxy", "backend", "world", "survival",
                        Set.of("member"), Instant.EPOCH),
                xrayObservation).action());
    }

    private static IntegrityScopeRule directory(String scope, String root, String extension) {
        return IntegrityScopeRule.newBuilder()
                .setScope(scope)
                .setRelativeRoot(root)
                .setMaxEntries(64)
                .setMaxFileBytes(16 * 1024 * 1024)
                .addAllowedExtensions(extension)
                .build();
    }

    private static String fixtureValue(String systemProperty, String environmentVariable) {
        String value = System.getProperty(systemProperty, "");
        return value.isBlank() ? System.getenv().getOrDefault(environmentVariable, "") : value;
    }
}
