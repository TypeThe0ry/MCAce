package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import com.ellan.mcace.protocol.generated.DetectionCatalogEntry;
import com.ellan.mcace.protocol.generated.DetectionCatalogSelection;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DispositionAction;
import com.ellan.mcace.protocol.generated.DispositionPolicyConfiguration;
import com.google.protobuf.TextFormat;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Regression guard for the safe, content-free catalog example shipped to administrators. */
final class DispositionCatalogExampleSafetyTest {
    private static final long RETRIEVED_AT_EPOCH_MS = 1_786_204_800_000L;
    private static final Clock CLOCK = Clock.fixed(
            Instant.ofEpochMilli(RETRIEVED_AT_EPOCH_MS + 86_400_000L), ZoneOffset.UTC);
    private static final String MANIFEST_PATH = "src/main/resources/fabric.mod.json";
    private static final Pattern SHA_256_HEX = Pattern.compile("(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])");

    @TempDir Path directory;

    @Test void repositoryCatalogIsPreviewableAndPublishableWithoutEnablingIdentityDetections() throws Exception {
        Path example = repositoryExample();
        byte[] originalBytes = Files.readAllBytes(example);
        DispositionPolicyConfiguration configuration = parse(originalBytes);
        Path policy = directory.resolve("policy/disposition-policy.pb");
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(
                policy, CLOCK, Ed25519Keys.generate(new SecureRandom()));

        var preview = publisher.preview(example);
        PublishedDispositionPolicy published = publisher.publish(example);

        assertEquals(configuration.getCatalogEntriesCount(), preview.catalogEntryCount());
        assertEquals(0, preview.selectedEntryCount());
        assertEquals(configuration.getRulesCount(), preview.compiledRuleCount());
        assertTrue(preview.warnings().contains("UNSELECTED_CATALOG_ENTRY"));
        assertEquals(configuration.getRulesCount(), published.ruleCount(),
                "only manually configured rules may be published when all catalog identities are disabled");
        assertTrue(Files.isRegularFile(policy));
        assertArrayEquals(originalBytes, Files.readAllBytes(example), "publishing must never rewrite the example");

        assertFalse(SHA_256_HEX.matcher(new String(originalBytes, java.nio.charset.StandardCharsets.UTF_8)).find(),
                "the example must not contain a real or placeholder SHA-256 value");
        Map<String, String> expectedIdentityCommits = Map.of(
                "wurst", "64dfabaea5fa0afa4e33bc38997917c4c0c17cce",
                "liquidbounce", "97bf05cc272f397fe5b7a7a6abe00130460e84d0",
                "meteor-client", "9ffe8e4d6dcaa2d2a73c7fc09e37054f0a9dff7c");
        for (DetectionCatalogEntry entry : configuration.getCatalogEntriesList()) {
            assertFalse(entry.getDefaultEnabled(), "catalog identities must be opt-in");
            assertEquals(DetectionCatalogCategory.CHEAT_MOD, entry.getCategory());
            assertEquals(DetectionArtifactType.DETECTION_ARTIFACT_MOD, entry.getSelector().getArtifactType());
            assertEquals(DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION, entry.getSelector().getMatchType());
            assertEquals(DetectionConfidence.DETECTION_CONFIDENCE_LOW, entry.getConfidence());
            assertEquals(DispositionAction.DISPOSITION_OBSERVE, entry.getSuggestedAction());
            assertTrue(entry.getSelector().getSha256().isEmpty(), "catalog examples must not embed artifact bytes");
            assertTrue(entry.getSelector().getContentRootSha256().isEmpty(),
                    "catalog examples must not embed content-root bytes");
            assertTrue(entry.getSha256Hex().isBlank(), "catalog examples must not embed artifact hashes");
            assertTrue(entry.getContentRootSha256Hex().isBlank(),
                    "catalog examples must not embed content-root hashes");
            String expectedCommit = expectedIdentityCommits.get(entry.getSelector().getArtifactId());
            assertNotNull(expectedCommit, "catalog entry must use an approved manifest identity");
            assertTrue(entry.getSourceSummary().contains(expectedCommit),
                    "catalog identity provenance must be pinned to its manifest revision");
            assertEquals(expectedCommit, entry.getSourceRevision());
            assertEquals(MANIFEST_PATH, entry.getSourceManifestPath());
            assertEquals(RETRIEVED_AT_EPOCH_MS, entry.getSourceRetrievedAtEpochMs());
            assertEquals(expectedSourceUri(entry.getSelector().getArtifactId(), expectedCommit), entry.getSourceUri());
            assertNoMoreThanWarnForNonExactSelector(entry.getSelector().getMatchType(), entry.getSuggestedAction());
        }
        for (DetectionCatalogSelection selection : configuration.getCatalogSelectionsList()) {
            assertFalse(selection.getEnabled(), "identity catalog selections must default to disabled");
            assertNoMoreThanWarn(selection.getFinalAction(), "catalog final action");
        }
        Set<String> expectedIdentityIds = expectedIdentityCommits.keySet();
        assertEquals(expectedIdentityIds.size(), configuration.getCatalogEntriesCount());
        assertEquals(expectedIdentityIds.size(), configuration.getCatalogSelectionsCount());
        assertEquals(expectedIdentityIds,
                configuration.getCatalogEntriesList().stream()
                        .map(entry -> entry.getSelector().getArtifactId())
                        .collect(java.util.stream.Collectors.toSet()),
                "the starter catalog must contain only the three manifest-confirmed identities");
        configuration.getRulesList().forEach(rule -> {
            assertFalse(rule.getRule().getDefaultAction() == DispositionAction.DISPOSITION_DENY,
                    "the example must not create an automatic DENY rule");
            assertNoMoreThanWarnForNonExactSelector(
                    rule.getRule().getSelector().getMatchType(), rule.getRule().getDefaultAction());
            assertTrue(rule.getSha256Hex().isBlank(), "manual example rules must not contain fake artifact hashes");
            assertTrue(rule.getContentRootSha256Hex().isBlank(),
                    "manual example rules must not contain fake content-root hashes");
        });
    }

    private static DispositionPolicyConfiguration parse(byte[] bytes) throws Exception {
        DispositionPolicyConfiguration.Builder builder = DispositionPolicyConfiguration.newBuilder();
        TextFormat.getParser().merge(new String(bytes, java.nio.charset.StandardCharsets.UTF_8), builder);
        return builder.build();
    }

    private static void assertNoMoreThanWarnForNonExactSelector(
            DetectionMatchType matchType, DispositionAction action) {
        if (matchType != DetectionMatchType.DETECTION_MATCH_EXACT_SHA256) {
            assertNoMoreThanWarn(action, "non-exact catalog selector action");
        }
    }

    private static void assertNoMoreThanWarn(DispositionAction action, String description) {
        assertTrue(action.getNumber() <= DispositionAction.DISPOSITION_WARN_VALUE,
                () -> description + " must not exceed WARN: " + action);
    }

    private static String expectedSourceUri(String artifactId, String revision) {
        return switch (artifactId) {
            case "wurst" -> "https://raw.githubusercontent.com/Wurst-Imperium/Wurst7/";
            case "liquidbounce" -> "https://raw.githubusercontent.com/CCBlueX/LiquidBounce/";
            case "meteor-client" -> "https://raw.githubusercontent.com/MeteorDevelopment/meteor-client/";
            default -> throw new AssertionError("unexpected catalog artifact identity: " + artifactId);
        } + revision + "/" + MANIFEST_PATH;
    }

    private static Path repositoryExample() {
        for (Path directory = Path.of("").toAbsolutePath(); directory != null; directory = directory.getParent()) {
            Path example = directory.resolve("examples/disposition-catalog.textproto");
            if (Files.isRegularFile(example)) {
                return example;
            }
        }
        throw new AssertionError("examples/disposition-catalog.textproto is not available from the test working directory");
    }
}
