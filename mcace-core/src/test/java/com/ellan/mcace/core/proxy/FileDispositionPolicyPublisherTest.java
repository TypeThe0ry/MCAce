package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileDispositionPolicyPublisherTest {
    private static final long NOW = 1_786_320_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
    @TempDir Path directory;
    private KeyPair keyPair;
    private Path policy;
    private Path configuration;

    @BeforeEach void setUp() throws Exception {
        keyPair = Ed25519Keys.generate(new SecureRandom());
        policy = directory.resolve("policy").resolve("disposition-policy.pb");
        configuration = directory.resolve("policy").resolve("disposition-policy.textproto");
        Files.createDirectories(configuration.getParent());
    }

    @Test void publishesAChainedPolicyAndWritesHistoryBeforeReplacingCurrent() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        PublishedDispositionPolicy result = publisher.publish(configuration);
        DispositionPolicyDocument published = document(policy);

        assertEquals("admin-observe-1", result.version());
        assertEquals(2L, result.sequence());
        assertEquals(0, result.ruleCount());
        assertEquals(2L, published.getSequence());
        assertEquals("mcace-default-observe", published.getPolicyId());
        assertEquals(32, published.getPreviousDocumentSha256().size());
        assertArrayEquals(result.documentSha256(), DispositionPolicyDocuments.documentSha256(published));
        assertTrue(Files.list(policy.getParent().resolve("history")).anyMatch(path -> path.getFileName().toString()
                .startsWith("00000000000000000001-")));
    }

    @Test void supportsEveryDispositionActionAndGlobalServerGameplayAndPlayerScopes() throws Exception {
        Files.writeString(configuration, configurationWithAllActions());
        PublishedDispositionPolicy result = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair).publish(configuration);
        DispositionPolicyDocument document = document(policy);

        assertEquals(8, result.ruleCount());
        assertEquals(8, document.getRulesCount());
        assertEquals(0, document.getRules(0).getScope().getProxyIdsCount()); // global
        assertEquals("proxy-a", document.getRules(1).getScope().getProxyIds(0)); // server/proxy
        assertEquals("survival", document.getRules(2).getScope().getGameModes(0)); // gameplay
        assertEquals("00000000-0000-0000-0000-000000000001", document.getRules(3).getScope().getPlayerIds(0));
        assertEquals(NOW, document.getRules(0).getIntroducedAtEpochMs());
        assertEquals(NOW, document.getRules(0).getEffectiveFromEpochMs());
        assertTrue(document.getRules(0).getExpiresAtEpochMs() > NOW);
    }

    @Test void catalogPreviewIsContentFreeAndHasNoWriteSideEffects() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeCatalogExampleConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);

        var preview = publisher.preview(configuration);

        assertEquals(1, preview.catalogEntryCount());
        assertEquals(0, preview.selectedEntryCount());
        assertTrue(preview.warnings().contains("UNSELECTED_CATALOG_ENTRY"));
        assertTrue(preview.warnings().stream().noneMatch(value -> value.contains("/")
                || value.contains("\\") || value.matches(".*[0-9a-fA-F]{64}.*")));
        assertTrue(Files.notExists(policy));
    }

    @Test void repositoryCatalogExampleParsesThroughTheProductionPreviewPath() throws Exception {
        Path example = Path.of("..", "examples", "disposition-catalog.textproto")
                .toAbsolutePath().normalize();
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);

        var preview = publisher.preview(example);

        assertEquals(3, preview.catalogEntryCount());
        assertEquals(0, preview.selectedEntryCount());
        assertEquals(1, preview.compiledRuleCount());
        assertTrue(preview.warnings().contains("UNSELECTED_CATALOG_ENTRY"));
        assertTrue(Files.notExists(policy));
    }

    @Test void publishesOnlyExplicitlySelectedCatalogEntryWithProvenance() throws Exception {
        Files.writeString(configuration, baseConfiguration()
                + "catalog_entries { entry_id: \"cheat-entry\" category: CHEAT_MOD "
                + "selector { artifact_type: DETECTION_ARTIFACT_MOD "
                + "match_type: DETECTION_MATCH_EXACT_SHA256 } "
                + "sha256_hex: \"" + "00".repeat(32) + "\" "
                + "confidence: DETECTION_CONFIDENCE_CONFIRMED suggested_action: DISPOSITION_WARN "
                + "player_message_key: \"mcace.catalog.warn\" "
                + "operator_reason: \"confirmed test artifact\" "
                + "false_positive_notes: \"test note\" source_id: \"test-source\" "
                + "source_summary: \"controlled test source\" default_enabled: false "
                + "source_uri: \"https://example.test/catalog\" source_revision: \"8a4c9f1\" "
                + "source_manifest_path: \"src/main/resources/fabric.mod.json\" "
                + "source_retrieved_at_epoch_ms: 1786204800000 }\n"
                + "catalog_selections { entry_id: \"cheat-entry\" enabled: true "
                + "final_action: DISPOSITION_WARN priority: 10 }\n");

        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        publisher.publish(configuration);
        var published = document(policy);

        assertEquals(1, published.getRulesCount());
        assertEquals("cheat-entry", published.getRules(0).getCatalogEntryId());
        assertEquals("test-source", published.getRules(0).getSourceId());
        assertEquals(10, published.getRules(0).getPriority());
        assertEquals(32, published.getRules(0).getSelector().getSha256().size());
        assertEquals("https://example.test/catalog", published.getRules(0).getSourceUri());
        assertEquals("8a4c9f1", published.getRules(0).getSourceRevision());
        assertEquals("src/main/resources/fabric.mod.json", published.getRules(0).getSourceManifestPath());
        assertEquals(1_786_204_800_000L, published.getRules(0).getSourceRetrievedAtEpochMs());
    }

    @Test void invalidCatalogSourceProvenanceCannotReplaceCurrentBytes() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        publisher.publish(configuration);
        byte[] before = Files.readAllBytes(policy);

        for (String candidate : List.of(
                catalogSourceConfiguration("https://example.test/catalog", "", "fabric.mod.json", NOW),
                catalogSourceConfiguration("http://example.test/catalog", "8a4c9f1", "fabric.mod.json", NOW),
                catalogSourceConfiguration("https://example.test/catalog", "8a4c9f1", "../fabric.mod.json", NOW),
                catalogSourceConfiguration("https://example.test/catalog", "8a4c9f1", "fabric.mod.json", NOW + 1))) {
            Files.writeString(configuration, candidate);
            assertThrows(PolicyException.class, () -> publisher.publish(configuration));
            assertArrayEquals(before, Files.readAllBytes(policy));
        }
    }

    @Test void catalogContentRootDenyFailsDuringPreviewAndCannotReplaceCurrentPolicy() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        publisher.publish(configuration);
        byte[] before = Files.readAllBytes(policy);
        Files.writeString(configuration, baseConfiguration()
                + "catalog_entries { entry_id: \"root-deny\" category: XRAY_RESOURCE_PACK "
                + "selector { artifact_type: DETECTION_ARTIFACT_RESOURCE_PACK "
                + "match_type: DETECTION_MATCH_CONTENT_ROOT } "
                + "content_root_sha256_hex: \"" + "00".repeat(32) + "\" "
                + "confidence: DETECTION_CONFIDENCE_LOW suggested_action: DISPOSITION_QUARANTINE "
                + "player_message_key: \"mcace.catalog.root\" operator_reason: \"reviewed root\" "
                + "false_positive_notes: \"root is not a single artifact\" source_id: \"test-source\" "
                + "source_summary: \"controlled test source\" default_enabled: false }\n"
                + "catalog_selections { entry_id: \"root-deny\" enabled: true "
                + "final_action: DISPOSITION_DENY priority: 10 }\n");

        assertThrows(PolicyException.class, () -> publisher.preview(configuration));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
    }

    @Test void legacyRulesOnlyTextprotoStillPublishesWithoutCatalogFields() throws Exception {
        Files.writeString(configuration, baseConfiguration()
                + rule("legacy-warn", "DISPOSITION_WARN", "DETECTION_MATCH_MOD_ID_VERSION", "", false, false));

        PublishedDispositionPolicy published = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair).publish(configuration);
        DispositionPolicyDocument document = document(policy);

        assertEquals(2L, published.sequence());
        assertEquals(1, published.ruleCount());
        assertEquals("legacy-warn", document.getRules(0).getRuleId());
        assertTrue(document.getRules(0).getCatalogEntryId().isEmpty());
    }

    @Test void invalidUnknownDuplicateAndOversizedConfigurationsDoNotChangeCurrentBytes() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        publisher.publish(configuration);
        byte[] before = Files.readAllBytes(policy);

        Files.writeString(configuration, "schema_version: 1\nversion: \"one\"\nversion: \"two\"\nrollout_stage: \"OBSERVE\"\nvalidity_seconds: 60\n");
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration() + "unknown_field: true\n");
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
        Files.writeString(configuration, baseConfiguration() + rule("timed", "DISPOSITION_WARN",
                "DETECTION_MATCH_ADMIN_CLASSIFICATION", "", false, false)
                .replace(" exception:", " introduced_at_epoch_ms: 1 exception:"));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
        Files.writeString(configuration, "x".repeat(FileDispositionPolicyPublisher.MAX_CONFIGURATION_BYTES + 1));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
    }

    @Test void unsafeRulesCannotReplaceCurrentBytes() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        publisher.publish(configuration);
        byte[] before = Files.readAllBytes(policy);
        Files.writeString(configuration, baseConfiguration() + rule("bad-deny", "DISPOSITION_DENY", "DETECTION_MATCH_MOD_ID_VERSION", "", false, false));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
        Files.writeString(configuration, baseConfiguration() + rule("bad-limit", "DISPOSITION_LIMIT", "DETECTION_MATCH_MOD_ID_VERSION", "", false, false));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
        Files.writeString(configuration, baseConfiguration() + rule("bad-foundation", "DISPOSITION_ALLOW", "DETECTION_MATCH_ADMIN_CLASSIFICATION", "", false, true));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
    }

    @Test void manualTextprotoSelectorSafetyMatrixPreservesCurrentSignedBytes() throws Exception {
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        StringBuilder safe = new StringBuilder(baseConfiguration());
        for (String matchType : nonExactMatchTypes()) {
            safe.append(ruleForSelector("warn-" + matchType, "DISPOSITION_WARN", matchType));
        }
        safe.append(ruleForSelector("root-quarantine", "DISPOSITION_QUARANTINE",
                "DETECTION_MATCH_CONTENT_ROOT"));
        safe.append(ruleForSelector("exact-deny", "DISPOSITION_DENY",
                "DETECTION_MATCH_EXACT_SHA256"));
        Files.writeString(configuration, safe);

        publisher.publish(configuration);
        assertEquals(7, document(policy).getRulesCount());
        byte[] before = Files.readAllBytes(policy);

        for (String matchType : nonExactMatchTypes()) {
            for (String action : List.of("DISPOSITION_CHALLENGE", "DISPOSITION_LIMIT",
                    "DISPOSITION_QUARANTINE", "DISPOSITION_DENY")) {
                Files.writeString(configuration, baseConfiguration()
                        + ruleForSelector("unsafe-" + matchType + "-" + action, action, matchType));
                assertThrows(PolicyException.class, () -> publisher.preview(configuration));
                assertThrows(PolicyException.class, () -> publisher.publish(configuration));
                assertArrayEquals(before, Files.readAllBytes(policy),
                        () -> matchType + " must not replace current policy with " + action);
            }
        }
        Files.writeString(configuration, baseConfiguration() + ruleForSelector(
                "root-deny", "DISPOSITION_DENY", "DETECTION_MATCH_CONTENT_ROOT"));
        assertThrows(PolicyException.class, () -> publisher.preview(configuration));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
    }

    @Test void exactDenyUsesCanonicalHexAndRejectsInvalidOrMismatchedHexWithoutReplacement() throws Exception {
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        String canonical = baseConfiguration() + rule("exact-deny", "DISPOSITION_DENY",
                "DETECTION_MATCH_EXACT_SHA256", "", false, false);
        Files.writeString(configuration, canonical.replace("00".repeat(32), "AB".repeat(32)));
        publisher.publish(configuration);
        assertArrayEquals(new byte[] {(byte) 0xab}, document(policy).getRules(0).getSelector().getSha256()
                .substring(0, 1).toByteArray());
        byte[] before = Files.readAllBytes(policy);
        Files.writeString(configuration, canonical.replace("00".repeat(32), "f".repeat(63)));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
        Files.writeString(configuration, canonical.replace(" }\n",
                " content_root_sha256_hex: \"" + "00".repeat(32) + "\" }\n"));
        assertThrows(PolicyException.class, () -> publisher.publish(configuration));
        assertArrayEquals(before, Files.readAllBytes(policy));
    }

    @Test void concurrentPublicationsAreStrictlySequenced() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        List<Callable<PublishedDispositionPolicy>> calls = new ArrayList<>();
        for (int index = 0; index < 8; index++) calls.add(() -> publisher.publish(configuration));
        try (var executor = Executors.newFixedThreadPool(4)) {
            List<Long> sequences = executor.invokeAll(calls).stream().map(future -> {
                try { return future.get().sequence(); } catch (Exception exception) { throw new AssertionError(exception); }
            }).sorted().toList();
            assertEquals(List.of(2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L), sequences);
        }
        assertEquals(9L, document(policy).getSequence());
    }

    @Test void firstBootstrapAndConcurrentPublishersShareOneLockWithoutDeadlock() throws Exception {
        Files.writeString(configuration, FileDispositionPolicyPublisher.safeDefaultConfiguration());
        FileSignedDispositionPolicySource source = new FileSignedDispositionPolicySource(policy, CLOCK, keyPair);
        FileDispositionPolicyPublisher publisher = new FileDispositionPolicyPublisher(policy, CLOCK, keyPair);
        try (var executor = Executors.newFixedThreadPool(5)) {
            List<Callable<Object>> calls = new ArrayList<>();
            calls.add(source::current);
            for (int index = 0; index < 4; index++) calls.add(() -> publisher.publish(configuration));
            var futures = executor.invokeAll(calls);
            for (var future : futures) future.get(5, TimeUnit.SECONDS);
        }
        DispositionPolicyDocument current = document(policy);
        assertEquals(5L, current.getSequence());
        assertEquals(32, current.getPreviousDocumentSha256().size());
    }

    private DispositionPolicyDocument document(Path path) throws Exception {
        return DispositionPolicyDocuments.verifySignatureAndStructure(
                new FileSignedDispositionPolicySource(path, CLOCK, keyPair).current(), keyPair.getPublic());
    }

    private static String configurationWithAllActions() {
        StringBuilder text = new StringBuilder(baseConfiguration());
        String[] actions = {"DISPOSITION_OBSERVE", "DISPOSITION_NOTICE", "DISPOSITION_WARN", "DISPOSITION_ALLOW",
                "DISPOSITION_CHALLENGE", "DISPOSITION_LIMIT", "DISPOSITION_QUARANTINE", "DISPOSITION_DENY"};
        for (int index = 0; index < actions.length; index++) {
            String scope = switch (index) {
                case 1 -> "scope { proxy_ids: \"proxy-a\" }";
                case 2 -> "scope { game_modes: \"survival\" }";
                case 3 -> "scope { player_ids: \"00000000-0000-0000-0000-000000000001\" }";
                default -> "";
            };
            String match = index >= 4 ? "DETECTION_MATCH_EXACT_SHA256" : "DETECTION_MATCH_ADMIN_CLASSIFICATION";
            text.append(rule("rule-" + index, actions[index], match, scope, index == 3, false));
        }
        return text.toString();
    }

    private static String baseConfiguration() {
        return "schema_version: 1\nversion: \"admin-v2\"\nrollout_stage: \"OBSERVE\"\nvalidity_seconds: 3600\n";
    }

    private static String catalogSourceConfiguration(
            String uri, String revision, String path, long retrievedAtEpochMs) {
        return baseConfiguration()
                + "catalog_entries { entry_id: \"source-entry\" category: CHEAT_MOD "
                + "selector { artifact_type: DETECTION_ARTIFACT_MOD "
                + "match_type: DETECTION_MATCH_MOD_ID_VERSION artifact_id: \"public-project\" } "
                + "confidence: DETECTION_CONFIDENCE_LOW suggested_action: DISPOSITION_OBSERVE "
                + "player_message_key: \"mcace.catalog.observe\" operator_reason: \"review only\" "
                + "false_positive_notes: \"identity is not binary proof\" source_id: \"test-source\" "
                + "source_summary: \"controlled test source\" default_enabled: false "
                + "source_uri: \"" + uri + "\" source_revision: \"" + revision + "\" "
                + "source_manifest_path: \"" + path + "\" source_retrieved_at_epoch_ms: "
                + retrievedAtEpochMs + " }\n";
    }

    private static String rule(String id, String action, String matchType, String scope, boolean exception, boolean foundation) {
        boolean exactHash = "DETECTION_MATCH_EXACT_SHA256".equals(matchType);
        return "rules { rule { rule_id: \"" + id + "\" priority: 1 revision: 1 confidence: DETECTION_CONFIDENCE_HIGH "
                + "default_action: " + action + " selector { artifact_type: DETECTION_ARTIFACT_MOD match_type: " + matchType
                + (exactHash ? "" : " artifact_id: \"classification-" + id + "\"")
                + " } " + scope + " exception: " + exception
                + " foundation_security: " + foundation + " }"
                + (exactHash ? " sha256_hex: \"" + "00".repeat(32) + "\"" : "") + " }\n";
    }

    private static List<String> nonExactMatchTypes() {
        return List.of(
                "DETECTION_MATCH_MOD_ID_VERSION",
                "DETECTION_MATCH_SIGNER",
                "DETECTION_MATCH_METADATA",
                "DETECTION_MATCH_BEHAVIOR_CORRELATION",
                "DETECTION_MATCH_ADMIN_CLASSIFICATION");
    }

    private static String ruleForSelector(String id, String action, String matchType) {
        String selectorField = switch (matchType) {
            case "DETECTION_MATCH_EXACT_SHA256", "DETECTION_MATCH_CONTENT_ROOT" -> "";
            case "DETECTION_MATCH_MOD_ID_VERSION", "DETECTION_MATCH_ADMIN_CLASSIFICATION" ->
                    " artifact_id: \"identity-" + id + "\"";
            case "DETECTION_MATCH_SIGNER" -> " signer: \"reviewed-signer\"";
            case "DETECTION_MATCH_METADATA" -> " metadata { key: \"classification\" value: \"automation\" }";
            case "DETECTION_MATCH_BEHAVIOR_CORRELATION" -> " behavior_rule_id: \"reach-correlation\"";
            default -> throw new IllegalArgumentException("unsupported test selector: " + matchType);
        };
        String hashHelper = switch (matchType) {
            case "DETECTION_MATCH_EXACT_SHA256" -> " sha256_hex: \"" + "00".repeat(32) + "\"";
            case "DETECTION_MATCH_CONTENT_ROOT" -> " content_root_sha256_hex: \"" + "00".repeat(32) + "\"";
            default -> "";
        };
        return "rules { rule { rule_id: \"" + id + "\" priority: 1 revision: 1 "
                + "confidence: DETECTION_CONFIDENCE_HIGH default_action: " + action
                + " selector { artifact_type: DETECTION_ARTIFACT_MOD match_type: " + matchType
                + selectorField + " } exception: false foundation_security: false }"
                + hashHelper + " }\n";
    }
}
