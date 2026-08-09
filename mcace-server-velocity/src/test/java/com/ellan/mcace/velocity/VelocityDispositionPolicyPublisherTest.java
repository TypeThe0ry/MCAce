package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class VelocityDispositionPolicyPublisherTest {
    @TempDir Path temporaryDirectory;

    @Test
    void publishCreatesSafeExampleAndRefreshesVelocityToNextSequence() throws Exception {
        KeyPair identity = identity();
        VelocityDispositionPolicyRuntime runtime = runtime(identity);
        assertEquals(1L, runtime.refresh().activeSequence().orElseThrow());
        VelocityDispositionPolicyPublisher publisher = VelocityDispositionPolicyPublisher.create(
                temporaryDirectory, Clock.systemUTC(), identity, runtime);

        publisher.createSafeDefaultConfigurationIfMissing();
        VelocityDispositionPolicyPublisher.PublishResult published = publisher.publishAndRefresh();

        assertEquals(2L, published.sequence());
        assertEquals("admin-observe-1", published.version());
        assertEquals(0, published.ruleCount());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE, published.status().refreshStatus());
        assertEquals(2L, published.status().activeSequence().orElseThrow());
        assertTrue(Files.readString(publisher.configurationPath()).contains("rollout_stage: \"OBSERVE\""));
    }

    @Test
    void nameOnlyDenyDoesNotReplaceKnownGoodSignedPolicy() throws Exception {
        KeyPair identity = identity();
        VelocityDispositionPolicyRuntime runtime = runtime(identity);
        runtime.refresh();
        VelocityDispositionPolicyPublisher publisher = VelocityDispositionPolicyPublisher.create(
                temporaryDirectory, Clock.systemUTC(), identity, runtime);
        publisher.createSafeDefaultConfigurationIfMissing();
        assertEquals(2L, publisher.publishAndRefresh().sequence());
        Path policyPath = temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb");
        byte[] before = Files.readAllBytes(policyPath);
        Files.writeString(publisher.configurationPath(), nameOnlyDeny(), StandardCharsets.UTF_8);

        assertThrows(PolicyException.class, publisher::publishAndRefresh);

        assertArrayEquals(before, Files.readAllBytes(policyPath));
        assertEquals(2L, runtime.status().activeSequence().orElseThrow());
    }

    @Test
    void safeExampleNeverOverwritesAnOperatorConfiguration() throws Exception {
        KeyPair identity = identity();
        VelocityDispositionPolicyPublisher publisher = VelocityDispositionPolicyPublisher.create(
                temporaryDirectory, Clock.systemUTC(), identity, runtime(identity));
        Files.createDirectories(publisher.configurationPath().getParent());
        Files.writeString(publisher.configurationPath(), "operator-managed", StandardCharsets.UTF_8);

        publisher.createSafeDefaultConfigurationIfMissing();

        assertEquals("operator-managed", Files.readString(publisher.configurationPath()));
    }

    @Test
    void catalogPreviewIsReadOnlyAndReturnsOnlyBoundedDiagnostics() throws Exception {
        KeyPair identity = identity();
        VelocityDispositionPolicyPublisher publisher = VelocityDispositionPolicyPublisher.create(
                temporaryDirectory, Clock.systemUTC(), identity, runtime(identity));
        Files.createDirectories(publisher.configurationPath().getParent());
        Files.writeString(publisher.configurationPath(),
                com.ellan.mcace.core.proxy.FileDispositionPolicyPublisher.safeCatalogExampleConfiguration());
        Path policyPath = temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb");

        var preview = publisher.preview();

        assertEquals(1, preview.catalogEntryCount());
        assertEquals(0, preview.selectedEntryCount());
        assertEquals(0, preview.compiledRuleCount());
        assertTrue(preview.warnings().contains("UNSELECTED_CATALOG_ENTRY"));
        assertTrue(Files.notExists(policyPath));
        assertTrue(Files.notExists(policyPath.getParent().resolve("history")));
    }

    @Test
    void invalidCatalogCannotReplaceLastKnownGoodPolicy() throws Exception {
        KeyPair identity = identity();
        VelocityDispositionPolicyRuntime runtime = runtime(identity);
        VelocityDispositionPolicyPublisher publisher = VelocityDispositionPolicyPublisher.create(
                temporaryDirectory, Clock.systemUTC(), identity, runtime);
        publisher.createSafeDefaultConfigurationIfMissing();
        assertEquals(2L, publisher.publishAndRefresh().sequence());
        Path policyPath = temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb");
        byte[] before = Files.readAllBytes(policyPath);
        Files.writeString(publisher.configurationPath(), invalidAccessibilityCatalog());

        assertThrows(PolicyException.class, publisher::preview);
        assertThrows(PolicyException.class, publisher::publishAndRefresh);

        assertArrayEquals(before, Files.readAllBytes(policyPath));
        assertEquals(2L, runtime.status().activeSequence().orElseThrow());
    }

    private VelocityDispositionPolicyRuntime runtime(KeyPair identity) {
        return VelocityDispositionPolicyRuntime.create(
                temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb"),
                Clock.systemUTC(),
                identity);
    }

    private static KeyPair identity() throws Exception {
        return Ed25519Keys.generate(new SecureRandom());
    }

    private static String nameOnlyDeny() {
        return """
                schema_version: 1
                version: "invalid-name-only-deny"
                rollout_stage: "OBSERVE"
                validity_seconds: 86400
                rules {
                  rule_id: "name-only-deny"
                  priority: 1
                  selector {
                    artifact_type: DETECTION_ARTIFACT_MOD
                    match_type: DETECTION_MATCH_MOD_ID_VERSION
                    artifact_id: "suspicious-mod"
                  }
                  confidence: DETECTION_CONFIDENCE_HIGH
                  default_action: DISPOSITION_DENY
                  revision: 1
                }
                """;
    }

    private static String invalidAccessibilityCatalog() {
        return com.ellan.mcace.core.proxy.FileDispositionPolicyPublisher.safeCatalogExampleConfiguration()
                + "catalog_selections { entry_id: \"example-accessibility\" enabled: true "
                + "final_action: DISPOSITION_DENY priority: 1 }\n";
    }
}
