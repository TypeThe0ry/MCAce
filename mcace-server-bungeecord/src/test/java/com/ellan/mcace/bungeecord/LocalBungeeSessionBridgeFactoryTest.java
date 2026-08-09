package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LocalBungeeSessionBridgeFactoryTest {
    @Test
    void builtInBridgeCreatesPersistentIdentityAndBeginsSharedCoreHandshake(@TempDir Path directory)
            throws Exception {
        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                directory, Logger.getLogger("mcace-bungeecord-test"));
        UUID playerId = UUID.randomUUID();

        assertTrue(bridge.begin(playerId).isPresent());
        assertTrue(bridge.api().snapshot(playerId).isPresent());
        assertTrue(bridge.admissionSigningKey().isPresent());
        assertTrue(bridge.federationRuntime().isPresent());
        assertTrue(!bridge.federationRuntime().orElseThrow().status().enabled());
        assertTrue(bridge.dispositionPolicyRuntime().isPresent());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE,
                bridge.dispositionPolicyRuntime().orElseThrow().refresh());
        assertTrue(bridge.dispositionPolicyPublisher().isPresent());
        BungeePublishedDispositionPolicy published = bridge.dispositionPolicyPublisher()
                .orElseThrow().publish();
        assertEquals("admin-observe-1", published.version());
        assertEquals(2L, published.sequence());
        assertEquals(0L, published.ruleCount());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE,
                bridge.dispositionPolicyRuntime().orElseThrow().refresh());
        assertEquals(2L, bridge.dispositionPolicyRuntime().orElseThrow().activeSequence().orElseThrow());
        assertTrue(Files.isRegularFile(directory.resolve("identity/server-private-key.pk8")));
        assertTrue(Files.isRegularFile(directory.resolve("identity/server-public-key.txt")));
        assertTrue(Files.isRegularFile(directory.resolve("disposition-policy.pb")));
        assertTrue(Files.isRegularFile(directory.resolve("disposition-policy.textproto")));
        assertTrue(Files.isRegularFile(directory.resolve("federation.properties")));
        assertTrue(Files.isDirectory(directory.resolve("history")));
    }

    @Test
    void invalidFederationConfigurationDoesNotDisableTheSharedHandshakeBridge(@TempDir Path directory)
            throws Exception {
        Files.writeString(directory.resolve("federation.properties"),
                "schema.version=1\nenabled=true\nunknown=value\n", StandardCharsets.UTF_8);

        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                directory, Logger.getLogger("mcace-bungeecord-invalid-federation-test"));
        UUID playerId = UUID.randomUUID();

        assertTrue(bridge.begin(playerId).isPresent());
        assertTrue(bridge.api().snapshot(playerId).isPresent());
        assertTrue(bridge.federationRuntime().isPresent());
        assertTrue(!bridge.federationRuntime().orElseThrow().status().enabled());
        assertEquals("mcace-bungeecord",
                bridge.federationRuntime().orElseThrow().status().localNetworkId());
    }

    @Test
    void builtInBridgeFactoryIsPackagedAsTheSingleProvider() {
        long providers = ServiceLoader.load(BungeeSessionBridgeFactory.class).stream()
                .map(ServiceLoader.Provider::type)
                .filter(LocalBungeeSessionBridgeFactory.class::equals)
                .count();

        assertEquals(1L, providers);
    }

    @Test
    void relativeBungeeDataFolderIsNormalizedBeforeCreatingThePolicySource(@TempDir Path directory)
            throws Exception {
        Path workingDirectory = Path.of("").toAbsolutePath().normalize();
        Path relativeDirectory = workingDirectory.relativize(directory.toAbsolutePath().normalize());

        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                relativeDirectory, Logger.getLogger("mcace-bungeecord-relative-path-test"));

        assertTrue(bridge.dispositionPolicyRuntime().isPresent());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE,
                bridge.dispositionPolicyRuntime().orElseThrow().refresh());
        assertTrue(Files.isRegularFile(directory.resolve("disposition-policy.pb")));
    }

    @Test
    void badDispositionConfigurationDoesNotReplaceTheLastValidPolicy(@TempDir Path directory)
            throws Exception {
        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                directory, Logger.getLogger("mcace-bungeecord-bad-policy-test"));
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE,
                bridge.dispositionPolicyRuntime().orElseThrow().refresh());
        long originalSequence = bridge.dispositionPolicyRuntime().orElseThrow()
                .activeSequence().orElseThrow();
        Files.writeString(directory.resolve("disposition-policy.textproto"), "unknown_field: 1\n",
                StandardCharsets.UTF_8);

        assertThrows(PolicyException.class, () -> bridge.dispositionPolicyPublisher().orElseThrow().publish());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE,
                bridge.dispositionPolicyRuntime().orElseThrow().refresh());
        assertEquals(originalSequence, bridge.dispositionPolicyRuntime().orElseThrow()
                .activeSequence().orElseThrow());
    }

    @Test
    void catalogPreviewIsReadOnlyAndExposesOnlyBoundedDiagnostics(@TempDir Path directory)
            throws Exception {
        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                directory, Logger.getLogger("mcace-bungeecord-preview-test"));
        bridge.dispositionPolicyRuntime().orElseThrow().refresh();
        Path policy = directory.resolve("disposition-policy.pb");
        byte[] before = Files.readAllBytes(policy);
        Files.writeString(directory.resolve("disposition-policy.textproto"),
                com.ellan.mcace.core.proxy.FileDispositionPolicyPublisher.safeCatalogExampleConfiguration());

        var preview = bridge.dispositionPolicyPublisher().orElseThrow().preview();

        assertEquals(1, preview.catalogEntryCount());
        assertEquals(0, preview.selectedEntryCount());
        assertEquals(0, preview.compiledRuleCount());
        assertTrue(preview.warnings().contains("UNSELECTED_CATALOG_ENTRY"));
        assertEquals(0, java.util.Arrays.compare(before, Files.readAllBytes(policy)));
    }

    @Test
    void invalidCatalogCannotReplaceLastKnownGoodPolicy(@TempDir Path directory)
            throws Exception {
        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                directory, Logger.getLogger("mcace-bungeecord-invalid-catalog-test"));
        var runtime = bridge.dispositionPolicyRuntime().orElseThrow();
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE, runtime.refresh());
        assertEquals(2L, bridge.dispositionPolicyPublisher().orElseThrow().publish().sequence());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE, runtime.refresh());
        Path policy = directory.resolve("disposition-policy.pb");
        byte[] before = Files.readAllBytes(policy);
        Files.writeString(directory.resolve("disposition-policy.textproto"), invalidAccessibilityCatalog());

        assertThrows(PolicyException.class, () -> bridge.dispositionPolicyPublisher().orElseThrow().preview());
        assertThrows(PolicyException.class, () -> bridge.dispositionPolicyPublisher().orElseThrow().publish());

        assertEquals(0, java.util.Arrays.compare(before, Files.readAllBytes(policy)));
        assertEquals(2L, runtime.activeSequence().orElseThrow());
    }

    private static String invalidAccessibilityCatalog() {
        return com.ellan.mcace.core.proxy.FileDispositionPolicyPublisher.safeCatalogExampleConfiguration()
                + "catalog_selections { entry_id: \"example-accessibility\" enabled: true "
                + "final_action: DISPOSITION_DENY priority: 1 }\n";
    }
}
