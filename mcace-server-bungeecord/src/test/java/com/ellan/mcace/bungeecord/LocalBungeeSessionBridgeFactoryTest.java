package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.observation.LoadedModObservation;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Clock;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LocalBungeeSessionBridgeFactoryTest {
    @Test
    void relayUsesTheCurrentlyInstalledDispositionSink() {
        AtomicReference<AuthenticatedManifestDispositionEvent> delivered = new AtomicReference<>();
        AtomicReference<Consumer<AuthenticatedManifestDispositionEvent>> sink =
                new AtomicReference<>(delivered::set);
        AuthenticatedManifestDispositionEvent event = new AuthenticatedManifestDispositionEvent(
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                "dynamic-session", Instant.parse("2026-08-26T00:00:00Z"),
                DispositionAction.WARN, Optional.of("dynamic-pack-rule"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-v1"), Optional.of(7L),
                Optional.of(Instant.parse("2026-08-26T00:05:00Z")),
                ObservationOrigin.CLIENT_REPORTED, Optional.empty(), Optional.empty(), Optional.empty());

        LocalBungeeSessionBridgeFactory.relayDispositionEvent(sink, event);

        assertEquals(event, delivered.get(),
                "Bungee dynamic observations must reach the same disposition event sink as login manifests");
    }

    @Test
    void acceptedDynamicObservationPastTheAuditRetentionBudgetReachesTheBridgeSink(
            @TempDir Path directory) throws Exception {
        BungeeSessionBridge bridge = new LocalBungeeSessionBridgeFactory().create(
                directory, Logger.getLogger("mcace-bungeecord-dynamic-relay-test"));
        Files.writeString(directory.resolve("disposition-policy.textproto"),
                dynamicWarningPolicy(), StandardCharsets.UTF_8);
        bridge.dispositionPolicyPublisher().orElseThrow().publish();
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE,
                bridge.dispositionPolicyRuntime().orElseThrow().refresh());

        KeyPair serverIdentity = BungeeIdentityStore.loadOrCreate(directory.resolve("identity"));
        Clock clock = Clock.systemUTC();
        UUID playerId = UUID.randomUUID();
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, "0.0.1-test", "1.21.11", "fabric-phase2-dev", LoaderType.FABRIC,
                serverIdentity.getPublic(), clock, new SecureRandom());
        client.prepareServerHello(bridge.begin(playerId).orElseThrow(), "test.example:25565",
                new VerifiedPolicyCache(directory.resolve("client-policy-cache"), clock));
        ClientIntegrityBundle bundle = emptyBungeeBundle(clock.instant());
        List<ClientHandshakeEngine.OutboundFrame> authentication = client.createAuthenticationFrames(
                bundle, List.of(), List.of(), List.of(), List.of(new LoadedModObservation(
                        "fabricloader", "0.19.3",
                        LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", "")));
        BungeeBridgeAction authenticationResult = BungeeBridgeAction.none();
        for (ClientHandshakeEngine.OutboundFrame frame : authentication) {
            authenticationResult = bridge.receive(playerId, frame.data());
        }
        assertTrue(client.receiveAuthResult(
                authenticationResult.outboundFrames().getFirst()).getAccepted());

        AtomicReference<AuthenticatedManifestDispositionEvent> dynamicEvent = new AtomicReference<>();
        CountDownLatch dynamicWarn = new CountDownLatch(1);
        bridge.setDispositionEventHandler(event -> {
            if (event.highestAction() == DispositionAction.WARN) {
                dynamicEvent.set(event);
                dynamicWarn.countDown();
            }
        });
        List<LoadedModObservation> loadedMods = new ArrayList<>(65);
        for (int index = 0; index < 64; index++) {
            loadedMods.add(new LoadedModObservation(
                    "aaa-benign-" + String.format(java.util.Locale.ROOT, "%03d", index), "1.0.0",
                    LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", ""));
        }
        loadedMods.add(new LoadedModObservation(
                "wurst", "7.50", LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", ""));
        ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared =
                client.prepareArtifactObservationUpdate(
                        bundle, List.of(), List.of(), List.of(), loadedMods);
        BungeeBridgeAction updateResult = BungeeBridgeAction.none();
        for (ClientHandshakeEngine.OutboundFrame frame : prepared.frames()) {
            updateResult = bridge.receive(playerId, frame.data());
        }
        ClientHandshakeEngine.VerifiedArtifactObservationResult verified =
                client.receiveArtifactObservationResult(
                        updateResult.outboundFrames().getFirst(), prepared);
        assertTrue(verified.accepted());
        client.commitArtifactObservationUpdate(prepared);

        assertTrue(dynamicWarn.await(5, TimeUnit.SECONDS),
                "the accepted dynamic manifest must traverse the asynchronous Bungee audit relay");
        AuthenticatedManifestDispositionEvent event = dynamicEvent.get();
        assertEquals(playerId, event.playerId());
        assertEquals(client.authenticatedSessionId(), event.sessionId());
        assertEquals(ObservationOrigin.CLIENT_REPORTED, event.authorityOrigin());
        assertEquals(DispositionAction.WARN, event.highestAction());
        assertEquals("dynamic-wurst-warning", event.winningRuleId().orElseThrow());
        assertTrue(event.hasBoundActivePolicyIdentity());
        assertFalse(event.hasAdmissionEffect());
        bridge.close();
    }

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

    private static ClientIntegrityBundle emptyBungeeBundle(Instant capturedAt) throws Exception {
        byte[] emptyRoot = IntegrityDigests.scopeRoot(List.of());
        return ClientIntegrityBundle.of(List.of(
                new ScopeIntegrityManifest("mods", "mods", true, capturedAt, List.of(), emptyRoot),
                new ScopeIntegrityManifest("resourcepacks", "resourcepacks", false,
                        capturedAt, List.of(), emptyRoot),
                new ScopeIntegrityManifest("shaderpacks", "shaderpacks", false,
                        capturedAt, List.of(), emptyRoot),
                new ScopeIntegrityManifest("config", "", false, capturedAt, List.of(), emptyRoot)));
    }

    private static String dynamicWarningPolicy() {
        return """
                schema_version: 1
                version: "dynamic-warning-test"
                rollout_stage: "OBSERVE"
                validity_seconds: 86400
                rules {
                  rule {
                    rule_id: "dynamic-wurst-warning"
                    priority: 100
                    revision: 1
                    selector {
                      artifact_type: DETECTION_ARTIFACT_MOD
                      match_type: DETECTION_MATCH_MOD_ID_VERSION
                      artifact_id: "wurst"
                      metadata { key: "loaded" value: "true" }
                    }
                    confidence: DETECTION_CONFIDENCE_LOW
                    default_action: DISPOSITION_WARN
                    player_message_key: "mcace.dynamic.warning"
                    false_positive_notes: "Controlled dynamic relay integration test."
                    operator_reason: "Verify a winner beyond the bounded retained audit list."
                  }
                }
                """;
    }
}
