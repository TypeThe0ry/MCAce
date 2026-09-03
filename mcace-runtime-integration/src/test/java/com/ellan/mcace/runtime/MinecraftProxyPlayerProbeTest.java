package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.federation.FederationTokenVault;
import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityEntry;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.policy.VerifiedPolicy;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.observation.LoadedModObservation;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.FederationPresentation;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.federation.FederationDocuments;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.DataFormatException;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * Test-only real Minecraft wire peer. It deliberately does not launch a Minecraft client.
 * The peer proves TCP/login/configuration/plugin-channel reachability and reports the exact
 * boundary if a proxy/server requires behavior outside this bounded implementation.
 */
final class MinecraftProxyPlayerProbeTest {
    private static final int MAX_PACKET_BYTES = 2 * 1024 * 1024;
    private static final String PLAYER_NAME = "MCAceProbe";
    private static final String BUILD_ID = "fabric-phase2-dev";
    private static final String PLAYER_ID = "mcace:probe";
    /**
     * The integration probe is also used by the exact release/matrix runner.  Resolve the
     * plugin artifact name from the Gradle-provided test property instead of pinning the
     * snapshot filename, otherwise a release-versioned build (for example 0.0.1) compiles
     * successfully but the probe cannot launch its own freshly-built plugin.
     */
    private static String productVersion() {
        return System.getProperty("mcace.test.product-version", "0.1.0-SNAPSHOT");
    }

    private static Path repositoryArtifact(Path repository, String module) {
        return repository.resolve(module + "/build/libs/" + module + "-" + productVersion() + ".jar");
    }
    private static final String VELOCITY_OBSERVER_JAR_PROPERTY =
            "mcace.runtime.velocity-observer.jar";
    private static final String VELOCITY_OBSERVER_READY_MARKER =
            "MCACE_RUNTIME_OBSERVER_READY";
    private static final String VELOCITY_OBSERVER_DISCONNECT_MARKER =
            "MCACE_RUNTIME_OBSERVER_DISCONNECT_LAST_LISTENER_OBSERVED";
    /** Product-owned, content-free marker emitted only after its exact login cleanup completes. */
    private static final String VELOCITY_LOGIN_CLEANUP_READY_MARKER =
            "MCAce LOGIN_CLEANUP_READY";
    private static final byte[] SYNTHETIC_FIXTURE_BYTES =
            "MCAce harmless runtime disposition fixture v1"
                    .getBytes(StandardCharsets.US_ASCII);

    private static byte[] syntheticFixtureSha256() throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(SYNTHETIC_FIXTURE_BYTES);
    }

    @Test
    void temporaryProxyPrivateKeyCleanupCoversIdentityAndDelegatedPolicyKeys(
            @TempDir Path temporaryDirectory) throws Exception {
        Path velocityData = temporaryDirectory.resolve("velocity");
        List<Path> velocityPrivateKeys = ProbeHarness.temporaryProxyPrivateKeyPaths(velocityData);
        assertEquals(List.of(
                velocityData.resolve("identity/server-private-key.pk8"),
                velocityData.resolve("policy/delegated-key/delegated-private-key.pk8")),
                velocityPrivateKeys);
        for (Path privateKey : velocityPrivateKeys) {
            Files.createDirectories(privateKey.getParent());
            Files.write(privateKey, new byte[] {1, 2, 3});
        }
        ProbeHarness.deleteTemporaryProxyPrivateKeys(velocityPrivateKeys);
        assertTrue(velocityPrivateKeys.stream().noneMatch(Files::exists));

        Path bungeeData = temporaryDirectory.resolve("bungee");
        List<Path> bungeePrivateKeys = ProbeHarness.temporaryProxyPrivateKeyPaths(bungeeData);
        Path bungeeIdentity = bungeePrivateKeys.get(0);
        Files.createDirectories(bungeeIdentity.getParent());
        Files.write(bungeeIdentity, new byte[] {4, 5, 6});
        assertTrue(!Files.exists(bungeePrivateKeys.get(1)));
        ProbeHarness.deleteTemporaryProxyPrivateKeys(bungeePrivateKeys);
        assertTrue(bungeePrivateKeys.stream().noneMatch(Files::exists));
    }

    @Test
    void verifiedBackendAdmissionCounterBindsMarkerAndStateToTheSameLine() {
        String verified = "[INFO] Accepted signed MCAce admission state: "
                + "admission=VERIFIED, trust=VERIFIED, risk=0";
        assertEquals(2, ProbeHarness.verifiedAdmissionCount(verified + "\n" + verified));
        assertEquals(0, ProbeHarness.verifiedAdmissionCount(
                "Accepted signed MCAce admission state\n"
                        + "unrelated admission=VERIFIED, trust=VERIFIED\n"));
    }

    @Test
    @Timeout(180)
    @EnabledIfSystemProperty(named = "mcace.runtime.player-probe.enabled", matches = "true")
    void realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel() throws Exception {
        ProbeReport report = run(ProxyKind.VELOCITY);
        assertTrue(report.forwardingConfigured(), report.toJson());
        assertTrue(report.loginSuccess(), report.toJson());
        assertTrue(report.serverHello(), report.toJson());
        assertTrue(report.authResult(), report.toJson());
        assertTrue(report.authAccepted(), report.toJson());
        assertTrue(report.backendAdmission(), report.toJson());
        assertTrue(report.backendContextShadowAudit(), report.toJson());
    }

    @Test
    @Timeout(180)
    @EnabledIfSystemProperty(named = "mcace.runtime.player-probe.enabled", matches = "true")
    void realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel() throws Exception {
        ProbeReport report = run(ProxyKind.BUNGEE);
        assertTrue(report.forwardingConfigured(), report.toJson());
        assertTrue(report.loginSuccess(), report.toJson());
        assertTrue(report.serverHello(), report.toJson());
        assertTrue(report.authResult(), report.toJson());
        assertTrue(report.authAccepted(), report.toJson());
        assertTrue(report.backendAdmission(), report.toJson());
        assertTrue(report.backendContextShadowAudit(), report.toJson());
    }

    @Test
    @Timeout(300)
    @EnabledIfSystemProperty(named = "mcace.runtime.folia-context.enabled", matches = "true")
    void realVelocityModernForwardingToFoliaReturnsShadowContext() throws Exception {
        assertPassingPlayerProbe(run(ProxyKind.VELOCITY, BackendKind.FOLIA));
    }

    @Test
    @Timeout(300)
    @EnabledIfSystemProperty(named = "mcace.runtime.folia-context.enabled", matches = "true")
    void realBungeeIpForwardingToFoliaReturnsShadowContext() throws Exception {
        assertPassingPlayerProbe(run(ProxyKind.BUNGEE, BackendKind.FOLIA));
    }

    private static void assertPassingPlayerProbe(ProbeReport report) {
        assertTrue(report.forwardingConfigured(), report.toJson());
        assertTrue(report.loginSuccess(), report.toJson());
        assertTrue(report.serverHello(), report.toJson());
        assertTrue(report.authResult(), report.toJson());
        assertTrue(report.authAccepted(), report.toJson());
        assertTrue(report.backendAdmission(), report.toJson());
        assertTrue(report.backendContextShadowAudit(), report.toJson());
    }

    @Test
    void federationFixtureUsesThirtySecondHandshakeWindow() {
        assertEquals("policy.server-id=velocity-network\n"
                        + "policy.minecraft-versions=1.21.11\n"
                        + "policy.client-build-ids=fabric-phase2-dev\n"
                        + "handshake.timeout.seconds=30\n",
                federationLocalConfiguration(
                        ProxyKind.VELOCITY, "velocity-network", "1.21.11"));
        assertEquals("server.id=bungee-network\n"
                        + "minecraft.version=1.21.11\n"
                        + "client.build-id=fabric-phase2-dev\n"
                        + "handshake.timeout.seconds=30\n",
                federationLocalConfiguration(
                        ProxyKind.BUNGEE, "bungee-network", "1.21.11"));
    }

    @Test
    void proxyReadinessMarkerIsBoundToTheSelectedLoopbackPort() {
        assertEquals("Listening on /127.0.0.1:25565",
                proxyListenerReadyMarker(ProxyKind.VELOCITY, 25565));
        assertEquals("Listening on /127.0.0.1:25566",
                proxyListenerReadyMarker(ProxyKind.BUNGEE, 25566));
    }

    @Test
    void federationPlayServerHelloWaitsForBackendGameJoin() {
        assertTrue(shouldDeferFederationServerHello(State.PLAY, false, PacketType.SERVER_HELLO));
        assertTrue(!shouldDeferFederationServerHello(
                State.PLAY, true, PacketType.SERVER_HELLO));
        assertTrue(!shouldDeferFederationServerHello(
                State.CONFIGURATION, false, PacketType.SERVER_HELLO));
        assertTrue(!shouldDeferFederationServerHello(
                State.PLAY, false, PacketType.AUTH_RESULT));
        assertTrue(!shouldRequestFederationIssue(
                FederationPeerRole.SOURCE, true, State.PLAY, false, false));
        assertTrue(shouldRequestFederationIssue(
                FederationPeerRole.SOURCE, true, State.PLAY, true, false));
        assertTrue(!shouldRequestFederationIssue(
                FederationPeerRole.SOURCE, true, State.PLAY, true, true));
    }

    @Test
    @Timeout(360)
    void federationVelocityToVelocityRealProcessGate() throws Exception {
        federationOptIn();
        assertTrue(runFederation(ProxyKind.VELOCITY, ProxyKind.VELOCITY).passed());
    }

    @Test
    @Timeout(360)
    void federationVelocityToBungeeRealProcessGate() throws Exception {
        federationOptIn();
        assertTrue(runFederation(ProxyKind.VELOCITY, ProxyKind.BUNGEE).passed());
    }

    @Test
    @Timeout(360)
    void federationBungeeToVelocityRealProcessGate() throws Exception {
        federationOptIn();
        assertTrue(runFederation(ProxyKind.BUNGEE, ProxyKind.VELOCITY).passed());
    }

    @Test
    @Timeout(360)
    void federationBungeeToBungeeRealProcessGate() throws Exception {
        federationOptIn();
        assertTrue(runFederation(ProxyKind.BUNGEE, ProxyKind.BUNGEE).passed());
    }

    /**
     * Explicit residual-risk gate, deliberately separate from the normal one-process replay test.
     * It proves the current honest limitation: a target restart clears its process-memory replay
     * guard. The test-only raw peer retains the already validated grant and source session key in
     * JVM memory only; neither is reported, logged, or written to disk.
     */
    @Test
    @Timeout(480)
    void federationVelocityTargetRestartResidualReplayRealProcessGate() throws Exception {
        federationRestartOptIn();
        assertTrue(runFederationTargetRestartResidual(ProxyKind.VELOCITY).passed());
    }

    private static void federationOptIn() {
        Assumptions.assumeTrue(Boolean.getBoolean("mcace.runtime.federation.enabled"),
                "real federation proxy matrix is opt-in");
    }

    private static void federationRestartOptIn() {
        Assumptions.assumeTrue(Boolean.getBoolean("mcace.runtime.federation.restart.enabled"),
                "target-restart federation residual gate is opt-in");
    }

    private static String federationLocalConfiguration(
            ProxyKind kind, String localNetworkId, String minecraftVersion) {
        return kind == ProxyKind.VELOCITY
                ? "policy.server-id=" + localNetworkId
                        + "\npolicy.minecraft-versions=" + minecraftVersion
                        + "\npolicy.client-build-ids=" + BUILD_ID
                        + "\nhandshake.timeout.seconds=30\n"
                : "server.id=" + localNetworkId
                        + "\nminecraft.version=" + minecraftVersion
                        + "\nclient.build-id=" + BUILD_ID
                        + "\nhandshake.timeout.seconds=30\n";
    }

    private static String proxyListenerReadyMarker(ProxyKind kind, int port) {
        Objects.requireNonNull(kind, "kind");
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("proxy listener port is outside the TCP range");
        }
        return "Listening on /127.0.0.1:" + port;
    }

    private static boolean shouldDeferFederationServerHello(
            State state, boolean playJoinSeen, PacketType packetType) {
        return state == State.PLAY && !playJoinSeen && packetType == PacketType.SERVER_HELLO;
    }

    private static boolean shouldRequestFederationIssue(
            FederationPeerRole role,
            boolean authAccepted,
            State state,
            boolean playJoinSeen,
            boolean federationIssueSent) {
        return role == FederationPeerRole.SOURCE && authAccepted && state == State.PLAY
                && playJoinSeen && !federationIssueSent;
    }

    private FederationTargetRestartReport runFederationTargetRestartResidual(ProxyKind targetKind)
            throws Exception {
        Path repository = repositoryRoot();
        String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
        Path runRoot = repository.resolve("build/runtime-federation-target-restart/runs")
                .resolve("velocity-target-" + targetKind.name().toLowerCase() + "-" + runId);
        Files.createDirectories(runRoot);
        String sourceNetworkId = "restart-source-velocity";
        String targetNetworkId = "restart-target-" + targetKind.name().toLowerCase();
        SecureRandom random = new SecureRandom();
        KeyPair sourceIdentity = Ed25519Keys.generate(random);
        KeyPair targetIdentity = Ed25519Keys.generate(random);
        KeyPair sourceSessionKey = Ed25519Keys.generate(random);
        ProbeHarness source = new ProbeHarness(repository, runRoot.resolve("source"), ProxyKind.VELOCITY);
        ProbeHarness target = new ProbeHarness(repository, runRoot.resolve("target"), targetKind);
        boolean sourceAuthenticated = false;
        boolean grantStored = false;
        boolean sourceDisconnected = false;
        boolean targetOneAuthenticated = false;
        boolean targetOneObserved = false;
        boolean targetProxyStopped = false;
        boolean targetPaperKeptRunning = false;
        boolean targetIdentityPreserved = false;
        boolean targetConfigurationPreserved = false;
        boolean targetTwoAuthenticated = false;
        boolean targetSessionChanged = false;
        boolean targetChallengeChanged = false;
        boolean oldOuterSessionRejected = false;
        boolean oldSessionProofRejected = false;
        boolean invalidOldProofsNoObservation = false;
        boolean residualReacceptance = false;
        boolean postRestartSameProcessReplayRejected = false;
        boolean contentFreeAudit = false;
        boolean sourceAuditHealthy = false;
        boolean targetAuditHealthy = false;
        boolean localStateUnchanged = false;
        boolean targetBackendAdmission = false;
        boolean temporaryProxyPrivateKeysRemoved = false;
        List<String> limitations = new ArrayList<>();
        Exception failure = null;
        TestOnlyRetainedGrant retained = null;
        byte[] oldPresentation = new byte[0];
        byte[] oldOuterPresentation = new byte[0];
        try (FederationTokenVault vault = new FederationTokenVault()) {
            source.prepareFederation(sourceNetworkId, sourceIdentity, targetNetworkId,
                    targetIdentity.getPublic(), "ISSUE_TO");
            target.prepareFederation(targetNetworkId, targetIdentity, sourceNetworkId,
                    sourceIdentity.getPublic(), "ACCEPT_FROM");
            source.start();
            target.start();
            sourceAuditHealthy = source.federationAuditHealthy();
            targetAuditHealthy = target.federationAuditHealthy();

            FederationPeerResult sourceResult = new MinecraftWirePeer(source).federationSourceProbe(
                    vault, sourceSessionKey, targetNetworkId);
            sourceAuthenticated = sourceResult.authResult() != null && sourceResult.authResult().getAccepted();
            grantStored = sourceResult.grantStored();
            sourceDisconnected = sourceResult.socketClosed();
            retained = sourceResult.testOnlyRetainedGrant();
            if (!sourceAuthenticated || !grantStored || !sourceDisconnected || retained == null) {
                throw new IOException("source restart-residual phase incomplete");
            }

            FederationPeerResult firstTarget = new MinecraftWirePeer(target).federationTargetProbe(
                    vault, targetNetworkId);
            targetOneAuthenticated = firstTarget.authResult() != null && firstTarget.authResult().getAccepted();
            target.waitForProxyMarker("federation presentation status=OBSERVED", 30);
            targetOneObserved = true;
            oldPresentation = firstTarget.presentationBytes();
            oldOuterPresentation = firstTarget.presentationOuterBytes();
            if (!targetOneAuthenticated || oldPresentation.length == 0 || oldOuterPresentation.length == 0) {
                throw new IOException("first target presentation did not produce an in-memory proof");
            }

            // This stops only the target proxy. Paper stays alive; the target plugin identity and
            // configuration are preserved in the same run directory and are re-read by a new JVM.
            TargetProxyRestartResult restart = target.restartProxyPreservingState();
            targetProxyStopped = restart.oldProxyTerminated();
            targetPaperKeptRunning = restart.paperKeptRunning();
            targetIdentityPreserved = restart.identityPreserved();
            targetConfigurationPreserved = restart.configurationPreserved();

            FederationPeerResult restartedTarget = new MinecraftWirePeer(target)
                    .federationRestartTargetProbe(retained, oldOuterPresentation, oldPresentation, targetNetworkId);
            targetTwoAuthenticated = restartedTarget.authResult() != null
                    && restartedTarget.authResult().getAccepted();
            targetSessionChanged = restartedTarget.targetSessionChanged();
            targetChallengeChanged = restartedTarget.targetChallengeChanged();
            oldOuterSessionRejected = restartedTarget.oldOuterSessionRejected();
            oldSessionProofRejected = restartedTarget.oldSessionProofRejected();
            invalidOldProofsNoObservation = restartedTarget.invalidOldProofsNoObservation();
            residualReacceptance = restartedTarget.restartResidualObserved();
            postRestartSameProcessReplayRejected = restartedTarget.replaySent()
                    && target.proxyProcessOutput().contains("federation presentation status=REPLAYED");
            target.waitForProxyMarker("federation presentation status=INVALID_FRAME", 30);
            target.waitForProxyMarker("federation presentation status=INVALID_PRESENTATION", 30);
            target.waitForProxyMarker("federation presentation status=OBSERVED", 30);
            sourceAuditHealthy = sourceAuditHealthy && source.federationAuditHealthy();
            targetAuditHealthy = target.federationAuditHealthy();
            String audit = target.waitForFederationAudit(30,
                    "PRESENTATION_REJECTED\tINVALID_PRESENTATION",
                    "PRESENTATION_REJECTED\tREPLAYED",
                    "PRESENTATION_ACCEPTED\tSUCCEEDED");
            contentFreeAudit = contentFreeFederationAudit(audit);
            targetBackendAdmission = target.waitForPaperAdmission(20);
            AuthResult targetAuth = restartedTarget.authResult();
            String proxyLog = target.proxyProcessOutput();
            String paperLog = target.paperLogs();
            localStateUnchanged = targetAuth != null && targetAuth.getAccepted()
                    && targetAuth.getRiskScore() == 0
                    && targetAuth.getTrustLevel()
                            == com.ellan.mcace.protocol.generated.TrustLevel.VERIFIED
                    && !proxyLog.contains("protocol-violation=true")
                    && !proxyLog.contains("MCAce protocol violation")
                    && paperLog.contains("admission=VERIFIED, trust=VERIFIED, risk=0");
            if (!contentFreeAudit) limitations.add("target restart audit was not content-free");
            if (!localStateUnchanged) {
                limitations.add("target local trust/risk/admission invariants were not preserved");
            }
        } catch (Exception exception) {
            limitations.add(exception.getClass().getSimpleName() + ": " + safeMessage(exception));
            failure = exception;
        } finally {
            java.util.Arrays.fill(oldPresentation, (byte) 0);
            java.util.Arrays.fill(oldOuterPresentation, (byte) 0);
            if (retained != null) retained.close();
            target.close();
            source.close();
        }
        assertTrue(!source.sensitiveForwardingFileRetained() && !target.sensitiveForwardingFileRetained(),
                "temporary proxy forwarding secret was retained after target restart cleanup");
        temporaryProxyPrivateKeysRemoved = !source.temporaryProxyPrivateKeyRetained()
                && !target.temporaryProxyPrivateKeyRetained();
        assertTrue(temporaryProxyPrivateKeysRemoved,
                "temporary proxy private key was retained after target restart cleanup");
        List<Integer> cleanupIds = new ArrayList<>(source.cleanupProcessIds);
        cleanupIds.addAll(target.cleanupProcessIds);
        List<Long> remaining = new ArrayList<>(source.remainingRunProcesses());
        remaining.addAll(target.remainingRunProcesses());
        FederationTargetRestartReport report = new FederationTargetRestartReport(targetKind,
                sourceAuthenticated, grantStored, sourceDisconnected, targetOneAuthenticated,
                targetOneObserved, targetProxyStopped, targetPaperKeptRunning, targetIdentityPreserved,
                targetConfigurationPreserved, targetTwoAuthenticated, targetSessionChanged,
                targetChallengeChanged, oldOuterSessionRejected, oldSessionProofRejected,
                invalidOldProofsNoObservation, residualReacceptance, postRestartSameProcessReplayRejected,
                contentFreeAudit, sourceAuditHealthy, targetAuditHealthy,
                localStateUnchanged, targetBackendAdmission,
                temporaryProxyPrivateKeysRemoved,
                List.copyOf(limitations), List.copyOf(cleanupIds), List.copyOf(remaining));
        Files.writeString(runRoot.resolve("report.json"), report.toJson(), StandardCharsets.UTF_8);
        Files.writeString(runRoot.resolve("report.md"), report.toMarkdown(), StandardCharsets.UTF_8);
        System.out.println("FEDERATION_TARGET_RESTART_REPORT|" + runRoot.resolve("report.json"));
        System.out.println(report.toJson());
        assertTrue(report.remainingRunProcesses().isEmpty(), report.toJson());
        if (failure != null) throw failure;
        assertTrue(report.passed(), report.toJson());
        return report;
    }

    private FederationMatrixReport runFederation(ProxyKind sourceKind, ProxyKind targetKind) throws Exception {
        Path repository = repositoryRoot();
        String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
        String pair = sourceKind.name().toLowerCase() + "-to-" + targetKind.name().toLowerCase();
        Path runRoot = repository.resolve("build/runtime-federation-matrix/runs").resolve(pair + "-" + runId);
        Files.createDirectories(runRoot);
        String sourceNetworkId = "matrix-source-" + sourceKind.name().toLowerCase();
        String targetNetworkId = "matrix-target-" + targetKind.name().toLowerCase();
        SecureRandom random = new SecureRandom();
        KeyPair sourceIdentity = Ed25519Keys.generate(random);
        KeyPair targetIdentity = Ed25519Keys.generate(random);
        KeyPair clientSessionKey = Ed25519Keys.generate(random);
        ProbeHarness source = new ProbeHarness(repository, runRoot.resolve("source"), sourceKind);
        ProbeHarness target = new ProbeHarness(repository, runRoot.resolve("target"), targetKind);
        boolean sourceAuthenticated = false;
        boolean grantStored = false;
        boolean sourceDisconnected = false;
        boolean targetAuthenticated = false;
        boolean presentationSent = false;
        int firstOuterLength = 0;
        int innerLength = 0;
        boolean nonceDistinctAttempted = false;
        boolean observed = false;
        boolean replayRejected = false;
        boolean contentFreeAudit = false;
        boolean sourceAuditHealthy = false;
        boolean targetAuditHealthy = false;
        boolean localStateUnchanged = false;
        boolean targetBackendAdmission = false;
        List<String> limitations = new ArrayList<>();
        Exception failure = null;
        try (FederationTokenVault vault = new FederationTokenVault()) {
            source.prepareFederation(sourceNetworkId, sourceIdentity, targetNetworkId,
                    targetIdentity.getPublic(), "ISSUE_TO");
            target.prepareFederation(targetNetworkId, targetIdentity, sourceNetworkId,
                    sourceIdentity.getPublic(), "ACCEPT_FROM");
            source.start();
            target.start();
            sourceAuditHealthy = source.federationAuditHealthy();
            targetAuditHealthy = target.federationAuditHealthy();

            FederationPeerResult sourceResult = new MinecraftWirePeer(source).federationSourceProbe(
                    vault, clientSessionKey, targetNetworkId);
            sourceAuthenticated = sourceResult.authResult() != null
                    && sourceResult.authResult().getAccepted();
            grantStored = sourceResult.grantStored();
            sourceDisconnected = sourceResult.socketClosed();
            sourceAuditHealthy = sourceAuditHealthy && source.federationAuditHealthy();
            if (!sourceAuthenticated || !grantStored || !sourceDisconnected) {
                throw new IOException("source federation phase incomplete: " + sourceResult);
            }

            // There is deliberately no live source-to-target broker. The source client socket is
            // closed before the retained in-memory key/grant is used for a fresh target auth.
            Thread.sleep(500L);
            FederationPeerResult targetResult = new MinecraftWirePeer(target).federationTargetProbe(
                    vault, targetNetworkId);
            targetAuthenticated = targetResult.authResult() != null
                    && targetResult.authResult().getAccepted();
            presentationSent = targetResult.presentationSent();
            firstOuterLength = targetResult.firstOuterLength();
            innerLength = targetResult.innerLength();
            nonceDistinctAttempted = targetResult.nonceDistinctAttempted();
            target.waitForProxyMarker("federation presentation status=OBSERVED", 30);
            observed = true;
            target.waitForProxyMarker("federation presentation status=REPLAYED", 30);
            replayRejected = true;
            targetAuditHealthy = target.federationAuditHealthy();
            targetBackendAdmission = target.waitForPaperAdmission(20);

            String audit = target.waitForFederationAudit(30,
                    "PRESENTATION_ACCEPTED\tSUCCEEDED", "PRESENTATION_REJECTED\tREPLAYED");
            contentFreeAudit = contentFreeFederationAudit(audit);
            String proxyLog = target.proxyLogs();
            String paperLog = target.paperLogs();
            AuthResult targetAuth = targetResult.authResult();
            localStateUnchanged = targetAuth != null
                    && targetAuth.getAccepted()
                    && targetAuth.getRiskScore() == 0
                    && targetAuth.getTrustLevel()
                            == com.ellan.mcace.protocol.generated.TrustLevel.VERIFIED
                    && !proxyLog.contains("protocol-violation=true")
                    && !proxyLog.contains("MCAce protocol violation")
                    && paperLog.contains("admission=VERIFIED, trust=VERIFIED, risk=0");
            if (!contentFreeAudit) limitations.add("target federation audit was not content-free");
            if (!localStateUnchanged) limitations.add("target local trust/risk/admission invariants were not preserved");
        } catch (Exception exception) {
            limitations.add(exception.getClass().getSimpleName() + ": " + safeMessage(exception));
            failure = exception;
        } finally {
            target.close();
            source.close();
        }
        assertTrue(!source.sensitiveForwardingFileRetained() && !target.sensitiveForwardingFileRetained(),
                "temporary proxy forwarding secret was retained after federation cleanup");
        List<Integer> cleanupIds = new ArrayList<>(source.cleanupProcessIds);
        cleanupIds.addAll(target.cleanupProcessIds);
        List<Long> remaining = new ArrayList<>(source.remainingRunProcesses());
        remaining.addAll(target.remainingRunProcesses());
        FederationMatrixReport report = new FederationMatrixReport(
                sourceKind, targetKind, sourceNetworkId, targetNetworkId,
                sourceAuthenticated, grantStored, sourceDisconnected, targetAuthenticated,
                presentationSent, firstOuterLength, innerLength, nonceDistinctAttempted,
                observed, replayRejected, contentFreeAudit, sourceAuditHealthy, targetAuditHealthy,
                localStateUnchanged,
                targetBackendAdmission, List.copyOf(limitations), List.copyOf(cleanupIds),
                List.copyOf(remaining));
        Files.writeString(runRoot.resolve("report.json"), report.toJson(), StandardCharsets.UTF_8);
        Files.writeString(runRoot.resolve("report.md"), report.toMarkdown(), StandardCharsets.UTF_8);
        System.out.println("FEDERATION_PROXY_MATRIX_REPORT|" + runRoot.resolve("report.json"));
        System.out.println(report.toJson());
        assertTrue(report.remainingRunProcesses().isEmpty(), report.toJson());
        if (failure != null) throw failure;
        assertTrue(report.passed(), report.toJson());
        return report;
    }

    private static boolean contentFreeFederationAudit(String content) {
        if (content == null || content.isBlank()) return false;
        List<String> lines = content.lines().filter(line -> !line.isBlank()).toList();
        if (lines.size() < 2 || lines.stream().anyMatch(line -> line.split("\\t", -1).length != 9)) {
            return false;
        }
        String normalized = content.toLowerCase(java.util.Locale.ROOT);
        return !normalized.contains("session")
                && !normalized.contains("challenge")
                && !normalized.contains("signature")
                && !normalized.contains("private")
                && !normalized.contains("grant")
                && !normalized.contains("risk")
                && !normalized.contains("admission");
    }

    private ProbeReport run(ProxyKind kind) throws Exception {
        return run(kind, BackendKind.PAPER);
    }

    private ProbeReport run(ProxyKind kind, BackendKind backendKind) throws Exception {
        Path repository = repositoryRoot();
        String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
        String runPrefix = kind.name().toLowerCase()
                + (backendKind == BackendKind.FOLIA ? "-folia" : "");
        Path runRoot = repository.resolve("build/runtime-player-probe/runs")
                .resolve(runPrefix + "-" + runId);
        Files.createDirectories(runRoot);
        ProbeHarness harness = new ProbeHarness(repository, runRoot, kind, backendKind);
        ProbeReport report = null;
        Exception failure = null;
        try {
            harness.prepare();
            harness.start();
            report = new MinecraftWirePeer(harness).probe();
        } catch (Exception exception) {
            report = ProbeReport.failure(kind, backendKind, harness.backendMinecraftVersion,
                    harness.proxyPort, harness.paperPort,
                    List.of(exception.getClass().getSimpleName() + ": " + safeMessage(exception)));
            failure = exception;
        } finally {
            harness.close();
        }
        assertTrue(!harness.sensitiveForwardingFileRetained(),
                "temporary proxy forwarding secret was retained after cleanup");
        assertTrue(!harness.temporaryProxyPrivateKeyRetained(),
                "temporary proxy private key was retained after cleanup");
        report = report.withCleanup(harness.cleanupProcessIds, harness.remainingRunProcesses());
        Files.writeString(runRoot.resolve("report.json"), report.toJson(), StandardCharsets.UTF_8);
        Files.writeString(runRoot.resolve("report.md"), report.toMarkdown(), StandardCharsets.UTF_8);
        System.out.println("MINECRAFT_PLAYER_PROBE_REPORT|" + runRoot.resolve("report.json"));
        System.out.println(report.toJson());
        assertTrue(report.remainingRunProcesses().isEmpty(), report.toJson());
        if (failure != null) throw failure;
        return report;
    }

    private static Path repositoryRoot() throws IOException {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isRegularFile(current.resolve("settings.gradle.kts"))) return current;
            current = current.getParent();
        }
        throw new IOException("could not locate MCAce repository root from user.dir=" + System.getProperty("user.dir"));
    }

    /**
     * Runs one isolated Velocity disposition case through the administrator publisher, the real
     * proxy wire path, and three independent Paper processes. The mutable work tree is always
     * deleted before this method returns; callers may retain only a sanitized aggregate report.
     */
    static DispositionCaseOutcome runVelocityDispositionCase(DispositionScenario scenario) {
        ProbeHarness harness = null;
        Path workRoot = null;
        boolean forwardingConfigured = false;
        boolean publisherActive = false;
        boolean syntheticManifestSent = false;
        boolean authenticationAccepted = false;
        boolean dispositionResultObserved = false;
        boolean lobbyAdmission = false;
        boolean limitedAdmission = false;
        boolean quarantineAdmission = false;
        boolean anyRouteLifecycleObserved = false;
        RouteCompletion routeCompletion = RouteCompletion.NONE;
        boolean connectionRetained = false;
        boolean cleanupZero = false;
        boolean workMaterialRemoved = false;
        try {
            Path repository = repositoryRoot();
            String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
            Path workParent = repository.resolve("build/runtime-disposition-matrix/work");
            cleanupAbortedDispositionWork(workParent);
            workRoot = workParent
                    .resolve(scenario.name().toLowerCase() + "-" + runId);
            Files.createDirectories(workRoot);
            harness = new ProbeHarness(repository, workRoot, ProxyKind.VELOCITY);
            harness.prepareDisposition(scenario);
            forwardingConfigured = harness.forwardingConfigured;
            harness.startDisposition();
            publisherActive = harness.publishSyntheticDispositionPolicy(scenario);
            DispositionPeerResult peer = new MinecraftWirePeer(harness, true)
                    .dispositionProbe(scenario);
            syntheticManifestSent = peer.syntheticManifestSent();
            authenticationAccepted = peer.authenticationAcceptedAnyPhase();
            dispositionResultObserved = peer.dispositionResultObserved();
            lobbyAdmission = peer.lobbyAdmission();
            limitedAdmission = peer.limitedAdmission();
            quarantineAdmission = peer.quarantineAdmission();
            anyRouteLifecycleObserved = peer.anyRouteLifecycleObserved();
            routeCompletion = peer.routeCompletion();
            connectionRetained = peer.connectionRetained();
        } catch (Exception ignored) {
            // The sanitized caller report records only fixed booleans/enums. Raw exception text,
            // process logs, paths, policy bytes and runtime identities are deliberately discarded.
        } finally {
            if (harness != null) {
                harness.close();
                cleanupZero = harness.remainingRunProcesses().isEmpty();
            }
            if (workRoot != null) {
                try {
                    deleteOwnedWorkTree(workRoot);
                    workMaterialRemoved = !Files.exists(workRoot);
                } catch (Exception ignored) {
                    workMaterialRemoved = false;
                }
            }
        }
        return new DispositionCaseOutcome(
                scenario, forwardingConfigured, publisherActive, syntheticManifestSent,
                authenticationAccepted, dispositionResultObserved, lobbyAdmission,
                limitedAdmission, quarantineAdmission, anyRouteLifecycleObserved,
                routeCompletion, connectionRetained, cleanupZero, workMaterialRemoved);
    }

    /**
     * Runs Bungee's advisory-origin guard case in a separate disposable process tree. The synthetic
     * client-reported observation must remain on the lobby and must not enter any route lifecycle.
     */
    static BungeeDispositionCaseOutcome runBungeeDispositionCase(DispositionScenario scenario) {
        ProbeHarness harness = null;
        Path workRoot = null;
        boolean forwardingConfigured = false;
        boolean publisherActive = false;
        PublisherGate publisherGate = PublisherGate.NOT_ATTEMPTED;
        boolean syntheticManifestSent = false;
        boolean authenticationAccepted = false;
        boolean authenticationAcceptedAnyPhase = false;
        ServerHelloStage serverHelloStage = ServerHelloStage.NOT_OBSERVED;
        AuthOutboundStage authOutboundStage = AuthOutboundStage.NOT_SENT;
        AuthResultStage authResultStage = AuthResultStage.NOT_OBSERVED;
        boolean dispositionResultObserved = false;
        boolean deferredRouteObserved = false;
        boolean deferredRouteDispatched = false;
        boolean anyRouteLifecycleObserved = false;
        boolean lobbyAdmission = false;
        boolean limitedAdmission = false;
        boolean quarantineAdmission = false;
        RouteCompletion routeCompletion = RouteCompletion.NONE;
        RemoteLiveness remoteLiveness = RemoteLiveness.NOT_ATTEMPTED;
        boolean connectionRetained = false;
        boolean cleanupZero = false;
        boolean workMaterialRemoved = false;
        try {
            Path repository = repositoryRoot();
            String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
            Path workParent = repository.resolve("build/runtime-disposition-matrix/work");
            cleanupAbortedDispositionWork(workParent);
            workRoot = workParent.resolve("bungee-" + scenario.name().toLowerCase() + "-" + runId);
            Files.createDirectories(workRoot);
            harness = new ProbeHarness(repository, workRoot, ProxyKind.BUNGEE);
            harness.prepareDisposition(scenario);
            forwardingConfigured = harness.forwardingConfigured;
            harness.startDisposition();
            publisherActive = harness.publishSyntheticDispositionPolicy(scenario);
            publisherGate = harness.bungeePublisherGate();
            DispositionPeerResult peer = new MinecraftWirePeer(harness, true)
                    .dispositionProbe(scenario);
            syntheticManifestSent = peer.syntheticManifestSent();
            authenticationAccepted = peer.authenticationAccepted();
            authenticationAcceptedAnyPhase = peer.authenticationAcceptedAnyPhase();
            serverHelloStage = peer.authenticationEvidence().serverHelloStage();
            authOutboundStage = peer.authenticationEvidence().authOutboundStage();
            authResultStage = peer.authenticationEvidence().authResultStage();
            dispositionResultObserved = peer.dispositionResultObserved();
            deferredRouteObserved = peer.deferredRouteObserved();
            deferredRouteDispatched = peer.deferredRouteDispatched();
            anyRouteLifecycleObserved = peer.anyRouteLifecycleObserved();
            lobbyAdmission = peer.lobbyAdmission();
            limitedAdmission = peer.limitedAdmission();
            quarantineAdmission = peer.quarantineAdmission();
            routeCompletion = peer.routeCompletion();
            remoteLiveness = peer.remoteLiveness();
            connectionRetained = peer.connectionRetained();
            if (!publisherGate.success() && dispositionResultObserved) {
                publisherGate = PublisherGate.RUNTIME_POLICY_MATCHED;
                publisherActive = true;
            }
        } catch (Exception ignored) {
            // The report exposes only fixed booleans/enums. The disposable tree contains all raw
            // proxy output and is removed in finally before the report is written.
        } finally {
            if (harness != null) {
                harness.close();
                cleanupZero = harness.remainingRunProcesses().isEmpty();
            }
            if (workRoot != null) {
                try {
                    deleteOwnedWorkTree(workRoot);
                    workMaterialRemoved = !Files.exists(workRoot);
                } catch (Exception ignored) {
                    workMaterialRemoved = false;
                }
            }
        }
        return new BungeeDispositionCaseOutcome(
                scenario, forwardingConfigured, publisherActive, publisherGate, syntheticManifestSent,
                authenticationAccepted, authenticationAcceptedAnyPhase, serverHelloStage, authOutboundStage,
                authResultStage, dispositionResultObserved, deferredRouteObserved,
                deferredRouteDispatched, anyRouteLifecycleObserved, lobbyAdmission, limitedAdmission, quarantineAdmission,
                routeCompletion, remoteLiveness, connectionRetained, cleanupZero, workMaterialRemoved);
    }

    /** Runs one operator-reviewed exact-hash route through a real proxy and three Paper processes. */
    static TrustedDispositionCaseOutcome runTrustedDispositionCase(
            ProxyKind kind, DispositionScenario scenario) {
        ProbeHarness harness = null;
        Path workRoot = null;
        boolean forwardingConfigured = false;
        boolean publisherActive = false;
        boolean authenticationAccepted = false;
        boolean reviewCommandSent = false;
        boolean authorizationObserved = false;
        boolean authorizationPersisted = false;
        boolean authorizationPersistedBeforeExecution = false;
        boolean dispositionResultObserved = false;
        boolean lobbyAdmission = false;
        boolean limitedAdmission = false;
        boolean quarantineAdmission = false;
        RouteCompletion routeCompletion = RouteCompletion.NONE;
        boolean connectionRetained = false;
        boolean cleanupZero = false;
        boolean workMaterialRemoved = false;
        try {
            Path repository = repositoryRoot();
            String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
            Path workParent = repository.resolve("build/runtime-trusted-disposition/work");
            cleanupAbortedDispositionWork(workParent);
            workRoot = workParent.resolve(kind.name().toLowerCase(java.util.Locale.ROOT)
                    + "-" + scenario.name().toLowerCase(java.util.Locale.ROOT) + "-" + runId);
            Files.createDirectories(workRoot);
            harness = new ProbeHarness(repository, workRoot, kind);
            harness.prepareTrustedDisposition(scenario);
            forwardingConfigured = harness.forwardingConfigured;
            harness.startDisposition();
            publisherActive = harness.publishSyntheticDispositionPolicy(scenario);
            TrustedDispositionPeerResult peer = new MinecraftWirePeer(harness, false)
                    .trustedDispositionProbe(scenario);
            if (!publisherActive && kind == ProxyKind.BUNGEE
                    && peer.authorizationObserved() && peer.dispositionResultObserved()) {
                // The exact review request matched the synthetic rule/action in the active signed
                // runtime policy even when Bungee's duplicated console/file marker cursor raced.
                harness.markBungeeRuntimePolicyMatched();
                publisherActive = harness.bungeePublisherGate().success();
            }
            authenticationAccepted = peer.authenticationAccepted();
            reviewCommandSent = peer.reviewCommandSent();
            String action = scenario.actionName();
            TrustedAuthorizationEvidence authorization =
                    harness.trustedDispositionAuthorizationEvidence(action);
            authorizationObserved = authorization.commandObserved();
            authorizationPersisted = authorization.journalRecordMatched();
            authorizationPersistedBeforeExecution = authorization.persistedBeforeExecution();
            dispositionResultObserved = peer.dispositionResultObserved()
                    && authorizationPersistedBeforeExecution;
            lobbyAdmission = peer.lobbyAdmission();
            limitedAdmission = peer.limitedAdmission();
            quarantineAdmission = peer.quarantineAdmission();
            routeCompletion = peer.routeCompletion();
            connectionRetained = peer.connectionRetained();
        } catch (Exception ignored) {
            // Raw logs, command text, paths and policy bytes remain inside the disposable work tree.
        } finally {
            if (harness != null) {
                harness.close();
                cleanupZero = harness.remainingRunProcesses().isEmpty();
            }
            if (workRoot != null) {
                try {
                    deleteOwnedWorkTree(workRoot);
                    workMaterialRemoved = !Files.exists(workRoot);
                } catch (Exception ignored) {
                    workMaterialRemoved = false;
                }
            }
        }
        return new TrustedDispositionCaseOutcome(
                kind, scenario, forwardingConfigured, publisherActive, authenticationAccepted,
                reviewCommandSent, authorizationObserved, authorizationPersisted,
                authorizationPersistedBeforeExecution,
                dispositionResultObserved, lobbyAdmission, limitedAdmission,
                quarantineAdmission, routeCompletion, connectionRetained,
                cleanupZero, workMaterialRemoved);
    }
    /**
     * Exercises DENY and a clean reconnect as two sessions of the same offline identity while the
     * same Velocity and three Paper processes remain running. No UUID or session material leaves
     * this method; the caller receives only fixed booleans/enums for its sanitized report.
     */
    static DenyReconnectOutcome runVelocityDenyReconnectCase() {
        ProbeHarness harness = null;
        Path workRoot = null;
        boolean forwardingConfigured = false;
        boolean fixtureLoginRatelimitDisabled = false;
        boolean publisherActive = false;
        boolean firstCleanManifestSent = false;
        boolean firstAuthenticationAccepted = false;
        boolean firstLobbyVerifiedAdmission = false;
        boolean reviewCommandSent = false;
        boolean authorizationObserved = false;
        boolean authorizationPersisted = false;
        boolean authorizationPersistedBeforeExecution = false;
        boolean deniedResultObserved = false;
        DisconnectEvidence disconnectEvidence = DisconnectEvidence.NONE;
        boolean limitedAdmission = false;
        boolean quarantineAdmission = false;
        boolean sameOfflineIdentity = false;
        boolean independentAuthenticatedSession = false;
        boolean cleanManifestSent = false;
        boolean reconnectAuthenticationAccepted = false;
        boolean reconnectConfigurationCompleted = false;
        boolean reconnectLobbyVerifiedAdmission = false;
        CleanReconnectStage cleanReconnectStage = CleanReconnectStage.NOT_STARTED;
        CleanReconnectTermination cleanReconnectTermination = CleanReconnectTermination.NONE;
        OldSessionCleanup oldSessionCleanup = OldSessionCleanup.NOT_STARTED;
        boolean cleanupZero = false;
        boolean workMaterialRemoved = false;
        try {
            Path repository = repositoryRoot();
            String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
            Path workParent = repository.resolve("build/runtime-disposition-matrix/work");
            cleanupAbortedDispositionWork(workParent);
            workRoot = workParent.resolve("enforce_deny_reconnect-" + runId);
            Files.createDirectories(workRoot);
            harness = new ProbeHarness(repository, workRoot, ProxyKind.VELOCITY);
            harness.prepareTrustedDisposition(DispositionScenario.ENFORCE_DENY);
            forwardingConfigured = harness.forwardingConfigured;
            fixtureLoginRatelimitDisabled = harness.velocityLoginRatelimitDisabled;
            harness.startDisposition();
            if (!harness.runtimeDisconnectObserverReady()) {
                oldSessionCleanup = OldSessionCleanup.OBSERVER_UNAVAILABLE;
                throw new IOException("test-only disconnect observer is unavailable");
            }
            publisherActive = harness.publishSyntheticDispositionPolicy("DISPOSITION_DENY");
            CleanupMarkerBaseline cleanupMarkerBaseline =
                    harness.captureCurrentGenerationCleanupMarkerBaseline();

            MinecraftWirePeer deniedPeer = new MinecraftWirePeer(harness, false);
            DenyPeerResult denied = deniedPeer.trustedDenyDispositionProbe();
            firstCleanManifestSent = denied.cleanManifestSent();
            firstAuthenticationAccepted = denied.authenticationAccepted();
            firstLobbyVerifiedAdmission = denied.lobbyAdmission();
            reviewCommandSent = denied.reviewCommandSent();
            TrustedAuthorizationEvidence authorization =
                    harness.trustedDispositionAuthorizationEvidence("DENY");
            authorizationObserved = authorization.commandObserved();
            authorizationPersisted = authorization.journalRecordMatched();
            authorizationPersistedBeforeExecution = authorization.persistedBeforeExecution();
            deniedResultObserved = denied.deniedResultObserved()
                    && authorizationPersistedBeforeExecution;
            disconnectEvidence = denied.disconnectEvidence();

            if (disconnectEvidence != DisconnectEvidence.NONE) {
                oldSessionCleanup = harness.waitForOldSessionCleanup(
                        cleanupMarkerBaseline, 10);
            }
            int lobbyAdmissionsBeforeReconnect = -1;
            if (mayOpenCleanReconnect(oldSessionCleanup)) {
                try {
                    lobbyAdmissionsBeforeReconnect = harness.waitForStableBackendAdmissionCount(
                            "paper-lobby", harness.paperRoot, 500, 3);
                } catch (IOException exception) {
                    oldSessionCleanup = OldSessionCleanup.TIMEOUT;
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    oldSessionCleanup = OldSessionCleanup.TIMEOUT;
                }
            }
            if (mayOpenCleanReconnect(oldSessionCleanup)) {
                MinecraftWirePeer cleanPeer = new MinecraftWirePeer(harness, false);
                CleanReconnectPeerResult clean = cleanPeer.cleanReconnectProbe(
                        lobbyAdmissionsBeforeReconnect);
                sameOfflineIdentity = Objects.equals(deniedPeer.playerId, cleanPeer.playerId);
                independentAuthenticatedSession = denied.authenticatedSessionId() != null
                        && clean.authenticatedSessionId() != null
                        && !denied.authenticatedSessionId().equals(clean.authenticatedSessionId());
                cleanManifestSent = clean.cleanManifestSent();
                reconnectAuthenticationAccepted = clean.authenticationAccepted();
                reconnectConfigurationCompleted = clean.configurationCompleted();
                reconnectLobbyVerifiedAdmission = clean.newLobbyVerifiedAdmission();
                cleanReconnectStage = clean.stage();
                cleanReconnectTermination = clean.termination();
            }
            limitedAdmission = harness.backendAccepted("paper-limited", harness.limitedPaperRoot);
            quarantineAdmission = harness.backendAccepted(
                    "paper-quarantine", harness.quarantinePaperRoot);
        } catch (Exception ignored) {
            // Raw exceptions/logs/frames and runtime identities remain in the disposable work tree.
            // The caller receives only fixed false/stage-enum evidence when a stage does not complete.
        } finally {
            if (harness != null) {
                harness.close();
                cleanupZero = harness.remainingRunProcesses().isEmpty();
            }
            if (workRoot != null) {
                try {
                    deleteOwnedWorkTree(workRoot);
                    workMaterialRemoved = !Files.exists(workRoot);
                } catch (Exception ignored) {
                    workMaterialRemoved = false;
                }
            }
        }
        return new DenyReconnectOutcome(
                forwardingConfigured, fixtureLoginRatelimitDisabled,
                publisherActive, firstCleanManifestSent,
                firstAuthenticationAccepted, firstLobbyVerifiedAdmission,
                reviewCommandSent, authorizationObserved, authorizationPersisted,
                authorizationPersistedBeforeExecution,
                deniedResultObserved, disconnectEvidence,
                limitedAdmission, quarantineAdmission, sameOfflineIdentity,
                independentAuthenticatedSession, cleanManifestSent,
                reconnectAuthenticationAccepted, reconnectConfigurationCompleted,
                reconnectLobbyVerifiedAdmission, cleanReconnectStage,
                cleanReconnectTermination, oldSessionCleanup, cleanupZero,
                workMaterialRemoved);
    }

    /** Bungee counterpart to the trusted current-connection DENY and clean reconnect gate. */
    static BungeeDenyReconnectOutcome runBungeeTrustedDenyReconnectCase() {
        ProbeHarness harness = null;
        Path workRoot = null;
        boolean forwardingConfigured = false;
        boolean publisherActive = false;
        boolean firstCleanManifestSent = false;
        boolean firstAuthenticationAccepted = false;
        boolean firstLobbyVerifiedAdmission = false;
        boolean reviewCommandSent = false;
        boolean authorizationObserved = false;
        boolean authorizationPersisted = false;
        boolean authorizationPersistedBeforeExecution = false;
        boolean deniedResultObserved = false;
        DisconnectEvidence disconnectEvidence = DisconnectEvidence.NONE;
        boolean proxyRegistryEmptyBeforeReconnect = false;
        boolean limitedAdmission = false;
        boolean quarantineAdmission = false;
        boolean sameOfflineIdentity = false;
        boolean independentAuthenticatedSession = false;
        boolean cleanManifestSent = false;
        boolean reconnectAuthenticationAccepted = false;
        boolean reconnectConfigurationCompleted = false;
        boolean reconnectLobbyVerifiedAdmission = false;
        CleanReconnectStage cleanReconnectStage = CleanReconnectStage.NOT_STARTED;
        CleanReconnectTermination cleanReconnectTermination = CleanReconnectTermination.NONE;
        boolean cleanupZero = false;
        boolean workMaterialRemoved = false;
        try {
            Path repository = repositoryRoot();
            String runId = Instant.now().toString().replace(':', '-').replace('.', '-');
            Path workParent = repository.resolve("build/runtime-trusted-disposition/work");
            cleanupAbortedDispositionWork(workParent);
            workRoot = workParent.resolve("bungee-enforce_deny_reconnect-" + runId);
            Files.createDirectories(workRoot);
            harness = new ProbeHarness(repository, workRoot, ProxyKind.BUNGEE);
            harness.prepareTrustedDisposition(DispositionScenario.ENFORCE_DENY);
            forwardingConfigured = harness.forwardingConfigured;
            harness.startDisposition();
            publisherActive = harness.publishSyntheticDispositionPolicy("DISPOSITION_DENY");

            MinecraftWirePeer deniedPeer = new MinecraftWirePeer(harness, false);
            DenyPeerResult denied = deniedPeer.trustedDenyDispositionProbe();
            if (!publisherActive && denied.authorizationObserved() && denied.deniedResultObserved()) {
                harness.markBungeeRuntimePolicyMatched();
                publisherActive = harness.bungeePublisherGate().success();
            }
            firstCleanManifestSent = denied.cleanManifestSent();
            firstAuthenticationAccepted = denied.authenticationAccepted();
            firstLobbyVerifiedAdmission = denied.lobbyAdmission();
            reviewCommandSent = denied.reviewCommandSent();
            TrustedAuthorizationEvidence authorization =
                    harness.trustedDispositionAuthorizationEvidence("DENY");
            authorizationObserved = authorization.commandObserved();
            authorizationPersisted = authorization.journalRecordMatched();
            authorizationPersistedBeforeExecution = authorization.persistedBeforeExecution();
            deniedResultObserved = denied.deniedResultObserved()
                    && authorizationPersistedBeforeExecution;
            disconnectEvidence = denied.disconnectEvidence();

            if (disconnectEvidence != DisconnectEvidence.NONE) {
                proxyRegistryEmptyBeforeReconnect = harness.waitForControlledProxyRegistryEmpty(10);
            }
            int lobbyAdmissionsBeforeReconnect = -1;
            if (proxyRegistryEmptyBeforeReconnect) {
                lobbyAdmissionsBeforeReconnect = harness.waitForStableBackendAdmissionCount(
                        "paper-lobby", harness.paperRoot, 500, 3);
                MinecraftWirePeer cleanPeer = new MinecraftWirePeer(harness, false);
                CleanReconnectPeerResult clean = cleanPeer.cleanReconnectProbe(
                        lobbyAdmissionsBeforeReconnect);
                sameOfflineIdentity = Objects.equals(deniedPeer.playerId, cleanPeer.playerId);
                independentAuthenticatedSession = denied.authenticatedSessionId() != null
                        && clean.authenticatedSessionId() != null
                        && !denied.authenticatedSessionId().equals(clean.authenticatedSessionId());
                cleanManifestSent = clean.cleanManifestSent();
                reconnectAuthenticationAccepted = clean.authenticationAccepted();
                reconnectConfigurationCompleted = clean.configurationCompleted();
                reconnectLobbyVerifiedAdmission = clean.newLobbyVerifiedAdmission();
                cleanReconnectStage = clean.stage();
                cleanReconnectTermination = clean.termination();
            }
            limitedAdmission = harness.backendAccepted("paper-limited", harness.limitedPaperRoot);
            quarantineAdmission = harness.backendAccepted(
                    "paper-quarantine", harness.quarantinePaperRoot);
        } catch (Exception ignored) {
            // Only bounded booleans/enums escape this disposable process tree.
        } finally {
            if (harness != null) {
                harness.close();
                cleanupZero = harness.remainingRunProcesses().isEmpty();
            }
            if (workRoot != null) {
                try {
                    deleteOwnedWorkTree(workRoot);
                    workMaterialRemoved = !Files.exists(workRoot);
                } catch (Exception ignored) {
                    workMaterialRemoved = false;
                }
            }
        }
        return new BungeeDenyReconnectOutcome(
                forwardingConfigured, publisherActive, firstCleanManifestSent,
                firstAuthenticationAccepted, firstLobbyVerifiedAdmission,
                reviewCommandSent, authorizationObserved, authorizationPersisted,
                authorizationPersistedBeforeExecution,
                deniedResultObserved, disconnectEvidence, proxyRegistryEmptyBeforeReconnect,
                limitedAdmission, quarantineAdmission, sameOfflineIdentity,
                independentAuthenticatedSession, cleanManifestSent,
                reconnectAuthenticationAccepted, reconnectConfigurationCompleted,
                reconnectLobbyVerifiedAdmission, cleanReconnectStage,
                cleanReconnectTermination, cleanupZero, workMaterialRemoved);
    }

    @FunctionalInterface
    interface MillisSleeper {
        void sleep(long millis) throws InterruptedException;
    }

    /** Pure bounded stability gate shared by the real harness and fake-clock unit tests. */
    static int waitForStableCount(
            java.util.function.IntSupplier count,
            java.util.function.BooleanSupplier sourceAlive,
            int stableMillis,
            int maxMillis,
            java.util.function.LongSupplier nanoTime,
            MillisSleeper sleeper) throws IOException, InterruptedException {
        if (stableMillis <= 0 || maxMillis < stableMillis) {
            throw new IllegalArgumentException("invalid stability bounds");
        }
        if (!sourceAlive.getAsBoolean()) {
            throw new IOException("stability source is unavailable");
        }
        int previous = count.getAsInt();
        long now = nanoTime.getAsLong();
        long stableSince = now;
        long deadline = now + TimeUnit.MILLISECONDS.toNanos(maxMillis);
        while (now < deadline) {
            sleeper.sleep(50L);
            if (!sourceAlive.getAsBoolean()) {
                throw new IOException("stability source stopped");
            }
            int current = count.getAsInt();
            now = nanoTime.getAsLong();
            if (current != previous) {
                previous = current;
                stableSince = now;
            } else if (now - stableSince >= TimeUnit.MILLISECONDS.toNanos(stableMillis)) {
                return current;
            }
        }
        throw new IOException("stability deadline elapsed");
    }

    /**
     * Content-free three-signal cleanup gate. The current proxy generation must first report an
     * empty registry, then both the product-owned cleanup-ready marker and the test-only
     * PostOrder.LAST marker must advance beyond their pre-login baselines. A timeout, marker from
     * another generation, or unavailable observer is terminal and never authorizes construction
     * of the second peer.
     */
    static OldSessionCleanup waitForOldSessionCleanupGate(
            java.util.function.BooleanSupplier sourceAlive,
            java.util.function.BooleanSupplier observerReady,
            java.util.function.BooleanSupplier registryEmpty,
            java.util.function.BooleanSupplier productCleanupReadyMarkerAdvanced,
            java.util.function.BooleanSupplier disconnectMarkerAdvanced,
            int maxMillis,
            java.util.function.LongSupplier nanoTime,
            MillisSleeper sleeper) throws InterruptedException {
        if (maxMillis <= 0) throw new IllegalArgumentException("invalid cleanup bound");
        if (!sourceAlive.getAsBoolean() || !observerReady.getAsBoolean()) {
            return OldSessionCleanup.OBSERVER_UNAVAILABLE;
        }
        long deadline = nanoTime.getAsLong() + TimeUnit.MILLISECONDS.toNanos(maxMillis);
        OldSessionCleanup state = OldSessionCleanup.NOT_STARTED;
        while (nanoTime.getAsLong() < deadline) {
            if (!sourceAlive.getAsBoolean() || !observerReady.getAsBoolean()) {
                return OldSessionCleanup.OBSERVER_UNAVAILABLE;
            }
            if (registryEmpty.getAsBoolean()) {
                state = OldSessionCleanup.REGISTRY_EMPTY;
                break;
            }
            sleeper.sleep(50L);
        }
        if (state != OldSessionCleanup.REGISTRY_EMPTY) return OldSessionCleanup.TIMEOUT;
        while (nanoTime.getAsLong() < deadline) {
            if (!sourceAlive.getAsBoolean() || !observerReady.getAsBoolean()) {
                return OldSessionCleanup.OBSERVER_UNAVAILABLE;
            }
            // The status result is generation-bound too. Do not authorize a reconnect from a
            // stale earlier empty sample if another connection appeared while markers advanced.
            if (!registryEmpty.getAsBoolean()) {
                sleeper.sleep(50L);
                continue;
            }
            boolean productReady = productCleanupReadyMarkerAdvanced.getAsBoolean();
            boolean observerLast = disconnectMarkerAdvanced.getAsBoolean();
            if (observerLast) {
                state = OldSessionCleanup.DISCONNECT_LAST_LISTENER_OBSERVED;
            }
            if (productReady && observerLast) {
                return OldSessionCleanup.RECONNECT_FIXTURE_READY;
            }
            sleeper.sleep(50L);
        }
        return state == OldSessionCleanup.REGISTRY_EMPTY
                ? OldSessionCleanup.TIMEOUT : state;
    }

    static boolean mayOpenCleanReconnect(OldSessionCleanup cleanup) {
        return cleanup == OldSessionCleanup.RECONNECT_FIXTURE_READY;
    }

    /** Disables only the disposable loopback fixture's IP login throttle, exactly once. */
    static String disableVelocityFixtureLoginRatelimit(String configuration) throws IOException {
        String defaultLoginRatelimit = "login-ratelimit = 3000";
        if (configuration.indexOf(defaultLoginRatelimit) < 0
                || configuration.indexOf(defaultLoginRatelimit)
                != configuration.lastIndexOf(defaultLoginRatelimit)) {
            throw new IOException("Velocity fixture login-ratelimit default is unavailable");
        }
        String configured = configuration.replace(
                defaultLoginRatelimit, "login-ratelimit = 0");
        if (!configured.contains("login-ratelimit = 0")
                || configured.contains(defaultLoginRatelimit)) {
            throw new IOException("Velocity fixture login-ratelimit was not disabled");
        }
        return configured;
    }

    /** Parses only the controlled status response's players.online integer; no body is retained. */
    static boolean controlledStatusRegistryEmpty(String statusJson) throws IOException {
        int playersKey = statusJson.indexOf("\"players\"");
        int playersStart = playersKey < 0 ? -1 : statusJson.indexOf('{', playersKey);
        int playersEnd = playersStart < 0 ? -1 : matchingJsonObjectEnd(statusJson, playersStart);
        int onlineKey = playersStart < 0 ? -1 : statusJson.indexOf("\"online\"", playersStart);
        if (playersStart < 0 || playersEnd < 0 || onlineKey < 0 || onlineKey >= playersEnd) {
            throw new IOException("controlled status response lacks players.online");
        }
        int colon = statusJson.indexOf(':', onlineKey + "\"online\"".length());
        if (colon < 0 || colon >= playersEnd) {
            throw new IOException("controlled status response has invalid players.online");
        }
        int cursor = colon + 1;
        while (cursor < playersEnd && Character.isWhitespace(statusJson.charAt(cursor))) cursor++;
        int start = cursor;
        while (cursor < playersEnd && Character.isDigit(statusJson.charAt(cursor))) cursor++;
        if (start == cursor) {
            throw new IOException("controlled status response has non-integer players.online");
        }
        int delimiter = cursor;
        while (delimiter < playersEnd && Character.isWhitespace(statusJson.charAt(delimiter))) {
            delimiter++;
        }
        if (delimiter < playersEnd && statusJson.charAt(delimiter) != ',') {
            throw new IOException("controlled status response has invalid players.online delimiter");
        }
        try {
            return Integer.parseInt(statusJson.substring(start, cursor)) == 0;
        } catch (NumberFormatException exception) {
            throw new IOException("controlled status response players.online is out of range",
                    exception);
        }
    }

    private static int matchingJsonObjectEnd(String json, int objectStart) {
        int depth = 0;
        boolean quoted = false;
        boolean escaped = false;
        for (int index = objectStart; index < json.length(); index++) {
            char current = json.charAt(index);
            if (quoted) {
                if (escaped) escaped = false;
                else if (current == '\\') escaped = true;
                else if (current == '"') quoted = false;
                continue;
            }
            if (current == '"') quoted = true;
            else if (current == '{') depth++;
            else if (current == '}' && --depth == 0) return index;
        }
        return -1;
    }

    /** Removes only prior aborted roots that no live process identifies in its command line. */
    private static void cleanupAbortedDispositionWork(Path workParent) throws IOException {
        if (!Files.isDirectory(workParent)) return;
        Path normalizedParent = workParent.toAbsolutePath().normalize();
        try (var children = Files.list(normalizedParent)) {
            for (Path child : children.filter(Files::isDirectory).toList()) {
                Path normalized = child.toAbsolutePath().normalize();
                boolean ownedProcessAlive = ProcessHandle.allProcesses()
                        .filter(ProcessHandle::isAlive)
                        .anyMatch(handle -> handle.info().commandLine()
                                .map(line -> line.contains(normalized.toString())).orElse(false));
                if (!ownedProcessAlive && normalized.getParent().equals(normalizedParent)) {
                    deleteOwnedWorkTree(normalized);
                }
            }
        }
    }

    private static void deleteOwnedWorkTree(Path workRoot) throws IOException {
        Path normalized = workRoot.toAbsolutePath().normalize();
        Path repository = repositoryRoot();
        List<Path> expectedParents = List.of(
                repository.resolve("build/runtime-disposition-matrix/work")
                        .toAbsolutePath().normalize(),
                repository.resolve("build/runtime-trusted-disposition/work")
                        .toAbsolutePath().normalize());
        boolean owned = expectedParents.stream()
                .anyMatch(parent -> normalized.startsWith(parent) && !normalized.equals(parent));
        if (!owned) {
            throw new IOException("refusing to delete a non-owned disposition work tree");
        }
        if (!Files.exists(normalized)) return;
        IOException lastFailure = null;
        for (int attempt = 0; attempt < 20; attempt++) {
            try {
                try (var paths = Files.walk(normalized)) {
                    for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                        Files.deleteIfExists(path);
                    }
                }
                if (!Files.exists(normalized)) return;
            } catch (IOException exception) {
                lastFailure = exception;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while deleting owned disposition work tree", exception);
            }
        }
        throw new IOException("owned disposition work tree remained after bounded retries", lastFailure);
    }

    enum DispositionScenario {
        MONITOR_LIMIT("MONITOR", "DISPOSITION_LIMIT", "NOT_ENFORCED"),
        ENFORCE_LIMIT("LIMITED_ROUTE", "DISPOSITION_LIMIT", "LIMITED_DISPATCHED"),
        ENFORCE_QUARANTINE("LIMITED_ROUTE", "DISPOSITION_QUARANTINE", "QUARANTINED_DISPATCHED"),
        ENFORCE_DENY("LIMITED_ROUTE", "DISPOSITION_DENY", "DENIED");

        private final String mode;
        private final String policyAction;
        private final String expectedResult;

        DispositionScenario(String mode, String policyAction, String expectedResult) {
            this.mode = mode;
            this.policyAction = policyAction;
            this.expectedResult = expectedResult;
        }

        String mode() { return mode; }
        String policyAction() { return policyAction; }
        String expectedResult() { return expectedResult; }
        String actionName() {
            return switch (this) {
                case ENFORCE_QUARANTINE -> "QUARANTINE";
                case ENFORCE_DENY -> "DENY";
                default -> "LIMIT";
            };
        }

        String manifestExecutionResult() {
            return switch (this) {
                case ENFORCE_QUARANTINE -> "QUARANTINED_DEFERRED";
                case ENFORCE_DENY -> "DENIED";
                default -> "LIMITED_DEFERRED";
            };
        }
    }

    enum RouteCompletion {
        NONE,
        SUCCESS,
        ALREADY_CONNECTED,
        CONNECTION_IN_PROGRESS,
        CONNECTION_CANCELLED,
        SERVER_DISCONNECTED,
        FAILED,
        NON_SUCCESS
    }

    enum DisconnectEvidence {
        NONE,
        PROTOCOL_DISCONNECT,
        REMOTE_EOF_OR_RESET
    }

    enum CleanReconnectStage {
        NOT_STARTED,
        TCP_CONNECTED,
        LOGIN_SUCCESS,
        CONFIGURATION,
        SERVER_HELLO,
        AUTH_SENT,
        AUTH_ACCEPTED,
        PLAY,
        LOBBY_VERIFIED
    }

    enum CleanReconnectTermination {
        NONE,
        LOGIN_DISCONNECT,
        CONFIGURATION_DISCONNECT,
        REMOTE_EOF_OR_RESET,
        READ_TIMEOUT,
        PROTOCOL_ERROR
    }

    enum OldSessionCleanup {
        NOT_STARTED,
        REGISTRY_EMPTY,
        /** Only proves the observer's final listener ran; it does not prove product cleanup. */
        DISCONNECT_LAST_LISTENER_OBSERVED,
        /** Registry is empty and both current-generation lifecycle markers advanced. */
        RECONNECT_FIXTURE_READY,
        TIMEOUT,
        OBSERVER_UNAVAILABLE
    }

    /** Content-free terminal diagnostic for the per-source Bungee publish evidence gate. */
    enum PublisherGate {
        NOT_ATTEMPTED,
        ACTIVE,
        MIRRORED_MATCH,
        CROSS_SOURCE_MATCH,
        RUNTIME_POLICY_MATCHED,
        SOURCE_SET_CHANGED,
        SOURCE_UNAVAILABLE,
        SOURCE_IDENTITY_CHANGED,
        SOURCE_TRUNCATED,
        BASELINE_INVALID,
        SUFFIX_INVALID,
        NO_NEW_MARKER,
        SOURCE_INCOMPLETE,
        SOURCE_DUPLICATE_ACK,
        SOURCE_DUPLICATE_ACTIVE,
        SEQUENCE_MISMATCH,
        CROSS_SOURCE_CONFLICT,
        NOT_FRESH,
        PROXY_EXIT,
        TIMEOUT;

        boolean success() { return this == ACTIVE || this == MIRRORED_MATCH || this == CROSS_SOURCE_MATCH || this == RUNTIME_POLICY_MATCHED; }
    }

    enum ServerHelloStage { NOT_OBSERVED, LOGIN, CONFIGURATION, PLAY }
    enum AuthOutboundStage { NOT_SENT, EMPTY, LOGIN, CONFIGURATION, PLAY }
    enum AuthResultStage {
        NOT_OBSERVED,
        REJECTED_LOGIN, REJECTED_CONFIGURATION, REJECTED_PLAY,
        ACCEPTED_LOGIN, ACCEPTED_CONFIGURATION, ACCEPTED_PLAY
    }
    enum RemoteLiveness {
        NOT_ATTEMPTED, PACKET, QUIET_TIMEOUT, DATA_FORMAT, EOF_OR_RESET, IO_FAILURE;
        boolean openOutcome() {
            return this == PACKET || this == QUIET_TIMEOUT || this == DATA_FORMAT;
        }
    }

    record DispositionCaseOutcome(
            DispositionScenario scenario,
            boolean forwardingConfigured,
            boolean publisherActive,
            boolean syntheticManifestSent,
            boolean authenticationAccepted,
            boolean dispositionResultObserved,
            boolean lobbyAdmission,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean anyRouteLifecycleObserved,
            RouteCompletion routeCompletion,
            boolean connectionRetained,
            boolean cleanupZero,
            boolean workMaterialRemoved) {
        boolean passed() {
            boolean advisoryOnly = !anyRouteLifecycleObserved
                    && routeCompletion == RouteCompletion.NONE
                    && lobbyAdmission && !limitedAdmission && !quarantineAdmission;
            return forwardingConfigured && publisherActive && syntheticManifestSent
                    && authenticationAccepted && dispositionResultObserved && advisoryOnly
                    && connectionRetained && cleanupZero && workMaterialRemoved;
        }
    }

    /** Bungee-only Phase-2 evidence, including the required deferred one-shot hand-off. */
    record BungeeDispositionCaseOutcome(
            DispositionScenario scenario,
            boolean forwardingConfigured,
            boolean publisherActive,
            PublisherGate publisherGate,
            boolean syntheticManifestSent,
            boolean authenticationAccepted,
            boolean authenticationAcceptedAnyPhase,
            ServerHelloStage serverHelloStage,
            AuthOutboundStage authOutboundStage,
            AuthResultStage authResultStage,
            boolean dispositionResultObserved,
            boolean deferredRouteObserved,
            boolean deferredRouteDispatched,
            boolean anyRouteLifecycleObserved,
            boolean lobbyAdmission,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            RouteCompletion routeCompletion,
            RemoteLiveness remoteLiveness,
            boolean connectionRetained,
            boolean cleanupZero,
            boolean workMaterialRemoved) {
        BungeeDispositionCaseOutcome {
            Objects.requireNonNull(publisherGate, "publisherGate");
            Objects.requireNonNull(serverHelloStage, "serverHelloStage");
            Objects.requireNonNull(authOutboundStage, "authOutboundStage");
            Objects.requireNonNull(authResultStage, "authResultStage");
            Objects.requireNonNull(remoteLiveness, "remoteLiveness");
            publisherActive = publisherGate.success();
            authenticationAccepted = serverHelloStage == ServerHelloStage.CONFIGURATION
                    && authOutboundStage == AuthOutboundStage.CONFIGURATION
                    && authResultStage == AuthResultStage.ACCEPTED_CONFIGURATION;
            authenticationAcceptedAnyPhase = switch (authResultStage) {
                case ACCEPTED_LOGIN, ACCEPTED_CONFIGURATION, ACCEPTED_PLAY -> true;
                default -> false;
            };
        }
        boolean passed() {
            boolean advisoryOnly = routeCompletion == RouteCompletion.NONE
                    && !deferredRouteObserved && !deferredRouteDispatched
                    && !anyRouteLifecycleObserved
                    && lobbyAdmission && !limitedAdmission && !quarantineAdmission;
            return forwardingConfigured && publisherActive && syntheticManifestSent
                    && authenticationAcceptedAnyPhase && dispositionResultObserved && advisoryOnly
                    && connectionRetained && cleanupZero && workMaterialRemoved;
        }
    }

    record TrustedDispositionCaseOutcome(
            ProxyKind kind,
            DispositionScenario scenario,
            boolean forwardingConfigured,
            boolean publisherActive,
            boolean authenticationAccepted,
            boolean reviewCommandSent,
            boolean authorizationObserved,
            boolean authorizationPersisted,
            boolean authorizationPersistedBeforeExecution,
            boolean dispositionResultObserved,
            boolean lobbyAdmission,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            RouteCompletion routeCompletion,
            boolean connectionRetained,
            boolean cleanupZero,
            boolean workMaterialRemoved) {
        boolean passed() {
            boolean expectedTarget = scenario == DispositionScenario.ENFORCE_QUARANTINE
                    ? quarantineAdmission && !limitedAdmission
                    : limitedAdmission && !quarantineAdmission;
            return forwardingConfigured && publisherActive && authenticationAccepted
                    && reviewCommandSent && authorizationObserved && authorizationPersisted
                    && authorizationPersistedBeforeExecution
                    && dispositionResultObserved && lobbyAdmission && expectedTarget
                    && routeCompletion == RouteCompletion.SUCCESS && connectionRetained
                    && cleanupZero && workMaterialRemoved;
        }
    }
    record BungeeDenyReconnectOutcome(
            boolean forwardingConfigured,
            boolean publisherActive,
            boolean firstCleanManifestSent,
            boolean firstAuthenticationAccepted,
            boolean firstLobbyVerifiedAdmission,
            boolean reviewCommandSent,
            boolean authorizationObserved,
            boolean authorizationPersisted,
            boolean authorizationPersistedBeforeExecution,
            boolean deniedResultObserved,
            DisconnectEvidence disconnectEvidence,
            boolean proxyRegistryEmptyBeforeReconnect,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean sameOfflineIdentity,
            boolean independentAuthenticatedSession,
            boolean cleanManifestSent,
            boolean reconnectAuthenticationAccepted,
            boolean reconnectConfigurationCompleted,
            boolean reconnectLobbyVerifiedAdmission,
            CleanReconnectStage cleanReconnectStage,
            CleanReconnectTermination cleanReconnectTermination,
            boolean cleanupZero,
            boolean workMaterialRemoved) {
        boolean firstConnectionClosed() {
            return disconnectEvidence != DisconnectEvidence.NONE;
        }

        boolean passed() {
            return forwardingConfigured && publisherActive && firstCleanManifestSent
                    && firstAuthenticationAccepted && firstLobbyVerifiedAdmission
                    && reviewCommandSent && authorizationObserved && authorizationPersisted
                    && authorizationPersistedBeforeExecution
                    && deniedResultObserved && firstConnectionClosed()
                    && proxyRegistryEmptyBeforeReconnect
                    && !limitedAdmission && !quarantineAdmission
                    && sameOfflineIdentity && independentAuthenticatedSession && cleanManifestSent
                    && reconnectAuthenticationAccepted && reconnectConfigurationCompleted
                    && reconnectLobbyVerifiedAdmission
                    && cleanReconnectStage == CleanReconnectStage.LOBBY_VERIFIED
                    && cleanReconnectTermination == CleanReconnectTermination.NONE
                    && cleanupZero && workMaterialRemoved;
        }

        String reconnectOutcome() {
            return reconnectAuthenticationAccepted && reconnectConfigurationCompleted
                    && reconnectLobbyVerifiedAdmission
                    && cleanReconnectStage == CleanReconnectStage.LOBBY_VERIFIED
                    && cleanReconnectTermination == CleanReconnectTermination.NONE
                    ? "VERIFIED_LOBBY" : "NOT_VERIFIED";
        }
    }

    record DenyReconnectOutcome(
            boolean forwardingConfigured,
            boolean fixtureLoginRatelimitDisabled,
            boolean publisherActive,
            boolean firstCleanManifestSent,
            boolean firstAuthenticationAccepted,
            boolean firstLobbyVerifiedAdmission,
            boolean reviewCommandSent,
            boolean authorizationObserved,
            boolean authorizationPersisted,
            boolean authorizationPersistedBeforeExecution,
            boolean deniedResultObserved,
            DisconnectEvidence disconnectEvidence,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean sameOfflineIdentity,
            boolean independentAuthenticatedSession,
            boolean cleanManifestSent,
            boolean reconnectAuthenticationAccepted,
            boolean reconnectConfigurationCompleted,
            boolean reconnectLobbyVerifiedAdmission,
            CleanReconnectStage cleanReconnectStage,
            CleanReconnectTermination cleanReconnectTermination,
            OldSessionCleanup oldSessionCleanup,
            boolean cleanupZero,
            boolean workMaterialRemoved) {
        boolean firstConnectionClosed() {
            return disconnectEvidence != DisconnectEvidence.NONE;
        }

        boolean reconnectFixtureReady() {
            return oldSessionCleanup == OldSessionCleanup.RECONNECT_FIXTURE_READY;
        }

        boolean passed() {
            return forwardingConfigured && fixtureLoginRatelimitDisabled
                    && publisherActive && firstCleanManifestSent
                    && firstAuthenticationAccepted && firstLobbyVerifiedAdmission
                    && reviewCommandSent && authorizationObserved && authorizationPersisted
                    && authorizationPersistedBeforeExecution
                    && deniedResultObserved
                    && firstConnectionClosed() && !limitedAdmission && !quarantineAdmission
                    && reconnectFixtureReady()
                    && sameOfflineIdentity && independentAuthenticatedSession && cleanManifestSent
                    && reconnectAuthenticationAccepted && reconnectConfigurationCompleted
                    && reconnectLobbyVerifiedAdmission
                    && cleanReconnectStage == CleanReconnectStage.LOBBY_VERIFIED
                    && cleanReconnectTermination == CleanReconnectTermination.NONE
                    && cleanupZero && workMaterialRemoved;
        }

        String reconnectOutcome() {
            return reconnectAuthenticationAccepted && reconnectConfigurationCompleted
                    && reconnectLobbyVerifiedAdmission
                    && cleanReconnectStage == CleanReconnectStage.LOBBY_VERIFIED
                    && cleanReconnectTermination == CleanReconnectTermination.NONE
                    ? "VERIFIED_LOBBY" : "NOT_VERIFIED";
        }
    }

    enum ProxyKind { VELOCITY, BUNGEE }
    enum BackendKind { PAPER, FOLIA }

    static final class ProbeHarness implements AutoCloseable {
        private final Path repository;
        private final Path runRoot;
        private final ProxyKind kind;
        private final BackendKind backendKind;
        private final RuntimeProcessAssets runtimeAssets;
        private final List<OwnedProcess> processes = new ArrayList<>();
        private final List<Integer> cleanupProcessIds = new ArrayList<>();
        private Path proxyRoot;
        private Path paperRoot;
        /**
         * Immutable copy of the prepared runtime payload retained separately from the live
         * backend work tree. Newer Folia bootstrap versions may rewrite the version jar in-place
         * while starting; the release gate must verify the bytes that were actually handed to the
         * process, not the post-bootstrap mutable copy.
         */
        private Path preparedSnapshotRoot;
        private Path limitedPaperRoot;
        private Path quarantinePaperRoot;
        private int proxyPort;
        private int paperPort;
        private int limitedPaperPort;
        private int quarantinePaperPort;
        private PublicKey proxyPublicKey;
        private String forwardingMode;
        private boolean forwardingConfigured;
        private String backendMinecraftVersion;
        private MinecraftWireProfile wireProfile;
        private boolean velocityLoginRatelimitDisabled;
        private int processGeneration;
        private PublisherGate lastBungeePublisherGate = PublisherGate.NOT_ATTEMPTED;
        private boolean trustedDispositionCase;
        private final List<Path> sensitiveForwardingFiles = new ArrayList<>();
        private final List<Path> temporaryProxyPrivateKeys = new ArrayList<>();

        private ProbeHarness(Path repository, Path runRoot, ProxyKind kind) {
            this(repository, runRoot, kind, BackendKind.PAPER);
        }

        private ProbeHarness(
                Path repository, Path runRoot, ProxyKind kind, BackendKind backendKind) {
            this.repository = repository;
            this.runRoot = runRoot;
            this.kind = kind;
            this.backendKind = backendKind;
            this.runtimeAssets = RuntimeProcessAssets.fromSystemProperties(
                    backendKind.name(), kind.name());
            this.wireProfile = runtimeAssets.wireProfile();
            this.backendMinecraftVersion = wireProfile.minecraftVersion();
        }

        private void prepare() throws Exception {
            proxyPort = freePort();
            paperPort = freePort();
            while (paperPort == proxyPort) paperPort = freePort();
            proxyRoot = runRoot.resolve("proxy");
            paperRoot = runRoot.resolve("paper");
            Files.createDirectories(proxyRoot.resolve("plugins"));
            Path proxyJar = runtimeAssets.proxyJar();
            Path proxyPlugin = kind == ProxyKind.VELOCITY
                    ? repositoryArtifact(repository, "mcace-server-velocity")
                    : repositoryArtifact(repository, "mcace-server-bungeecord");
            Path backendJar = runtimeAssets.backendJar();
            Path paperPlugin = repositoryArtifact(repository, "mcace-server-paper");
            Path prepared = runtimeAssets.preparedRoot();
            requireArtifact(proxyJar, "proxy artifact");
            requireArtifact(proxyPlugin, "proxy MCAce plugin");
            requireArtifact(backendJar, backendKind + " artifact");
            requireArtifact(paperPlugin, "Paper/Folia MCAce plugin");
            requireArtifact(prepared.resolve("cache"), "prepared " + backendKind + " cache");
            requireArtifact(prepared.resolve("libraries"), "prepared " + backendKind + " libraries");
            requireArtifact(prepared.resolve("versions"), "prepared " + backendKind + " versions");
            Files.copy(proxyJar, proxyRoot.resolve(kind == ProxyKind.VELOCITY ? "velocity.jar" : "BungeeCord.jar"));
            Files.copy(proxyPlugin, proxyRoot.resolve("plugins/mcace.jar"));
            if (kind == ProxyKind.VELOCITY) {
                String config;
                try (ZipFile archive = new ZipFile(proxyJar.toFile())) {
                    var entry = archive.getEntry("default-velocity.toml");
                    if (entry == null) throw new IOException("Velocity default-velocity.toml missing");
                    try (InputStream input = archive.getInputStream(entry)) {
                        config = new String(input.readAllBytes(), StandardCharsets.UTF_8);
                    }
                }
                config = config.replace("bind = \"0.0.0.0:25565\"", "bind = \"127.0.0.1:" + proxyPort + "\"")
                        .replace("online-mode = true", "online-mode = false")
                        .replace("force-key-authentication = true", "force-key-authentication = false")
                        .replace("lobby = \"127.0.0.1:30066\"", "lobby = \"127.0.0.1:" + paperPort + "\"")
                        .replace("player-info-forwarding-mode = \"NONE\"", "player-info-forwarding-mode = \"modern\"");
                config = disableVelocityFixtureLoginRatelimit(config);
                velocityLoginRatelimitDisabled = config.contains("login-ratelimit = 0")
                        && !config.contains("login-ratelimit = 3000");
                if (!velocityLoginRatelimitDisabled) {
                    throw new IOException("Velocity fixture login-ratelimit was not disabled");
                }
                Files.writeString(proxyRoot.resolve("velocity.toml"), config, StandardCharsets.UTF_8);
                Path secret = proxyRoot.resolve("forwarding.secret");
                Files.writeString(secret, Base64.getEncoder().encodeToString(randomBytes(32)) + "\n", StandardCharsets.US_ASCII);
                sensitiveForwardingFiles.add(secret);
                forwardingMode = "velocity-modern";
            } else {
                Files.writeString(proxyRoot.resolve("config.yml"), bungeeConfig(), StandardCharsets.UTF_8);
                forwardingMode = "bungee-ip-forwarding";
            }
            preparedSnapshotRoot = runRoot.resolve("prepared-snapshot");
            copyPreparedRuntime(prepared, preparedSnapshotRoot);
            copyPreparedRuntime(prepared, paperRoot);
            createPrivatePaperPluginDirectory(paperRoot);
            Files.copy(backendJar, paperRoot.resolve(backendJarFileName()));
            Files.copy(paperPlugin, paperRoot.resolve("plugins/mcace.jar"));
            Files.writeString(paperRoot.resolve("eula.txt"), "eula=true\n", StandardCharsets.UTF_8);
            Files.writeString(paperRoot.resolve("server.properties"),
                    "online-mode=false\nserver-ip=127.0.0.1\nserver-port=" + paperPort
                            + "\nenable-query=false\nmotd=MCAce test-only "
                            + backendKind.name().toLowerCase(java.util.Locale.ROOT) + " player probe\n",
                    StandardCharsets.UTF_8);
            configurePaperForwarding();
            Path data = proxyDataDirectory();
            createPrivateProxyDataDirectory(data);
            // Velocity creates both the root identity and its delegated policy signing key on first
            // start. Register both before launch so normal, disposition and Folia probes cannot
            // retain either private key. The delegated path is harmlessly absent for Bungee.
            registerTemporaryProxyPrivateKeys(data);
            Files.writeString(data.resolve("mcace.properties"),
                    kind == ProxyKind.VELOCITY
                            ? "policy.server-id=mcace-velocity\n"
                                    + "policy.minecraft-versions=" + backendMinecraftVersion + "\n"
                                    + "policy.client-build-ids=" + BUILD_ID + "\n"
                                    + "handshake.timeout.seconds=5\n"
                                    + "storage.enabled=false\n"
                            : "server.id=mcace-bungee\n"
                                    + "minecraft.version=" + backendMinecraftVersion + "\n"
                                    + "client.build-id=" + BUILD_ID + "\n"
                                    + "handshake.timeout.seconds=5\n",
                    StandardCharsets.UTF_8);
        }

        private void prepareDisposition(DispositionScenario scenario) throws Exception {
            prepareDisposition(scenario.mode());
        }

        private void prepareTrustedDisposition(DispositionScenario scenario) throws Exception {
            trustedDispositionCase = true;
            prepareDisposition(scenario.mode());
        }

        private void prepareDisposition(String executionMode) throws Exception {
            prepare();
            if (kind == ProxyKind.VELOCITY) {
                installVelocityDisconnectObserver();
            }
            limitedPaperPort = distinctFreePort(proxyPort, paperPort);
            quarantinePaperPort = distinctFreePort(proxyPort, paperPort, limitedPaperPort);
            limitedPaperRoot = runRoot.resolve("paper-limited");
            quarantinePaperRoot = runRoot.resolve("paper-quarantine");

            if (kind == ProxyKind.VELOCITY) {
                Path velocityConfig = proxyRoot.resolve("velocity.toml");
                String config = Files.readString(velocityConfig, StandardCharsets.UTF_8);
                String lobbyLine = "lobby = \"127.0.0.1:" + paperPort + "\"";
                String threeBackends = lobbyLine
                        + "\nlimited = \"127.0.0.1:" + limitedPaperPort + "\""
                        + "\nquarantine = \"127.0.0.1:" + quarantinePaperPort + "\"";
                if (!config.contains(lobbyLine)) {
                    throw new IOException("Velocity lobby fixture entry is unavailable");
                }
                Files.writeString(velocityConfig, config.replace(lobbyLine, threeBackends),
                        StandardCharsets.UTF_8);
            } else {
                // Bungee must register all three names before MCAce constructs its route executor.
                // The ports are per-case loopback allocations, never production configuration.
                Files.writeString(proxyRoot.resolve("config.yml"), bungeeDispositionConfig(),
                        StandardCharsets.UTF_8);
            }

            Path data = proxyDataDirectory();
            createPrivateProxyDataDirectory(data);
            Files.writeString(data.resolve("mcace.properties"),
                    kind == ProxyKind.VELOCITY ? """
                            enforcement.mode=%s
                            disposition.limited.server=limited
                            disposition.quarantine.server=quarantine
                            handshake.timeout.seconds=5
                            policy.server-id=mcace-velocity
                            policy.minecraft-versions=%s
                            policy.client-build-ids=fabric-phase2-dev
                            storage.enabled=false
                            heartbeat.missing.enabled=false
                            heartbeat.missing.consecutive-polls=3
                            heartbeat.missing.action=NOTICE
                            """.formatted(executionMode, backendMinecraftVersion) : """
                            server.id=mcace-bungee
                            minecraft.version=%s
                            client.build-id=fabric-phase2-dev
                            handshake.timeout.seconds=5
                            disposition.enforcement.mode=%s
                            disposition.limited.server=limited
                            disposition.quarantine.server=quarantine
                            heartbeat.missing.enabled=false
                            heartbeat.missing.consecutive-polls=3
                            heartbeat.missing.action=NOTICE
                            """.formatted(backendMinecraftVersion, executionMode), StandardCharsets.UTF_8);

            prepareAdditionalPaper(limitedPaperRoot, limitedPaperPort);
            prepareAdditionalPaper(quarantinePaperRoot, quarantinePaperPort);
        }

        private void prepareAdditionalPaper(Path root, int port) throws Exception {
            Path prepared = runtimeAssets.preparedRoot();
            Path paperJar = runtimeAssets.backendJar();
            Path paperPlugin = repositoryArtifact(repository, "mcace-server-paper");
            copyPreparedRuntime(prepared, root);
            createPrivatePaperPluginDirectory(root);
            Files.copy(paperJar, root.resolve("paper.jar"));
            Files.copy(paperPlugin, root.resolve("plugins/mcace.jar"));
            Files.writeString(root.resolve("eula.txt"), "eula=true\n", StandardCharsets.UTF_8);
            Files.writeString(root.resolve("server.properties"),
                    "online-mode=false\nserver-ip=127.0.0.1\nserver-port=" + port
                            + "\nenable-query=false\nmotd=MCAce test-only disposition backend\n",
                    StandardCharsets.UTF_8);
            configurePaperForwarding(root);
        }

        /**
         * The production Paper plugin reads the proxy public-key pin through an integrity-
         * protected authority path.  A plain createDirectories call inherits the workspace
         * ACL on Windows, which grants write access to Users and is correctly rejected by the
         * fail-closed preflight.  Create this test-only data directory with the same owner+
         * SYSTEM private ACL contract used by the runtime.
         */
        private void createPrivatePaperPluginDirectory(Path paperRoot) throws IOException {
            AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                    paperRoot.resolve("plugins/MCAce"), "test Paper MCAce data directory");
        }

        private void createPrivateProxyDataDirectory(Path data) throws IOException {
            AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                    data, "test proxy MCAce data directory");
        }

        private void installVelocityDisconnectObserver() throws IOException {
            String configured = System.getProperty(VELOCITY_OBSERVER_JAR_PROPERTY);
            if (configured == null || configured.isBlank()) {
                throw new IOException("test-only disconnect observer artifact is unavailable");
            }
            Path observerJar = Path.of(configured).toAbsolutePath().normalize();
            requireArtifact(observerJar, "test-only disconnect observer artifact");
            Files.copy(observerJar,
                    proxyRoot.resolve("plugins/mcace-runtime-disconnect-observer.jar"));
        }

        private static int distinctFreePort(int... used) throws IOException {
            while (true) {
                int candidate = freePort();
                boolean distinct = true;
                for (int value : used) distinct &= candidate != value;
                if (distinct) return candidate;
            }
        }

        private void prepareFederation(
                String localNetworkId,
                KeyPair identity,
                String peerNetworkId,
                PublicKey peerIdentity,
                String capability) throws Exception {
            prepare();
            Path data = proxyDataDirectory();
            Path identityDirectory = data.resolve("identity");
            AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                    identityDirectory, "test proxy identity directory");
            Path temporaryPrivateKey = identityDirectory.resolve("server-private-key.pk8");
            byte[] privateBytes = identity.getPrivate().getEncoded();
            try {
                AuthorityFilePreflight.writePrivateFileAtomically(
                        identityDirectory, temporaryPrivateKey, privateBytes,
                        "test proxy private identity key");
            } finally {
                java.util.Arrays.fill(privateBytes, (byte) 0);
            }
            if (!temporaryProxyPrivateKeys.contains(temporaryPrivateKey)) {
                temporaryProxyPrivateKeys.add(temporaryPrivateKey);
            }
            AuthorityFilePreflight.writePrivateFileAtomically(
                    identityDirectory,
                    identityDirectory.resolve("server-public-key.txt"),
                    (Base64.getEncoder().encodeToString(identity.getPublic().getEncoded()) + "\n")
                            .getBytes(StandardCharsets.US_ASCII),
                    "test proxy public identity key");
            String localConfiguration = federationLocalConfiguration(
                    kind, localNetworkId, backendMinecraftVersion);
            Files.writeString(data.resolve("mcace.properties"), localConfiguration,
                    StandardCharsets.UTF_8);
            String peerKey = Base64.getEncoder().encodeToString(peerIdentity.getEncoded());
            String peerPin = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(peerIdentity.getEncoded()));
            Files.writeString(data.resolve("federation.properties"), """
                    schema.version=1
                    enabled=true
                    local.network-id=%s
                    assertion.ttl.seconds=120
                    peer.ids=%s
                    peer.%s.public-key-x509-base64=%s
                    peer.%s.key-id-sha256=%s
                    peer.%s.capabilities=%s
                    """.formatted(localNetworkId, peerNetworkId, peerNetworkId, peerKey,
                            peerNetworkId, peerPin, peerNetworkId, capability),
                    StandardCharsets.UTF_8);
        }

        private Path proxyDataDirectory() {
            return proxyRoot.resolve(kind == ProxyKind.VELOCITY ? "plugins/mcace" : "plugins/MCAce");
        }

        private String backendJarFileName() {
            return backendKind == BackendKind.FOLIA ? "folia.jar" : "paper.jar";
        }

        private String backendProcessName() {
            return backendKind.name().toLowerCase(java.util.Locale.ROOT);
        }

        private void start() throws Exception {
            startProxy();
            Path identity = kind == ProxyKind.VELOCITY
                    ? proxyRoot.resolve("plugins/mcace/identity/server-public-key.txt")
                    : proxyRoot.resolve("plugins/MCAce/identity/server-public-key.txt");
            waitForPath(identity, 30);
            proxyPublicKey = Ed25519Keys.decodePublic(Base64.getDecoder().decode(
                    Files.readString(identity, StandardCharsets.UTF_8).trim()));
            Files.copy(identity, paperRoot.resolve("plugins/MCAce/proxy-public-key.txt"));
            OwnedProcess backend = startProcess(backendProcessName(), paperRoot,
                    paperRoot.resolve(backendJarFileName()), "-Xmx1024m");
            int backendStartupTimeoutSeconds = backendStartupTimeoutSeconds();
            waitFor(backend, "MCAce signed proxy admission channel enabled",
                    backendStartupTimeoutSeconds);
            if (backendKind == BackendKind.FOLIA) {
                waitFor(backend, "MCAce task runtime=FOLIA", backendStartupTimeoutSeconds);
            }
            waitFor(backend, "Done (", backendStartupTimeoutSeconds);
            verifyBackendBanner(backend);
        }

        /**
         * Minecraft 26.2 performs a first-run data-pack/world bootstrap before Bukkit plugin
         * enablement.  On a cold Windows checkout behind either proxy this can exceed two
         * minutes; keep the gate bounded, but do not turn a slow legitimate startup into a
         * false compatibility failure.  The warmed Velocity case is normally much faster, but
         * using the same bound keeps the matrix deterministic across proxy orderings.
         */
        private int backendStartupTimeoutSeconds() {
            return "26.2".equals(backendMinecraftVersion)
                    ? 300 : 120;
        }

        private void startDisposition() throws Exception {
            startProxy();
            Path identity = proxyDataDirectory().resolve("identity/server-public-key.txt");
            waitForPath(identity, 30);
            proxyPublicKey = Ed25519Keys.decodePublic(Base64.getDecoder().decode(
                    Files.readString(identity, StandardCharsets.UTF_8).trim()));
            for (Path root : List.of(paperRoot, limitedPaperRoot, quarantinePaperRoot)) {
                Files.copy(identity, root.resolve("plugins/MCAce/proxy-public-key.txt"));
            }
            startNamedPaper("paper-lobby", paperRoot);
            startNamedPaper("paper-limited", limitedPaperRoot);
            startNamedPaper("paper-quarantine", quarantinePaperRoot);
        }

        private boolean runtimeDisconnectObserverReady() throws InterruptedException {
            OwnedProcess generation = currentProxyProcess();
            if (generation == null) return false;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            while (System.nanoTime() < deadline) {
                if (!isCurrentGenerationAlive(generation)) return false;
                if (currentGenerationContains(generation, VELOCITY_OBSERVER_READY_MARKER)) return true;
                Thread.sleep(50L);
            }
            return false;
        }

        /**
         * Captures marker counters only from the currently running proxy process.  The process
         * identity is retained in memory solely to reject a proxy restart; it is never reported.
         */
        private CleanupMarkerBaseline captureCurrentGenerationCleanupMarkerBaseline()
                throws IOException {
            OwnedProcess proxy = currentProxyProcess();
            if (proxy == null || !proxy.process().isAlive()) {
                throw new IOException("current Velocity generation is unavailable");
            }
            String output = currentGenerationOutput(proxy);
            if (output == null) throw new IOException("current Velocity generation changed");
            return new CleanupMarkerBaseline(
                    proxy,
                    markerCount(output, VELOCITY_LOGIN_CLEANUP_READY_MARKER),
                    markerCount(output, VELOCITY_OBSERVER_DISCONNECT_MARKER));
        }

        private OldSessionCleanup waitForOldSessionCleanup(
                CleanupMarkerBaseline baseline, int seconds) throws InterruptedException {
            return waitForOldSessionCleanupGate(
                    () -> isCurrentGenerationAlive(baseline.proxy()),
                    () -> currentGenerationContains(baseline.proxy(), VELOCITY_OBSERVER_READY_MARKER),
                    () -> controlledStatusReportsRegistryEmpty(baseline.proxy()),
                    () -> currentGenerationMarkerAdvanced(
                            baseline.proxy(), VELOCITY_LOGIN_CLEANUP_READY_MARKER,
                            baseline.productReadyMarkerCount()),
                    () -> currentGenerationMarkerAdvanced(
                            baseline.proxy(), VELOCITY_OBSERVER_DISCONNECT_MARKER,
                            baseline.observerLastMarkerCount()),
                    Math.multiplyExact(seconds, 1_000),
                    System::nanoTime,
                    Thread::sleep);
        }

        private boolean waitForControlledProxyRegistryEmpty(int seconds)
                throws InterruptedException {
            OwnedProcess proxy = currentProxyProcess();
            if (proxy == null) return false;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (!isCurrentGenerationAlive(proxy)) return false;
                if (controlledStatusReportsRegistryEmpty(proxy)) return true;
                Thread.sleep(50L);
            }
            return false;
        }

        /** A bounded loopback status ping. The response body and player count never leave this call. */
        private boolean controlledStatusReportsRegistryEmpty(OwnedProcess expectedProxy) {
            if (!isCurrentGenerationAlive(expectedProxy)) return false;
            try (Socket status = new Socket()) {
                status.connect(new java.net.InetSocketAddress(
                        InetAddress.getLoopbackAddress(), proxyPort), 1_000);
                status.setSoTimeout(1_000);
                DataInputStream statusInput = new DataInputStream(status.getInputStream());
                DataOutputStream statusOutput = new DataOutputStream(status.getOutputStream());
                writeUncompressedPacket(statusOutput, 0, concat(
                        varInt(wireProfile.protocolVersion()),
                        string("127.0.0.1"),
                        shortBytes(proxyPort),
                        varInt(1)));
                writeUncompressedPacket(statusOutput, 0, new byte[0]);
                int frameLength = readVarInt(statusInput);
                if (frameLength <= 0 || frameLength > MAX_PACKET_BYTES) return false;
                byte[] frame = statusInput.readNBytes(frameLength);
                if (frame.length != frameLength) return false;
                DataInputStream packet = new DataInputStream(new ByteArrayInputStream(frame));
                if (readVarInt(packet) != 0) return false;
                return isCurrentGenerationAlive(expectedProxy)
                        && controlledStatusRegistryEmpty(readString(packet));
            } catch (IOException exception) {
                return false;
            }
        }

        private OwnedProcess currentProxyProcess() {
            if (processes.isEmpty()) return null;
            OwnedProcess proxy = processes.getFirst();
            return proxy.name().equals("proxy") ? proxy : null;
        }

        private boolean isCurrentGenerationAlive(OwnedProcess expectedProxy) {
            return expectedProxy != null && currentProxyProcess() == expectedProxy
                    && expectedProxy.process().isAlive();
        }

        private String currentGenerationOutput(OwnedProcess expectedProxy) {
            if (!isCurrentGenerationAlive(expectedProxy)) return null;
            String output = readProcessOutput(expectedProxy);
            return isCurrentGenerationAlive(expectedProxy) ? output : null;
        }

        private boolean currentGenerationContains(OwnedProcess expectedProxy, String marker) {
            String output = currentGenerationOutput(expectedProxy);
            return output != null && output.contains(marker);
        }

        private boolean currentGenerationMarkerAdvanced(
                OwnedProcess expectedProxy, String marker, int baseline) {
            String output = currentGenerationOutput(expectedProxy);
            return output != null && markerCount(output, marker) > baseline;
        }

        private static int markerCount(String output, String marker) {
            int count = 0;
            int offset = 0;
            while ((offset = output.indexOf(marker, offset)) >= 0) {
                count++;
                offset += marker.length();
            }
            return count;
        }

        private static void writeUncompressedPacket(
                DataOutputStream output, int packetId, byte[] payload) throws IOException {
            byte[] packet = concat(varInt(packetId), payload);
            output.write(varInt(packet.length));
            output.write(packet);
            output.flush();
        }

        private void startNamedPaper(String name, Path root) throws Exception {
            OwnedProcess paper = startProcess(name, root, root.resolve("paper.jar"), "-Xmx768m");
            waitFor(paper, "MCAce signed proxy admission channel enabled", 120);
            waitFor(paper, "Done (", 120);
            verifyBackendBanner(paper);
        }

        private void verifyBackendBanner(OwnedProcess process) throws IOException {
            HostileAdmissionGateLogic.BannerResult result = HostileAdmissionGateLogic.validateBanner(
                    readStartupOutput(process),
                    backendKind == BackendKind.FOLIA ? "Folia" : "Paper",
                    backendMinecraftVersion);
            if (result != HostileAdmissionGateLogic.BannerResult.VERIFIED) {
                throw new IOException("RUNTIME_BACKEND_BANNER_MISMATCH|" + result
                        + "|platform=" + backendKind + "|minecraft=" + backendMinecraftVersion);
            }
        }

        private boolean publishSyntheticDispositionPolicy(DispositionScenario scenario) throws Exception {
            return publishSyntheticDispositionPolicy(scenario.policyAction());
        }

        private void issueAdministratorDispositionReview(DispositionScenario scenario) throws Exception {
            String hash = HexFormat.of().formatHex(syntheticFixtureSha256());
            sendProxyCommand("mcacedisposition review " + PLAYER_NAME
                    + " runtime-" + scenario.name().toLowerCase(java.util.Locale.ROOT)
                    + " mod mcace-runtime-synthetic-fixture.jar 1 " + hash);
        }

        private TrustedAuthorizationEvidence trustedDispositionAuthorizationEvidence(String action)
                throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            UUID authorizationId = null;
            boolean journalMatched = false;
            boolean orderedExecution = false;
            do {
                String output = proxyProcessOutput();
                if (authorizationId == null) {
                    authorizationId = trustedDispositionAuthorizationId(output, action).orElse(null);
                }
                if (authorizationId != null) {
                    journalMatched |= trustedDispositionJournalContains(authorizationId, action);
                    orderedExecution |= trustedDispositionExecutionFollowsDurableAppend(
                            output, action, authorizationId, kind);
                    if (journalMatched && orderedExecution) {
                        return new TrustedAuthorizationEvidence(true, true, true);
                    }
                }
                if (System.nanoTime() >= deadline) break;
                Thread.sleep(50L);
            } while (true);
            return new TrustedAuthorizationEvidence(
                    authorizationId != null, journalMatched, journalMatched && orderedExecution);
        }

        private boolean trustedDispositionJournalContains(UUID authorizationId, String action) {
            Path journal = proxyDataDirectory().resolve("trusted-disposition-authorizations.log");
            if (!Files.isRegularFile(journal)) return false;
            try {
                for (String line : Files.readAllLines(journal, StandardCharsets.UTF_8)) {
                    if (trustedDispositionJournalLineMatches(line, authorizationId, action)) {
                        return true;
                    }
                }
            } catch (IOException exception) {
                return false;
            }
            return false;
        }

        private boolean publishSyntheticDispositionPolicy(String policyAction) throws Exception {
            Path configuration = syntheticDispositionConfigurationPath(proxyDataDirectory(), kind);
            Files.createDirectories(configuration.getParent());
            Files.writeString(configuration, syntheticDispositionConfiguration(policyAction),
                    StandardCharsets.UTF_8);
            PublisherSnapshot publisherBefore = kind == ProxyKind.BUNGEE
                    ? captureBungeePublisherSnapshot() : null;
            sendProxyCommand(kind == ProxyKind.VELOCITY
                    ? "mcacepolicy publish" : "mcace disposition publish");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (System.nanoTime() < deadline) {
                if (kind == ProxyKind.VELOCITY) {
                    String output = proxyProcessOutput();
                    if (output.contains("MCAce disposition policy published: sequence=")
                            && output.contains("status=ACTIVE")) return true;
                }
                // Bungee's built-in /mcace command logs a catalog publish acknowledgement while
                // refreshDispositionPolicy emits the independent ACTIVE runtime marker.
                if (kind == ProxyKind.BUNGEE) {
                    lastBungeePublisherGate = bungeePublisherGate(
                            publisherBefore, captureBungeePublisherSnapshot());
                    if (lastBungeePublisherGate.success()) return true;
                }
                if (!processes.getFirst().process().isAlive()) {
                    if (kind == ProxyKind.BUNGEE) lastBungeePublisherGate = PublisherGate.PROXY_EXIT;
                    return false;
                }
                Thread.sleep(100L);
            }
            if (kind == ProxyKind.BUNGEE
                    && (lastBungeePublisherGate == PublisherGate.NOT_ATTEMPTED
                    || lastBungeePublisherGate == PublisherGate.NO_NEW_MARKER)) {
                lastBungeePublisherGate = PublisherGate.TIMEOUT;
            }
            return false;
        }

        PublisherGate bungeePublisherGate() { return lastBungeePublisherGate; }

        private void markBungeeRuntimePolicyMatched() {
            if (kind == ProxyKind.BUNGEE && !lastBungeePublisherGate.success()) {
                lastBungeePublisherGate = PublisherGate.RUNTIME_POLICY_MATCHED;
            }
        }

        /**
         * The two adapters intentionally use different persisted authoring locations. Keep this
         * mapping explicit so a Bungee fixture cannot silently publish its generated default
         * document instead of the synthetic exact-match policy for this case.
         */
        static Path syntheticDispositionConfigurationPath(Path dataDirectory, ProxyKind kind) {
            Objects.requireNonNull(dataDirectory, "dataDirectory");
            Objects.requireNonNull(kind, "kind");
            return kind == ProxyKind.BUNGEE
                    ? dataDirectory.resolve("disposition-policy.textproto")
                    : dataDirectory.resolve("policy/disposition-policy.textproto");
        }

        /**
         * Requires a new successful console acknowledgement from this publish command plus a new
         * ACTIVE transition. A pre-existing ACTIVE document, a failed acknowledgement, or an
         * `active-sequence=none` line is insufficient.
         */
        static boolean bungeeFreshPublisherActivationObserved(String before, String after) {
            Objects.requireNonNull(before, "before");
            Objects.requireNonNull(after, "after");
            return bungeePublisherGate(
                    PublisherSnapshot.singleSource("legacy", before),
                    PublisherSnapshot.singleSource("legacy", after)).success();
        }

        /**
         * Evaluates only each source's append-only suffix. A source identity change, loss,
         * truncation, or rewrite is non-evidence; no raw source content or path escapes this gate.
         */
        static PublisherGate bungeePublisherGate(PublisherSnapshot before, PublisherSnapshot after) {
            if (!before.available() || !after.available()) return PublisherGate.SOURCE_UNAVAILABLE;
            if (!before.sources().keySet().equals(after.sources().keySet())) return PublisherGate.SOURCE_SET_CHANGED;
            List<Long> baselineSequences = new ArrayList<>();
            List<Long> acknowledgements = new ArrayList<>();
            List<Long> activeSequences = new ArrayList<>();
            int contributingSources = 0;
            int completeSources = 0;
            for (String source : before.sources().keySet()) {
                PublisherSourceCursor oldSource = before.sources().get(source);
                PublisherSourceCursor newSource = after.sources().get(source);
                if (!oldSource.identity().equals(newSource.identity())) return PublisherGate.SOURCE_IDENTITY_CHANGED;
                if (newSource.byteLength() < oldSource.byteLength()
                        || !newSource.content().startsWith(oldSource.content())) {
                    return PublisherGate.SOURCE_TRUNCATED;
                }
                SequenceParse baseline = bungeePublisherSequences(oldSource.content());
                if (!baseline.valid()) return PublisherGate.BASELINE_INVALID;
                baselineSequences.addAll(baseline.publishAcknowledgements());
                baselineSequences.addAll(baseline.activeSequences());
                SequenceParse suffix = bungeePublisherSequences(
                        newSource.content().substring(oldSource.content().length()));
                if (!suffix.valid()) return PublisherGate.SUFFIX_INVALID;
                if (suffix.publishAcknowledgements().size() > 1) {
                    return PublisherGate.SOURCE_DUPLICATE_ACK;
                }
                if (suffix.activeSequences().size() > 1) {
                    return PublisherGate.SOURCE_DUPLICATE_ACTIVE;
                }
                if (!suffix.publishAcknowledgements().isEmpty()
                        || !suffix.activeSequences().isEmpty()) {
                    contributingSources++;
                }
                if (!suffix.publishAcknowledgements().isEmpty()
                        && !suffix.activeSequences().isEmpty()) {
                    completeSources++;
                }
                acknowledgements.addAll(suffix.publishAcknowledgements());
                activeSequences.addAll(suffix.activeSequences());
            }
            if (acknowledgements.isEmpty() && activeSequences.isEmpty()) {
                return PublisherGate.NO_NEW_MARKER;
            }
            if (acknowledgements.isEmpty() || activeSequences.isEmpty()) {
                return PublisherGate.SOURCE_INCOMPLETE;
            }
            long acknowledgement = acknowledgements.getFirst();
            long active = activeSequences.getFirst();
            if (acknowledgements.stream().anyMatch(candidate -> candidate != acknowledgement)
                    || activeSequences.stream().anyMatch(candidate -> candidate != active)) {
                return PublisherGate.CROSS_SOURCE_CONFLICT;
            }
            if (acknowledgement != active) return PublisherGate.SEQUENCE_MISMATCH;
            long baselineMaximum = baselineSequences.stream().mapToLong(Long::longValue).max().orElse(0L);
            if (acknowledgement <= baselineMaximum) return PublisherGate.NOT_FRESH;
            if (contributingSources == 1) return PublisherGate.ACTIVE;
            if (completeSources == contributingSources) return PublisherGate.MIRRORED_MATCH;
            return PublisherGate.CROSS_SOURCE_MATCH;
        }

        record PublisherSourceCursor(String identity, long byteLength, String content) {
            PublisherSourceCursor {
                Objects.requireNonNull(identity, "identity");
                Objects.requireNonNull(content, "content");
                if (byteLength < 0L) throw new IllegalArgumentException("negative byteLength");
            }
        }

        record PublisherSnapshot(boolean available, Map<String, PublisherSourceCursor> sources) {
            PublisherSnapshot {
                sources = Map.copyOf(sources);
            }
            static PublisherSnapshot singleSource(String identity, String content) {
                return new PublisherSnapshot(true, Map.of("source",
                        new PublisherSourceCursor(identity,
                                content.getBytes(StandardCharsets.UTF_8).length, content)));
            }
        }

        /** Bounded parser for append-only Bungee console output; never scans arbitrary token text. */
        private static SequenceParse bungeePublisherSequences(String output) {
            final int maxCharacters = 1_048_576;
            final int maxLines = 8_192;
            final int maxLineCharacters = 1_024;
            if (output.length() > maxCharacters) return SequenceParse.invalid();
            List<Long> acknowledgements = new ArrayList<>();
            List<Long> active = new ArrayList<>();
            int start = 0;
            int lines = 0;
            while (start <= output.length()) {
                if (++lines > maxLines) return SequenceParse.invalid();
                int end = start;
                while (end < output.length() && output.charAt(end) != '\n' && output.charAt(end) != '\r') end++;
                if (end - start > maxLineCharacters) return SequenceParse.invalid();
                String line = output.substring(start, end);
                String message = bungeeMessage(line);
                if (message != null && (message.startsWith("MCAce: disposition catalog publish version=")
                        || message.startsWith("MCAce: disposition policy published version="))) {
                    Optional<Long> acknowledgement = bungeePositiveSequenceToken(message, "active-sequence=");
                    if (acknowledgement.isEmpty()) return SequenceParse.invalid();
                    acknowledgements.add(acknowledgement.orElseThrow());
                }
                if (message != null && message.startsWith("MCAce: disposition status=ACTIVE ")) {
                    Optional<Long> activeSequence = bungeePositiveSequenceToken(message, "sequence=");
                    if (activeSequence.isEmpty()) return SequenceParse.invalid();
                    active.add(activeSequence.orElseThrow());
                }
                while (end < output.length() && (output.charAt(end) == '\n' || output.charAt(end) == '\r')) end++;
                if (end == output.length()) break;
                start = end;
            }
            return new SequenceParse(true, acknowledgements, active);
        }

        /**
         * Allows only the bounded, controlled forms emitted by Bungee's logger. This deliberately
         * rejects arbitrary text containing an embedded marker: the harness never preserves raw
         * output and only consumes a product marker after the logger boundary.
         */
        private static String bungeeMessage(String line) {
            return bungeeControlledMessage(line, "MCAce:");
        }

        /** Bungee's route lifecycle markers intentionally use {@code MCAce } rather than {@code MCAce:}. */
        private static String bungeeRouteMessage(String line) {
            return bungeeControlledMessage(line, "MCAce ");
        }

        private static String bungeeControlledMessage(String line, String markerText) {
            int marker = line.indexOf(markerText);
            if (marker < 0 || marker > 256 || line.indexOf(markerText, marker + markerText.length()) >= 0) {
                return null;
            }
            String prefix = line.substring(0, marker);
            if (prefix.chars().anyMatch(character -> Character.isISOControl((char) character))) return null;
            if (!prefix.isEmpty() && !prefix.endsWith("INFO: ") && !prefix.endsWith("信息: ")
                    && !prefix.endsWith("[INFO] ")) return null;
            return line.substring(marker);
        }

        private static Optional<Long> bungeePositiveSequenceToken(String message, String token) {
            int start = message.indexOf(token);
            if (start <= 0 || !Character.isWhitespace(message.charAt(start - 1))
                    || message.indexOf(token, start + token.length()) >= 0) {
                return Optional.empty();
            }
            start += token.length();
            int end = start;
            while (end < message.length() && !Character.isWhitespace(message.charAt(end))) end++;
            if (start == end) return Optional.empty();
            String value = message.substring(start, end);
            if (value.length() > 19 || value.chars().anyMatch(character -> character < '0' || character > '9')) {
                return Optional.empty();
            }
            try {
                long parsed = Long.parseLong(value);
                return parsed > 0L ? Optional.of(parsed) : Optional.empty();
            } catch (NumberFormatException exception) {
                return Optional.empty();
            }
        }

        private record SequenceParse(
                boolean valid, List<Long> publishAcknowledgements, List<Long> activeSequences) {
            private SequenceParse {
                publishAcknowledgements = List.copyOf(publishAcknowledgements);
                activeSequences = List.copyOf(activeSequences);
            }

            static SequenceParse invalid() { return new SequenceParse(false, List.of(), List.of()); }

            long maximumObservedSequence() {
                return java.util.stream.Stream.concat(
                                publishAcknowledgements.stream(), activeSequences.stream())
                        .mapToLong(Long::longValue).max().orElse(0L);
            }
        }

        private static String syntheticDispositionConfiguration(String policyAction)
                throws Exception {
            String hash = HexFormat.of().formatHex(syntheticFixtureSha256());
            return """
                    schema_version: 1
                    version: "runtime-synthetic-v1"
                    rollout_stage: "OBSERVE"
                    validity_seconds: 3600
                    rules {
                      rule {
                        rule_id: "runtime-synthetic-exact"
                        priority: 100
                        revision: 1
                        selector {
                          artifact_type: DETECTION_ARTIFACT_MOD
                          match_type: DETECTION_MATCH_EXACT_SHA256
                        }
                        confidence: DETECTION_CONFIDENCE_LOW
                        default_action: %s
                        player_message_key: "mcace.runtime.synthetic"
                        operator_reason: "Fixed harmless test-only synthetic fixture."
                        false_positive_notes: "Runtime integration fixture only."
                      }
                      sha256_hex: "%s"
                    }
                    """.formatted(policyAction, hash);
        }

        private DispositionObservation waitForDispositionObservation(
                DispositionScenario scenario, int seconds) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            DispositionObservation observation = currentDispositionObservation(scenario);
            long resultAt = Long.MIN_VALUE;
            while (System.nanoTime() < deadline) {
                observation = currentDispositionObservation(scenario);
                if (observation.resultObserved() && resultAt == Long.MIN_VALUE) {
                    resultAt = System.nanoTime();
                }
                if (observation.resultObserved() && observation.lobbyAdmission()
                        && !observation.limitedAdmission() && !observation.quarantineAdmission()
                        && !observation.anyRouteLifecycleObserved()
                        && observation.routeCompletion() == RouteCompletion.NONE
                        && System.nanoTime() - resultAt >= TimeUnit.SECONDS.toNanos(3)) break;
                Thread.sleep(100L);
            }
            return currentDispositionObservation(scenario);
        }

        private DispositionObservation currentDispositionObservation(DispositionScenario scenario) {
            String action = scenario.actionName();
            String proxyOutput = proxyProcessOutput();
            boolean advisoryGuard = kind == ProxyKind.BUNGEE
                    ? advisoryGuardObserved(proxyOutput, "MCAce authenticated-manifest audit")
                    : advisoryGuardObserved(proxyOutput, "MCAce manifest audit:");
            boolean trustedResult = trustedDispositionCase
                    && trustedDispositionAuthorizationObserved(proxyOutput, action)
                    && trustedDispositionExecutionObserved(proxyOutput, action, kind);
            if (kind == ProxyKind.BUNGEE) {
                return new DispositionObservation(
                        trustedDispositionCase ? trustedResult : advisoryGuard,
                        backendAccepted("paper-lobby", paperRoot),
                        backendAccepted("paper-limited", limitedPaperRoot),
                        backendAccepted("paper-quarantine", quarantinePaperRoot),
                        proxyOutput.contains("MCAce manifest disposition: action=" + action
                                + " result=" + scenario.manifestExecutionResult()),
                        bungeeDeferredDispositionDispatchObserved(proxyOutput, action),
                        routeCompletion(proxyOutput, kind, scenario, trustedDispositionCase),
                        bungeeAnyRouteLifecycleObserved(proxyOutput));
            }
            return new DispositionObservation(
                    trustedDispositionCase ? trustedResult : advisoryGuard,
                    backendAccepted("paper-lobby", paperRoot),
                    backendAccepted("paper-limited", limitedPaperRoot),
                    backendAccepted("paper-quarantine", quarantinePaperRoot),
                    false, false, routeCompletion(proxyOutput, kind, scenario, trustedDispositionCase),
                    velocityAnyRouteLifecycleObserved(proxyOutput));
        }

        private static boolean advisoryGuardObserved(String output, String auditMarker) {
            for (String line : output.split("\\R")) {
                if (line.contains(auditMarker)
                        && line.contains("policyVersion=runtime-synthetic-v1")
                        && line.matches(".*advisoryBlocks=[1-9][0-9]*.*")) {
                    return true;
                }
            }
            return false;
        }

        private static boolean trustedDispositionAuthorizationObserved(String output, String action) {
            return trustedDispositionAuthorizationId(output, action).isPresent();
        }

        private static Optional<UUID> trustedDispositionAuthorizationId(String output, String action) {
            for (String line : output.split("\\R")) {
                if (line.contains("MCAce: disposition review authorized")
                        && line.contains("action=" + action)
                        && line.contains("rule=runtime-synthetic-exact")
                        && line.contains("policy-sequence=")
                        && line.contains("authorization=")
                        && line.contains("session-bound=true execution-context-bound=true "
                                + "execution-queued=true")) {
                    int start = line.indexOf("authorization=") + "authorization=".length();
                    int end = start;
                    while (end < line.length() && !Character.isWhitespace(line.charAt(end))) end++;
                    try {
                        return Optional.of(UUID.fromString(line.substring(start, end)));
                    } catch (IllegalArgumentException ignored) {
                        return Optional.empty();
                    }
                }
            }
            return Optional.empty();
        }

        private static boolean trustedDispositionExecutionObserved(
                String output, String action, ProxyKind kind) {
            Optional<UUID> authorizationId = trustedDispositionAuthorizationId(output, action);
            return authorizationId.isPresent()
                    && trustedDispositionExecutionFollowsDurableAppend(
                    output, action, authorizationId.orElseThrow(), kind);
        }

        private static boolean trustedDispositionExecutionFollowsDurableAppend(
                String output, String action, UUID authorizationId, ProxyKind kind) {
            String id = authorizationId.toString();
            int durable = -1;
            int execution = -1;
            String immediate = action.equals("QUARANTINE")
                    ? "QUARANTINED_DISPATCHED" : "LIMITED_DISPATCHED";
            String deferred = action.equals("QUARANTINE")
                    ? "QUARANTINED_DEFERRED" : "LIMITED_DEFERRED";
            int offset = 0;
            for (String line : output.split("\\R", -1)) {
                int lineOffset = offset;
                offset += line.length() + 1;
                if (line.contains("MCAce trusted disposition authorization persisted:")
                        && line.contains("authorization=" + id)
                        && line.contains("journal-durable=true execution-context-bound=true")
                        && line.contains("action=" + action)) {
                    durable = lineOffset;
                }
                if (!line.contains("MCAce manifest disposition: action=" + action + " result=")) continue;
                if (line.contains("authorization=" + id)
                        && line.contains("session-bound=true execution-context-bound=true")
                        && (line.contains("result=" + immediate)
                        || (kind == ProxyKind.BUNGEE && line.contains("result=" + deferred))
                        || (kind == ProxyKind.VELOCITY && line.contains("result=DEFERRED"))
                        || (action.equals("DENY") && line.contains("result=DENIED")))) {
                    execution = lineOffset;
                    break;
                }
            }
            return durable >= 0 && execution > durable;
        }

        @SuppressWarnings("unused") // package-level logic tests exercise this bounded parser directly.
        static boolean trustedDispositionAuthorizationChainObservedForTest(
                String output, String journalLine, String action, ProxyKind kind) {
            Optional<UUID> id = trustedDispositionAuthorizationId(output, action);
            if (id.isEmpty()) return false;
            boolean journalMatched = trustedDispositionJournalLineMatches(
                    journalLine, id.orElseThrow(), action);
            return journalMatched && trustedDispositionExecutionFollowsDurableAppend(
                    output, action, id.orElseThrow(), kind);
        }

        /** Exact V3 journal boundary; unversioned/V2 fourteen-column records fail closed. */
        private static boolean trustedDispositionJournalLineMatches(
                String journalLine, UUID authorizationId, String action) {
            String[] fields = journalLine.split("\\t", -1);
            if (fields.length != 16
                    || !fields[0].equals("v3")
                    || !fields[1].equals(authorizationId.toString())
                    || !fields[2].matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
                    || !fields[3].matches("[0-9]+")
                    || !fields[4].matches("[0-9a-f]{64}")
                    || !fields[5].matches("[0-9a-f]{64}")
                    || !fields[6].matches("[0-9a-f]{64}")
                    || !fields[7].equals("ADMIN_REVIEWED")
                    || fields[8].equals("-")
                    || fields[9].equals("-")
                    || !fields[10].equals(action)
                    || !fields[11].equals("runtime-synthetic-exact")
                    || !fields[12].equals("ACTIVE")
                    || fields[13].equals("-")
                    || !fields[14].matches("[0-9]+")
                    || !fields[15].matches("[0-9]+")) {
                return false;
            }
            try {
                return Long.parseLong(fields[15]) > Long.parseLong(fields[3]);
            } catch (NumberFormatException exception) {
                return false;
            }
        }

        static boolean velocityAnyRouteLifecycleObserved(String output) {
            final int maxCharacters = 1_048_576;
            final int maxLines = 8_192;
            final int maxLineCharacters = 1_024;
            if (output == null || output.length() > maxCharacters) return true;
            int lines = 0;
            for (String line : output.split("\\R", -1)) {
                if (++lines > maxLines || line.length() > maxLineCharacters) return true;
                if (line.contains("MCAce deferred disposition route")
                        || line.contains("MCAce manifest disposition route result=")) {
                    return true;
                }
                if (line.contains("MCAce manifest disposition: action=")
                        && (line.contains(" result=DEFERRED ")
                        || line.contains(" result=LIMITED_DISPATCHED ")
                        || line.contains(" result=QUARANTINED_DISPATCHED ")
                        || line.contains(" result=DENIED "))) {
                    return true;
                }
            }
            return false;
        }

        private boolean requiredRouteEvidenceObserved(
                DispositionScenario scenario, DispositionObservation observation) {
            if (trustedDispositionCase) {
                return observation.routeCompletion() == RouteCompletion.SUCCESS;
            }
            if (kind == ProxyKind.BUNGEE) {
                return observation.deferredRouteObserved() && observation.deferredRouteDispatched()
                        && observation.routeCompletion() == RouteCompletion.SUCCESS;
            }
            return observation.routeCompletion() == RouteCompletion.SUCCESS;
        }

        /**
         * Accepts only the product's deferred-disposition flush for this exact policy action.
         * A heartbeat route, a different action, or any merely dispatched direct route is not
         * evidence for the Bungee early-route case.
         */
        private static boolean bungeeDeferredDispositionDispatchObserved(String output, String action) {
            for (String line : output.split("\\R")) {
                if (line.contains("MCAce deferred disposition route result=DISPATCHED")
                        && line.contains("action=" + action + " source=DISPOSITION"
                                + " session-bound=true")) {
                    return true;
                }
            }
            return false;
        }

        /**
         * MONITOR is inert only when no Bungee route lifecycle occurred at all. Unlike the
         * enforced evidence parser, this rejects direct, heartbeat, foreign-source deferred,
         * dispatch, retry, and completion markers without attributing their raw contents.
         */
        static boolean bungeeAnyRouteLifecycleObserved(String output) {
            final int maxCharacters = 1_048_576;
            final int maxLines = 8_192;
            final int maxLineCharacters = 1_024;
            if (output == null || output.length() > maxCharacters) return true;
            int start = 0;
            int lines = 0;
            while (start <= output.length()) {
                if (++lines > maxLines) return true;
                int end = start;
                while (end < output.length() && output.charAt(end) != '\n' && output.charAt(end) != '\r') end++;
                if (end - start > maxLineCharacters) return true;
                String message = bungeeRouteMessage(output.substring(start, end));
                if (message != null && (message.startsWith("MCAce disposition route ")
                        || message.startsWith("MCAce deferred disposition route ")
                        || message.startsWith("MCAce heartbeat missing temporary route ")
                        || message.startsWith("MCAce manifest disposition route "))) {
                    return true;
                }
                while (end < output.length() && (output.charAt(end) == '\n' || output.charAt(end) == '\r')) end++;
                if (end == output.length()) break;
                start = end;
            }
            return false;
        }

        private static RouteCompletion routeCompletion(
                String output, ProxyKind kind, DispositionScenario scenario, boolean trusted) {
            if (kind == ProxyKind.BUNGEE) {
                return trusted
                        ? bungeeTrustedDispositionRouteCompletion(output, scenario)
                        : bungeeDispositionRouteCompletion(output, scenario);
            }
            String action = scenario.actionName();
            Optional<UUID> trustedAuthorization = trusted
                    ? trustedDispositionAuthorizationId(output, action) : Optional.empty();
            if (trusted && trustedAuthorization.isEmpty()) return RouteCompletion.NONE;
            RouteCompletion terminal = RouteCompletion.NONE;
            boolean routeMarkerSeen = false;
            for (String rawLine : output.split("\\R")) {
                String line = rawLine.toUpperCase(java.util.Locale.ROOT);
                if ((!line.contains("MCACE MANIFEST DISPOSITION ROUTE RESULT=")
                        && !line.contains("MCACE MANIFEST DISPOSITION ROUTE RESULT:"))
                        || !line.contains("ACTION=" + action)) continue;
                if (trusted && !line.contains("AUTHORIZATION="
                        + trustedAuthorization.orElseThrow().toString().toUpperCase(java.util.Locale.ROOT))) {
                    continue;
                }
                if (line.contains("MCACE MANIFEST DISPOSITION ROUTE RESULT=FAIL")
                        || line.contains("MCACE MANIFEST DISPOSITION ROUTE FAILED:")) {
                    terminal = RouteCompletion.FAILED;
                    routeMarkerSeen = true;
                    continue;
                }
                if (line.contains("MCACE MANIFEST DISPOSITION ROUTE RESULT=SUCCESS")) {
                    terminal = RouteCompletion.SUCCESS;
                    routeMarkerSeen = true;
                    continue;
                }
                routeMarkerSeen = true;
                for (RouteCompletion candidate : List.of(
                        RouteCompletion.ALREADY_CONNECTED,
                        RouteCompletion.CONNECTION_IN_PROGRESS,
                        RouteCompletion.CONNECTION_CANCELLED,
                        RouteCompletion.SERVER_DISCONNECTED)) {
                    if (line.contains(candidate.name())) terminal = candidate;
                }
            }
            if (terminal != RouteCompletion.NONE) return terminal;
            return routeMarkerSeen ? RouteCompletion.NON_SUCCESS : RouteCompletion.NONE;
        }

        /**
         * Accepts only the terminal callback for this exact deferred disposition case. A direct
         * route, a heartbeat route, a different action, or merely a dispatch marker cannot be
         * credited as the Bungee ServerConnected hand-off completion.
         */
        static RouteCompletion bungeeDispositionRouteCompletion(
                String output, DispositionScenario scenario) {
            Objects.requireNonNull(output, "output");
            Objects.requireNonNull(scenario, "scenario");
            String action = scenario.actionName();
            RouteCompletion terminal = RouteCompletion.NONE;
            boolean routeMarkerSeen = false;
            for (String rawLine : output.split("\\R")) {
                if (!rawLine.contains("MCAce disposition route completion=")) continue;
                if (!rawLine.contains("action=" + action + " source=deferred-disposition"
                        + " session-bound=true")) continue;
                routeMarkerSeen = true;
                if (rawLine.contains("completion=FAILED")) return RouteCompletion.FAILED;
                if (rawLine.contains("completion=SUCCESS")) terminal = RouteCompletion.SUCCESS;
            }
            return terminal != RouteCompletion.NONE ? terminal
                    : routeMarkerSeen ? RouteCompletion.NON_SUCCESS : RouteCompletion.NONE;
        }

        static RouteCompletion bungeeTrustedDispositionRouteCompletion(
                String output, DispositionScenario scenario) {
            Objects.requireNonNull(output, "output");
            Objects.requireNonNull(scenario, "scenario");
            String action = scenario.actionName();
            Optional<UUID> authorizationId = trustedDispositionAuthorizationId(output, action);
            if (authorizationId.isEmpty()) return RouteCompletion.NONE;
            RouteCompletion terminal = RouteCompletion.NONE;
            boolean routeMarkerSeen = false;
            for (String rawLine : output.split("\\R")) {
                if (!rawLine.contains("MCAce disposition route completion=")) continue;
                if (!rawLine.contains("action=" + action)
                        || !rawLine.contains("session-bound=true")) continue;
                if (!rawLine.contains("authorization=" + authorizationId.orElseThrow())) continue;
                if (!rawLine.contains("source=direct")
                        && !rawLine.contains("source=deferred-disposition")) continue;
                routeMarkerSeen = true;
                if (rawLine.contains("completion=FAILED")) return RouteCompletion.FAILED;
                if (rawLine.contains("completion=SUCCESS")) terminal = RouteCompletion.SUCCESS;
            }
            return terminal != RouteCompletion.NONE ? terminal
                    : routeMarkerSeen ? RouteCompletion.NON_SUCCESS : RouteCompletion.NONE;
        }

        private boolean backendAccepted(String processName, Path root) {
            return backendVerifiedAdmissionCount(processName, root) > 0;
        }

        private int backendVerifiedAdmissionCount(String processName, Path root) {
            OwnedProcess process = processes.stream()
                    .filter(candidate -> candidate.name().equals(processName))
                    .findFirst().orElse(null);
            if (process == null) return 0;
            Path log = root.resolve("logs/latest.log");
            String processEvidence = readProcessOutput(process);
            String platformEvidence = "";
            if (Files.isRegularFile(log)) {
                try { platformEvidence = Files.readString(log, StandardCharsets.UTF_8); }
                catch (IOException ignored) { }
            }
            // Paper's rolling log may lag its redirected stdout while the process is live. Do not
            // prefer either source globally: count complete lines in each and take the maximum.
            // This avoids duplicate counting while keeping reconnect baselines monotonic when one
            // append-only sink is temporarily behind the other.
            return Math.max(verifiedAdmissionCount(processEvidence),
                    verifiedAdmissionCount(platformEvidence));
        }

        private static int verifiedAdmissionCount(String evidence) {
            String marker = "Accepted signed MCAce admission state";
            int count = 0;
            for (String line : evidence.split("\\R")) {
                if (line.contains(marker)
                        && line.contains("admission=VERIFIED, trust=VERIFIED")) count++;
            }
            return count;
        }

        private int waitForStableBackendAdmissionCount(
                String processName, Path root, int stableMillis, int maxSeconds)
                throws InterruptedException, IOException {
            OwnedProcess process = processes.stream()
                    .filter(candidate -> candidate.name().equals(processName))
                    .findFirst().orElseThrow(() -> new IOException(
                            "backend admission stability source is unavailable"));
            return waitForStableCount(
                    () -> backendVerifiedAdmissionCount(processName, root),
                    () -> process.process().isAlive(),
                    stableMillis,
                    Math.multiplyExact(maxSeconds, 1_000),
                    System::nanoTime,
                    Thread::sleep);
        }

        private boolean denyDispositionObserved() {
            return proxyProcessOutput().contains(
                    "MCAce manifest disposition: action=DENY result=DENIED");
        }

        /**
         * Restarts only the owned proxy process. This is deliberately test-only lifecycle control:
         * the already-running Paper backend, identity directory and federation configuration remain
         * in place, so a new target proxy process loads the same offline identity/pins.
         */
        private TargetProxyRestartResult restartProxyPreservingState() throws Exception {
            if (processes.size() < 2 || !"proxy".equals(processes.getFirst().name())) {
                throw new IOException("target proxy/Paper process pair is unavailable for restart");
            }
            Path data = proxyDataDirectory();
            List<Path> preserved = List.of(
                    data.resolve("identity/server-private-key.pk8"),
                    data.resolve("identity/server-public-key.txt"),
                    data.resolve("mcace.properties"), data.resolve("federation.properties"));
            List<byte[]> before = new ArrayList<>();
            for (Path path : preserved) {
                if (!Files.isRegularFile(path)) throw new IOException("restart state file missing: " + path.getFileName());
                before.add(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
            }
            OwnedProcess oldProxy = processes.removeFirst();
            long paperPid = processes.getFirst().process().pid();
            terminateOwnedProcess(oldProxy);
            if (oldProxy.process().isAlive()) {
                throw new IOException("old target proxy process remained alive after termination");
            }
            startProxy();
            Path identity = data.resolve("identity/server-public-key.txt");
            waitForPath(identity, 30);
            proxyPublicKey = Ed25519Keys.decodePublic(Base64.getDecoder().decode(
                    Files.readString(identity, StandardCharsets.UTF_8).trim()));
            boolean identityPreserved = true;
            boolean configurationPreserved = true;
            for (int index = 0; index < preserved.size(); index++) {
                byte[] after = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(preserved.get(index)));
                if (!MessageDigest.isEqual(before.get(index), after)) {
                    if (index < 2) identityPreserved = false;
                    else configurationPreserved = false;
                }
            }
            OwnedProcess paper = processes.getLast();
            return new TargetProxyRestartResult(!oldProxy.process().isAlive(),
                    paper.process().pid() == paperPid && paper.process().isAlive(),
                    identityPreserved, configurationPreserved);
        }

        private void startProxy() throws Exception {
            Path proxyJar = kind == ProxyKind.VELOCITY
                    ? proxyRoot.resolve("velocity.jar") : proxyRoot.resolve("BungeeCord.jar");
            OwnedProcess proxy = startProcess("proxy", proxyRoot, proxyJar, "-Xmx512m");
            // The rest of this deliberately small harness treats index 0 as proxy and the final
            // entry as Paper. Preserve that invariant when a proxy is restarted beside Paper.
            if (processes.size() > 1) {
                processes.removeLast();
                processes.addFirst(proxy);
            }
            if (kind == ProxyKind.VELOCITY) {
                // On Windows a live child may buffer or exclusively hold both console and rolling
                // log files. The identity pin is created by the MCAce plugin after its phase-2
                // initialization, so it is a stronger startup barrier than a text marker.
                waitForPath(proxy, proxyDataDirectory().resolve("identity/server-public-key.txt"), 90);
            } else {
                waitFor(proxy, "MCAce BungeeCord adapter enabled", 90);
            }
            // Do not infer bind readiness from logging. Probe the actual loopback socket so a
            // restart or a buffered log cannot make the next phase race the listener.
            waitForLoopbackListener(proxy, proxyPort, 30);
        }

        private void waitForLoopbackListener(OwnedProcess process, int port, int seconds)
                throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 250);
                    return;
                } catch (IOException ignored) {
                    // The listener is still booting or the port is not bound yet.
                }
                if (!process.process().isAlive()) {
                    throw new IOException(process.name() + " exited before listener " + port
                            + "\n" + readStartupOutput(process));
                }
                Thread.sleep(250L);
            }
            throw new IOException(process.name() + " did not bind loopback listener " + port
                    + "\n" + readStartupOutput(process));
        }

        private String bungeeConfig() {
            return """
                    ip_forward: true
                    online_mode: false
                    forge_support: false
                    listeners:
                    - query_port: 25577
                      motd: '&1MCAce test-only probe'
                      tab_list: GLOBAL_PING
                      query_enabled: false
                      proxy_protocol: false
                      forced_hosts: {}
                      ping_passthrough: false
                      priorities:
                      - lobby
                      bind_local_address: true
                      host: 127.0.0.1:%d
                      max_players: 20
                      tab_size: 60
                      force_default_server: true
                    timeout: 30000
                    connection_throttle: 4000
                    connection_throttle_limit: 3
                    disabled_commands: []
                    servers:
                      lobby:
                        motd: '&1MCAce Paper probe'
                        address: 127.0.0.1:%d
                        restricted: false
                    """.formatted(proxyPort, paperPort);
        }

        /** Three distinct registered loopback targets for the Bungee Phase-2 matrix only. */
        private String bungeeDispositionConfig() {
            return """
                    ip_forward: true
                    online_mode: false
                    forge_support: false
                    listeners:
                    - query_port: 25577
                      motd: '&1MCAce Bungee disposition test-only probe'
                      tab_list: GLOBAL_PING
                      query_enabled: false
                      proxy_protocol: false
                      forced_hosts: {}
                      ping_passthrough: false
                      priorities:
                      - lobby
                      bind_local_address: true
                      host: 127.0.0.1:%d
                      max_players: 20
                      tab_size: 60
                      force_default_server: true
                    timeout: 30000
                    connection_throttle: 4000
                    connection_throttle_limit: 3
                    disabled_commands: []
                    servers:
                      lobby:
                        motd: '&1MCAce Paper lobby disposition probe'
                        address: 127.0.0.1:%d
                        restricted: false
                      limited:
                        motd: '&1MCAce Paper limited disposition probe'
                        address: 127.0.0.1:%d
                        restricted: false
                      quarantine:
                        motd: '&1MCAce Paper quarantine disposition probe'
                        address: 127.0.0.1:%d
                        restricted: false
                    """.formatted(proxyPort, paperPort, limitedPaperPort, quarantinePaperPort);
        }

        private void configurePaperForwarding() throws IOException {
            configurePaperForwarding(paperRoot);
        }

        private void configurePaperForwarding(Path targetPaperRoot) throws IOException {
            Path configDirectory = targetPaperRoot.resolve("config");
            Files.createDirectories(configDirectory);
            if (kind == ProxyKind.VELOCITY) {
                String secret = Files.readString(proxyRoot.resolve("forwarding.secret"), StandardCharsets.US_ASCII).trim();
                Path paperGlobal = configDirectory.resolve("paper-global.yml");
                Files.writeString(paperGlobal, """
                        proxies:
                          velocity:
                            enabled: true
                            online-mode: false
                            secret: "%s"
                        """.formatted(secret), StandardCharsets.UTF_8);
                sensitiveForwardingFiles.add(paperGlobal);
                forwardingConfigured = true;
                return;
            }
            Path spigot = targetPaperRoot.resolve("spigot.yml");
            Path preparedSpigot = runtimeAssets.preparedRoot().resolve("spigot.yml");
            // Keep the complete, version-matched Spigot configuration copied from the
            // prepared runtime tree. A tiny synthetic document can trigger a legacy
            // config-upgrade path on newer Folia builds and makes cold-start timing noisy.
            // Mutate only the forwarding switch in-place so the platform sees the same
            // config shape it would generate itself (including config-version).
            if (!Files.isRegularFile(preparedSpigot, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("prepared spigot.yml is missing: " + preparedSpigot);
            }
            Files.copy(preparedSpigot, spigot, StandardCopyOption.REPLACE_EXISTING);
            List<String> lines = Files.readAllLines(spigot, StandardCharsets.UTF_8);
            int bungeeLine = -1;
            for (int index = 0; index < lines.size(); index++) {
                String line = lines.get(index);
                if (line.matches("^\\s{2}bungeecord:\\s*(?:true|false)\\s*$")) {
                    if (bungeeLine >= 0) {
                        throw new IOException("prepared spigot.yml has duplicate settings.bungeecord: "
                                + spigot);
                    }
                    if (!line.trim().equals("bungeecord: false")) {
                        throw new IOException("prepared spigot.yml is not the immutable default template: "
                                + spigot);
                    }
                    bungeeLine = index;
                }
            }
            if (bungeeLine < 0) {
                throw new IOException("prepared spigot.yml has no settings.bungeecord: " + spigot);
            }
            if (lines.stream().noneMatch(
                    line -> line.matches("^config-version:\\s+\\d+\\s*$"))) {
                throw new IOException("prepared spigot.yml has no config-version: " + spigot);
            }
            lines.set(bungeeLine, "  bungeecord: true");
            Files.writeString(spigot, String.join("\n", lines) + "\n", StandardCharsets.UTF_8);
            forwardingConfigured = true;
        }

        private OwnedProcess startProcess(String name, Path workingDirectory, Path jar, String heap) throws IOException {
            int generation = ++processGeneration;
            Path stdout = runRoot.resolve(name + "-" + generation + ".stdout.log");
            Path stderr = runRoot.resolve(name + "-" + generation + ".stderr.log");
            ProcessBuilder builder = new ProcessBuilder(
                    javaExecutable(), heap, "-jar", jar.toString());
            // The matrix runner may set JAVA_TOOL_OPTIONS/GRADLE_OPTS to keep the
            // Gradle build deterministic on Helio.  Those build-only flags (notably
            // TieredStopAtLevel=0) also propagate to the real Paper/Velocity child
            // and can leave an interpreted server JVM stuck in bootstrap long enough
            // to trip the startup timeout.  The server process must use the normal
            // JIT/runtime environment; its executable and all input artifacts remain
            // explicitly pinned above.
            builder.environment().remove("JAVA_TOOL_OPTIONS");
            builder.environment().remove("GRADLE_OPTS");
            if (name.startsWith("paper") || name.startsWith("folia")) {
                builder.command().add("--nogui");
            }
            builder.directory(workingDirectory.toFile());
            builder.redirectOutput(stdout.toFile());
            builder.redirectError(stderr.toFile());
            Process process = builder.start();
            OwnedProcess owned = new OwnedProcess(name, process, stdout, stderr);
            processes.add(owned);
            return owned;
        }

        private void waitFor(OwnedProcess process, String marker, int seconds) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (readStartupOutput(process).contains(marker)) return;
                if (!process.process().isAlive()) {
                    throw new IOException(process.name() + " exited before marker " + marker
                            + "\n" + readStartupOutput(process));
                }
                Thread.sleep(250);
            }
            throw new IOException(process.name() + " did not emit marker: " + marker
                    + "\n" + readStartupOutput(process));
        }

        private void waitForPath(Path path, int seconds) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (Files.isRegularFile(path)) return;
                Thread.sleep(250);
            }
            throw new IOException("identity was not created: " + path);
        }

        private void waitForPath(OwnedProcess process, Path path, int seconds) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (Files.isRegularFile(path)) return;
                if (!process.process().isAlive()) {
                    throw new IOException(process.name() + " exited before identity was created: " + path
                            + "\n" + readStartupOutput(process));
                }
                Thread.sleep(250L);
            }
            throw new IOException(process.name() + " did not create identity within " + seconds
                    + " seconds: " + path + "\n" + readStartupOutput(process));
        }

        private void sendProxyCommand(String command) throws IOException {
            if (processes.isEmpty() || !processes.getFirst().process().isAlive()) {
                throw new IOException("proxy is unavailable for console command");
            }
            OutputStream console = processes.getFirst().process().getOutputStream();
            console.write((command + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
            console.flush();
        }

        private void waitForProxyMarker(String marker, int seconds) throws Exception {
            if (processes.isEmpty()) throw new IOException("proxy is not started");
            waitFor(processes.getFirst(), marker, seconds);
        }

        private boolean federationAuditHealthy() throws Exception {
            Map<String, Integer> before = federationStatusLineCounts(proxyProcessOutput());
            sendProxyCommand("mcacefederation status");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            while (System.nanoTime() < deadline) {
                Map<String, Integer> remaining = new java.util.HashMap<>(before);
                List<String> fresh = new ArrayList<>();
                for (String line : proxyProcessOutput().split("\\R")) {
                    if (!line.contains("MCAce: federation ")) {
                        continue;
                    }
                    int prior = remaining.getOrDefault(line, 0);
                    if (prior > 0) {
                        remaining.put(line, prior - 1);
                    } else {
                        fresh.add(line);
                    }
                }
                for (String line : fresh) {
                    if (line.contains("audit=FAILED")) return false;
                    if (line.contains("enabled=true")
                            && line.contains("configured=true")
                            && line.contains("audit=HEALTHY")
                            && line.contains("audit_failures=0")) {
                        return true;
                    }
                }
                Thread.sleep(100L);
            }
            return false;
        }

        private static Map<String, Integer> federationStatusLineCounts(String output) {
            Map<String, Integer> counts = new java.util.HashMap<>();
            for (String line : output.split("\\R")) {
                if (line.contains("MCAce: federation ")) {
                    counts.merge(line, 1, Integer::sum);
                }
            }
            return counts;
        }

        /** Fresh-work-root runtime marker search including the proxy's own rolling log. */
        private void waitForProxyRuntimeMarker(String marker, int seconds) throws Exception {
            if (processes.isEmpty()) throw new IOException("proxy is not started");
            OwnedProcess proxy = processes.getFirst();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (readLogs(proxy).contains(marker)) return;
                if (!proxy.process().isAlive()) {
                    throw new IOException("proxy exited before runtime marker " + marker);
                }
                Thread.sleep(250L);
            }
            throw new IOException("proxy did not emit runtime marker: " + marker);
        }

        private boolean proxyRuntimeMarkerObserved(String marker) {
            if (processes.isEmpty()) return false;
            OwnedProcess proxy = processes.getFirst();
            return proxy.process().isAlive() && readLogs(proxy).contains(marker);
        }

        private String waitForFederationAudit(int seconds, String... markers) throws Exception {
            Path audit = proxyDataDirectory().resolve("federation-audit.log");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (Files.isRegularFile(audit)) {
                    String content = Files.readString(audit, StandardCharsets.UTF_8);
                    boolean complete = true;
                    for (String marker : markers) complete &= content.contains(marker);
                    if (complete) return content;
                }
                Thread.sleep(100L);
            }
            throw new IOException("federation audit did not contain required markers: "
                    + String.join(",", markers));
        }

        private long federationAuditSize() throws IOException {
            Path audit = proxyDataDirectory().resolve("federation-audit.log");
            return Files.isRegularFile(audit) ? Files.size(audit) : 0L;
        }

        private String waitForFederationAuditSince(long offset, int seconds, String... markers)
                throws Exception {
            Path audit = proxyDataDirectory().resolve("federation-audit.log");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (Files.isRegularFile(audit)) {
                    byte[] full = Files.readAllBytes(audit);
                    if (offset >= 0L && offset <= full.length) {
                        String content = new String(full, (int) offset, full.length - (int) offset,
                                StandardCharsets.UTF_8);
                        boolean complete = true;
                        for (String marker : markers) complete &= content.contains(marker);
                        if (complete) return content;
                    }
                }
                Thread.sleep(100L);
            }
            throw new IOException("federation audit did not contain required post-restart markers: "
                    + String.join(",", markers));
        }

        private String proxyLogs() {
            return processes.isEmpty() ? "" : readLogs(processes.getFirst());
        }

        /** Captures deterministic Bungee publisher cursors without retaining their identities in reports. */
        private PublisherSnapshot captureBungeePublisherSnapshot() {
            if (processes.isEmpty()) return new PublisherSnapshot(false, Map.of());
            try {
                Map<String, PublisherSourceCursor> sources = new LinkedHashMap<>();
                capturePublisherSource(sources, "stdout", processes.getFirst().stdout());
                capturePublisherSource(sources, "stderr", processes.getFirst().stderr());
                if (kind == ProxyKind.BUNGEE) {
                    try (var stream = Files.list(proxyRoot)) {
                        for (Path path : stream
                                .filter(candidate -> candidate.getFileName().toString().startsWith("proxy.log."))
                                .sorted(java.util.Comparator.comparing(candidate -> candidate.getFileName().toString()))
                                .toList()) {
                            capturePublisherSource(sources,
                                    "proxy-log:" + path.getFileName(), path);
                        }
                    }
                }
                return new PublisherSnapshot(true, sources);
            } catch (IOException | SecurityException exception) {
                return new PublisherSnapshot(false, Map.of());
            }
        }

        private static void capturePublisherSource(
                Map<String, PublisherSourceCursor> sources, String sourceName, Path path) throws IOException {
            if (!Files.exists(path)) {
                sources.put(sourceName, new PublisherSourceCursor(sourceName + ":absent", 0L, ""));
                return;
            }
            BasicFileAttributes before = Files.readAttributes(path, BasicFileAttributes.class);
            if (before.size() > 1_048_576L) {
                throw new IOException("publisher source exceeds bounded capture size");
            }
            int prefixLength = Math.toIntExact(before.size());
            byte[] bytes;
            try (var input = Files.newInputStream(path)) {
                bytes = input.readNBytes(prefixLength);
            }
            BasicFileAttributes after = Files.readAttributes(path, BasicFileAttributes.class);
            if (bytes.length != prefixLength || after.size() < prefixLength
                    || !Objects.equals(before.fileKey(), after.fileKey())) {
                throw new IOException("publisher source was replaced or truncated during capture");
            }
            String fileKey = String.valueOf(before.fileKey());
            String identity = sourceName + ':' + fileKey + ':' + before.creationTime().toMillis();
            sources.put(sourceName, new PublisherSourceCursor(identity, bytes.length,
                    new String(bytes, StandardCharsets.UTF_8)));
        }

        /** Current generation only; restart gates must never match a prior proxy's markers. */
        private String proxyProcessOutput() {
            if (processes.isEmpty()) return "";
            StringBuilder output = new StringBuilder(readProcessOutput(processes.getFirst()));
            // Bungee's console command acknowledgement and plugin callbacks are commonly written
            // to proxy.log.N rather than inherited stdout. This work tree contains exactly one
            // Bungee generation, and it is deleted before the sanitized report is emitted.
            if (kind == ProxyKind.BUNGEE) {
                try (var stream = Files.list(proxyRoot)) {
                    stream.filter(path -> path.getFileName().toString().startsWith("proxy.log."))
                            .forEach(path -> {
                                try {
                                    output.append(Files.readString(path, StandardCharsets.UTF_8))
                                            .append('\n');
                                } catch (IOException ignored) {
                                    // Missing/rotated fixture output is ordinary non-evidence.
                                }
                            });
                } catch (IOException ignored) {
                    // The later bounded publisher/route waits fail closed if markers never arrive.
                }
            }
            return output.toString();
        }

        private String paperLogs() {
            return processes.size() < 2 ? "" : readLogs(processes.getLast());
        }

        private String readLogs(OwnedProcess process) {
            StringBuilder result = new StringBuilder();
            result.append(readProcessOutput(process));
            for (Path path : List.of(platformLogFor(process))) {
                if (Files.isRegularFile(path)) {
                    try { result.append(Files.readString(path, StandardCharsets.UTF_8)).append('\n'); }
                    catch (IOException ignored) { }
                }
            }
            try {
                if (process.name().equals("proxy") && kind == ProxyKind.BUNGEE) {
                    try (var stream = Files.list(proxyRoot)) {
                        stream.filter(path -> path.getFileName().toString().startsWith("proxy.log."))
                                .forEach(path -> { try { result.append(Files.readString(path)).append('\n'); } catch (IOException ignored) { } });
                    }
                }
            } catch (IOException ignored) { }
            return result.toString();
        }

        private Path platformLogFor(OwnedProcess process) {
            return switch (process.name()) {
                case "paper", "folia", "paper-lobby" -> paperRoot.resolve("logs/latest.log");
                case "paper-limited" -> limitedPaperRoot.resolve("logs/latest.log");
                case "paper-quarantine" -> quarantinePaperRoot.resolve("logs/latest.log");
                default -> proxyRoot.resolve("logs/latest.log");
            };
        }

        private static String readProcessOutput(OwnedProcess process) {
            StringBuilder result = new StringBuilder();
            for (Path path : List.of(process.stdout(), process.stderr())) {
                if (Files.isRegularFile(path)) {
                    // The proxy is still appending while evidence is sampled. Decode a byte
                    // snapshot with replacement semantics so a trailing partial UTF-8 sequence
                    // cannot turn an otherwise valid append-only snapshot into empty evidence.
                    try { result.append(new String(Files.readAllBytes(path), StandardCharsets.UTF_8)).append('\n'); }
                    catch (IOException ignored) { }
                }
            }
            return result.toString();
        }

        private String readStartupOutput(OwnedProcess process) {
            StringBuilder result = new StringBuilder(readProcessOutput(process));
            // On Windows, ProcessBuilder's redirected stdout may be exclusively held by the
            // child while it is still booting. Velocity also mirrors its startup messages to
            // the rolling log, so include that append-only source before waiting for markers.
            Path platformLog = platformLogFor(process);
            if (Files.isRegularFile(platformLog)) {
                try {
                    result.append(Files.readString(platformLog, StandardCharsets.UTF_8))
                            .append('\n');
                } catch (IOException ignored) {
                    // A log being rotated or temporarily locked is ordinary during startup.
                }
            }
            // BungeeCord writes its live bootstrap/plugin output to proxy.log.N before the
            // inherited stdout redirect is reliably flushed. This fallback is only used for
            // Bungee's initial startup; the Velocity restart residual gate uses the exact
            // generation stdout via proxyProcessOutput(), never these carry-over files.
            if (process.name().equals("proxy") && kind == ProxyKind.BUNGEE) {
                try (var stream = Files.list(proxyRoot)) {
                    stream.filter(path -> path.getFileName().toString().startsWith("proxy.log."))
                            .forEach(path -> {
                                try { result.append(Files.readString(path, StandardCharsets.UTF_8)).append('\n'); }
                                catch (IOException ignored) { }
                            });
                } catch (IOException ignored) { }
            }
            return result.toString();
        }

        private boolean waitForPaperAdmission(int seconds) throws InterruptedException {
            if (processes.isEmpty()) return false;
            OwnedProcess paper = processes.getLast();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            while (System.nanoTime() < deadline) {
                if (readLogs(paper).contains("Accepted signed MCAce admission state")
                        && readLogs(paper).contains("admission=VERIFIED, trust=VERIFIED")) return true;
                if (!paper.process().isAlive()) return false;
                Thread.sleep(250);
            }
            return false;
        }

        @Override public void close() {
            for (OwnedProcess owned : processes.reversed()) {
                terminateOwnedProcess(owned);
            }
            List<ProcessHandle> leftovers = ProcessHandle.allProcesses()
                    .filter(handle -> handle.isAlive())
                    .filter(handle -> handle.info().commandLine().map(line -> line.contains(runRoot.toString())).orElse(false))
                    .toList();
            for (ProcessHandle leftover : leftovers) {
                cleanupProcessIds.add(leftover.pid() > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) leftover.pid());
                leftover.destroy();
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (System.nanoTime() < deadline && !remainingRunProcesses().isEmpty()) {
                try { Thread.sleep(100); } catch (InterruptedException exception) { Thread.currentThread().interrupt(); break; }
            }
            for (ProcessHandle leftover : ProcessHandle.allProcesses()
                    .filter(handle -> handle.isAlive())
                    .filter(handle -> handle.info().commandLine().map(line -> line.contains(runRoot.toString())).orElse(false))
                    .toList()) {
                cleanupProcessIds.add(leftover.pid() > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) leftover.pid());
                leftover.destroyForcibly();
            }
            for (Path sensitive : sensitiveForwardingFiles) {
                try { Files.deleteIfExists(sensitive); } catch (IOException ignored) { }
            }
            deleteTemporaryProxyPrivateKeys(temporaryProxyPrivateKeys);
        }

        private void terminateOwnedProcess(OwnedProcess owned) {
            cleanupProcessIds.add(owned.process().pid() > Integer.MAX_VALUE
                    ? Integer.MAX_VALUE : (int) owned.process().pid());
            if (owned.process().isAlive()) {
                owned.process().destroy();
                try {
                    if (!owned.process().waitFor(10, TimeUnit.SECONDS)) owned.process().destroyForcibly();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    owned.process().destroyForcibly();
                }
            }
            if (owned.process().isAlive()) {
                try { owned.process().waitFor(10, TimeUnit.SECONDS); }
                catch (InterruptedException exception) { Thread.currentThread().interrupt(); }
            }
        }

        private List<Long> remainingRunProcesses() {
            return ProcessHandle.allProcesses().filter(handle -> handle.isAlive())
                    .filter(handle -> handle.info().commandLine().map(line -> line.contains(runRoot.toString())).orElse(false))
                    .map(ProcessHandle::pid).toList();
        }

        private boolean sensitiveForwardingFileRetained() {
            return sensitiveForwardingFiles.stream().anyMatch(path -> Files.exists(path));
        }

        private boolean temporaryProxyPrivateKeyRetained() {
            return temporaryProxyPrivateKeys.stream().anyMatch(Files::exists);
        }

        private void registerTemporaryProxyPrivateKeys(Path dataDirectory) {
            for (Path privateKey : temporaryProxyPrivateKeyPaths(dataDirectory)) {
                if (!temporaryProxyPrivateKeys.contains(privateKey)) {
                    temporaryProxyPrivateKeys.add(privateKey);
                }
            }
        }

        private static List<Path> temporaryProxyPrivateKeyPaths(Path dataDirectory) {
            return List.of(
                    dataDirectory.resolve("identity/server-private-key.pk8"),
                    dataDirectory.resolve("policy/delegated-key/delegated-private-key.pk8"));
        }

        private static void deleteTemporaryProxyPrivateKeys(List<Path> privateKeys) {
            for (Path privateKey : privateKeys) {
                try { Files.deleteIfExists(privateKey); } catch (IOException ignored) { }
            }
        }

        private static void copyPreparedRuntime(Path source, Path destination) throws IOException {
            // Copy only the immutable runtime bootstrap roots that the asset manifest binds.
            // Paper/Folia create disposable world/config/log state inside the isolated run root.
            for (String directory : List.of("cache", "libraries", "versions")) {
                Path from = source.resolve(directory);
                Path to = destination.resolve(directory);
                try (var walk = Files.walk(from)) {
                    walk.forEach(path -> {
                        try {
                            Path target = to.resolve(from.relativize(path));
                            if (Files.isDirectory(path)) Files.createDirectories(target);
                            else Files.copy(path, target, StandardCopyOption.REPLACE_EXISTING);
                        } catch (IOException exception) { throw new RuntimeException(exception); }
                    });
                }
            }
        }

        private String javaExecutable() {
            return runtimeAssets.serverJava().toString();
        }

        private static int freePort() throws IOException {
            try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                return socket.getLocalPort();
            }
        }

        private static byte[] randomBytes(int length) {
            byte[] bytes = new byte[length];
            new SecureRandom().nextBytes(bytes);
            return bytes;
        }

        private static void requireArtifact(Path path, String label) throws IOException {
            if (!Files.exists(path)) throw new IOException(label + " missing: " + path);
        }
    }

    private record OwnedProcess(String name, Process process, Path stdout, Path stderr) { }
    /** In-memory only counters that bind cleanup evidence to one proxy process generation. */
    private record CleanupMarkerBaseline(
            OwnedProcess proxy, int productReadyMarkerCount, int observerLastMarkerCount) { }
    private record DispositionObservation(
            boolean resultObserved,
            boolean lobbyAdmission,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean deferredRouteObserved,
            boolean deferredRouteDispatched,
            RouteCompletion routeCompletion,
            boolean anyRouteLifecycleObserved) { }
    private record DispositionPeerResult(
            boolean syntheticManifestSent,
            AuthenticationEvidence authenticationEvidence,
            boolean dispositionResultObserved,
            boolean lobbyAdmission,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean deferredRouteObserved,
            boolean deferredRouteDispatched,
            boolean anyRouteLifecycleObserved,
            RouteCompletion routeCompletion,
            RemoteLiveness remoteLiveness,
            boolean connectionRetained) {
        boolean authenticationAccepted() { return authenticationEvidence.acceptedDuringConfiguration(); }
        boolean authenticationAcceptedAnyPhase() {
            return authenticationEvidence.authenticationAcceptedAnyPhase();
        }
    }
    private record TrustedDispositionPeerResult(
            boolean authenticationAccepted,
            boolean reviewCommandSent,
            boolean authorizationObserved,
            boolean dispositionResultObserved,
            boolean lobbyAdmission,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            RouteCompletion routeCompletion,
            boolean connectionRetained) { }
    /** Sanitized booleans only; the per-run UUID and commitments never leave the disposable tree. */
    private record TrustedAuthorizationEvidence(
            boolean commandObserved,
            boolean journalRecordMatched,
            boolean persistedBeforeExecution) { }
    /** Content-free raw-peer phase evidence. The CONFIGURATION admission gate remains exact. */
    record AuthenticationEvidence(
            ServerHelloStage serverHelloStage,
            AuthOutboundStage authOutboundStage,
            AuthResultStage authResultStage,
            boolean authenticationAcceptedAnyPhase) {
        boolean acceptedDuringConfiguration() {
            return serverHelloStage == ServerHelloStage.CONFIGURATION
                    && authOutboundStage == AuthOutboundStage.CONFIGURATION
                    && authResultStage == AuthResultStage.ACCEPTED_CONFIGURATION;
        }
    }
    private record DenyWireObservation(
            boolean deniedResultObserved,
            DisconnectEvidence disconnectEvidence) { }
    private record DenyPeerResult(
            boolean cleanManifestSent,
            boolean authenticationAccepted,
            boolean lobbyAdmission,
            boolean reviewCommandSent,
            boolean authorizationObserved,
            boolean deniedResultObserved,
            DisconnectEvidence disconnectEvidence,
            String authenticatedSessionId) { }
    private record CleanReconnectPeerResult(
            boolean cleanManifestSent,
            boolean authenticationAccepted,
            boolean configurationCompleted,
            boolean newLobbyVerifiedAdmission,
            String authenticatedSessionId,
            CleanReconnectStage stage,
            CleanReconnectTermination termination) { }
    private record TargetProxyRestartResult(
            boolean oldProxyTerminated,
            boolean paperKeptRunning,
            boolean identityPreserved,
            boolean configurationPreserved) { }
    private record StandardBackendObservation(
            boolean admission,
            boolean shadowContext) { }

    private static final class MinecraftWirePeer {
        private final ProbeHarness harness;
        private final List<String> channels = new ArrayList<>();
        private final List<String> limitations = new ArrayList<>();
        private final List<String> packetTrace = new ArrayList<>();
        private boolean loginSuccess;
        private boolean compressionSeen;
        private boolean configurationFinished;
        private boolean playJoinSeen;
        private boolean playChannelRegistrationSent;
        private Payload pendingPlayServerHello;
        private boolean serverHelloSeen;
        private boolean authResultSeen;
        private boolean authAccepted;
        private boolean authenticationSent;
        private ServerHelloStage serverHelloStage = ServerHelloStage.NOT_OBSERVED;
        private AuthOutboundStage authOutboundStage = AuthOutboundStage.NOT_SENT;
        private AuthResultStage authResultStage = AuthResultStage.NOT_OBSERVED;
        private UUID playerId;
        private int compressionThreshold = -1;
        private ClientHandshakeEngine engine;
        private byte[] federationFirstOuter;
        private byte[] federationReplayPresentation;
        private boolean federationIssueSent;
        private Socket socket;
        private java.io.PushbackInputStream pushbackInput;
        private DataInputStream input;
        private DataOutputStream output;
        private State state = State.LOGIN;
        private final boolean syntheticManifest;
        private DispositionScenario activeDispositionScenario;
        private DispositionObservation inlineDispositionObservation;
        private boolean activeTrustedDispositionProbe;
        private boolean trustedReviewCommandSent;
        private RemoteLiveness remoteLiveness = RemoteLiveness.NOT_ATTEMPTED;
        private boolean activeDenyProbe;
        private boolean activeTrustedDenyProbe;
        private DenyWireObservation inlineDenyObservation;
        private boolean activeCleanReconnectProbe;
        private int reconnectLobbyAdmissionBaseline;
        private boolean reconnectNewLobbyAdmission;
        private boolean standardBackendAdmissionDriven;
        private boolean inlineBackendAdmission;
        private boolean inlineBackendContextShadowAudit;
        private CleanReconnectStage cleanReconnectStage = CleanReconnectStage.NOT_STARTED;
        private CleanReconnectTermination cleanReconnectTermination =
                CleanReconnectTermination.NONE;

        private MinecraftWirePeer(ProbeHarness harness) { this(harness, false); }

        private MinecraftWirePeer(ProbeHarness harness, boolean syntheticManifest) {
            this.harness = harness;
            this.syntheticManifest = syntheticManifest;
        }

        private void advanceCleanReconnectStage(CleanReconnectStage candidate) {
            if (activeCleanReconnectProbe
                    && candidate.ordinal() > cleanReconnectStage.ordinal()) {
                cleanReconnectStage = candidate;
            }
        }

        private void terminateCleanReconnect(CleanReconnectTermination termination) {
            if (activeCleanReconnectProbe
                    && cleanReconnectTermination == CleanReconnectTermination.NONE) {
                cleanReconnectTermination = termination;
            }
        }

        private ProbeReport probe() throws Exception {
            playerId = UUID.nameUUIDFromBytes(("OfflinePlayer:" + PLAYER_NAME).getBytes(StandardCharsets.UTF_8));
            MinecraftWireProfile.ConfigurationPackets configurationPackets =
                    harness.wireProfile.configuration();
            MinecraftWireProfile.PlayPackets playPackets = harness.wireProfile.play();
            try (Socket connected = new Socket(InetAddress.getLoopbackAddress(), harness.proxyPort)) {
                socket = connected;
                advanceCleanReconnectStage(CleanReconnectStage.TCP_CONNECTED);
                socket.setSoTimeout(10_000);
                pushbackInput = new java.io.PushbackInputStream(socket.getInputStream(), 1);
                input = new DataInputStream(pushbackInput);
                output = new DataOutputStream(socket.getOutputStream());
                send(0, handshake(playerId, harness.wireProfile.protocolVersion()));
                send(0, loginStart(playerId));
                // Folia can complete the backend join before its region scheduler has flushed
                // the first clientbound login frame through Velocity.  Keep the probe bounded,
                // but give that real process path a larger, version-independent window.  Paper
                // retains the original 25-second contract so a stalled proxy still fails fast.
                int loginDeadlineSeconds = harness.backendKind == BackendKind.FOLIA ? 60 : 25;
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(loginDeadlineSeconds);
                while (System.nanoTime() < deadline && socket.isConnected()) {
                    // Cold Paper/Folia bootstrap can leave the proxy channel quiet for more
                    // than ten seconds after TCP accept. Recompute the read timeout from the
                    // same deadline on every frame so an idle scheduling interval is tolerated
                    // without allowing a single read to outlive the probe budget.
                    long remainingNanos = deadline - System.nanoTime();
                    if (remainingNanos <= 0L) break;
                    long remainingMillis = TimeUnit.NANOSECONDS.toMillis(remainingNanos);
                    socket.setSoTimeout((int) Math.max(1L, Math.min(45_000L, remainingMillis + 1L)));
                    Packet packet;
                    try {
                        packet = read();
                    } catch (SocketTimeoutException exception) {
                        if (!activeCleanReconnectProbe) throw exception;
                        terminateCleanReconnect(CleanReconnectTermination.READ_TIMEOUT);
                        break;
                    } catch (EOFException | java.net.SocketException exception) {
                        terminateCleanReconnect(CleanReconnectTermination.REMOTE_EOF_OR_RESET);
                        limitations.add("peer disconnected");
                        break;
                    } catch (IOException | DataFormatException exception) {
                        if (!activeCleanReconnectProbe) throw exception;
                        terminateCleanReconnect(CleanReconnectTermination.PROTOCOL_ERROR);
                        break;
                    }
                    if (packetTrace.size() < 256) {
                        packetTrace.add(state + ":0x" + Integer.toHexString(packet.id()));
                    } else if (packetTrace.size() == 256) {
                        packetTrace.add("packet trace capped at 256 entries");
                    }
                    if (state == State.LOGIN) {
                        if (packet.id() == 0x00) {
                            // Disconnect component/reason is deliberately neither parsed nor saved.
                            terminateCleanReconnect(CleanReconnectTermination.LOGIN_DISCONNECT);
                            break;
                        } else if (packet.id() == 0x03) {
                            compressionThreshold = readVarInt(new ByteArrayInputStream(packet.payload()));
                            compressionSeen = true;
                        } else if (packet.id() == 0x02) {
                            loginSuccess = true;
                            advanceCleanReconnectStage(CleanReconnectStage.LOGIN_SUCCESS);
                            send(0x03, new byte[0]);
                            state = State.CONFIGURATION;
                            advanceCleanReconnectStage(CleanReconnectStage.CONFIGURATION);
                            send(configurationPackets.serverboundClientInformation(),
                                    clientInformation(harness.wireProfile));
                            // Give the proxy's backend connection a bounded head start before
                            // forwarding the client channel registration during configuration.
                            Thread.sleep(1_000);
                            sendCustomPayload("minecraft:register",
                                    "mcace:handshake\0mcace:payload\0mcace:context".getBytes(StandardCharsets.UTF_8));
                        } else if (packet.id() == 0x04) {
                            LoginPlugin request = parseLoginPlugin(packet.payload());
                            send(0x02, concat(varInt(request.messageId()), new byte[] {0}));
                        } else if (packet.id() == 0x01) {
                            limitations.add("proxy requested encryption; offline-mode peer cannot continue");
                            terminateCleanReconnect(CleanReconnectTermination.PROTOCOL_ERROR);
                            break;
                        }
                    } else if (state == State.CONFIGURATION) {
                        if (packet.id() == configurationPackets.clientboundCustomPayload()) {
                            Payload payload = parsePayload(packet.payload());
                            handlePayload(payload);
                        } else if (packet.id() == configurationPackets.clientboundFinish()) {
                            send(configurationPackets.serverboundFinish(), new byte[0]);
                            configurationFinished = true;
                            state = State.PLAY;
                            advanceCleanReconnectStage(CleanReconnectStage.PLAY);
                        } else if (packet.id() == configurationPackets.clientboundKeepAlive()) {
                            send(configurationPackets.serverboundKeepAlive(), packet.payload());
                        } else if (packet.id() == configurationPackets.clientboundPing()) {
                            send(configurationPackets.serverboundPong(), packet.payload());
                        } else if (packet.id() == configurationPackets.clientboundSelectKnownPacks()) {
                            send(configurationPackets.serverboundSelectKnownPacks(), varInt(0));
                        } else if (packet.id() == configurationPackets.clientboundCookieRequest()) {
                            CookieRequest cookie = parseCookieRequest(packet.payload());
                            send(configurationPackets.serverboundCookieResponse(),
                                    concat(string(cookie.key()), new byte[] {0}));
                        } else if (packet.id() == configurationPackets.clientboundDisconnect()) {
                            // Disconnect component/reason is deliberately neither parsed nor saved.
                            terminateCleanReconnect(
                                    CleanReconnectTermination.CONFIGURATION_DISCONNECT);
                            limitations.add("proxy/server disconnected during configuration");
                            break;
                        }
                    } else {
                        if (packet.id() == playPackets.clientboundLogin()
                                && !playChannelRegistrationSent) {
                            playJoinSeen = true;
                            sendCustomPayload("minecraft:register",
                                    "mcace:handshake\0mcace:payload\0mcace:context"
                                            .getBytes(StandardCharsets.UTF_8));
                            playChannelRegistrationSent = true;
                            packetTrace.add("PLAY:channel-registration-after-game-join");
                            if (pendingPlayServerHello != null) {
                                Payload pending = pendingPlayServerHello;
                                pendingPlayServerHello = null;
                                packetTrace.add("PLAY:server-hello-resumed-after-game-join");
                                handlePayloadAfterChannelRecord(pending);
                            }
                        } else if (packet.id() == playPackets.clientboundCustomPayload()) {
                            try {
                                Payload payload = parsePayload(packet.payload());
                                channels.add(payload.channel());
                                if (payload.channel().startsWith("mcace:")) {
                                    packetTrace.add("PLAY:custom:" + payload.channel() + ":" + payload.data().length);
                                    if ("mcace:handshake".equals(payload.channel())
                                            && !serverHelloSeen && !playJoinSeen) {
                                        // Velocity can flush its PLAY-state server hello before the
                                        // backend GameJoin reaches the client. A real Fabric play
                                        // receiver cannot safely answer until its play handler and
                                        // channel registration are established, so model that here.
                                        pendingPlayServerHello = payload;
                                        packetTrace.add("PLAY:server-hello-deferred-until-game-join");
                                    } else {
                                        handlePayloadAfterChannelRecord(payload);
                                    }
                                }
                            } catch (IOException ignored) {
                                limitations.add("ignored non-custom play packet with id 0x"
                                        + Integer.toHexString(packet.id()));
                            }
                        } else if (packet.id() == playPackets.clientboundKeepAlive()) {
                            send(playPackets.serverboundKeepAlive(), packet.payload());
                        }
                    }
                    boolean standardProbeReady = playJoinSeen
                            || activeDispositionScenario != null
                            || activeDenyProbe
                            || activeCleanReconnectProbe;
                    if (authResultSeen && standardProbeReady) {
                        if ((activeTrustedDispositionProbe || activeTrustedDenyProbe)
                                && !harness.backendAccepted("paper-lobby", harness.paperRoot)) {
                            Thread.sleep(50L);
                            continue;
                        }
                        if (activeTrustedDispositionProbe && !trustedReviewCommandSent) {
                            harness.issueAdministratorDispositionReview(activeDispositionScenario);
                            trustedReviewCommandSent = true;
                        } else if (activeTrustedDenyProbe && !trustedReviewCommandSent) {
                            harness.issueAdministratorDispositionReview(DispositionScenario.ENFORCE_DENY);
                            trustedReviewCommandSent = true;
                        }
                        // Keep the raw connection alive until the named backend evidence arrives.
                        // A dispatched Velocity connection request can otherwise be cancelled by
                        // this test peer closing before the target backend finishes joining.
                        if (activeDispositionScenario != null) {
                            inlineDispositionObservation = driveDispositionProtocol(
                                    activeDispositionScenario, 25);
                            remoteLiveness = boundedRemoteConnectionProbe(connected);
                        } else if (activeDenyProbe) {
                            inlineDenyObservation = driveDenyProtocol(15);
                        } else if (activeCleanReconnectProbe) {
                            reconnectNewLobbyAdmission = driveCleanReconnectProtocol(
                                    reconnectLobbyAdmissionBaseline, 25);
                        } else {
                            // Modern Paper can finish the player join/channel registration just
                            // after AuthResult. Keep the raw peer alive and service PLAY/CONFIG
                            // keepalives until a periodic proxy refresh reaches the backend;
                            // sleeping a fixed five seconds races the first usable refresh.
                            standardBackendAdmissionDriven = true;
                            StandardBackendObservation observation =
                                    driveStandardBackendAdmissionProtocol(20);
                            inlineBackendAdmission = observation.admission();
                            inlineBackendContextShadowAudit = observation.shadowContext();
                        }
                        break;
                    }
                }
                if (activeCleanReconnectProbe
                        && cleanReconnectStage != CleanReconnectStage.LOBBY_VERIFIED
                        && cleanReconnectTermination == CleanReconnectTermination.NONE) {
                    terminateCleanReconnect(CleanReconnectTermination.READ_TIMEOUT);
                }
                if (!serverHelloSeen) limitations.add("MCAce server hello was not observed on a real custom-payload packet");
                if (!authResultSeen) limitations.add("MCAce auth result was not observed after signed CLIENT_HELLO/AUTH_REQUEST; proxy emitted only limited backend admission");
            }
            boolean backendAdmission;
            if (syntheticManifest) {
                backendAdmission = false;
            } else if (activeCleanReconnectProbe) {
                backendAdmission = reconnectNewLobbyAdmission;
            } else if (standardBackendAdmissionDriven) {
                // The standard probe must observe admission while this exact socket is still open.
                // Falling back to a post-close log match would reintroduce the cold-join race this
                // protocol driver exists to prove absent.
                backendAdmission = inlineBackendAdmission;
            } else {
                backendAdmission = harness.waitForPaperAdmission(20);
            }
            if (activeCleanReconnectProbe && backendAdmission) {
                advanceCleanReconnectStage(CleanReconnectStage.LOBBY_VERIFIED);
            }
            if (!syntheticManifest && !backendAdmission) {
                limitations.add(harness.backendKind + " backend admission was not observed");
            }
            boolean backendContextShadowAudit = false;
            if (!syntheticManifest && !activeCleanReconnectProbe && backendAdmission) {
                if (standardBackendAdmissionDriven) {
                    backendContextShadowAudit = inlineBackendContextShadowAudit;
                    if (!backendContextShadowAudit) {
                        limitations.add("proxy did not emit runtime marker: backend context shadow audit");
                    }
                } else {
                    try {
                        harness.waitForProxyRuntimeMarker("backend context shadow audit", 20);
                        backendContextShadowAudit = true;
                    } catch (IOException exception) {
                        limitations.add(exception.getMessage());
                    }
                }
            }
            return new ProbeReport(harness.kind, harness.backendKind,
                    harness.backendMinecraftVersion,
                    harness.forwardingMode, harness.forwardingConfigured,
                    harness.proxyPort, harness.paperPort, true, loginSuccess,
                    compressionSeen, configurationFinished, serverHelloSeen, authResultSeen, authAccepted,
                    backendAdmission, backendContextShadowAudit,
                    List.copyOf(channels), List.copyOf(packetTrace), List.copyOf(limitations), List.of(), List.of());
        }

        private DispositionPeerResult dispositionProbe(DispositionScenario scenario) throws Exception {
            activeDispositionScenario = scenario;
            ProbeReport baseline = probe();
            DispositionObservation observation = inlineDispositionObservation == null
                    ? new DispositionObservation(false, false, false, false, false, false,
                            RouteCompletion.NONE, false)
                    : inlineDispositionObservation;
            boolean remoteDisconnectObserved = baseline.limitations().stream()
                    .anyMatch(item -> item.contains("disconnected") || item.contains("EOF"));
            return new DispositionPeerResult(
                    syntheticManifest && authenticationSent,
                    authenticationEvidence(),
                    observation.resultObserved(),
                    observation.lobbyAdmission(),
                    observation.limitedAdmission(),
                    observation.quarantineAdmission(),
                    observation.deferredRouteObserved(),
                    observation.deferredRouteDispatched(),
                    observation.anyRouteLifecycleObserved(),
                    observation.routeCompletion(),
                    remoteLiveness,
                    remoteLiveness.openOutcome() && !remoteDisconnectObserved);
        }

        private TrustedDispositionPeerResult trustedDispositionProbe(
                DispositionScenario scenario) throws Exception {
            activeTrustedDispositionProbe = true;
            activeDispositionScenario = scenario;
            ProbeReport baseline = probe();
            DispositionObservation observation = inlineDispositionObservation == null
                    ? new DispositionObservation(false, false, false, false, false, false,
                            RouteCompletion.NONE, false)
                    : inlineDispositionObservation;
            String action = scenario.actionName();
            String proxyOutput = harness.proxyProcessOutput();
            boolean remoteDisconnectObserved = baseline.limitations().stream()
                    .anyMatch(item -> item.contains("disconnected") || item.contains("EOF"));
            return new TrustedDispositionPeerResult(
                    baseline.authAccepted(),
                    trustedReviewCommandSent,
                    ProbeHarness.trustedDispositionAuthorizationObserved(proxyOutput, action),
                    observation.resultObserved(),
                    observation.lobbyAdmission(),
                    observation.limitedAdmission(),
                    observation.quarantineAdmission(),
                    observation.routeCompletion(),
                    remoteLiveness.openOutcome() && !remoteDisconnectObserved);
        }

        private DenyPeerResult trustedDenyDispositionProbe() throws Exception {
            activeDenyProbe = true;
            activeTrustedDenyProbe = true;
            ProbeReport baseline = probe();
            DenyWireObservation observation = inlineDenyObservation == null
                    ? new DenyWireObservation(false, DisconnectEvidence.NONE)
                    : inlineDenyObservation;
            String proxyOutput = harness.proxyProcessOutput();
            return new DenyPeerResult(
                    !syntheticManifest && authenticationSent,
                    baseline.authAccepted(),
                    harness.backendAccepted("paper-lobby", harness.paperRoot),
                    trustedReviewCommandSent,
                    ProbeHarness.trustedDispositionAuthorizationObserved(proxyOutput, "DENY"),
                    observation.deniedResultObserved(),
                    observation.disconnectEvidence(),
                    baseline.authAccepted() && engine != null
                            ? engine.authenticatedSessionId() : null);
        }

        private CleanReconnectPeerResult cleanReconnectProbe(int previousLobbyAdmissionCount)
                throws Exception {
            activeCleanReconnectProbe = true;
            reconnectLobbyAdmissionBaseline = previousLobbyAdmissionCount;
            try {
                probe();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                terminateCleanReconnect(CleanReconnectTermination.READ_TIMEOUT);
            } catch (Exception exception) {
                terminateCleanReconnect(CleanReconnectTermination.PROTOCOL_ERROR);
            }
            // The live protocol driver already waits for the new named-Paper marker while the
            // second socket is open. Never credit a later log write after that socket has closed.
            boolean newAdmission = reconnectNewLobbyAdmission;
            if (newAdmission) advanceCleanReconnectStage(CleanReconnectStage.LOBBY_VERIFIED);
            return new CleanReconnectPeerResult(
                    !syntheticManifest && authenticationSent,
                    authAccepted,
                    configurationFinished,
                    newAdmission,
                    authAccepted && engine != null ? engine.authenticatedSessionId() : null,
                    cleanReconnectStage,
                    cleanReconnectTermination);
        }

        /** Waits for the DENY audit result and a connection-local protocol close signal. */
        private DenyWireObservation driveDenyProtocol(int seconds) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            boolean denied = false;
            DisconnectEvidence evidence = DisconnectEvidence.NONE;
            // Poll before beginning a frame. Once the first byte is available, allow a full
            // bounded frame read so a short quiet tick can never desynchronise a partial frame.
            socket.setSoTimeout(10_000);
            while (System.nanoTime() < deadline) {
                denied |= harness.denyDispositionObserved();
                try {
                    if (input.available() == 0) {
                        if (denied && evidence != DisconnectEvidence.NONE) break;
                        if (denied) {
                            try {
                                socket.setSoTimeout(50);
                                int firstByte = pushbackInput.read();
                                if (firstByte < 0) {
                                    evidence = DisconnectEvidence.REMOTE_EOF_OR_RESET;
                                } else {
                                    pushbackInput.unread(firstByte);
                                }
                            } catch (SocketTimeoutException exception) {
                                // A bounded quiet connection is not closure evidence.
                            } finally {
                                socket.setSoTimeout(10_000);
                            }
                            if (evidence != DisconnectEvidence.NONE) break;
                        }
                        Thread.sleep(50L);
                        continue;
                    }
                    Packet packet = read();
                    if (state == State.CONFIGURATION
                            && packet.id() == harness.wireProfile.configuration().clientboundDisconnect()) {
                        evidence = DisconnectEvidence.PROTOCOL_DISCONNECT;
                    } else {
                        driveDispositionPacket(packet);
                    }
                } catch (EOFException | java.net.SocketException exception) {
                    evidence = DisconnectEvidence.REMOTE_EOF_OR_RESET;
                }
                if (denied && evidence != DisconnectEvidence.NONE) break;
            }
            denied |= harness.denyDispositionObserved();
            return new DenyWireObservation(denied, evidence);
        }

        /** Completes the clean second session through CONFIGURATION until lobby accepts it. */
        private boolean driveCleanReconnectProtocol(int previousLobbyAdmissionCount, int seconds)
                throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            socket.setSoTimeout(10_000);
            while (System.nanoTime() < deadline) {
                boolean newAdmission = harness.backendVerifiedAdmissionCount(
                        "paper-lobby", harness.paperRoot) > previousLobbyAdmissionCount;
                if (state == State.PLAY && newAdmission) {
                    advanceCleanReconnectStage(CleanReconnectStage.LOBBY_VERIFIED);
                    return true;
                }
                if (input.available() == 0) {
                    Thread.sleep(50L);
                    continue;
                }
                try {
                    Packet packet = read();
                    if (state == State.LOGIN && packet.id() == 0x00) {
                        terminateCleanReconnect(CleanReconnectTermination.LOGIN_DISCONNECT);
                        return false;
                    }
                    if (state == State.CONFIGURATION
                            && packet.id() == harness.wireProfile.configuration().clientboundDisconnect()) {
                        terminateCleanReconnect(
                                CleanReconnectTermination.CONFIGURATION_DISCONNECT);
                        return false;
                    }
                    driveDispositionPacket(packet);
                } catch (SocketTimeoutException exception) {
                    terminateCleanReconnect(CleanReconnectTermination.READ_TIMEOUT);
                    return false;
                } catch (EOFException | java.net.SocketException exception) {
                    terminateCleanReconnect(CleanReconnectTermination.REMOTE_EOF_OR_RESET);
                    return false;
                } catch (IOException | DataFormatException exception) {
                    terminateCleanReconnect(CleanReconnectTermination.PROTOCOL_ERROR);
                    return false;
                }
            }
            boolean complete = state == State.PLAY && harness.backendVerifiedAdmissionCount(
                    "paper-lobby", harness.paperRoot) > previousLobbyAdmissionCount;
            if (complete) advanceCleanReconnectStage(CleanReconnectStage.LOBBY_VERIFIED);
            else terminateCleanReconnect(CleanReconnectTermination.READ_TIMEOUT);
            return complete;
        }

        /** Keeps the ordinary raw peer live through backend admission and its shadow-context reply. */
        private StandardBackendObservation driveStandardBackendAdmissionProtocol(int seconds)
                throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            boolean liveAdmission = false;
            boolean liveShadowContext = false;
            while (System.nanoTime() < deadline) {
                // Sample the marker first, but do not trust it until the following read proves the
                // socket remained live. Locking the sample also avoids requiring a 250 ms quiet
                // gap while modern servers stream registry or chunk packets continuously.
                boolean admissionSeen = harness.backendAccepted(
                        harness.backendProcessName(), harness.paperRoot);
                boolean shadowContextSeen = harness.proxyRuntimeMarkerObserved(
                        "backend context shadow audit");
                // Probe one byte with a short timeout, then push it back before decoding the whole
                // packet. Unlike InputStream.available(), this distinguishes quiet from EOF while
                // avoiding a timeout halfway through a packet prefix. Admission is consulted only
                // after this liveness probe, so a queued FIN cannot be hidden by a later log line.
                socket.setSoTimeout(250);
                int firstByte;
                try {
                    firstByte = pushbackInput.read();
                } catch (SocketTimeoutException quiet) {
                    liveAdmission |= admissionSeen;
                    liveShadowContext |= shadowContextSeen;
                    if (liveAdmission && liveShadowContext) {
                        return new StandardBackendObservation(true, true);
                    }
                    continue;
                }
                if (firstByte < 0) {
                    limitations.add("peer disconnected before standard backend evidence completed");
                    return new StandardBackendObservation(liveAdmission, liveShadowContext);
                }
                pushbackInput.unread(firstByte);
                socket.setSoTimeout(10_000);
                Packet packet = read();
                if (packetTrace.size() < 256) {
                    packetTrace.add(state + ":0x" + Integer.toHexString(packet.id()));
                } else if (packetTrace.size() == 256) {
                    packetTrace.add("packet trace capped at 256 entries");
                }
                driveDispositionPacket(packet);
                liveAdmission |= admissionSeen;
                liveShadowContext |= shadowContextSeen;
                if (liveAdmission && liveShadowContext) {
                    return new StandardBackendObservation(true, true);
                }
            }
            return new StandardBackendObservation(liveAdmission, liveShadowContext);
        }

        /**
         * Any complete packet, or a bounded quiet timeout, proves that the remote side did not
         * close the current connection. EOF/reset proves closure. A partial-prefix timeout is
         * harmless because this test socket closes immediately after the probe.
         */
        private RemoteLiveness boundedRemoteConnectionProbe(Socket connected) {
            try {
                connected.setSoTimeout(500);
                read();
                return RemoteLiveness.PACKET;
            } catch (SocketTimeoutException exception) {
                return RemoteLiveness.QUIET_TIMEOUT;
            } catch (EOFException | java.net.SocketException exception) {
                return RemoteLiveness.EOF_OR_RESET;
            } catch (DataFormatException exception) {
                return RemoteLiveness.DATA_FORMAT;
            } catch (IOException exception) {
                return RemoteLiveness.IO_FAILURE;
            }
        }

        /** Completes the exact-profile PLAY -> CONFIGURATION -> PLAY cycle during a backend switch. */
        private DispositionObservation driveDispositionProtocol(
                DispositionScenario scenario, int seconds) throws Exception {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
            long monitorResultAt = Long.MIN_VALUE;
            socket.setSoTimeout(10_000);
            while (System.nanoTime() < deadline) {
                DispositionObservation observation = harness.currentDispositionObservation(scenario);
                if (observation.resultObserved() && monitorResultAt == Long.MIN_VALUE) {
                    monitorResultAt = System.nanoTime();
                }
                boolean expectedTrustedTarget = scenario == DispositionScenario.ENFORCE_QUARANTINE
                        ? observation.quarantineAdmission() && !observation.limitedAdmission()
                        : observation.limitedAdmission() && !observation.quarantineAdmission();
                if (harness.trustedDispositionCase && observation.resultObserved()
                        && observation.lobbyAdmission() && expectedTrustedTarget
                        && harness.requiredRouteEvidenceObserved(scenario, observation)) {
                    return observation;
                }
                if (!harness.trustedDispositionCase
                        && observation.resultObserved() && observation.lobbyAdmission()
                        && !observation.limitedAdmission() && !observation.quarantineAdmission()
                        && !observation.anyRouteLifecycleObserved()
                        && observation.routeCompletion() == RouteCompletion.NONE
                        && System.nanoTime() - monitorResultAt >= TimeUnit.SECONDS.toNanos(3)) {
                    return observation;
                }
                if (input.available() == 0) {
                    Thread.sleep(50L);
                    continue;
                }
                driveDispositionPacket(read());
            }
            return harness.currentDispositionObservation(scenario);
        }

        private void driveDispositionPacket(Packet packet) throws Exception {
            MinecraftWireProfile.ConfigurationPackets configurationPackets =
                    harness.wireProfile.configuration();
            MinecraftWireProfile.PlayPackets playPackets = harness.wireProfile.play();
            if (state == State.PLAY) {
                if (packet.id() == playPackets.clientboundStartConfiguration()) {
                    send(playPackets.serverboundConfigurationAcknowledged(), new byte[0]);
                    state = State.CONFIGURATION;
                } else if (packet.id() == playPackets.clientboundCustomPayload()) {
                    try { handlePayload(parsePayload(packet.payload())); }
                    catch (IOException ignored) { }
                } else if (packet.id() == playPackets.clientboundKeepAlive()) {
                    send(playPackets.serverboundKeepAlive(), packet.payload());
                }
                return;
            }
            if (state != State.CONFIGURATION) return;
            if (packet.id() == configurationPackets.clientboundCustomPayload()) {
                handlePayload(parsePayload(packet.payload()));
            } else if (packet.id() == configurationPackets.clientboundFinish()) {
                send(configurationPackets.serverboundFinish(), new byte[0]);
                configurationFinished = true;
                state = State.PLAY;
                advanceCleanReconnectStage(CleanReconnectStage.PLAY);
            } else if (packet.id() == configurationPackets.clientboundKeepAlive()) {
                send(configurationPackets.serverboundKeepAlive(), packet.payload());
            } else if (packet.id() == configurationPackets.clientboundPing()) {
                send(configurationPackets.serverboundPong(), packet.payload());
            } else if (packet.id() == configurationPackets.clientboundSelectKnownPacks()) {
                send(configurationPackets.serverboundSelectKnownPacks(), varInt(0));
            } else if (packet.id() == configurationPackets.clientboundCookieRequest()) {
                CookieRequest cookie = parseCookieRequest(packet.payload());
                send(configurationPackets.serverboundCookieResponse(),
                        concat(string(cookie.key()), new byte[] {0}));
            } else if (packet.id() == configurationPackets.clientboundDisconnect()) {
                throw new EOFException("remote disconnected during disposition backend switch");
            }
        }

        private FederationPeerResult federationSourceProbe(
                FederationTokenVault vault,
                KeyPair sourceSessionKey,
                String targetNetworkId) throws Exception {
            return federationProbe(FederationPeerRole.SOURCE, vault,
                    Objects.requireNonNull(sourceSessionKey, "sourceSessionKey"), null, null,
                    null, targetNetworkId);
        }

        private FederationPeerResult federationTargetProbe(
                FederationTokenVault vault,
                String targetNetworkId) throws Exception {
            return federationProbe(FederationPeerRole.TARGET, vault, null, null, null, null, targetNetworkId);
        }

        private FederationPeerResult federationRestartTargetProbe(
                TestOnlyRetainedGrant retainedGrant,
                byte[] oldOuterPresentation,
                byte[] oldPresentation,
                String targetNetworkId) throws Exception {
            return federationProbe(FederationPeerRole.RESTART_TARGET, null, null,
                    Objects.requireNonNull(retainedGrant, "retainedGrant"),
                    Objects.requireNonNull(oldOuterPresentation, "oldOuterPresentation").clone(),
                    Objects.requireNonNull(oldPresentation, "oldPresentation").clone(), targetNetworkId);
        }

        /**
         * Test-only raw federation peer. SOURCE automatically exercises the response that a real
         * Fabric UI may produce only after visible Allow-once consent; this is not a UI test.
         */
        private FederationPeerResult federationProbe(
                FederationPeerRole role,
                FederationTokenVault vault,
                KeyPair sourceSessionKey,
                TestOnlyRetainedGrant retainedGrant,
                byte[] oldOuterPresentation,
                byte[] oldPresentation,
                String targetNetworkId) throws Exception {
            if (role != FederationPeerRole.RESTART_TARGET) Objects.requireNonNull(vault, "vault");
            playerId = UUID.nameUUIDFromBytes(("OfflinePlayer:" + PLAYER_NAME).getBytes(StandardCharsets.UTF_8));
            AuthResult authResult = null;
            boolean grantStored = false;
            boolean presentationSent = false;
            boolean replaySent = false;
            boolean oldOuterSent = false;
            boolean oldInnerSent = false;
            boolean oldOuterSessionRejected = false;
            boolean oldSessionProofRejected = false;
            boolean invalidOldProofsNoObservation = false;
            boolean restartResidualObserved = false;
            boolean targetSessionChanged = false;
            boolean targetChallengeChanged = false;
            long restartAuditOffset = -1L;
            int firstOuterLength = 0;
            int innerLength = 0;
            boolean nonceDistinctAttempted = false;
            long playEnteredAtNanos = Long.MIN_VALUE;
            boolean playJoinSeen = false;
            boolean playChannelRegistrationSent = false;
            MinecraftWireProfile.ConfigurationPackets configurationPackets =
                    harness.wireProfile.configuration();
            MinecraftWireProfile.PlayPackets playPackets = harness.wireProfile.play();
            Payload pendingFederationPlayServerHello = null;
            TestOnlyRetainedGrant capturedGrant = null;
            try (Socket connected = new Socket(InetAddress.getLoopbackAddress(), harness.proxyPort)) {
                socket = connected;
                // The federation driver must keep advancing while PLAY is quiet, but a short
                // SO_TIMEOUT can expire after a frame prefix has already been consumed and
                // permanently desynchronise this deliberately small raw decoder. Use a long
                // mid-frame bound and poll available() before starting a frame instead.
                socket.setSoTimeout(45_000);
                input = new DataInputStream(socket.getInputStream());
                output = new DataOutputStream(socket.getOutputStream());
                send(0, handshake(playerId, harness.wireProfile.protocolVersion()));
                send(0, loginStart(playerId));
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(45);
                while (System.nanoTime() < deadline && socket.isConnected()) {
                    Packet packet = null;
                    try {
                        if (input.available() > 0) {
                            packet = read();
                        } else {
                            Thread.sleep(50L);
                        }
                    } catch (EOFException exception) {
                        limitations.add("federation peer disconnected: " + safeMessage(exception));
                        break;
                    }
                    if (packet != null && state == State.LOGIN) {
                        if (packet.id() == 0x03) {
                            compressionThreshold = readVarInt(new ByteArrayInputStream(packet.payload()));
                        } else if (packet.id() == 0x02) {
                            loginSuccess = true;
                            send(0x03, new byte[0]);
                            state = State.CONFIGURATION;
                            send(configurationPackets.serverboundClientInformation(),
                                    clientInformation(harness.wireProfile));
                            Thread.sleep(1_000L);
                            sendCustomPayload("minecraft:register",
                                    "mcace:handshake\0mcace:payload\0mcace:context".getBytes(StandardCharsets.UTF_8));
                        } else if (packet.id() == 0x04) {
                            LoginPlugin request = parseLoginPlugin(packet.payload());
                            send(0x02, concat(varInt(request.messageId()), new byte[] {0}));
                        } else if (packet.id() == 0x01) {
                            throw new IOException("proxy requested encryption from offline federation peer");
                        }
                        continue;
                    }
                    if (packet != null && state == State.CONFIGURATION) {
                        if (packet.id() == configurationPackets.clientboundCustomPayload()) {
                            Payload payload = parsePayload(packet.payload());
                            if ("mcace:handshake".equals(payload.channel())) {
                                FederationExchangeProgress progress = handleFederationPayload(
                                        role, payload.data(), vault, sourceSessionKey, retainedGrant, targetNetworkId,
                                        authResult, grantStored, presentationSent, replaySent);
                                authResult = progress.authResult();
                                grantStored = progress.grantStored();
                                presentationSent = progress.presentationSent();
                                replaySent = progress.replaySent();
                                if (progress.testOnlyRetainedGrant() != null) {
                                    capturedGrant = progress.testOnlyRetainedGrant();
                                }
                            }
                        } else if (packet.id() == configurationPackets.clientboundFinish()) {
                            send(configurationPackets.serverboundFinish(), new byte[0]);
                            state = State.PLAY;
                            socket.setSoTimeout(45_000);
                        } else if (packet.id() == configurationPackets.clientboundKeepAlive()) {
                            send(configurationPackets.serverboundKeepAlive(), packet.payload());
                        } else if (packet.id() == configurationPackets.clientboundPing()) {
                            send(configurationPackets.serverboundPong(), packet.payload());
                        } else if (packet.id() == configurationPackets.clientboundSelectKnownPacks()) {
                            send(configurationPackets.serverboundSelectKnownPacks(), varInt(0));
                        } else if (packet.id() == configurationPackets.clientboundCookieRequest()) {
                            CookieRequest cookie = parseCookieRequest(packet.payload());
                            send(configurationPackets.serverboundCookieResponse(),
                                    concat(string(cookie.key()), new byte[] {0}));
                        } else if (packet.id() == configurationPackets.clientboundDisconnect()) {
                            throw new IOException("federation peer disconnected during configuration");
                        }
                    } else if (packet != null) {
                        if (packet.id() == playPackets.clientboundLogin()
                                && !playChannelRegistrationSent) {
                            playJoinSeen = true;
                            sendCustomPayload("minecraft:register",
                                    "mcace:handshake\0mcace:payload\0mcace:context"
                                            .getBytes(StandardCharsets.UTF_8));
                            playChannelRegistrationSent = true;
                            playEnteredAtNanos = System.nanoTime();
                            packetTrace.add("PLAY:channel-registration-after-game-join");
                            if (pendingFederationPlayServerHello != null) {
                                Payload pending = pendingFederationPlayServerHello;
                                pendingFederationPlayServerHello = null;
                                packetTrace.add("PLAY:federation-server-hello-resumed-after-game-join");
                                FederationExchangeProgress progress = handleFederationPayload(
                                        role, pending.data(), vault, sourceSessionKey, retainedGrant,
                                        targetNetworkId, authResult, grantStored, presentationSent, replaySent);
                                authResult = progress.authResult();
                                grantStored = progress.grantStored();
                                presentationSent = progress.presentationSent();
                                replaySent = progress.replaySent();
                                if (progress.testOnlyRetainedGrant() != null) {
                                    capturedGrant = progress.testOnlyRetainedGrant();
                                }
                            }
                        } else if (packet.id() == playPackets.clientboundCustomPayload()) {
                            Payload payload = null;
                            try {
                                payload = parsePayload(packet.payload());
                            } catch (IOException ignored) {
                                // The exact custom-payload ID was present but the payload was malformed.
                            }
                            if (payload != null && "mcace:handshake".equals(payload.channel())) {
                                PacketType packetType = SignedEnvelope.parseFrom(payload.data())
                                        .getHeader().getPacketType();
                                if (shouldDeferFederationServerHello(state, playJoinSeen, packetType)) {
                                    if (pendingFederationPlayServerHello != null) {
                                        throw new IOException("duplicate deferred federation SERVER_HELLO");
                                    }
                                    pendingFederationPlayServerHello = payload;
                                    packetTrace.add("PLAY:federation-server-hello-deferred-until-game-join");
                                } else {
                                    FederationExchangeProgress progress = handleFederationPayload(
                                            role, payload.data(), vault, sourceSessionKey, retainedGrant,
                                            targetNetworkId, authResult, grantStored, presentationSent, replaySent);
                                    authResult = progress.authResult();
                                    grantStored = progress.grantStored();
                                    presentationSent = progress.presentationSent();
                                    replaySent = progress.replaySent();
                                    if (progress.testOnlyRetainedGrant() != null) {
                                        capturedGrant = progress.testOnlyRetainedGrant();
                                    }
                                }
                            }
                        } else if (packet.id() == playPackets.clientboundKeepAlive()) {
                            send(playPackets.serverboundKeepAlive(), packet.payload());
                        }
                    }
                    if (shouldRequestFederationIssue(role,
                            authResult != null && authResult.getAccepted(), state, playJoinSeen,
                            federationIssueSent)) {
                        // Real proxies may drop plugin messages emitted while configuration is
                        // finishing. Issue only once the player is unambiguously in PLAY.
                        Thread.sleep(500L);
                        harness.sendProxyCommand(
                                "mcacefederation issue " + PLAYER_NAME + " " + targetNetworkId);
                        federationIssueSent = true;
                    }
                    if (role == FederationPeerRole.TARGET && authResult != null
                            && authResult.getAccepted() && state == State.PLAY && !presentationSent
                            && playEnteredAtNanos != Long.MIN_VALUE
                            && System.nanoTime() - playEnteredAtNanos
                                    >= TimeUnit.MILLISECONDS.toNanos(500L)) {
                        FederationTokenVault.PreparedPresentation prepared = vault.preparePresentation(
                                engine.authenticatedServerId(), playerId, engine.authenticatedSessionId(),
                                engine.federationChallengeNonce(), Clock.systemUTC()).orElseThrow(() ->
                                        new IOException("federation presentation was unavailable"));
                        federationReplayPresentation = prepared.encoded();
                        federationFirstOuter = engine.createFederationPresentationFrame(
                                federationReplayPresentation);
                        SignedEnvelope firstEnvelope = SignedEnvelope.parseFrom(federationFirstOuter);
                        firstOuterLength = federationFirstOuter.length;
                        innerLength = firstEnvelope.getPayload().size();
                        packetTrace.add("FEDERATION_PRESENTATION:first:outer="
                                + federationFirstOuter.length + ":inner="
                                + firstEnvelope.getPayload().size() + ":nonce="
                                + firstEnvelope.getHeader().getNonce().size());
                        sendCustomPayload("mcace:handshake", federationFirstOuter);
                        if (vault.commit(prepared, Clock.systemUTC()).isEmpty()) {
                            throw new IOException("federation vault commit failed");
                        }
                        presentationSent = true;
                    }
                    if (role == FederationPeerRole.RESTART_TARGET && authResult != null
                            && authResult.getAccepted() && state == State.PLAY && !presentationSent
                            && playEnteredAtNanos != Long.MIN_VALUE
                            && System.nanoTime() - playEnteredAtNanos
                                    >= TimeUnit.MILLISECONDS.toNanos(500L)) {
                        if (oldOuterPresentation == null || oldOuterPresentation.length == 0
                                || oldPresentation == null || oldPresentation.length == 0) {
                            throw new IOException("restart residual gate has no old target presentation");
                        }
                        FederationPresentation prior = FederationPresentation.parseFrom(oldPresentation);
                        targetSessionChanged = !prior.getPresentationProof().getTargetAuthenticatedSessionId()
                                .equals(engine.authenticatedSessionId());
                        targetChallengeChanged = !java.util.Arrays.equals(
                                prior.getPresentationProof().getTargetChallengeNonce().toByteArray(),
                                engine.federationChallengeNonce());
                        if (!targetSessionChanged || !targetChallengeChanged) {
                            throw new IOException("target restart did not produce a fresh local session/challenge");
                        }
                        if (restartAuditOffset < 0L) restartAuditOffset = harness.federationAuditSize();
                        if (!oldOuterSent) {
                            // Original outer frame: it remains tied to target-1's local session.
                            // Rejection here proves the target-side envelope/session boundary.
                            sendCustomPayload("mcace:handshake", oldOuterPresentation);
                            oldOuterSent = true;
                            packetTrace.add("FEDERATION_PRESENTATION:old-outer:sent");
                        } else if (!oldOuterSessionRejected) {
                            if (harness.proxyProcessOutput().contains(
                                    "federation presentation status=INVALID_FRAME")) {
                                oldOuterSessionRejected = true;
                            }
                        } else if (!oldInnerSent) {
                            // A fresh outer envelope makes the test prove the *inner* old PoP is
                            // invalid for the new target session, rather than merely rejecting an
                            // already-seen outer nonce.
                            sendCustomPayload("mcace:handshake",
                                    engine.createFederationPresentationFrame(oldPresentation));
                            oldInnerSent = true;
                            packetTrace.add("FEDERATION_PRESENTATION:old-session-proof:sent");
                        } else if (!oldSessionProofRejected) {
                            if (harness.proxyProcessOutput().contains(
                                    "federation presentation status=INVALID_PRESENTATION")) {
                                oldSessionProofRejected = true;
                            }
                        } else if (!invalidOldProofsNoObservation) {
                            String audit = harness.waitForFederationAuditSince(restartAuditOffset, 15,
                                    "PRESENTATION_REJECTED\tINVALID_PRESENTATION");
                            if (audit.contains("PRESENTATION_ACCEPTED")) {
                                throw new IOException("invalid old target proof installed an observation");
                            }
                            invalidOldProofsNoObservation = true;
                        } else {
                            FederationPresentation fresh = FederationDocuments.presentation(
                                    retainedGrant.grant(), retainedGrant.sourceSessionKeyPair().getPrivate(),
                                    engine.authenticatedSessionId(), engine.federationChallengeNonce(),
                                    Clock.systemUTC());
                            federationReplayPresentation = FederationDocuments.encode(fresh);
                            federationFirstOuter = engine.createFederationPresentationFrame(
                                    federationReplayPresentation);
                            SignedEnvelope freshEnvelope = SignedEnvelope.parseFrom(federationFirstOuter);
                            firstOuterLength = federationFirstOuter.length;
                            innerLength = freshEnvelope.getPayload().size();
                            sendCustomPayload("mcace:handshake", federationFirstOuter);
                            presentationSent = true;
                            packetTrace.add("FEDERATION_PRESENTATION:fresh-after-target-restart:sent");
                        }
                    }
                    if (role == FederationPeerRole.TARGET && presentationSent && !replaySent
                            && harness.proxyLogs().contains("federation presentation status=OBSERVED")) {
                        // The main thread keeps consuming Minecraft traffic while the real proxy
                        // processes the first presentation. Only then is the replay emitted.
                        byte[] replayOuter = engine.createFederationPresentationFrame(
                                federationReplayPresentation);
                        SignedEnvelope firstEnvelope = SignedEnvelope.parseFrom(federationFirstOuter);
                        SignedEnvelope replayEnvelope = SignedEnvelope.parseFrom(replayOuter);
                        if (!firstEnvelope.getPayload().equals(replayEnvelope.getPayload())
                                || firstEnvelope.getHeader().getNonce().equals(
                                        replayEnvelope.getHeader().getNonce())) {
                            throw new IOException("replay harness did not preserve inner assertion with fresh outer nonce");
                        }
                        nonceDistinctAttempted = true;
                        packetTrace.add("FEDERATION_PRESENTATION:replay:outer="
                                + replayOuter.length + ":inner="
                                + replayEnvelope.getPayload().size() + ":nonce="
                                + replayEnvelope.getHeader().getNonce().size());
                        sendCustomPayload("mcace:handshake", replayOuter);
                        replaySent = true;
                    }
                    if (role == FederationPeerRole.SOURCE && grantStored) break;
                    if (role == FederationPeerRole.TARGET && replaySent
                            && harness.proxyLogs().contains("federation presentation status=REPLAYED")) {
                        Thread.sleep(500L);
                        break;
                    }
                    if (role == FederationPeerRole.RESTART_TARGET && presentationSent
                            && !restartResidualObserved && harness.proxyProcessOutput().contains(
                                    "federation presentation status=OBSERVED")) {
                        String audit = harness.waitForFederationAuditSince(restartAuditOffset, 15,
                                "PRESENTATION_ACCEPTED\tSUCCEEDED");
                        if (!audit.contains("PRESENTATION_REJECTED\tINVALID_PRESENTATION")) {
                            throw new IOException("target restart acceptance lacked old proof rejection audit");
                        }
                        restartResidualObserved = true;
                        byte[] replayOuter = engine.createFederationPresentationFrame(
                                federationReplayPresentation);
                        SignedEnvelope freshEnvelope = SignedEnvelope.parseFrom(federationFirstOuter);
                        SignedEnvelope replayEnvelope = SignedEnvelope.parseFrom(replayOuter);
                        if (!freshEnvelope.getPayload().equals(replayEnvelope.getPayload())
                                || freshEnvelope.getHeader().getNonce().equals(
                                        replayEnvelope.getHeader().getNonce())) {
                            throw new IOException("post-restart replay did not preserve fresh inner proof with new outer nonce");
                        }
                        sendCustomPayload("mcace:handshake", replayOuter);
                        replaySent = true;
                        packetTrace.add("FEDERATION_PRESENTATION:fresh-after-target-restart:replay-sent");
                    }
                    if (role == FederationPeerRole.RESTART_TARGET && replaySent
                            && harness.proxyProcessOutput().contains("federation presentation status=REPLAYED")) {
                        Thread.sleep(500L);
                        break;
                    }
                }
            }
            if (role == FederationPeerRole.TARGET) {
                if (authResult == null || !authResult.getAccepted()) {
                    throw new IOException("federation target authentication did not complete; peerState="
                            + state + "; trace=" + federationPacketTrace());
                }
                if (!presentationSent || federationReplayPresentation == null
                        || federationReplayPresentation.length == 0 || federationFirstOuter == null
                        || federationFirstOuter.length == 0) {
                    throw new IOException("federation target presentation was not created; peerState="
                            + state + "; trace=" + federationPacketTrace());
                }
            }
            return new FederationPeerResult(authResult, grantStored, presentationSent, replaySent,
                    firstOuterLength, innerLength, nonceDistinctAttempted, true,
                    oldOuterSessionRejected, oldSessionProofRejected, invalidOldProofsNoObservation,
                    targetSessionChanged, targetChallengeChanged, restartResidualObserved,
                    role == FederationPeerRole.TARGET ? federationReplayPresentation.clone() : new byte[0],
                    role == FederationPeerRole.TARGET ? federationFirstOuter.clone() : new byte[0],
                    capturedGrant);
        }

        private String federationPacketTrace() {
            return packetTrace.isEmpty() ? "none" : String.join(",", packetTrace);
        }

        private FederationExchangeProgress handleFederationPayload(
                FederationPeerRole role,
                byte[] frame,
                FederationTokenVault vault,
                KeyPair sourceSessionKey,
                TestOnlyRetainedGrant retainedGrant,
                String targetNetworkId,
                AuthResult priorAuthResult,
                boolean priorGrantStored,
                boolean priorPresentationSent,
                boolean priorReplaySent) throws Exception {
            SignedEnvelope envelope = SignedEnvelope.parseFrom(frame);
            PacketType type = envelope.getHeader().getPacketType();
            packetTrace.add("IN:" + type.name() + ":state=" + state.name() + ":bytes=" + frame.length);
            AuthResult result = priorAuthResult;
            boolean grantStored = priorGrantStored;
            boolean presentationSent = priorPresentationSent;
            boolean replaySent = priorReplaySent;
            TestOnlyRetainedGrant capturedGrant = null;
            if (type == PacketType.SERVER_HELLO) {
                if (engine != null) throw new IOException("duplicate federation SERVER_HELLO");
                if (role == FederationPeerRole.SOURCE) {
                    engine = new ClientHandshakeEngine(playerId, "mcace-test-peer",
                            harness.wireProfile.minecraftVersion(),
                            BUILD_ID, LoaderType.FABRIC, harness.proxyPublicKey,
                            Clock.systemUTC(), new SecureRandom(), sourceSessionKey);
                    authenticateEngine(engine, frame, "source");
                } else {
                    ClientHandshakeEngine provisional = new ClientHandshakeEngine(
                            playerId, "mcace-test-peer", harness.wireProfile.minecraftVersion(),
                            BUILD_ID, LoaderType.FABRIC,
                            harness.proxyPublicKey, Clock.systemUTC(), new SecureRandom());
                    provisional.prepareServerHello(frame, "127.0.0.1:" + harness.proxyPort,
                            new VerifiedPolicyCache(harness.runRoot.resolve("target-provisional-cache"),
                                    Clock.systemUTC()));
                    String verifiedTarget = provisional.verifiedServerId();
                    if (!targetNetworkId.equals(verifiedTarget)) {
                        throw new IOException("verified target network id mismatch: " + verifiedTarget);
                    }
                    if (role == FederationPeerRole.TARGET) {
                        engine = vault.newTargetHandshake(
                                verifiedTarget, playerId, "mcace-test-peer",
                                harness.wireProfile.minecraftVersion(), BUILD_ID,
                                LoaderType.FABRIC, harness.proxyPublicKey, Clock.systemUTC(),
                                new SecureRandom()).orElseThrow(() ->
                                        new IOException("federation vault did not release target handshake"));
                    } else {
                        retainedGrant.requireExactTarget(verifiedTarget, harness.proxyPublicKey);
                        engine = new ClientHandshakeEngine(playerId, "mcace-test-peer",
                                harness.wireProfile.minecraftVersion(),
                                BUILD_ID, LoaderType.FABRIC, harness.proxyPublicKey, Clock.systemUTC(),
                                new SecureRandom(), retainedGrant.sourceSessionKeyPair(),
                                retainedGrant.signedAssertionSha256());
                    }
                    authenticateEngine(engine, frame, "target");
                }
            } else if (type == PacketType.AUTH_RESULT) {
                if (engine == null || result != null) throw new IOException("unexpected federation AUTH_RESULT");
                result = engine.receiveAuthResult(frame);
                if (!result.getAccepted()) throw new IOException("federation local authentication rejected");
            } else if (type == PacketType.FEDERATION_CONSENT_REQUEST
                    && role == FederationPeerRole.SOURCE) {
                var request = engine.receiveFederationConsentRequest(frame);
                // Raw process harness auto-allows only this explicitly opt-in test. Real Fabric
                // requires the visible Allow-once UI; this test does not claim GUI coverage.
                sendCustomPayload("mcace:handshake", engine.createFederationConsentFrame(request));
            } else if (type == PacketType.FEDERATION_GRANT && role == FederationPeerRole.SOURCE) {
                engine.receiveFederationGrant(frame, vault);
                grantStored = true;
                SignedEnvelope grantEnvelope = SignedEnvelope.parseFrom(frame);
                capturedGrant = TestOnlyRetainedGrant.capture(
                        FederationGrant.parseFrom(grantEnvelope.getPayload()), sourceSessionKey);
            }
            return new FederationExchangeProgress(
                    result, grantStored, presentationSent, replaySent, capturedGrant);
        }

        private void authenticateEngine(ClientHandshakeEngine candidate, byte[] helloFrame, String cacheName)
                throws Exception {
            VerifiedPolicy verifiedPolicy = candidate.prepareServerHello(
                    helloFrame, "127.0.0.1:" + harness.proxyPort,
                    new VerifiedPolicyCache(harness.runRoot.resolve(cacheName + "-client-cache"),
                            Clock.systemUTC()));
            List<ClientHandshakeEngine.OutboundFrame> frames = candidate.createAuthenticationFrames(
                    emptyBundle(verifiedPolicy), List.of(), List.of(), List.of(),
                    probeLoadedModGraph());
            for (ClientHandshakeEngine.OutboundFrame outbound : frames) {
                SignedEnvelope outboundEnvelope = SignedEnvelope.parseFrom(outbound.data());
                packetTrace.add("OUT:" + outboundEnvelope.getHeader().getPacketType().name()
                        + ":channel=" + outbound.channel().name() + ":bytes=" + outbound.data().length);
                sendCustomPayload(outbound.channel() == ClientHandshakeEngine.OutboundChannel.PAYLOAD
                        ? "mcace:payload" : "mcace:handshake", outbound.data());
                if (frames.size() > 1 && outbound != frames.getLast()) Thread.sleep(50L);
            }
        }

        private void handlePayload(Payload payload) throws Exception {
            channels.add(payload.channel());
            handlePayloadAfterChannelRecord(payload);
        }

        private void handlePayloadAfterChannelRecord(Payload payload) throws Exception {
            if (!"mcace:handshake".equals(payload.channel())) return;
            if (!serverHelloSeen) {
                serverHelloSeen = true;
                serverHelloStage = serverHelloStageFor(state);
                advanceCleanReconnectStage(CleanReconnectStage.SERVER_HELLO);
                engine = new ClientHandshakeEngine(playerId, "mcace-test-peer",
                        harness.wireProfile.minecraftVersion(),
                        BUILD_ID, LoaderType.FABRIC, harness.proxyPublicKey,
                        Clock.systemUTC(), new SecureRandom());
                VerifiedPolicy verifiedPolicy = engine.prepareServerHello(payload.data(),
                        "127.0.0.1:" + harness.proxyPort,
                        new VerifiedPolicyCache(harness.runRoot.resolve("client-cache"), Clock.systemUTC()));
                List<ClientHandshakeEngine.OutboundFrame> authenticationFrames = engine.createAuthenticationFrames(
                        authenticationBundle(verifiedPolicy), List.of(), List.of(), List.of(),
                        probeLoadedModGraph());
                boolean allAuthenticationFramesDuringConfiguration = !authenticationFrames.isEmpty();
                for (ClientHandshakeEngine.OutboundFrame frame : authenticationFrames) {
                    allAuthenticationFramesDuringConfiguration &= state == State.CONFIGURATION;
                    packetTrace.add("SEND:" + describeEnvelope(frame.data()));
                    sendCustomPayload(frame.channel() == ClientHandshakeEngine.OutboundChannel.PAYLOAD
                            ? "mcace:payload" : "mcace:handshake", frame.data());
                    if (authenticationFrames.size() > 1 && frame != authenticationFrames.getLast()) {
                        Thread.sleep(50);
                    }
                }
                authenticationSent = true;
                authOutboundStage = authenticationFrames.isEmpty() ? AuthOutboundStage.EMPTY
                        : allAuthenticationFramesDuringConfiguration
                        ? AuthOutboundStage.CONFIGURATION : authOutboundStageFor(state);
                advanceCleanReconnectStage(CleanReconnectStage.AUTH_SENT);
            } else if (authenticationSent && engine != null && !authResultSeen) {
                authResultSeen = true;
                authAccepted = engine.receiveAuthResult(payload.data()).getAccepted();
                authResultStage = authResultStageFor(state, authAccepted);
                if (authAccepted) {
                    advanceCleanReconnectStage(CleanReconnectStage.AUTH_ACCEPTED);
                }
            }
        }

        private AuthenticationEvidence authenticationEvidence() {
            return new AuthenticationEvidence(serverHelloStage, authOutboundStage, authResultStage,
                    authAccepted);
        }

        private static ServerHelloStage serverHelloStageFor(State state) {
            return switch (state) {
                case LOGIN -> ServerHelloStage.LOGIN;
                case CONFIGURATION -> ServerHelloStage.CONFIGURATION;
                case PLAY -> ServerHelloStage.PLAY;
            };
        }

        private static AuthOutboundStage authOutboundStageFor(State state) {
            return switch (state) {
                case LOGIN -> AuthOutboundStage.LOGIN;
                case CONFIGURATION -> AuthOutboundStage.CONFIGURATION;
                case PLAY -> AuthOutboundStage.PLAY;
            };
        }

        private static AuthResultStage authResultStageFor(State state, boolean accepted) {
            return switch (state) {
                case LOGIN -> accepted ? AuthResultStage.ACCEPTED_LOGIN : AuthResultStage.REJECTED_LOGIN;
                case CONFIGURATION -> accepted ? AuthResultStage.ACCEPTED_CONFIGURATION
                        : AuthResultStage.REJECTED_CONFIGURATION;
                case PLAY -> accepted ? AuthResultStage.ACCEPTED_PLAY : AuthResultStage.REJECTED_PLAY;
            };
        }
        private void sendCustomPayload(String channel, byte[] data) throws IOException {
            byte[] payload = concat(string(channel), data);
            int packetId = state == State.CONFIGURATION
                    ? harness.wireProfile.configuration().serverboundCustomPayload()
                    : harness.wireProfile.play().serverboundCustomPayload();
            send(packetId, payload);
        }

        private static String describeEnvelope(byte[] encoded) {
            try {
                SignedEnvelope envelope = SignedEnvelope.parseFrom(encoded);
                return envelope.getHeader().getPacketType() + "/" + envelope.getHeader().getSessionId();
            } catch (Exception exception) {
                return "malformed:" + encoded.length;
            }
        }

        private Packet read() throws IOException, DataFormatException {
            int frameLength = readVarInt(input);
            if (frameLength <= 0 || frameLength > MAX_PACKET_BYTES) throw new IOException("invalid packet length: " + frameLength);
            byte[] frame = input.readNBytes(frameLength);
            if (frame.length != frameLength) throw new EOFException("truncated Minecraft packet");
            DataInputStream frameInput = new DataInputStream(new ByteArrayInputStream(frame));
            byte[] packetData;
            if (compressionThreshold >= 0) {
                int uncompressedLength = readVarInt(frameInput);
                byte[] remaining = frameInput.readAllBytes();
                if (uncompressedLength == 0) packetData = remaining;
                else packetData = inflate(remaining, uncompressedLength);
            } else {
                packetData = frame;
            }
            DataInputStream packetInput = new DataInputStream(new ByteArrayInputStream(packetData));
            int packetId = readVarInt(packetInput);
            return new Packet(packetId, packetInput.readAllBytes());
        }

        private void send(int packetId, byte[] payload) throws IOException {
            byte[] packetData = concat(varInt(packetId), payload);
            byte[] frameData;
            if (compressionThreshold >= 0) {
                if (packetData.length >= compressionThreshold) {
                    byte[] compressed = deflate(packetData);
                    frameData = concat(varInt(packetData.length), compressed);
                } else {
                    frameData = concat(varInt(0), packetData);
                }
            } else frameData = packetData;
            output.write(varInt(frameData.length));
            output.write(frameData);
            output.flush();
        }

        private static byte[] handshake(UUID playerId, int protocol) throws IOException {
            return concat(varInt(protocol), string("127.0.0.1"), shortBytes(25565), varInt(2));
        }

        private static byte[] loginStart(UUID playerId) throws IOException {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(string(PLAYER_NAME));
            output.write(longBytes(playerId.getMostSignificantBits()));
            output.write(longBytes(playerId.getLeastSignificantBits()));
            return output.toByteArray();
        }

        private static byte[] clientInformation(MinecraftWireProfile profile) throws IOException {
            byte[] legacy = concat(
                    string("en_us"), new byte[] {8}, varInt(0), new byte[] {1, 0},
                    varInt(1), new byte[] {0, 1});
            return profile.clientInformationIncludesParticleStatus()
                    ? concat(legacy, varInt(0)) : legacy;
        }

        private static ClientIntegrityBundle emptyBundle(VerifiedPolicy verifiedPolicy) throws Exception {
            List<ScopeIntegrityManifest> manifests = verifiedPolicy.policy().getIntegrityScopesList().stream()
                    .map(rule -> new ScopeIntegrityManifest(
                            rule.getScope(),
                            rule.getRelativeRoot(),
                            rule.getRequired(),
                            Instant.now(),
                            List.of(),
                            IntegrityDigests.scopeRoot(List.of())))
                    .toList();
            return ClientIntegrityBundle.of(manifests);
        }

        /** The raw peer still advertises Fabric Loader's built-in runtime entry. */
        private static List<LoadedModObservation> probeLoadedModGraph() {
            return List.of(new LoadedModObservation(
                    "fabricloader", "0.0.0-mcace-probe",
                    LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", ""));
        }

        private ClientIntegrityBundle authenticationBundle(VerifiedPolicy verifiedPolicy) throws Exception {
            if (!syntheticManifest) return emptyBundle(verifiedPolicy);
            byte[] sha256 = syntheticFixtureSha256();
            IntegrityEntry entry = new IntegrityEntry(
                    "mcace-runtime-synthetic-fixture.jar", SYNTHETIC_FIXTURE_BYTES.length, sha256);
            FileEntry wireEntry = FileEntry.newBuilder()
                    .setRelativePath(entry.relativePath())
                    .setFileSize(entry.fileSize())
                    .setSha256(ByteString.copyFrom(entry.sha256()))
                    .build();
            List<ScopeIntegrityManifest> manifests = verifiedPolicy.policy().getIntegrityScopesList().stream()
                    .map(rule -> {
                        boolean mods = "mods".equals(rule.getScope());
                        return new ScopeIntegrityManifest(
                                rule.getScope(),
                                rule.getRelativeRoot(),
                                mods || rule.getRequired(),
                                Instant.now(),
                                mods ? List.of(entry) : List.of(),
                                IntegrityDigests.scopeRoot(mods ? List.of(wireEntry) : List.of()));
                    })
                    .toList();
            return ClientIntegrityBundle.of(manifests);
        }

        private static Payload parsePayload(byte[] bytes) throws IOException {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes));
            return new Payload(readString(input), input.readAllBytes());
        }

        private static LoginPlugin parseLoginPlugin(byte[] bytes) throws IOException {
            DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes));
            return new LoginPlugin(readVarInt(input), readString(input), input.readAllBytes());
        }

        private static CookieRequest parseCookieRequest(byte[] bytes) throws IOException {
            return new CookieRequest(readString(new DataInputStream(new ByteArrayInputStream(bytes))));
        }
    }

    private enum State { LOGIN, CONFIGURATION, PLAY }
    private enum FederationPeerRole { SOURCE, TARGET, RESTART_TARGET }
    private record Packet(int id, byte[] payload) { }
    private record Payload(String channel, byte[] data) { }
    private record LoginPlugin(int messageId, String channel, byte[] data) { }
    private record CookieRequest(String key) { }
    private record FederationPeerResult(
            AuthResult authResult,
            boolean grantStored,
            boolean presentationSent,
            boolean replaySent,
            int firstOuterLength,
            int innerLength,
            boolean nonceDistinctAttempted,
            boolean socketClosed,
            boolean oldOuterSessionRejected,
            boolean oldSessionProofRejected,
            boolean invalidOldProofsNoObservation,
            boolean targetSessionChanged,
            boolean targetChallengeChanged,
            boolean restartResidualObserved,
            byte[] presentationBytes,
            byte[] presentationOuterBytes,
            TestOnlyRetainedGrant testOnlyRetainedGrant) {
        private FederationPeerResult {
            presentationBytes = presentationBytes == null ? new byte[0] : presentationBytes.clone();
            presentationOuterBytes = presentationOuterBytes == null ? new byte[0] : presentationOuterBytes.clone();
        }

        @Override public byte[] presentationBytes() { return presentationBytes.clone(); }
        @Override public byte[] presentationOuterBytes() { return presentationOuterBytes.clone(); }
    }
    private record FederationExchangeProgress(
            AuthResult authResult,
            boolean grantStored,
            boolean presentationSent,
            boolean replaySent,
            TestOnlyRetainedGrant testOnlyRetainedGrant) { }

    /**
     * Test harness only: the raw process peer must emulate a malicious client retaining an
     * unexpired grant and its ephemeral source session key across a target restart. This holder is
     * private, JVM-memory-only, never serialized/reported/logged, and cleared at test cleanup.
     */
    private static final class TestOnlyRetainedGrant implements AutoCloseable {
        private FederationGrant grant;
        private KeyPair sourceSessionKeyPair;
        private byte[] targetKeyId;
        private String targetNetworkId;

        private TestOnlyRetainedGrant(FederationGrant grant, KeyPair sourceSessionKeyPair) {
            this.grant = Objects.requireNonNull(grant, "grant");
            this.sourceSessionKeyPair = Objects.requireNonNull(sourceSessionKeyPair, "sourceSessionKeyPair");
            this.targetKeyId = grant.getClientConsent().getTargetKeyIdSha256().toByteArray();
            this.targetNetworkId = grant.getClientConsent().getTargetNetworkId();
        }

        private static TestOnlyRetainedGrant capture(FederationGrant grant, KeyPair sourceSessionKeyPair) {
            return new TestOnlyRetainedGrant(grant, sourceSessionKeyPair);
        }

        private FederationGrant grant() {
            if (grant == null) throw new IllegalStateException("test-only retained grant was cleared");
            return grant;
        }

        private KeyPair sourceSessionKeyPair() {
            if (sourceSessionKeyPair == null) {
                throw new IllegalStateException("test-only retained source key was cleared");
            }
            return sourceSessionKeyPair;
        }

        private byte[] signedAssertionSha256() throws NoSuchAlgorithmException {
            if (grant == null) throw new IllegalStateException("test-only retained grant was cleared");
            return MessageDigest.getInstance("SHA-256")
                    .digest(grant.getSignedAssertion().toByteArray());
        }

        private void requireExactTarget(String networkId, PublicKey targetIdentity) throws Exception {
            if (!Objects.equals(targetNetworkId, networkId)
                    || !MessageDigest.isEqual(targetKeyId,
                            MessageDigest.getInstance("SHA-256").digest(targetIdentity.getEncoded()))) {
                throw new IOException("retained test grant is not bound to restarted target identity");
            }
        }

        @Override public void close() {
            if (targetKeyId != null) java.util.Arrays.fill(targetKeyId, (byte) 0);
            targetKeyId = new byte[0];
            targetNetworkId = null;
            // Provider-owned key objects cannot be safely wiped; drop all references. This test
            // holder has no persistence or report path.
            grant = null;
            sourceSessionKeyPair = null;
        }
    }

    private record FederationMatrixReport(
            ProxyKind sourceProxy,
            ProxyKind targetProxy,
            String sourceNetworkId,
            String targetNetworkId,
            boolean sourceAuthenticated,
            boolean grantStored,
            boolean sourceDisconnected,
            boolean targetAuthenticated,
            boolean presentationSent,
            int firstOuterLength,
            int innerLength,
            boolean nonceDistinctAttempted,
            boolean targetObserved,
            boolean replayRejected,
            boolean contentFreeAudit,
            boolean sourceAuditHealthy,
            boolean targetAuditHealthy,
            boolean localStateUnchanged,
            boolean targetBackendAdmission,
            List<String> limitations,
            List<Integer> cleanupProcessIds,
            List<Long> remainingRunProcesses) {
        private boolean passed() {
            return sourceAuthenticated && grantStored && sourceDisconnected && targetAuthenticated
                    && presentationSent && firstOuterLength > 0 && innerLength > 0
                    && nonceDistinctAttempted
                    && targetObserved && replayRejected && contentFreeAudit
                    && sourceAuditHealthy && targetAuditHealthy && localStateUnchanged
                    && targetBackendAdmission && limitations.isEmpty() && remainingRunProcesses.isEmpty();
        }

        private String toJson() {
            return "{\n"
                    + "  \"schema\": 2,\n"
                    + "  \"source_proxy\": \"" + sourceProxy + "\",\n"
                    + "  \"target_proxy\": \"" + targetProxy + "\",\n"
                    + "  \"source_network_id\": \"" + sourceNetworkId + "\",\n"
                    + "  \"target_network_id\": \"" + targetNetworkId + "\",\n"
                    + "  \"source_authenticated\": " + sourceAuthenticated + ",\n"
                    + "  \"grant_stored_in_memory\": " + grantStored + ",\n"
                    + "  \"source_client_disconnected_before_target_auth\": " + sourceDisconnected + ",\n"
                    + "  \"target_locally_authenticated\": " + targetAuthenticated + ",\n"
                    + "  \"presentation_sent\": " + presentationSent + ",\n"
                    + "  \"first_outer_length\": " + firstOuterLength + ",\n"
                    + "  \"inner_length\": " + innerLength + ",\n"
                    + "  \"nonce_distinct_attempted\": " + nonceDistinctAttempted + ",\n"
                    + "  \"target_observed\": " + targetObserved + ",\n"
                    + "  \"same_assertion_replay_rejected\": " + replayRejected + ",\n"
                    + "  \"content_free_audit\": " + contentFreeAudit + ",\n"
                    + "  \"source_audit_healthy\": " + sourceAuditHealthy + ",\n"
                    + "  \"target_audit_healthy\": " + targetAuditHealthy + ",\n"
                    + "  \"local_trust_risk_admission_unchanged\": " + localStateUnchanged + ",\n"
                    + "  \"target_paper_admission_verified\": " + targetBackendAdmission + ",\n"
                    + "  \"fabric_gui_coverage\": false,\n"
                    + "  \"limitations\": " + ProbeReport.strings(limitations) + ",\n"
                    + "  \"cleanup_process_ids\": " + ProbeReport.numbers(cleanupProcessIds) + ",\n"
                    + "  \"remaining_run_processes\": " + ProbeReport.numbers(remainingRunProcesses) + ",\n"
                    + "  \"passed\": " + passed() + "\n"
                    + "}\n";
        }

        private String toMarkdown() {
            return "# MCAce federation real-process proxy gate\n\n"
                    + "- Pair: `" + sourceProxy + " -> " + targetProxy + "`\n"
                    + "- Client-carried grant after source disconnect: `" + grantStored + "`\n"
                    + "- Target local authentication then OBSERVED: `" + targetAuthenticated
                    + "` / `" + targetObserved + "`\n"
                    + "- Presentation sent / outer / inner / fresh nonce attempted: `"
                    + presentationSent + "` / `" + firstOuterLength + "` / `" + innerLength
                    + "` / `" + nonceDistinctAttempted + "`\n"
                    + "- Same assertion replay rejected: `" + replayRejected + "`\n"
                    + "- Content-free audit: `" + contentFreeAudit + "`\n"
                    + "- Source/target durable-audit health: `" + sourceAuditHealthy
                    + "` / `" + targetAuditHealthy + "`\n"
                    + "- Local trust/risk/admission unchanged: `" + localStateUnchanged + "`\n"
                    + "- Cleanup complete: `" + remainingRunProcesses.isEmpty() + "`\n"
                    + "- Fabric GUI coverage: `false` (raw peer auto-consent is test-only)\n\n"
                    + (limitations.isEmpty() ? "No limitations recorded.\n"
                            : limitations.stream().map(item -> "- " + item + "\n").reduce("", String::concat));
        }
    }

    /** A content-free report that intentionally records the current restart residual as true. */
    private record FederationTargetRestartReport(
            ProxyKind targetProxy,
            boolean sourceAuthenticated,
            boolean grantStored,
            boolean sourceDisconnected,
            boolean firstTargetAuthenticated,
            boolean firstTargetObserved,
            boolean oldTargetProxyTerminated,
            boolean targetPaperKeptRunning,
            boolean targetIdentityPreserved,
            boolean targetConfigurationPreserved,
            boolean restartedTargetAuthenticated,
            boolean targetSessionChanged,
            boolean targetChallengeChanged,
            boolean oldOuterSessionRejected,
            boolean oldSessionProofRejected,
            boolean invalidOldProofsNoObservation,
            boolean residualReacceptance,
            boolean postRestartSameProcessReplayRejected,
            boolean contentFreeAudit,
            boolean sourceAuditHealthy,
            boolean targetAuditHealthy,
            boolean localStateUnchanged,
            boolean targetBackendAdmission,
            boolean temporaryProxyPrivateKeysRemoved,
            List<String> limitations,
            List<Integer> cleanupProcessIds,
            List<Long> remainingRunProcesses) {
        private boolean passed() {
            return sourceAuthenticated && grantStored && sourceDisconnected
                    && firstTargetAuthenticated && firstTargetObserved && oldTargetProxyTerminated
                    && targetPaperKeptRunning && targetIdentityPreserved && targetConfigurationPreserved
                    && restartedTargetAuthenticated && targetSessionChanged && targetChallengeChanged
                    && oldOuterSessionRejected && oldSessionProofRejected && invalidOldProofsNoObservation
                    && residualReacceptance && postRestartSameProcessReplayRejected && contentFreeAudit
                    && sourceAuditHealthy && targetAuditHealthy
                    && localStateUnchanged && targetBackendAdmission && temporaryProxyPrivateKeysRemoved
                    && limitations.isEmpty()
                    && remainingRunProcesses.isEmpty();
        }

        private String toJson() {
            return "{\n"
                    + "  \"schema\": 2,\n"
                    + "  \"source_proxy\": \"VELOCITY\",\n"
                    + "  \"target_proxy\": \"" + targetProxy + "\",\n"
                    + "  \"source_authenticated\": " + sourceAuthenticated + ",\n"
                    + "  \"grant_stored_in_memory_test_harness\": " + grantStored + ",\n"
                    + "  \"source_client_disconnected_before_target_auth\": " + sourceDisconnected + ",\n"
                    + "  \"first_target_locally_authenticated\": " + firstTargetAuthenticated + ",\n"
                    + "  \"first_target_observed\": " + firstTargetObserved + ",\n"
                    + "  \"old_target_proxy_terminated\": " + oldTargetProxyTerminated + ",\n"
                    + "  \"target_paper_kept_running\": " + targetPaperKeptRunning + ",\n"
                    + "  \"target_identity_preserved\": " + targetIdentityPreserved + ",\n"
                    + "  \"target_federation_config_preserved\": " + targetConfigurationPreserved + ",\n"
                    + "  \"restarted_target_locally_authenticated\": " + restartedTargetAuthenticated + ",\n"
                    + "  \"target_session_changed\": " + targetSessionChanged + ",\n"
                    + "  \"target_challenge_changed\": " + targetChallengeChanged + ",\n"
                    + "  \"old_outer_session_rejected\": " + oldOuterSessionRejected + ",\n"
                    + "  \"old_session_proof_rejected\": " + oldSessionProofRejected + ",\n"
                    + "  \"invalid_old_proofs_no_observation\": " + invalidOldProofsNoObservation + ",\n"
                    + "  \"target_restart_residual_reobserved\": " + residualReacceptance + ",\n"
                    + "  \"residual_reacceptance\": " + residualReacceptance + ",\n"
                    + "  \"post_restart_same_process_replay_rejected\": "
                    + postRestartSameProcessReplayRejected + ",\n"
                    + "  \"residual_is_observation_only\": true,\n"
                    + "  \"durable_replay_protection\": false,\n"
                    + "  \"test_only_retained_grant_or_source_session_key_written_to_disk\": false,\n"
                    + "  \"local_trust_risk_admission_unchanged\": " + localStateUnchanged + ",\n"
                    + "  \"target_paper_admission_verified\": " + targetBackendAdmission + ",\n"
                    + "  \"content_free_audit\": " + contentFreeAudit + ",\n"
                    + "  \"source_audit_healthy\": " + sourceAuditHealthy + ",\n"
                    + "  \"target_audit_healthy\": " + targetAuditHealthy + ",\n"
                    + "  \"temporary_proxy_private_keys_removed\": "
                    + temporaryProxyPrivateKeysRemoved + ",\n"
                    + "  \"fabric_gui_coverage\": false,\n"
                    + "  \"limitations\": " + ProbeReport.strings(limitations) + ",\n"
                    + "  \"cleanup_process_ids\": " + ProbeReport.numbers(cleanupProcessIds) + ",\n"
                    + "  \"remaining_run_processes\": " + ProbeReport.numbers(remainingRunProcesses) + ",\n"
                    + "  \"passed\": " + passed() + "\n"
                    + "}\n";
        }

        private String toMarkdown() {
            return "# MCAce federation target-restart residual replay gate\n\n"
                    + "- Source proxy: `VELOCITY`; target proxy: `" + targetProxy + "`\n"
                    + "- Source grant then client disconnect: `" + grantStored + "` / `"
                    + sourceDisconnected + "`\n"
                    + "- First target local VERIFIED then OBSERVED: `" + firstTargetAuthenticated
                    + "` / `" + firstTargetObserved + "`\n"
                    + "- Old target proxy terminated; Paper retained; identity/configuration preserved: `"
                    + oldTargetProxyTerminated + "` / `" + targetPaperKeptRunning + "` / `"
                    + targetIdentityPreserved + "` / `" + targetConfigurationPreserved + "`\n"
                    + "- New target local VERIFIED; session/challenge changed: `"
                    + restartedTargetAuthenticated + "` / `" + targetSessionChanged + "` / `"
                    + targetChallengeChanged + "`\n"
                    + "- Old outer rejected; rewrapped old inner rejected without observation: `"
                    + oldOuterSessionRejected + "` / `" + oldSessionProofRejected + "` / `"
                    + invalidOldProofsNoObservation + "`\n"
                    + "- Residual reacceptance after restart: `" + residualReacceptance
                    + "` (expected current limitation; observation-only)\n"
                    + "- New target same-process replay rejected: `" + postRestartSameProcessReplayRejected + "`\n"
                    + "- Local trust/risk/admission unchanged: `" + localStateUnchanged + "`\n"
                    + "- Content-free audit; Paper local admission: `" + contentFreeAudit + "` / `"
                    + targetBackendAdmission + "`\n"
                    + "- Source/target durable-audit health: `" + sourceAuditHealthy
                    + "` / `" + targetAuditHealthy + "`\n"
                    + "- Temporary proxy fixture private keys removed: `"
                    + temporaryProxyPrivateKeysRemoved + "`\n"
                    + "- Cleanup complete: `" + remainingRunProcesses.isEmpty() + "`\n"
                    + "- Fabric GUI coverage: `false` (test-only raw peer; no UI claim)\n\n"
                    + "The proxy fixture intentionally persists its own identity/configuration until the "
                    + "restart assertion completes, then removes the temporary private keys during cleanup. "
                    + "The test-only retained grant and source session private key always stay only in JVM "
                    + "memory and are never written or reported; neither are proofs, nonces, challenges, "
                    + "or raw signed frames.\n\n"
                    + (limitations.isEmpty() ? "No limitations recorded.\n"
                            : limitations.stream().map(item -> "- " + item + "\n")
                                    .reduce("", String::concat));
        }
    }

    private record ProbeReport(
            ProxyKind proxy,
            BackendKind backend,
            String backendMinecraftVersion,
            String forwardingMode,
            boolean forwardingConfigured,
            int proxyPort,
            int paperPort,
            boolean tcpConnected,
            boolean loginSuccess,
            boolean compressionSeen,
            boolean configurationFinished,
            boolean serverHello,
            boolean authResult,
            boolean authAccepted,
            boolean backendAdmission,
            boolean backendContextShadowAudit,
            List<String> channels,
            List<String> packetTrace,
            List<String> limitations,
            List<Integer> cleanupProcessIds,
            List<Long> remainingRunProcesses) {
        private static ProbeReport failure(
                ProxyKind proxy,
                BackendKind backend,
                String backendMinecraftVersion,
                int proxyPort,
                int paperPort,
                List<String> limitations) {
            return new ProbeReport(proxy, backend, backendMinecraftVersion,
                    proxy == ProxyKind.VELOCITY ? "velocity-modern" : "bungee-ip-forwarding",
                    false, proxyPort, paperPort, false, false, false, false,
                    false, false, false, false, false, List.of(), List.of(), limitations, List.of(), List.of());
        }

        private ProbeReport withCleanup(List<Integer> processIds, List<Long> remaining) {
            return new ProbeReport(proxy, backend, backendMinecraftVersion,
                    forwardingMode, forwardingConfigured, proxyPort, paperPort,
                    tcpConnected, loginSuccess, compressionSeen,
                    configurationFinished, serverHello, authResult, authAccepted, backendAdmission,
                    backendContextShadowAudit,
                    channels, packetTrace, limitations, List.copyOf(processIds), List.copyOf(remaining));
        }

        private String toJson() {
            return "{\n"
                    + "  \"schema\": 4,\n"
                    + "  \"proxy\": \"" + proxy + "\",\n"
                    + "  \"backend_platform\": \"" + backend + "\",\n"
                    + "  \"backend_minecraft_version\": \""
                    + escape(backendMinecraftVersion) + "\",\n"
                    + "  \"forwarding_mode\": \"" + forwardingMode + "\",\n"
                    + "  \"forwarding_configured\": " + forwardingConfigured + ",\n"
                    + "  \"proxy_port\": " + proxyPort + ",\n"
                    + "  \"backend_port\": " + paperPort + ",\n"
                    + "  \"tcp_connected\": " + tcpConnected + ",\n"
                    + "  \"login_success\": " + loginSuccess + ",\n"
                    + "  \"compression_seen\": " + compressionSeen + ",\n"
                    + "  \"configuration_finished\": " + configurationFinished + ",\n"
                    + "  \"mcace_server_hello\": " + serverHello + ",\n"
                    + "  \"mcace_auth_result\": " + authResult + ",\n"
                    + "  \"mcace_auth_accepted\": " + authAccepted + ",\n"
                    + "  \"backend_admission\": " + backendAdmission + ",\n"
                    + "  \"backend_context_shadow_audit\": " + backendContextShadowAudit + ",\n"
                    + "  \"channels\": " + strings(channels) + ",\n"
                    + "  \"packet_trace\": " + strings(packetTrace) + ",\n"
                    + "  \"limitations\": " + strings(limitations) + ",\n"
                    + "  \"cleanup_process_ids\": " + numbers(cleanupProcessIds) + ",\n"
                    + "  \"remaining_run_processes\": " + numbers(remainingRunProcesses) + "\n"
                    + "}\n";
        }

        private String toMarkdown() {
            return "# MCAce real Minecraft player/protocol probe\n\n"
                    + "- Proxy: `" + proxy + "`\n"
                    + "- Backend: `" + backend + "` Minecraft `"
                    + backendMinecraftVersion + "`\n"
                    + "- Forwarding: `" + forwardingMode + "` configured=`" + forwardingConfigured + "`\n"
                    + "- Ports: proxy `" + proxyPort + "`, backend `" + paperPort + "`\n"
                    + "- TCP/login success: `" + loginSuccess + "`\n"
                    + "- MCAce server hello: `" + serverHello + "`\n"
                    + "- MCAce auth result: `" + authResult + "` accepted=`" + authAccepted + "`\n"
                    + "- Backend admission: `" + backendAdmission + "`\n"
                    + "- Backend context shadow audit: `" + backendContextShadowAudit + "`\n"
                    + "- Channels: `" + String.join("`, `", channels) + "`\n\n"
                    + "## Limitations\n\n"
                    + (limitations.isEmpty() ? "None recorded.\n" : limitations.stream().map(item -> "- " + item + "\n").reduce("", String::concat))
                    + "\nCleanup PIDs: `" + cleanupProcessIds + "`; remaining run processes: `" + remainingRunProcesses + "`.\n";
        }

        private static String strings(List<String> values) {
            return "[" + values.stream().map(value -> "\"" + escape(value) + "\"").reduce((a, b) -> a + ", " + b).orElse("") + "]";
        }

        private static String numbers(List<?> values) {
            return "[" + values.stream().map(Object::toString).reduce((a, b) -> a + ", " + b).orElse("") + "]";
        }

        private static String escape(String value) {
            return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
        }
    }

    private static int readVarInt(InputStream input) throws IOException {
        int result = 0;
        int shift = 0;
        while (shift < 35) {
            int value = input.read();
            if (value < 0) throw new EOFException("truncated VarInt");
            result |= (value & 0x7F) << shift;
            if ((value & 0x80) == 0) return result;
            shift += 7;
        }
        throw new IOException("VarInt exceeds five bytes");
    }

    private static String readString(InputStream input) throws IOException {
        int length = readVarInt(input);
        if (length < 0 || length > 32767) throw new IOException("invalid Minecraft string length");
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) throw new EOFException("truncated Minecraft string");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] varInt(int value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while ((value & ~0x7F) != 0) {
            output.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        output.write(value);
        return output.toByteArray();
    }

    private static byte[] string(String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return concat(varInt(bytes.length), bytes);
    }

    private static byte[] shortBytes(int value) { return new byte[] {(byte) (value >>> 8), (byte) value}; }

    private static byte[] longBytes(long value) {
        byte[] bytes = new byte[Long.BYTES];
        for (int index = 7; index >= 0; index--) { bytes[index] = (byte) value; value >>>= 8; }
        return bytes;
    }

    private static byte[] concat(byte[]... parts) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] part : parts) output.write(part);
        return output.toByteArray();
    }

    private static byte[] deflate(byte[] input) {
        Deflater deflater = new Deflater();
        deflater.setInput(input);
        deflater.finish();
        byte[] buffer = new byte[input.length + 128];
        int length = deflater.deflate(buffer);
        deflater.end();
        return java.util.Arrays.copyOf(buffer, length);
    }

    private static byte[] inflate(byte[] input, int expectedLength) throws IOException, DataFormatException {
        if (expectedLength <= 0 || expectedLength > MAX_PACKET_BYTES) throw new IOException("invalid uncompressed packet length");
        Inflater inflater = new Inflater();
        inflater.setInput(input);
        byte[] output = new byte[expectedLength];
        int length = inflater.inflate(output);
        boolean complete = inflater.finished() && length == expectedLength;
        inflater.end();
        if (!complete) throw new IOException("compressed packet did not reach declared length");
        return output;
    }

    private static String safeMessage(Throwable exception) {
        String message = exception.getMessage();
        return message == null || message.isBlank() ? exception.getClass().getSimpleName() : message.replace('\n', ' ');
    }
}
