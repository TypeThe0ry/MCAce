package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.proxy.AuthenticatedManifestEvaluator;
import com.ellan.mcace.core.proxy.AuthenticatedManifestObservationDeriver;
import com.ellan.mcace.core.proxy.BoundedAuthenticatedManifestAuditQueue;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditRecord;
import com.ellan.mcace.core.proxy.FileArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.FileDispositionPolicyPublisher;
import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.proxy.FileSignedDispositionPolicySource;
import com.ellan.mcace.core.proxy.ProxyFamily;
import com.ellan.mcace.core.proxy.SharedProxyDispositionPolicyRuntime;
import com.ellan.mcace.core.session.ServerHandshakeCoordinator;
import com.ellan.mcace.core.evidence.EvidenceAuditSink;
import com.ellan.mcace.core.evidence.EvidenceStorageConfiguration;
import com.ellan.mcace.core.evidence.EvidenceStorageRuntime;
import com.ellan.mcace.core.evidence.FileEvidenceAuditSink;
import com.ellan.mcace.core.evidence.EvidenceReviewEndpointConfiguration;
import com.ellan.mcace.core.evidence.LoopbackEvidenceReviewService;
import java.nio.file.Path;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

/** Built-in local bridge for a standalone BungeeCord deployment. */
public final class LocalBungeeSessionBridgeFactory implements BungeeSessionBridgeFactory {
    @Override
    public BungeeSessionBridge create(Path dataDirectory, Logger logger) throws Exception {
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        Objects.requireNonNull(logger, "logger");
        Path normalizedDataDirectory = dataDirectory.toAbsolutePath().normalize();
        BungeeBridgeConfiguration configuration = BungeeBridgeConfiguration.loadOrCreate(
                normalizedDataDirectory.resolve("mcace.properties"));
        KeyPair identity = BungeeIdentityStore.loadOrCreate(normalizedDataDirectory.resolve("identity"));
        Clock clock = Clock.systemUTC();
        BungeeSignedPolicyProvider handshakePolicy = new BungeeSignedPolicyProvider(configuration, identity, clock);
        Path dispositionPolicyPath = normalizedDataDirectory.resolve("disposition-policy.pb");
        Path dispositionConfigurationPath = normalizedDataDirectory.resolve("disposition-policy.textproto");
        ensureDefaultDispositionConfiguration(dispositionConfigurationPath);
        FileSignedDispositionPolicySource dispositionPolicy = new FileSignedDispositionPolicySource(
                dispositionPolicyPath, clock, identity);
        SharedProxyDispositionPolicyRuntime dispositionRuntime = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.BUNGEECORD, dispositionPolicy, identity.getPublic(), clock, Duration.ofSeconds(30));
        AuthenticatedManifestEvaluator manifestEvaluator = new AuthenticatedManifestEvaluator(
                new AuthenticatedManifestObservationDeriver(), dispositionRuntime, clock);
        ArtifactObservationAuditSink artifactObservationAudit = new FileArtifactObservationAuditSink(
                normalizedDataDirectory.resolve("artifact-observation-audit.log"), 8L * 1024 * 1024);
        AtomicReference<CoordinatorBungeeSessionBridge> bridgeHolder = new AtomicReference<>();
        BoundedAuthenticatedManifestAuditQueue manifestAuditQueue = new BoundedAuthenticatedManifestAuditQueue(1, 32, manifest -> {
            com.ellan.mcace.core.proxy.AuthenticatedManifestAuditResult audit = manifestEvaluator.evaluate(
                    manifest, new EvaluationContext(manifest.playerId(), "bungeecord", null, null, null, Set.of(), manifest.authenticatedAt()));
            logger.info("MCAce authenticated-manifest audit player=" + manifest.playerId()
                    + " observations=" + audit.evaluation().totalObservations() + " actions=" + audit.evaluation().actionCounts()
                    + " consistencyIssues=" + audit.consistencyIssues().size());
            CoordinatorBungeeSessionBridge bridge = bridgeHolder.get();
            if (bridge != null) {
                bridge.emitDispositionEvent(audit.dispositionEvent());
            }
        });
        BoundedAuthenticatedManifestAuditQueue artifactObservationAuditQueue = new BoundedAuthenticatedManifestAuditQueue(1, 32, manifest -> {
            com.ellan.mcace.core.proxy.AuthenticatedManifestAuditResult audit = manifestEvaluator.evaluate(
                    manifest, new EvaluationContext(manifest.playerId(), "bungeecord", null, null, null, Set.of(), manifest.authenticatedAt()));
            logger.info("MCAce artifact observation audit player=" + manifest.playerId()
                    + " observations=" + audit.evaluation().totalObservations() + " actions=" + audit.evaluation().actionCounts()
                    + " consistencyIssues=" + audit.consistencyIssues().size() + " (no admission effect)");
            artifactObservationAudit.append(new ArtifactObservationAuditRecord(
                    audit.playerId(), manifest.authenticatedAt(), clock.instant(), audit.evaluation().totalObservations(),
                    audit.consistencyIssues().size(), audit.evaluation().actionCounts(), audit.evaluation().refreshStatus()));
        });
        FileDispositionPolicyPublisher dispositionPublisher = new FileDispositionPolicyPublisher(
                dispositionPolicyPath, clock, identity);
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        EvidenceAuditSink evidenceAuditSink = new FileEvidenceAuditSink(
                normalizedDataDirectory.resolve("evidence-audit.log"), 8L * 1024 * 1024);
        EvidenceStorageRuntime evidenceStorage = EvidenceStorageConfiguration.loadOrCreate(
                normalizedDataDirectory.resolve("evidence-storage.properties"),
                normalizedDataDirectory.resolve("evidence"))
                .createRuntime(clock, new SecureRandom(), evidenceAuditSink);
        ServerHandshakeCoordinator coordinator = new ServerHandshakeCoordinator(
                clock,
                new SecureRandom(),
                identity,
                new RiskEngine(RiskPolicy.defaults()),
                api,
                configuration.handshakeTimeout(),
                handshakePolicy,
                com.ellan.mcace.core.persistence.SecurityAuditSink.noop(),
                ignored -> { },
                manifestAuditQueue::offer,
                artifactObservationAuditQueue::offer,
                evidenceStorage.contentStore(), evidenceAuditSink);
        logger.info("MCAce Bungee built-in bridge configured; server-key fingerprint="
                + BungeeIdentityStore.fingerprint(identity));
        BungeeDispositionPolicyPublisher policyPublisher = new BungeeDispositionPolicyPublisher() {
            @Override
            public BungeePublishedDispositionPolicy publish() throws com.ellan.mcace.protocol.policy.PolicyException {
                com.ellan.mcace.core.proxy.PublishedDispositionPolicy published = dispositionPublisher.publish(
                        dispositionConfigurationPath);
                return new BungeePublishedDispositionPolicy(
                        published.version(), published.sequence(), published.ruleCount());
            }

            @Override
            public DispositionCatalogPreview preview() throws com.ellan.mcace.protocol.policy.PolicyException {
                return dispositionPublisher.preview(dispositionConfigurationPath);
            }
        };
        BungeeFederationLifecycle federation = BungeeFederationLifecycle.loadOrDisabled(
                normalizedDataDirectory, clock, new SecureRandom(), identity, configuration.serverId(),
                exception -> logger.warning("MCAce federation disabled: " + safeMessage(exception)));
        CoordinatorBungeeSessionBridge bridge;
        try {
            bridge = new CoordinatorBungeeSessionBridge(
                    coordinator,
                    api,
                    identity.getPrivate(),
                    dispositionRuntime,
                    policyPublisher,
                    () -> { manifestAuditQueue.close(); artifactObservationAuditQueue.close(); },
                    evidenceStorage.contentStore(), evidenceStorage.adminService(),
                    configuration.dispositionExecutionMode(),
                    configuration.limitedServer().orElse(""), configuration.quarantineServer().orElse(""),
                    configuration.heartbeatMissingPolicy(), federation.runtime(), federation);
        } catch (RuntimeException exception) {
            federation.close();
            throw exception;
        }
        startEvidenceReview(normalizedDataDirectory, evidenceStorage, evidenceAuditSink, clock, logger)
                .ifPresent(bridge::setEvidenceReviewService);
        bridgeHolder.set(bridge);
        return bridge;
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }

    private static java.util.Optional<LoopbackEvidenceReviewService> startEvidenceReview(
            Path dataDirectory, EvidenceStorageRuntime storage, EvidenceAuditSink auditSink, Clock clock, Logger logger) {
        EvidenceReviewEndpointConfiguration configuration;
        try {
            configuration = EvidenceReviewEndpointConfiguration.loadOrCreate(
                    dataDirectory.resolve(EvidenceReviewEndpointConfiguration.FILE_NAME));
        } catch (Exception exception) {
            logger.warning("MCAce local evidence review disabled because its configuration is invalid");
            return java.util.Optional.empty();
        }
        if (!configuration.enabled() || storage.reviewReader().isEmpty()) {
            return java.util.Optional.empty();
        }
        try {
            LoopbackEvidenceReviewService service = LoopbackEvidenceReviewService.start(
                    storage.reviewReader().orElseThrow(), auditSink, clock, new SecureRandom(),
                    InetAddress.getByName(configuration.bindAddress()), configuration.port(),
                    Duration.ofSeconds(configuration.tokenTtlSeconds()), configuration.maxTokens());
            logger.info("MCAce local evidence review enabled on loopback; review URLs are console-only");
            return java.util.Optional.of(service);
        } catch (Exception exception) {
            logger.warning("MCAce local evidence review could not start; proxy operation is unchanged");
            return java.util.Optional.empty();
        }
    }

    private static void ensureDefaultDispositionConfiguration(Path configurationPath) throws java.io.IOException {
        try {
            Files.writeString(
                    configurationPath,
                    FileDispositionPolicyPublisher.safeDefaultConfiguration(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException ignored) {
            // Existing local configuration is operator-owned and is never overwritten.
        }
    }
}
