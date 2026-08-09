package com.ellan.mcace.cloud;

import com.ellan.mcace.cloud.anchor.AuditAnchorService;
import com.ellan.mcace.cloud.anchor.HttpsAuditAnchorPublisher;
import com.ellan.mcace.cloud.auth.AccessTokenCodec;
import com.ellan.mcace.cloud.auth.CloudAuthenticationService;
import com.ellan.mcace.cloud.auth.CloudIdentityStore;
import com.ellan.mcace.cloud.auth.FileServerIdentityRegistry;
import com.ellan.mcace.cloud.auth.PostgresAuthenticationChallengeStore;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.storage.postgres.Ed25519EvidenceChainSigner;
import com.ellan.mcace.storage.postgres.Ed25519AuditAnchorSigner;
import com.ellan.mcace.storage.postgres.Ed25519RevocationSigner;
import com.ellan.mcace.storage.postgres.PostgresDataSources;
import com.ellan.mcace.storage.postgres.PostgresSchemaMigrator;
import com.ellan.mcace.storage.postgres.PostgresSecurityAuditRepository;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Logger;
import javax.sql.DataSource;

public final class MCAceCloudMain {
    private static final Logger LOGGER = Logger.getLogger(MCAceCloudMain.class.getName());

    private MCAceCloudMain() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("MCAce Cloud accepts environment configuration only");
        CloudConfiguration configuration = CloudConfiguration.fromEnvironment(System.getenv());
        Clock clock = Clock.systemUTC();
        KeyPair authenticationIdentity = loadIdentity(configuration, "authentication");
        KeyPair auditIdentity = loadIdentity(configuration, "audit");
        FileServerIdentityRegistry registry = FileServerIdentityRegistry.load(configuration.serverRegistry());
        DataSource dataSource = PostgresDataSources.create(
                configuration.jdbcUrl(),
                configuration.databaseUsername(),
                configuration.databasePassword());
        PostgresSchemaMigrator.migrate(dataSource);
        Ed25519EvidenceChainSigner signer = new Ed25519EvidenceChainSigner(
                auditIdentity.getPrivate(), auditIdentity.getPublic());
        PostgresSecurityAuditRepository store = new PostgresSecurityAuditRepository(
                dataSource,
                signer,
                new Ed25519RevocationSigner(auditIdentity.getPrivate(), auditIdentity.getPublic()),
                new Ed25519AuditAnchorSigner(auditIdentity.getPrivate(), auditIdentity.getPublic()),
                clock);
        AccessTokenCodec tokenCodec = new AccessTokenCodec(
                authenticationIdentity.getPrivate(), authenticationIdentity.getPublic(),
                clock, Duration.ofMinutes(5));
        CloudAuthenticationService authentication = new CloudAuthenticationService(
                registry, tokenCodec, clock, new SecureRandom(), Duration.ofSeconds(30),
                new PostgresAuthenticationChallengeStore(dataSource));
        CloudApiServer api = configuration.webPublicOrigin().isPresent()
                ? new CloudApiServer(
                        configuration.bind(), authentication, store, store,
                        configuration.webPublicOrigin().orElseThrow(), clock)
                : new CloudApiServer(configuration.bind(), authentication, store, clock);
        AuditAnchorService auditAnchors = configuration.auditAnchor()
                .map(value -> new AuditAnchorService(
                        store,
                        new HttpsAuditAnchorPublisher(
                                value.endpoint(), value.bearerToken(), value.requestTimeout(), clock),
                        value.interval(), value.leaseDuration(), value.retryDelay(), LOGGER))
                .orElse(null);
        CountDownLatch shutdown = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(Thread.ofPlatform().name("mcace-cloud-shutdown").unstarted(() -> {
            if (auditAnchors != null) auditAnchors.close();
            api.close();
            shutdown.countDown();
        }));
        api.start();
        if (auditAnchors != null) auditAnchors.start();
        LOGGER.info(() -> "MCAce Cloud listening on " + api.address()
                + "; authentication key=" + CloudIdentityStore.keyId(authenticationIdentity)
                + "; audit key=" + CloudIdentityStore.keyId(auditIdentity)
                + "; web portal=" + configuration.webPublicOrigin()
                        .map(URI::toString).orElse("disabled")
                + "; external audit anchoring=" + (auditAnchors == null ? "disabled" : "enabled"));
        shutdown.await();
    }

    private static KeyPair loadIdentity(CloudConfiguration configuration, String purpose)
            throws IOException, EnvelopeException {
        return CloudIdentityStore.loadOrCreate(configuration.dataDirectory().resolve("identity").resolve(purpose));
    }
}
