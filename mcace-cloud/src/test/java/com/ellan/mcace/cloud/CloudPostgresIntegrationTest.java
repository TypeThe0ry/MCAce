package com.ellan.mcace.cloud;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.cloud.auth.AccessTokenCodec;
import com.ellan.mcace.cloud.auth.ApiScope;
import com.ellan.mcace.cloud.auth.CloudAuthenticationService;
import com.ellan.mcace.cloud.auth.FileServerIdentityRegistry;
import com.ellan.mcace.cloud.auth.AuthenticationException;
import com.ellan.mcace.cloud.auth.IssuedChallenge;
import com.ellan.mcace.cloud.auth.PostgresAuthenticationChallengeStore;
import com.ellan.mcace.cloud.auth.ServerIdentity;
import com.ellan.mcace.core.persistence.RevocationSignatureCodec;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.core.risk.PolicyCohortAssigner;
import com.ellan.mcace.storage.postgres.Ed25519EvidenceChainSigner;
import com.ellan.mcace.storage.postgres.Ed25519AuditAnchorSigner;
import com.ellan.mcace.storage.postgres.Ed25519RevocationSigner;
import com.ellan.mcace.storage.postgres.PostgresDataSources;
import com.ellan.mcace.storage.postgres.PostgresSchemaMigrator;
import com.ellan.mcace.storage.postgres.PostgresSecurityAuditRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers(disabledWithoutDocker = true)
final class CloudPostgresIntegrationTest {
    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.6-alpine")
            .withDatabaseName("mcace_cloud_test")
            .withUsername("mcace")
            .withPassword("integration-only-password");
    private static final Instant NOW = Instant.parse("2026-08-08T10:30:00Z");
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void coordinatesChallengesAndReplayAcrossCloudInstances() throws Exception {
        var dataSource = PostgresDataSources.create(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        PostgresSchemaMigrator.migrate(dataSource);
        KeyPair serverKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair authenticationKeys = Ed25519Keys.generate(new SecureRandom());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        ServerIdentity identity = new ServerIdentity(
                "distributed-postgres", serverKeys.getPublic(), EnumSet.of(ApiScope.RISK_WRITE));
        AccessTokenCodec tokenCodec = new AccessTokenCodec(
                authenticationKeys.getPrivate(), authenticationKeys.getPublic(),
                clock, Duration.ofMinutes(5));
        CloudAuthenticationService first = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity), tokenCodec, clock, new SecureRandom(),
                Duration.ofSeconds(30), new PostgresAuthenticationChallengeStore(dataSource));
        CloudAuthenticationService second = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity), tokenCodec, clock, new SecureRandom(),
                Duration.ofSeconds(30), new PostgresAuthenticationChallengeStore(dataSource));

        try (CloudApiServer apiA = new CloudApiServer(
                     new InetSocketAddress("127.0.0.1", 0), first,
                     new PostgresSecurityAuditRepository(
                             dataSource,
                             new Ed25519EvidenceChainSigner(
                                     authenticationKeys.getPrivate(), authenticationKeys.getPublic()),
                             clock),
                     clock);
             CloudApiServer apiB = new CloudApiServer(
                     new InetSocketAddress("127.0.0.1", 0), second,
                     new PostgresSecurityAuditRepository(
                             dataSource,
                             new Ed25519EvidenceChainSigner(
                                     authenticationKeys.getPrivate(), authenticationKeys.getPublic()),
                             clock),
                     clock)) {
            apiA.start();
            apiB.start();
            URI firstBase = URI.create("http://127.0.0.1:" + apiA.address().getPort());
            URI secondBase = URI.create("http://127.0.0.1:" + apiB.address().getPort());
            Response issued = post(firstBase, "/v1/auth/challenges",
                    "{\"server_id\":\"" + identity.serverId() + "\"}", null);
            String challengeId = issued.body().get("challenge_id").asText();
            String apiProof = sign(serverKeys, Base64.getUrlDecoder().decode(
                    issued.body().get("signing_payload").asText()));
            String exchangeBody = """
                    {"challenge_id":"%s","server_id":"%s","signature":"%s"}
                    """.formatted(challengeId, identity.serverId(), apiProof);
            assertEquals(201, post(secondBase, "/v1/auth/tokens", exchangeBody, null).status());
            assertEquals(401, post(firstBase, "/v1/auth/tokens", exchangeBody, null).status());
        }

        IssuedChallenge challenge = first.issue(identity.serverId());
        String proof = sign(serverKeys, challenge.signingPayload());
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<Boolean>> attempts = List.of(
                    executor.submit(() -> exchangeAfterGate(
                            first, challenge, identity.serverId(), proof, ready, start)),
                    executor.submit(() -> exchangeAfterGate(
                            second, challenge, identity.serverId(), proof, ready, start)));
            assertTrue(ready.await(2, TimeUnit.SECONDS));
            start.countDown();
            assertEquals(1, attempts.stream().filter(CloudPostgresIntegrationTest::successful).count());
        }
        assertThrows(AuthenticationException.class,
                () -> first.exchange(challenge.challengeId(), identity.serverId(), proof));

        for (int index = 0; index < 8; index++) {
            (index % 2 == 0 ? first : second).issue(identity.serverId());
        }
        assertThrows(AuthenticationException.class, () -> first.issue(identity.serverId()));
    }

    @Test
    void persistsAuthenticatedHttpIngestionAndSignedRevocation() throws Exception {
        var dataSource = PostgresDataSources.create(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        PostgresSchemaMigrator.migrate(dataSource);
        KeyPair serverKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair authenticationKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair auditKeys = Ed25519Keys.generate(new SecureRandom());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        Ed25519EvidenceChainSigner evidenceSigner = new Ed25519EvidenceChainSigner(
                auditKeys.getPrivate(), auditKeys.getPublic());
        PostgresSecurityAuditRepository store = new PostgresSecurityAuditRepository(
                dataSource,
                evidenceSigner,
                new Ed25519RevocationSigner(auditKeys.getPrivate(), auditKeys.getPublic()),
                new Ed25519AuditAnchorSigner(auditKeys.getPrivate(), auditKeys.getPublic()),
                clock);
        ServerIdentity identity = new ServerIdentity(
                "velocity-postgres", serverKeys.getPublic(), EnumSet.allOf(ApiScope.class));
        CloudAuthenticationService authentication = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity),
                new AccessTokenCodec(
                        authenticationKeys.getPrivate(), authenticationKeys.getPublic(),
                        clock, Duration.ofMinutes(5)),
                clock, new SecureRandom(), Duration.ofSeconds(30));

        UUID playerId = UUID.randomUUID();
        try (CloudApiServer api = new CloudApiServer(
                new InetSocketAddress("127.0.0.1", 0), authentication, store, clock)) {
            api.start();
            URI base = URI.create("http://127.0.0.1:" + api.address().getPort());
            String token = authenticate(base, identity.serverId(), serverKeys);

            assertEquals(202, post(base, "/v1/risk-events", """
                    {"event_id":"%s","session_id":null,"player_uuid":"%s",
                     "type":"BEHAVIOR_HIGH_RISK","source_component":"grim",
                     "origin":"SERVER_CONFIRMED","corroborated":true,"observed_at":"%s",
                     "details":{"fixture":true}}
                    """.formatted(UUID.randomUUID(), playerId, NOW), token).status());
            assertEquals(201, post(base, "/v1/evidence-metadata", """
                    {"evidence_id":"%s","player_uuid":"%s","session_id":null,
                     "evidence_type":"AUTH_LOG","origin":"SERVER_CONFIRMED","captured_at":"%s",
                     "content_size":42,"content_sha256":"%s",
                     "storage_uri":"s3://mcace-test/auth-log"}
                    """.formatted(UUID.randomUUID(), playerId, NOW, "22".repeat(32)), token).status());
            assertEquals(201, post(base, "/v1/revocations", """
                    {"revocation_id":"%s","subject_type":"POLICY_SIGNER",
                     "subject_id":"compromised-key","reason_code":"KEY_COMPROMISE_CONFIRMED",
                     "effective_at":"%s","expires_at":null,"review_ticket":"SEC-99",
                     "appeal_uri":"https://appeals.example.test/SEC-99"}
                    """.formatted(UUID.randomUUID(), NOW), token).status());

            UUID caseId = UUID.randomUUID();
            assertEquals(201, post(base, "/v1/reviews", """
                    {"case_id":"%s","player_uuid":"%s","title":"PostgreSQL review fixture",
                     "reason":"correlate the persisted risk and signed evidence metadata"}
                    """.formatted(caseId, playerId), token).status());
            assertEquals(200, post(base, "/v1/reviews/" + caseId + "/transitions", """
                    {"expected_version":1,"target_status":"UNDER_REVIEW",
                     "reason":"human reviewer assigned","recommendation":null}
                    """, token).status());
            assertEquals(200, post(base, "/v1/reviews/" + caseId + "/transitions", """
                    {"expected_version":2,"target_status":"ACTION_RECOMMENDED",
                     "reason":"server event and evidence were corroborated",
                     "recommendation":"restrict ranked queue pending appeal"}
                    """, token).status());
            UUID appealId = UUID.randomUUID();
            assertEquals(201, post(base, "/v1/appeals", """
                    {"appeal_id":"%s","case_id":"%s","player_uuid":"%s",
                     "statement":"Request independent review of the controlled fixture."}
                    """.formatted(appealId, caseId, playerId), token).status());
            assertEquals(200, post(base, "/v1/appeals/" + appealId + "/transitions", """
                    {"expected_version":1,"target_status":"UNDER_REVIEW",
                     "reason":"assigned to independent reviewer"}
                    """, token).status());
            assertEquals(200, post(base, "/v1/appeals/" + appealId + "/transitions", """
                    {"expected_version":2,"target_status":"GRANTED",
                     "reason":"known-good replay reproduced the controlled alert"}
                    """, token).status());
            Response timeline = get(base, "/v1/players/" + playerId + "/timeline", token);
            assertEquals(200, timeline.status());
            assertTrue(timeline.body().get("events").toString().contains("SERVER_CONFIRMED"));
            assertTrue(timeline.body().get("events").toString().contains("OPERATOR_AUDIT"));
            assertTrue(timeline.body().get("current_appeals").toString()
                    .contains("TRUSTED_APPEAL_PORTAL"));

            UUID policyId;
            do {
                policyId = UUID.randomUUID();
            } while (PolicyCohortAssigner.bucket(playerId, policyId) >= 2_500);
            assertEquals(201, post(base, "/v1/risk-policies", """
                    {"policy_id":"%s","version":"postgres-canary-%s",
                     "description":"real PostgreSQL rollout fixture",
                     "weights":{"MISSING_MCACE":20,"UNKNOWN_MOD":29,"MANIFEST_MISMATCH":50,
                     "AUTH_REPLAY":100,"AGENT_UNAVAILABLE":40,"EVIDENCE_ANOMALY":30,
                     "BEHAVIOR_HIGH_RISK":60,"POLICY_MISMATCH":50,"PROTOCOL_VIOLATION":80},
                     "watch_threshold":20,"restricted_threshold":50,"investigation_threshold":80}
                    """.formatted(policyId, policyId.toString().substring(0, 8)), token).status());
            assertEquals(201, post(base, "/v1/policy-rollouts", """
                    {"rollout_id":"%s","policy_id":"%s","stage":"SHADOW","percentage":0,
                     "reason":"measure without assignment"}
                    """.formatted(UUID.randomUUID(), policyId), token).status());
            UUID shadowEventId = UUID.randomUUID();
            Response shadow = post(base, "/v1/risk-events", """
                    {"event_id":"%s","player_uuid":"%s","type":"UNKNOWN_MOD",
                     "source_component":"postgres-shadow","origin":"SERVER_CONFIRMED",
                     "corroborated":true,"observed_at":"%s","details":{"rollout":"shadow"}}
                    """.formatted(shadowEventId, playerId, NOW), token);
            assertEquals(15, shadow.body().get("assigned_weight").asInt());
            assertEquals("SHADOW", shadow.body().get("rollout_stage").asText());
            assertEquals(201, post(base, "/v1/policy-rollouts", """
                    {"rollout_id":"%s","policy_id":"%s","stage":"CANARY","percentage":25,
                     "reason":"bounded deterministic cohort"}
                    """.formatted(UUID.randomUUID(), policyId), token).status());
            UUID canaryEventId = UUID.randomUUID();
            Response canary = post(base, "/v1/risk-events", """
                    {"event_id":"%s","player_uuid":"%s","type":"UNKNOWN_MOD",
                     "source_component":"postgres-canary","origin":"SERVER_CONFIRMED",
                     "corroborated":true,"observed_at":"%s","details":{"rollout":"canary"}}
                    """.formatted(canaryEventId, playerId, NOW), token);
            assertEquals(29, canary.body().get("assigned_weight").asInt());
            String candidateVersion = canary.body().get("applied_policy_version").asText();
            assertTrue(candidateVersion.startsWith("postgres-canary-"));
            assertEquals(201, post(base, "/v1/risk-feedback", """
                    {"feedback_id":"%s","event_id":"%s","review_case_id":"%s",
                     "label":"FALSE_POSITIVE","notes":"known-good PostgreSQL fixture"}
                    """.formatted(UUID.randomUUID(), canaryEventId, caseId), token).status());
            Response metrics = get(base, "/v1/policy-metrics?version=" + candidateVersion
                    + "&from=" + NOW.minusSeconds(1) + "&to=" + NOW.plusSeconds(1), token);
            assertEquals(200, metrics.status());
            assertEquals(2, metrics.body().get("evaluated_events").asInt());
            assertEquals(1, metrics.body().get("applied_events").asInt());
            assertEquals(1, metrics.body().get("shadow_events").asInt());
            assertEquals(1, metrics.body().get("false_positives").asInt());
        }

        assertEquals(3, store.findRiskEvents(playerId).size());
        assertTrue(store.findRiskEvents(playerId).stream().anyMatch(value -> value.weight() == 60));
        assertTrue(store.findRiskEvents(playerId).stream().anyMatch(value -> value.weight() == 29));
        assertTrue(store.findRiskEvents(playerId).stream().anyMatch(value -> value.weight() == 15));
        assertEquals(1, store.findEvidence().size());
        assertTrue(store.verifyEvidenceChain(Map.of(
                evidenceSigner.keyId(), auditKeys.getPublic())).valid());
        var revocations = store.findRevocationsAfter(0, NOW.plusSeconds(1), 10);
        assertEquals(1, revocations.size());
        assertTrue(RevocationSignatureCodec.verify(revocations.getFirst(), auditKeys.getPublic()));
        var timeline = store.findPlayerTimeline(playerId, 100);
        assertEquals(1, timeline.reviews().size());
        assertEquals(1, timeline.appeals().size());
        assertEquals("GRANTED", timeline.appeals().getFirst().status().name());
    }

    private String authenticate(URI base, String serverId, KeyPair serverKeys) throws Exception {
        Response challenge = post(base, "/v1/auth/challenges",
                "{\"server_id\":\"" + serverId + "\"}", null);
        byte[] payload = Base64.getUrlDecoder().decode(challenge.body().get("signing_payload").asText());
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(serverKeys.getPrivate());
        signature.update(payload);
        String proof = Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
        Response token = post(base, "/v1/auth/tokens", """
                {"challenge_id":"%s","server_id":"%s","signature":"%s"}
                """.formatted(challenge.body().get("challenge_id").asText(), serverId, proof), null);
        return token.body().get("access_token").asText();
    }

    private static String sign(KeyPair keys, byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keys.getPrivate());
        signature.update(payload);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    private static boolean exchangeAfterGate(
            CloudAuthenticationService service,
            IssuedChallenge challenge,
            String serverId,
            String proof,
            CountDownLatch ready,
            CountDownLatch start) throws InterruptedException {
        ready.countDown();
        start.await();
        try {
            service.exchange(challenge.challengeId(), serverId, proof);
            return true;
        } catch (AuthenticationException exception) {
            return false;
        }
    }

    private static boolean successful(Future<Boolean> attempt) {
        try {
            return attempt.get();
        } catch (Exception exception) {
            throw new AssertionError("distributed authentication attempt failed unexpectedly", exception);
        }
    }

    private Response post(URI base, String path, String body, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.resolve(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) request.header("Authorization", "Bearer " + token);
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Response(response.statusCode(), json.readTree(response.body()));
    }

    private Response get(URI base, String path, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(base.resolve(path)).GET();
        if (token != null) request.header("Authorization", "Bearer " + token);
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Response(response.statusCode(), json.readTree(response.body()));
    }

    private record Response(int status, JsonNode body) { }
}
