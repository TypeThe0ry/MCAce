package com.ellan.mcace.cloud;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.cloud.auth.AccessTokenCodec;
import com.ellan.mcace.cloud.auth.ApiScope;
import com.ellan.mcace.cloud.auth.CloudAuthenticationService;
import com.ellan.mcace.cloud.auth.FileServerIdentityRegistry;
import com.ellan.mcace.cloud.auth.ServerIdentity;
import com.ellan.mcace.core.persistence.CloudControlPlaneStore;
import com.ellan.mcace.core.persistence.AppealDraft;
import com.ellan.mcace.core.persistence.AppealStatus;
import com.ellan.mcace.core.persistence.AppealTransition;
import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.OperatorAuditRecord;
import com.ellan.mcace.core.persistence.PlayerTimeline;
import com.ellan.mcace.core.persistence.PlayerNotification;
import com.ellan.mcace.core.persistence.PolicyMetrics;
import com.ellan.mcace.core.persistence.PolicyRolloutDraft;
import com.ellan.mcace.core.persistence.PolicyRolloutStage;
import com.ellan.mcace.core.persistence.RevocationDraft;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.RiskFeedbackDraft;
import com.ellan.mcace.core.persistence.RiskFeedbackLabel;
import com.ellan.mcace.core.persistence.RiskPolicyDeployment;
import com.ellan.mcace.core.persistence.RiskPolicyEvaluation;
import com.ellan.mcace.core.persistence.RiskPolicyReleaseCodec;
import com.ellan.mcace.core.persistence.RiskPolicyReleaseDraft;
import com.ellan.mcace.core.persistence.ReviewCaseDraft;
import com.ellan.mcace.core.persistence.ReviewStatus;
import com.ellan.mcace.core.persistence.ReviewTransition;
import com.ellan.mcace.core.persistence.StoredEvidenceMetadata;
import com.ellan.mcace.core.persistence.StoredAppeal;
import com.ellan.mcace.core.persistence.StoredReviewCase;
import com.ellan.mcace.core.persistence.StoredPolicyRollout;
import com.ellan.mcace.core.persistence.StoredRiskPolicyRelease;
import com.ellan.mcace.core.persistence.StoredRevocation;
import com.ellan.mcace.core.persistence.StoredWebSession;
import com.ellan.mcace.core.persistence.WebPortalStore;
import com.ellan.mcace.core.persistence.WebPrincipalType;
import com.ellan.mcace.core.persistence.WebRole;
import com.ellan.mcace.core.persistence.WebSessionHandoff;
import com.ellan.mcace.core.persistence.WorkflowConflictException;
import com.ellan.mcace.core.persistence.WorkflowTimelineEvent;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.core.risk.PolicyCohortAssigner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class CloudApiServerTest {
    private static final Instant NOW = Instant.parse("2026-08-08T10:00:00Z");
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void authenticatesAndIngestsExplainableDataWithoutAutomaticEnforcement() throws Exception {
        KeyPair serverKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair cloudKeys = Ed25519Keys.generate(new SecureRandom());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        ServerIdentity serverIdentity = new ServerIdentity(
                "velocity-a",
                serverKeys.getPublic(),
                EnumSet.allOf(ApiScope.class));
        AccessTokenCodec tokenCodec = new AccessTokenCodec(
                cloudKeys.getPrivate(), cloudKeys.getPublic(), clock, Duration.ofMinutes(5));
        CloudAuthenticationService authentication = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(serverIdentity), tokenCodec, clock,
                new SecureRandom(), Duration.ofSeconds(30));
        InMemoryStore store = new InMemoryStore();

        try (CloudApiServer api = new CloudApiServer(
                new InetSocketAddress("127.0.0.1", 0), authentication, store, clock)) {
            api.start();
            URI base = URI.create("http://127.0.0.1:" + api.address().getPort());
            String token = authenticate(base, serverKeys);
            assertEquals(200, get(base, "/health/ready", null).status());
            UUID eventId = UUID.randomUUID();
            UUID playerId = UUID.randomUUID();

            Response risk = post(base, "/v1/risk-events", """
                    {
                      "event_id":"%s",
                      "session_id":"session-a",
                      "player_uuid":"%s",
                      "type":"UNKNOWN_MOD",
                      "source_component":"vulcan-adapter",
                      "origin":"SERVER_CONFIRMED",
                      "corroborated":true,
                      "observed_at":"%s",
                      "details":{"alert":"controlled-fixture"}
                    }
                    """.formatted(eventId, playerId, NOW), token);
            assertEquals(202, risk.status());
            assertEquals(15, risk.json().get("assigned_weight").asInt());
            assertEquals("NONE", risk.json().get("enforcement_action").asText());
            assertEquals(15, store.riskEvents.getFirst().weight());
            assertEquals("velocity-a:vulcan-adapter", store.riskEvents.getFirst().source());

            Response forgedWeight = post(base, "/v1/risk-events", """
                    {
                      "event_id":"%s",
                      "player_uuid":"%s",
                      "type":"UNKNOWN_MOD",
                      "source_component":"client",
                      "origin":"CLIENT_REPORTED",
                      "corroborated":false,
                      "observed_at":"%s",
                      "details":{},
                      "weight":999
                    }
                    """.formatted(UUID.randomUUID(), playerId, NOW), token);
            assertEquals(400, forgedWeight.status());
            assertEquals(1, store.riskEvents.size());

            Response evidence = post(base, "/v1/evidence-metadata", """
                    {
                      "evidence_id":"%s",
                      "player_uuid":"%s",
                      "session_id":"session-a",
                      "evidence_type":"MOD_LIST",
                      "origin":"CLIENT_REPORTED",
                      "captured_at":"%s",
                      "content_size":128,
                      "content_sha256":"%s",
                      "storage_uri":"s3://mcace-evidence/object-1"
                    }
                    """.formatted(UUID.randomUUID(), playerId, NOW, "11".repeat(32)), token);
            assertEquals(201, evidence.status());
            assertEquals(1, evidence.json().get("chain_sequence").asLong());

            UUID revocationId = UUID.randomUUID();
            Response revocation = post(base, "/v1/revocations", """
                    {
                      "revocation_id":"%s",
                      "subject_type":"CLIENT_BUILD",
                      "subject_id":"fabric-malicious-build",
                      "reason_code":"OPERATOR_REVIEW_CONFIRMED",
                      "effective_at":"%s",
                      "expires_at":null,
                      "review_ticket":"SEC-42",
                      "appeal_uri":"https://appeals.example.test/SEC-42"
                    }
                    """.formatted(revocationId, NOW), token);
            assertEquals(201, revocation.status());
            assertEquals("DISTRIBUTE_REVOCATION_ONLY",
                    revocation.json().get("enforcement_action").asText());
            assertEquals(1, store.audits.size());

            Response listed = get(base, "/v1/revocations?after_sequence=0", token);
            assertEquals(200, listed.status());
            assertEquals(revocationId.toString(),
                    listed.json().get("revocations").get(0).get("revocation_id").asText());

            UUID caseId = UUID.randomUUID();
            Response review = post(base, "/v1/reviews", """
                    {"case_id":"%s","player_uuid":"%s","title":"Correlated integrity alert",
                     "reason":"Server-confirmed behavior plus client integrity mismatch"}
                    """.formatted(caseId, playerId), token);
            assertEquals(201, review.status());
            assertEquals("OPEN", review.json().get("status").asText());
            assertEquals("NONE_REVIEW_ONLY", review.json().get("enforcement_action").asText());

            Response reviewing = post(base, "/v1/reviews/" + caseId + "/transitions", """
                    {"expected_version":1,"target_status":"UNDER_REVIEW",
                     "reason":"Assigned to a human reviewer","recommendation":null}
                    """, token);
            assertEquals(200, reviewing.status());
            Response recommended = post(base, "/v1/reviews/" + caseId + "/transitions", """
                    {"expected_version":2,"target_status":"ACTION_RECOMMENDED",
                     "reason":"Two independent server observations corroborate the mismatch",
                     "recommendation":"Temporarily restrict ranked access pending appeal"}
                    """, token);
            assertEquals(200, recommended.status());
            assertEquals("NONE_REVIEW_ONLY", recommended.json().get("enforcement_action").asText());
            Response stale = post(base, "/v1/reviews/" + caseId + "/transitions", """
                    {"expected_version":2,"target_status":"CLOSED_NO_ACTION",
                     "reason":"stale concurrent decision","recommendation":null}
                    """, token);
            assertEquals(409, stale.status());

            UUID appealId = UUID.randomUUID();
            Response appeal = post(base, "/v1/appeals", """
                    {"appeal_id":"%s","case_id":"%s","player_uuid":"%s",
                     "statement":"Please review possible network desynchronization."}
                    """.formatted(appealId, caseId, playerId), token);
            assertEquals(201, appeal.status());
            assertEquals("SUBMITTED", appeal.json().get("status").asText());
            assertEquals("NONE_APPEAL_DECISION_ONLY", appeal.json().get("enforcement_action").asText());
            Response appealReview = post(base, "/v1/appeals/" + appealId + "/transitions", """
                    {"expected_version":1,"target_status":"UNDER_REVIEW",
                     "reason":"Assigned to an independent appeal reviewer"}
                    """, token);
            assertEquals(200, appealReview.status());
            Response granted = post(base, "/v1/appeals/" + appealId + "/transitions", """
                    {"expected_version":2,"target_status":"GRANTED",
                     "reason":"Known-good replay reproduced the signal under packet loss"}
                    """, token);
            assertEquals(200, granted.status());
            assertEquals("GRANTED", granted.json().get("status").asText());

            Response timeline = get(base, "/v1/players/" + playerId + "/timeline?limit=25", token);
            assertEquals(200, timeline.status());
            assertTrue(timeline.json().get("events").toString().contains("SERVER_CONFIRMED"));
            assertTrue(timeline.json().get("events").toString().contains("OPERATOR_AUDIT"));
            assertTrue(timeline.json().get("current_appeals").toString()
                    .contains("TRUSTED_APPEAL_PORTAL"));
            assertTrue(timeline.json().get("current_appeals").toString().contains("GRANTED"));

            UUID policyId;
            do {
                policyId = UUID.randomUUID();
            } while (PolicyCohortAssigner.bucket(playerId, policyId) >= 2_500);
            Response policy = post(base, "/v1/risk-policies", """
                    {"policy_id":"%s","version":"phase3-canary-1","description":"controlled canary",
                     "weights":{"MISSING_MCACE":20,"UNKNOWN_MOD":27,"MANIFEST_MISMATCH":50,
                     "AUTH_REPLAY":100,"AGENT_UNAVAILABLE":40,"EVIDENCE_ANOMALY":30,
                     "BEHAVIOR_HIGH_RISK":60,"POLICY_MISMATCH":50,"PROTOCOL_VIOLATION":80},
                     "watch_threshold":20,"restricted_threshold":50,"investigation_threshold":80}
                    """.formatted(policyId), token);
            assertEquals(201, policy.status());
            assertEquals("NONE_IMMUTABLE_POLICY_ONLY", policy.json().get("enforcement_action").asText());

            assertEquals(201, post(base, "/v1/policy-rollouts", """
                    {"rollout_id":"%s","policy_id":"%s","stage":"SHADOW","percentage":0,
                     "reason":"compare candidate without assigning it"}
                    """.formatted(UUID.randomUUID(), policyId), token).status());
            UUID shadowEvent = UUID.randomUUID();
            Response shadowRisk = post(base, "/v1/risk-events", """
                    {"event_id":"%s","player_uuid":"%s","type":"UNKNOWN_MOD",
                     "source_component":"shadow-fixture","origin":"SERVER_CONFIRMED",
                     "corroborated":true,"observed_at":"%s","details":{"stage":"shadow"}}
                    """.formatted(shadowEvent, playerId, NOW), token);
            assertEquals(202, shadowRisk.status());
            assertEquals(15, shadowRisk.json().get("assigned_weight").asInt());
            assertEquals("phase1-v1", shadowRisk.json().get("applied_policy_version").asText());
            assertEquals("phase3-canary-1", shadowRisk.json().get("candidate_policy_version").asText());

            assertEquals(201, post(base, "/v1/policy-rollouts", """
                    {"rollout_id":"%s","policy_id":"%s","stage":"CANARY","percentage":25,
                     "reason":"bounded deterministic cohort"}
                    """.formatted(UUID.randomUUID(), policyId), token).status());
            UUID canaryEvent = UUID.randomUUID();
            Response canaryRisk = post(base, "/v1/risk-events", """
                    {"event_id":"%s","player_uuid":"%s","type":"UNKNOWN_MOD",
                     "source_component":"canary-fixture","origin":"SERVER_CONFIRMED",
                     "corroborated":true,"observed_at":"%s","details":{"stage":"canary"}}
                    """.formatted(canaryEvent, playerId, NOW), token);
            assertEquals(202, canaryRisk.status());
            assertEquals(27, canaryRisk.json().get("assigned_weight").asInt());
            assertEquals("phase3-canary-1", canaryRisk.json().get("applied_policy_version").asText());

            Response feedback = post(base, "/v1/risk-feedback", """
                    {"feedback_id":"%s","event_id":"%s","review_case_id":"%s",
                     "label":"FALSE_POSITIVE","notes":"known-good replay reproduced this signal"}
                    """.formatted(UUID.randomUUID(), canaryEvent, caseId), token);
            assertEquals(201, feedback.status());
            assertEquals("NONE_METRICS_ONLY", feedback.json().get("enforcement_action").asText());

            Response metrics = get(base, "/v1/policy-metrics?version=phase3-canary-1&from="
                    + NOW.minusSeconds(1) + "&to=" + NOW.plusSeconds(1), token);
            assertEquals(200, metrics.status());
            assertEquals(2, metrics.json().get("evaluated_events").asInt());
            assertEquals(1, metrics.json().get("applied_events").asInt());
            assertEquals(1, metrics.json().get("shadow_events").asInt());
            assertEquals(1, metrics.json().get("false_positives").asInt());
            assertEquals("NONE_OBSERVABILITY_ONLY", metrics.json().get("enforcement_action").asText());
            Response policyTimeline = get(
                    base, "/v1/players/" + playerId + "/timeline?limit=25", token);
            assertTrue(policyTimeline.json().get("events").toString().contains("phase3-canary-1"));
            assertTrue(policyTimeline.json().get("events").toString().contains("cohort_bucket"));
        }
    }

    @Test
    void rejectsMissingBearerAuthentication() throws Exception {
        KeyPair serverKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair cloudKeys = Ed25519Keys.generate(new SecureRandom());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        ServerIdentity identity = new ServerIdentity(
                "velocity-a", serverKeys.getPublic(), EnumSet.of(ApiScope.RISK_WRITE));
        CloudAuthenticationService authentication = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity),
                new AccessTokenCodec(cloudKeys.getPrivate(), cloudKeys.getPublic(), clock, Duration.ofMinutes(5)),
                clock, new SecureRandom(), Duration.ofSeconds(30));
        try (CloudApiServer api = new CloudApiServer(
                new InetSocketAddress("127.0.0.1", 0), authentication, new InMemoryStore(), clock)) {
            api.start();
            URI base = URI.create("http://127.0.0.1:" + api.address().getPort());
            Response response = post(
                    base, "/v1/risk-events", "{}", null);
            assertEquals(401, response.status());
            assertEquals("UNAUTHORIZED", response.json().get("error").get("code").asText());

            String riskOnlyToken = authenticate(base, serverKeys);
            Response forbidden = get(
                    base, "/v1/players/" + UUID.randomUUID() + "/timeline", riskOnlyToken);
            assertEquals(403, forbidden.status());
            assertEquals("INSUFFICIENT_SCOPE", forbidden.json().get("error").get("code").asText());
        }
    }

    @Test
    void exchangesOneTimeWebHandoffsAndEnforcesCookieCsrfRoleAndPlayerBoundaries() throws Exception {
        KeyPair serverKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair cloudKeys = Ed25519Keys.generate(new SecureRandom());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        ServerIdentity serverIdentity = new ServerIdentity(
                "velocity-a", serverKeys.getPublic(), EnumSet.allOf(ApiScope.class));
        CloudAuthenticationService authentication = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(serverIdentity),
                new AccessTokenCodec(
                        cloudKeys.getPrivate(), cloudKeys.getPublic(), clock, Duration.ofMinutes(5)),
                clock, new SecureRandom(), Duration.ofSeconds(30));
        InMemoryStore store = new InMemoryStore();
        UUID playerId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        store.createReviewCase(
                new ReviewCaseDraft(caseId, playerId, "Portal fixture", "Human review required", "fixture"),
                testAudit("fixture", "REVIEW_CREATED", "REVIEW_CASE", caseId));
        store.transitionReviewCase(
                new ReviewTransition(caseId, 1, ReviewStatus.UNDER_REVIEW, "assigned", "", "fixture"),
                testAudit("fixture", "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId));
        store.transitionReviewCase(
                new ReviewTransition(caseId, 2, ReviewStatus.ACTION_RECOMMENDED,
                        "corroborated", "restrict ranked access pending appeal", "fixture"),
                testAudit("fixture", "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId));

        URI origin = URI.create("https://portal.example.test");
        try (CloudApiServer api = new CloudApiServer(
                new InetSocketAddress("127.0.0.1", 0), authentication, store, store, origin, clock)) {
            api.start();
            URI base = URI.create("http://127.0.0.1:" + api.address().getPort());
            String token = authenticate(base, serverKeys);
            HttpResponse<String> loginPage = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/login")).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, loginPage.statusCode());
            assertTrue(loginPage.headers().firstValue("Content-Security-Policy").orElseThrow()
                    .contains("script-src 'self'"));
            assertEquals("DENY", loginPage.headers().firstValue("X-Frame-Options").orElseThrow());
            assertTrue(loginPage.body().contains("src=\"/assets/login.js\""));
            Response issued = post(base, "/v1/web-handoffs/player", """
                    {"player_uuid":"%s","redirect_path":"/appeal"}
                    """.formatted(playerId), token);
            assertEquals(201, issued.status());
            String loginUrl = issued.json().path("login_url").asText();
            assertTrue(loginUrl.startsWith("https://portal.example.test/login#code="));
            String code = loginUrl.substring(loginUrl.indexOf("#code=") + 6);

            HttpRequest exchangeRequest = HttpRequest.newBuilder(base.resolve("/web/api/session/exchange"))
                    .header("Origin", origin.toString())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            json.writeValueAsString(Map.of("code", code))))
                    .build();
            HttpResponse<String> exchanged = HttpClient.newHttpClient().send(
                    exchangeRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, exchanged.statusCode());
            List<String> setCookies = exchanged.headers().allValues("Set-Cookie");
            String sessionSetCookie = setCookies.stream()
                    .filter(value -> value.startsWith("__Host-MCAce-Session="))
                    .findFirst().orElseThrow();
            String csrfSetCookie = setCookies.stream()
                    .filter(value -> value.startsWith("__Host-MCAce-CSRF="))
                    .findFirst().orElseThrow();
            assertTrue(sessionSetCookie.contains("; Secure; HttpOnly; SameSite=Strict"));
            assertTrue(csrfSetCookie.contains("; Secure; SameSite=Strict"));
            assertTrue(!csrfSetCookie.contains("HttpOnly"));
            String sessionCookie = sessionSetCookie.substring(0, sessionSetCookie.indexOf(';'));
            String csrfCookie = csrfSetCookie.substring(0, csrfSetCookie.indexOf(';'));
            String cookies = sessionCookie + "; " + csrfCookie;
            String csrf = csrfCookie.substring(csrfCookie.indexOf('=') + 1);

            HttpResponse<String> replay = HttpClient.newHttpClient().send(
                    exchangeRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(401, replay.statusCode());
            HttpResponse<String> me = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/session"))
                            .header("Cookie", cookies).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, me.statusCode());
            assertEquals(playerId.toString(), json.readTree(me.body()).path("subject_id").asText());

            HttpResponse<String> operatorDenied = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/operator/reviews"))
                            .header("Cookie", cookies).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(403, operatorDenied.statusCode());
            HttpResponse<String> timeline = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/player/timeline"))
                            .header("Cookie", cookies).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, timeline.statusCode());
            assertEquals(playerId.toString(), json.readTree(timeline.body()).path("player_uuid").asText());

            String appealBody = json.writeValueAsString(Map.of(
                    "appeal_id", UUID.randomUUID().toString(), "case_id", caseId.toString(),
                    "statement", "Please review the controlled fixture."));
            HttpResponse<String> missingCsrf = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/player/appeals"))
                            .header("Origin", origin.toString()).header("Cookie", cookies)
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(appealBody)).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(403, missingCsrf.statusCode());
            HttpResponse<String> appeal = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/player/appeals"))
                            .header("Origin", origin.toString()).header("Cookie", cookies)
                            .header("X-MCAce-CSRF", csrf).header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(appealBody)).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(201, appeal.statusCode());
            assertEquals(playerId.toString(), json.readTree(appeal.body()).path("player_uuid").asText());

            HttpResponse<String> notifications = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/player/notifications"))
                            .header("Cookie", cookies).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, notifications.statusCode());
            assertTrue(json.readTree(notifications.body()).path("notifications").size() >= 4);

            Response viewerIssued = post(base, "/v1/web-handoffs/operator", """
                    {"subject_id":"viewer@example.test","roles":["OPERATOR_VIEWER"],
                     "redirect_path":"/dashboard"}
                    """, token);
            WebCookies viewer = exchangeWeb(base, origin, handoffCode(viewerIssued));
            HttpResponse<String> viewerQueue = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/operator/reviews"))
                            .header("Cookie", viewer.header()).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, viewerQueue.statusCode());
            String closeBody = json.writeValueAsString(Map.of(
                    "expected_version", 3, "target_status", "CLOSED_NO_ACTION",
                    "reason", "human reviewer found no actionable violation", "recommendation", ""));
            HttpResponse<String> viewerWrite = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve(
                                    "/web/api/operator/reviews/" + caseId + "/transitions"))
                            .header("Origin", origin.toString()).header("Cookie", viewer.header())
                            .header("X-MCAce-CSRF", viewer.csrf()).header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(closeBody)).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(403, viewerWrite.statusCode());

            Response reviewerIssued = post(base, "/v1/web-handoffs/operator", """
                    {"subject_id":"reviewer@example.test",
                     "roles":["OPERATOR_VIEWER","OPERATOR_REVIEWER"],
                     "redirect_path":"/dashboard"}
                    """, token);
            WebCookies reviewer = exchangeWeb(base, origin, handoffCode(reviewerIssued));
            HttpResponse<String> reviewerWrite = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve(
                                    "/web/api/operator/reviews/" + caseId + "/transitions"))
                            .header("Origin", origin.toString()).header("Cookie", reviewer.header())
                            .header("X-MCAce-CSRF", reviewer.csrf()).header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(closeBody)).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, reviewerWrite.statusCode());

            HttpResponse<String> wrongOriginLogout = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/logout"))
                            .header("Origin", "https://evil.example.test").header("Cookie", cookies)
                            .header("X-MCAce-CSRF", csrf)
                            .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(403, wrongOriginLogout.statusCode());
            HttpResponse<String> logout = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(base.resolve("/web/api/logout"))
                            .header("Origin", origin.toString()).header("Cookie", cookies)
                            .header("X-MCAce-CSRF", csrf)
                            .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assertEquals(200, logout.statusCode());
            assertTrue(logout.headers().allValues("Set-Cookie").stream()
                    .allMatch(value -> value.contains("Max-Age=0")));
        }
    }

    private static OperatorAuditRecord testAudit(
            String actor, String action, String targetType, UUID targetId) {
        return new OperatorAuditRecord(
                UUID.randomUUID(), actor, action, targetType, targetId.toString(), NOW, "{}");
    }

    private static String handoffCode(Response issued) {
        String loginUrl = issued.json().path("login_url").asText();
        return loginUrl.substring(loginUrl.indexOf("#code=") + 6);
    }

    private WebCookies exchangeWeb(URI base, URI origin, String code) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(base.resolve("/web/api/session/exchange"))
                        .header("Origin", origin.toString()).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                json.writeValueAsString(Map.of("code", code)))).build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertEquals(200, response.statusCode());
        String session = response.headers().allValues("Set-Cookie").stream()
                .filter(value -> value.startsWith("__Host-MCAce-Session="))
                .map(value -> value.substring(0, value.indexOf(';'))).findFirst().orElseThrow();
        String csrfCookie = response.headers().allValues("Set-Cookie").stream()
                .filter(value -> value.startsWith("__Host-MCAce-CSRF="))
                .map(value -> value.substring(0, value.indexOf(';'))).findFirst().orElseThrow();
        return new WebCookies(session + "; " + csrfCookie,
                csrfCookie.substring(csrfCookie.indexOf('=') + 1));
    }

    private record WebCookies(String header, String csrf) { }

    private String authenticate(URI base, KeyPair serverKeys) throws Exception {
        Response challenge = post(base, "/v1/auth/challenges", "{\"server_id\":\"velocity-a\"}", null);
        assertEquals(201, challenge.status());
        byte[] payload = Base64.getUrlDecoder().decode(challenge.json().get("signing_payload").asText());
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(serverKeys.getPrivate());
        signature.update(payload);
        String proof = Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
        Response token = post(base, "/v1/auth/tokens", """
                {"challenge_id":"%s","server_id":"velocity-a","signature":"%s"}
                """.formatted(challenge.json().get("challenge_id").asText(), proof), null);
        assertEquals(201, token.status());
        return token.json().get("access_token").asText();
    }

    private Response post(URI base, String path, String body, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(base.resolve(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return send(builder.build());
    }

    private Response get(URI base, String path, String token) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(base.resolve(path)).GET();
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return send(builder.build());
    }

    private Response send(HttpRequest request) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        return new Response(response.statusCode(), json.readTree(response.body()));
    }

    private record Response(int status, JsonNode json) { }

    private static final class InMemoryStore implements CloudControlPlaneStore, WebPortalStore {
        private final List<RiskEventAuditRecord> riskEvents = new ArrayList<>();
        private final List<StoredEvidenceMetadata> evidence = new ArrayList<>();
        private final List<StoredRevocation> revocations = new ArrayList<>();
        private final List<OperatorAuditRecord> audits = new ArrayList<>();
        private final Map<UUID, StoredReviewCase> reviews = new LinkedHashMap<>();
        private final Map<UUID, StoredAppeal> appeals = new LinkedHashMap<>();
        private final List<WorkflowTimelineEvent> workflowEvents = new ArrayList<>();
        private final Map<UUID, StoredRiskPolicyRelease> policies = new LinkedHashMap<>();
        private final List<StoredPolicyRollout> policyRollouts = new ArrayList<>();
        private final Map<UUID, RiskPolicyEvaluation> evaluations = new LinkedHashMap<>();
        private final List<RiskFeedbackDraft> feedback = new ArrayList<>();
        private final Map<UUID, WebSessionHandoff> handoffs = new LinkedHashMap<>();
        private final Map<String, StoredWebSession> webSessions = new LinkedHashMap<>();
        private final List<PlayerNotification> notifications = new ArrayList<>();

        @Override public void upsertSession(com.ellan.mcace.core.persistence.SessionAuditRecord session) { }

        @Override public void checkHealth() { }

        @Override public void appendRiskEvent(RiskEventAuditRecord event) {
            riskEvents.add(event);
        }

        @Override public StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft draft) {
            byte[] previous = evidence.isEmpty() ? new byte[32] : evidence.getLast().chainSha256();
            byte[] hash = digest(draft.contentSha256());
            StoredEvidenceMetadata stored = new StoredEvidenceMetadata(
                    draft, evidence.size() + 1L, NOW, previous, hash, new byte[64], "test-cloud-key");
            evidence.add(stored);
            return stored;
        }

        @Override public StoredRevocation appendRevocation(
                RevocationDraft draft, OperatorAuditRecord audit) {
            byte[] hash = digest(draft.revocationId().toString().getBytes(StandardCharsets.UTF_8));
            StoredRevocation stored = new StoredRevocation(
                    draft, revocations.size() + 1L, NOW, hash, new byte[64], "test-cloud-key");
            revocations.add(stored);
            audits.add(audit);
            return stored;
        }

        @Override public List<StoredRevocation> findRevocationsAfter(
                long sequence, Instant activeAt, int limit) {
            return revocations.stream()
                    .filter(value -> value.sequence() > sequence)
                    .limit(limit)
                    .toList();
        }

        @Override public void appendOperatorAudit(OperatorAuditRecord audit) {
            audits.add(audit);
        }

        @Override public StoredRiskPolicyRelease createRiskPolicyRelease(
                RiskPolicyReleaseDraft draft, OperatorAuditRecord audit) {
            StoredRiskPolicyRelease stored = new StoredRiskPolicyRelease(
                    draft, NOW, RiskPolicyReleaseCodec.hash(draft));
            policies.put(draft.policyId(), stored);
            audits.add(audit);
            return stored;
        }

        @Override public StoredPolicyRollout appendPolicyRollout(
                PolicyRolloutDraft draft, OperatorAuditRecord audit) {
            StoredPolicyRollout stored = new StoredPolicyRollout(
                    policyRollouts.size() + 1L, draft, NOW.plusSeconds(policyRollouts.size()));
            policyRollouts.add(stored);
            audits.add(audit);
            return stored;
        }

        @Override public List<StoredRiskPolicyRelease> findRiskPolicyReleases(int limit) {
            return policies.values().stream().limit(limit).toList();
        }

        @Override public List<StoredPolicyRollout> findPolicyRolloutsAfter(long sequence, int limit) {
            return policyRollouts.stream().filter(value -> value.sequence() > sequence).limit(limit).toList();
        }

        @Override public RiskPolicyDeployment findRiskPolicyDeployment() {
            if (policyRollouts.isEmpty()) return RiskPolicyDeployment.builtin();
            StoredPolicyRollout latest = policyRollouts.getLast();
            var baseline = policyRollouts.stream()
                    .filter(value -> value.draft().stage() == PolicyRolloutStage.FULL)
                    .reduce((first, second) -> second)
                    .map(value -> policies.get(value.draft().policyId()).draft().policy())
                    .orElse(com.ellan.mcace.core.risk.RiskPolicy.defaults());
            if (latest.draft().stage() == PolicyRolloutStage.SHADOW
                    || latest.draft().stage() == PolicyRolloutStage.CANARY
                    || latest.draft().stage() == PolicyRolloutStage.BROAD) {
                var candidate = policies.get(latest.draft().policyId()).draft().policy();
                return new RiskPolicyDeployment(
                        baseline, candidate, latest.draft().policyId(), latest.draft().rolloutId(),
                        latest.draft().stage(), latest.draft().percentage());
            }
            return new RiskPolicyDeployment(
                    baseline, null, null, null, latest.draft().stage(), latest.draft().percentage());
        }

        @Override public void appendCloudRiskEvent(
                RiskEventAuditRecord event, RiskPolicyEvaluation evaluation) {
            riskEvents.add(event);
            evaluations.put(event.eventId(), evaluation);
        }

        @Override public void appendRiskFeedback(
                RiskFeedbackDraft value, OperatorAuditRecord audit) {
            feedback.add(value);
            audits.add(audit);
        }

        @Override public PolicyMetrics policyMetrics(String version, Instant from, Instant to) {
            List<RiskPolicyEvaluation> relevant = evaluations.values().stream()
                    .filter(value -> !value.evaluatedAt().isBefore(from) && value.evaluatedAt().isBefore(to))
                    .filter(value -> value.appliedPolicyVersion().equals(version)
                            || value.candidatePolicyVersion().equals(version))
                    .toList();
            long applied = relevant.stream().filter(value -> value.appliedPolicyVersion().equals(version)).count();
            long shadow = relevant.stream().filter(value -> value.candidatePolicyVersion().equals(version)
                    && value.stage() == PolicyRolloutStage.SHADOW).count();
            List<RiskFeedbackDraft> labels = feedback.stream()
                    .filter(value -> relevant.stream().anyMatch(event -> event.eventId().equals(value.eventId())))
                    .toList();
            return new PolicyMetrics(
                    version, from, to, relevant.size(), applied, shadow,
                    riskEvents.stream().filter(value -> relevant.stream()
                            .anyMatch(event -> event.eventId().equals(value.eventId())) && value.corroborated()).count(),
                    labels.size(),
                    labels.stream().filter(value -> value.label() == RiskFeedbackLabel.CONFIRMED_SIGNAL).count(),
                    labels.stream().filter(value -> value.label() == RiskFeedbackLabel.FALSE_POSITIVE).count(),
                    labels.stream().filter(value -> value.label() == RiskFeedbackLabel.INCONCLUSIVE).count());
        }

        @Override public StoredReviewCase createReviewCase(
                ReviewCaseDraft draft, OperatorAuditRecord audit) {
            StoredReviewCase stored = new StoredReviewCase(
                    draft, ReviewStatus.OPEN, "", "", 1, NOW, NOW);
            reviews.put(draft.caseId(), stored);
            audits.add(audit);
            workflowEvents.add(new WorkflowTimelineEvent(
                    UUID.randomUUID(), draft.playerId(), "REVIEW_TRANSITION", draft.caseId(),
                    "", ReviewStatus.OPEN.name(), draft.createdBy(), draft.reason(), "", NOW));
            notifyPlayer(draft.playerId(), "REVIEW_OPENED", draft.caseId(), "Review opened");
            return stored;
        }

        @Override public StoredReviewCase transitionReviewCase(
                ReviewTransition transition, OperatorAuditRecord audit) {
            StoredReviewCase current = reviews.get(transition.caseId());
            if (current == null) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.NOT_FOUND, "review case does not exist");
            if (current.version() != transition.expectedVersion()) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.VERSION_MISMATCH, "review case version does not match");
            if (!current.status().permits(transition.targetStatus())) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.INVALID_TRANSITION, "review transition is not permitted");
            String recommendation = transition.targetStatus() == ReviewStatus.ACTION_RECOMMENDED
                    ? transition.recommendation() : current.recommendation();
            String resolution = switch (transition.targetStatus()) {
                case CLOSED_ACTIONED, CLOSED_NO_ACTION -> transition.reason();
                default -> current.resolution();
            };
            StoredReviewCase stored = new StoredReviewCase(
                    current.draft(), transition.targetStatus(), recommendation, resolution,
                    current.version() + 1, current.createdAt(), NOW.plusSeconds(current.version()));
            reviews.put(transition.caseId(), stored);
            audits.add(audit);
            workflowEvents.add(new WorkflowTimelineEvent(
                    UUID.randomUUID(), current.draft().playerId(), "REVIEW_TRANSITION",
                    transition.caseId(), current.status().name(), transition.targetStatus().name(),
                    transition.actorId(), transition.reason(), transition.recommendation(), stored.updatedAt()));
            notifyPlayer(current.draft().playerId(), "REVIEW_STATUS_CHANGED",
                    transition.caseId(), "Review status updated");
            return stored;
        }

        @Override public StoredAppeal createAppeal(AppealDraft draft, OperatorAuditRecord audit) {
            StoredReviewCase review = reviews.get(draft.caseId());
            if (review == null) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.NOT_FOUND, "review case does not exist");
            if (!review.draft().playerId().equals(draft.playerId())) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.PLAYER_MISMATCH, "player does not match");
            if (review.status() != ReviewStatus.ACTION_RECOMMENDED
                    && review.status() != ReviewStatus.CLOSED_ACTIONED) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.INVALID_TRANSITION, "review is not eligible for appeal");
            StoredAppeal stored = new StoredAppeal(draft, AppealStatus.SUBMITTED, "", 1, NOW, NOW);
            appeals.put(draft.appealId(), stored);
            audits.add(audit);
            workflowEvents.add(new WorkflowTimelineEvent(
                    UUID.randomUUID(), draft.playerId(), "APPEAL_TRANSITION", draft.appealId(),
                    "", AppealStatus.SUBMITTED.name(), draft.submittedBy(), draft.statement(), "", NOW));
            notifyPlayer(draft.playerId(), "APPEAL_SUBMITTED", draft.appealId(), "Appeal submitted");
            return stored;
        }

        @Override public StoredAppeal transitionAppeal(
                AppealTransition transition, OperatorAuditRecord audit) {
            StoredAppeal current = appeals.get(transition.appealId());
            if (current == null) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.NOT_FOUND, "appeal does not exist");
            if (current.version() != transition.expectedVersion()) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.VERSION_MISMATCH, "appeal version does not match");
            if (!current.status().permits(transition.targetStatus())) throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.INVALID_TRANSITION, "appeal transition is not permitted");
            String decision = switch (transition.targetStatus()) {
                case GRANTED, UPHELD -> transition.reason();
                default -> current.decisionReason();
            };
            StoredAppeal stored = new StoredAppeal(
                    current.draft(), transition.targetStatus(), decision, current.version() + 1,
                    current.createdAt(), NOW.plusSeconds(current.version()));
            appeals.put(transition.appealId(), stored);
            audits.add(audit);
            workflowEvents.add(new WorkflowTimelineEvent(
                    UUID.randomUUID(), current.draft().playerId(), "APPEAL_TRANSITION",
                    transition.appealId(), current.status().name(), transition.targetStatus().name(),
                    transition.actorId(), transition.reason(), "", stored.updatedAt()));
            notifyPlayer(current.draft().playerId(), "APPEAL_STATUS_CHANGED",
                    transition.appealId(), "Appeal status updated");
            return stored;
        }

        @Override public PlayerTimeline findPlayerTimeline(UUID playerId, int limit) {
            return new PlayerTimeline(
                    playerId, List.of(),
                    riskEvents.stream().filter(value -> value.playerId().equals(playerId)).limit(limit).toList(),
                    evaluations.values().stream().filter(value -> riskEvents.stream().anyMatch(
                            event -> event.playerId().equals(playerId)
                                    && event.eventId().equals(value.eventId()))).limit(limit).toList(),
                    evidence.stream().filter(value -> value.evidence().playerId().equals(playerId)).limit(limit).toList(),
                    reviews.values().stream().filter(value -> value.draft().playerId().equals(playerId))
                            .limit(limit).toList(),
                    appeals.values().stream().filter(value -> value.draft().playerId().equals(playerId))
                            .limit(limit).toList(),
                    workflowEvents.stream().filter(value -> value.playerId().equals(playerId))
                            .limit(limit).toList());
        }

        @Override public synchronized void createWebHandoff(WebSessionHandoff handoff) {
            handoffs.put(handoff.handoffId(), handoff);
        }

        @Override public synchronized Optional<WebSessionHandoff> consumeWebHandoff(UUID handoffId) {
            return Optional.ofNullable(handoffs.remove(handoffId));
        }

        @Override public synchronized void createWebSession(StoredWebSession session) {
            webSessions.put(hashKey(session.secretSha256()), session);
        }

        @Override public synchronized Optional<StoredWebSession> findActiveWebSession(
                byte[] secretSha256, Instant activeAt) {
            return Optional.ofNullable(webSessions.get(hashKey(secretSha256)))
                    .filter(value -> value.expiresAt().isAfter(activeAt));
        }

        @Override public synchronized void deleteWebSession(UUID sessionId, byte[] secretSha256) {
            String key = hashKey(secretSha256);
            StoredWebSession value = webSessions.get(key);
            if (value != null && value.sessionId().equals(sessionId)) webSessions.remove(key);
        }

        @Override public List<StoredReviewCase> findReviewQueue(int limit) {
            return reviews.values().stream().limit(limit).toList();
        }

        @Override public List<PlayerNotification> findPlayerNotifications(UUID playerId, int limit) {
            return notifications.stream().filter(value -> value.playerId().equals(playerId))
                    .limit(limit).toList();
        }

        @Override public void markPlayerNotificationRead(
                UUID playerId, UUID notificationId, Instant readAt) {
            for (int index = 0; index < notifications.size(); index++) {
                PlayerNotification value = notifications.get(index);
                if (value.playerId().equals(playerId) && value.notificationId().equals(notificationId)
                        && !value.read()) {
                    notifications.set(index, new PlayerNotification(
                            value.notificationId(), value.playerId(), value.type(), value.subjectId(),
                            value.title(), value.message(), value.createdBy(), value.createdAt(), readAt));
                }
            }
        }

        private void notifyPlayer(UUID playerId, String type, UUID subjectId, String title) {
            notifications.add(new PlayerNotification(
                    UUID.randomUUID(), playerId, type, subjectId.toString(), title,
                    "Workflow state changed.", "integration", NOW, null));
        }

        private static String hashKey(byte[] value) {
            return Base64.getEncoder().encodeToString(value);
        }

        private static byte[] digest(byte[] value) {
            try {
                return MessageDigest.getInstance("SHA-256").digest(value);
            } catch (java.security.NoSuchAlgorithmException exception) {
                throw new AssertionError(exception);
            }
        }
    }
}
