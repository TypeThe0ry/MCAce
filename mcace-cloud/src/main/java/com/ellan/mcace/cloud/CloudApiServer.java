package com.ellan.mcace.cloud;

import com.ellan.mcace.cloud.auth.ApiScope;
import com.ellan.mcace.cloud.auth.AuthenticatedServer;
import com.ellan.mcace.cloud.auth.AuthenticationException;
import com.ellan.mcace.cloud.auth.CloudAuthenticationService;
import com.ellan.mcace.cloud.auth.IssuedChallenge;
import com.ellan.mcace.cloud.web.EstablishedWebSession;
import com.ellan.mcace.cloud.web.IssuedWebHandoff;
import com.ellan.mcace.cloud.web.WebPortalException;
import com.ellan.mcace.cloud.web.WebPortalService;
import com.ellan.mcace.core.persistence.CloudControlPlaneStore;
import com.ellan.mcace.core.persistence.AppealDraft;
import com.ellan.mcace.core.persistence.AppealStatus;
import com.ellan.mcace.core.persistence.AppealTransition;
import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.persistence.OperatorAuditRecord;
import com.ellan.mcace.core.persistence.PlayerTimeline;
import com.ellan.mcace.core.persistence.PlayerNotification;
import com.ellan.mcace.core.persistence.PolicyMetrics;
import com.ellan.mcace.core.persistence.PolicyRolloutDraft;
import com.ellan.mcace.core.persistence.PolicyRolloutStage;
import com.ellan.mcace.core.persistence.RevocationDraft;
import com.ellan.mcace.core.persistence.RevocationSubjectType;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.RiskFeedbackDraft;
import com.ellan.mcace.core.persistence.RiskFeedbackLabel;
import com.ellan.mcace.core.persistence.RiskPolicyDeployment;
import com.ellan.mcace.core.persistence.RiskPolicyEvaluation;
import com.ellan.mcace.core.persistence.RiskPolicyReleaseDraft;
import com.ellan.mcace.core.persistence.ReviewCaseDraft;
import com.ellan.mcace.core.persistence.ReviewStatus;
import com.ellan.mcace.core.persistence.ReviewTransition;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
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
import com.ellan.mcace.core.persistence.WorkflowConflictException;
import com.ellan.mcace.core.persistence.WorkflowTimelineEvent;
import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.core.risk.PolicyCohortAssigner;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class CloudApiServer implements AutoCloseable {
    private static final int MAX_REQUEST_BYTES = 65_536;
    private static final long MAX_EVIDENCE_BYTES = 10L * 1024 * 1024 * 1024;
    private static final Duration MAX_PAST_OBSERVATION = Duration.ofDays(30);
    private static final Duration MAX_FUTURE_SKEW = Duration.ofMinutes(5);

    private final HttpServer server;
    private final ExecutorService executor;
    private final CloudAuthenticationService authentication;
    private final CloudControlPlaneStore store;
    private final Clock clock;
    private final ObjectMapper json;
    private final WebPortalStore webStore;
    private final WebPortalService webPortal;
    private final URI webPublicOrigin;

    public CloudApiServer(
            InetSocketAddress bind,
            CloudAuthenticationService authentication,
            CloudControlPlaneStore store,
            Clock clock) throws IOException {
        this(bind, authentication, store, null, null, clock);
    }

    public CloudApiServer(
            InetSocketAddress bind,
            CloudAuthenticationService authentication,
            CloudControlPlaneStore store,
            WebPortalStore webStore,
            URI webPublicOrigin,
            Clock clock) throws IOException {
        this.authentication = Objects.requireNonNull(authentication, "authentication");
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.json = createJsonMapper();
        this.webStore = webStore;
        this.webPublicOrigin = webPublicOrigin;
        if ((webStore == null) != (webPublicOrigin == null)) {
            throw new IllegalArgumentException("web portal store and public origin must be configured together");
        }
        this.webPortal = webStore == null ? null
                : new WebPortalService(webStore, clock, new SecureRandom());
        this.server = HttpServer.create(Objects.requireNonNull(bind, "bind"), 128);
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(executor);
        register("/health/live", this::liveness);
        register("/health/ready", this::readiness);
        register("/v1/auth/challenges", this::issueChallenge);
        register("/v1/auth/tokens", this::exchangeToken);
        register("/v1/risk-events", this::ingestRiskEvent);
        register("/v1/evidence-metadata", this::ingestEvidenceMetadata);
        register("/v1/revocations", this::revocations);
        register("/v1/reviews", this::createReview);
        registerPrefix("/v1/reviews/", this::transitionReview);
        register("/v1/appeals", this::createAppeal);
        registerPrefix("/v1/appeals/", this::transitionAppeal);
        registerPrefix("/v1/players/", this::playerTimeline);
        register("/v1/risk-policies", this::riskPolicies);
        register("/v1/policy-rollouts", this::policyRollouts);
        register("/v1/risk-feedback", this::riskFeedback);
        register("/v1/policy-metrics", this::policyMetrics);
        if (webPortal != null) {
            register("/v1/web-handoffs/operator", this::issueOperatorWebHandoff);
            register("/v1/web-handoffs/player", this::issuePlayerWebHandoff);
            register("/web/api/session/exchange", this::exchangeWebSession);
            register("/web/api/session", this::webSession);
            register("/web/api/logout", this::logoutWebSession);
            register("/web/api/operator/reviews", this::operatorReviewQueue);
            registerPrefix("/web/api/operator/reviews/", this::operatorReviewTransition);
            registerPrefix("/web/api/operator/players/", this::operatorPlayerTimeline);
            register("/web/api/player/timeline", this::playerSelfTimeline);
            register("/web/api/player/appeals", this::playerCreateAppeal);
            register("/web/api/player/notifications", this::playerNotifications);
            registerPrefix("/web/api/player/notifications/", this::playerNotificationRead);
            register("/login", this::loginPage);
            register("/dashboard", this::dashboardPage);
            register("/appeal", this::appealPage);
            registerPrefix("/assets/", this::webAsset);
        }
    }

    public void start() {
        server.start();
    }

    public InetSocketAddress address() {
        return server.getAddress();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.close();
    }

    private void register(String path, ExchangeHandler handler) {
        server.createContext(path, new SafeHandler(path, false, handler));
    }

    private void registerPrefix(String path, ExchangeHandler handler) {
        server.createContext(path, new SafeHandler(path, true, handler));
    }

    private void liveness(HttpExchange exchange, UUID requestId) throws IOException, ApiException {
        requireMethod(exchange, "GET");
        writeJson(exchange, 200, Map.of(
                "status", "ok",
                "service", "mcace-cloud",
                "time", clock.instant().toString(),
                "request_id", requestId.toString()));
    }

    private void readiness(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        store.checkHealth();
        writeJson(exchange, 200, Map.of(
                "status", "ready",
                "service", "mcace-cloud",
                "time", clock.instant().toString(),
                "request_id", requestId.toString()));
    }

    private void issueOperatorWebHandoff(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.WEB_OPERATOR_SESSION_WRITE);
        OperatorWebHandoffRequest request = readJson(exchange, OperatorWebHandoffRequest.class);
        Set<WebRole> roles = parseOperatorRoles(request.roles());
        IssuedWebHandoff handoff = webPortal.issueOperator(
                bounded(request.subjectId(), "subject_id", 128), roles,
                bounded(request.redirectPath(), "redirect_path", 128),
                "service:" + principal.serverId());
        writeJson(exchange, 201, handoffResponse(handoff, requestId));
    }

    private void issuePlayerWebHandoff(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.WEB_PLAYER_SESSION_WRITE);
        PlayerWebHandoffRequest request = readJson(exchange, PlayerWebHandoffRequest.class);
        IssuedWebHandoff handoff = webPortal.issuePlayer(
                parseUuid(request.playerUuid(), "player_uuid"),
                bounded(request.redirectPath(), "redirect_path", 128),
                "service:" + principal.serverId());
        writeJson(exchange, 201, handoffResponse(handoff, requestId));
    }

    private void exchangeWebSession(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        requireWebOrigin(exchange);
        WebSessionExchangeRequest request = readJson(exchange, WebSessionExchangeRequest.class);
        EstablishedWebSession established = webPortal.exchange(
                bounded(request.code(), "code", 160));
        long maxAge = Math.max(1L, Duration.between(clock.instant(), established.session().expiresAt()).toSeconds());
        setWebCookies(exchange, established.cookieToken(), established.csrfToken(), maxAge);
        writeJson(exchange, 200, Map.of(
                "principal_type", established.session().principalType().name(),
                "redirect_path", established.redirectPath(),
                "expires_at", established.session().expiresAt().toString(),
                "request_id", requestId.toString()));
    }

    private void webSession(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        StoredWebSession session = requireWebSession(exchange);
        writeJson(exchange, 200, webSessionResponse(session, requestId));
    }

    private void logoutWebSession(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        requireWebOrigin(exchange);
        requireCsrf(exchange);
        String sessionCookie = requireCookie(exchange, "__Host-MCAce-Session");
        webPortal.logout(sessionCookie);
        clearWebCookies(exchange);
        writeJson(exchange, 200, Map.of("status", "logged_out", "request_id", requestId.toString()));
    }

    private void operatorReviewQueue(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        requireWebRole(exchange, WebRole.OPERATOR_VIEWER);
        int limit = parseTimelineLimit(exchange.getRequestURI());
        writeJson(exchange, 200, Map.of(
                "reviews", webStore.findReviewQueue(limit).stream()
                        .map(CloudApiServer::reviewTimelineEntry).toList(),
                "request_id", requestId.toString()));
    }

    private void operatorReviewTransition(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        requireWebOrigin(exchange);
        StoredWebSession session = requireWebRole(exchange, WebRole.OPERATOR_REVIEWER);
        requireCsrf(exchange);
        UUID caseId = parseWorkflowPath(
                exchange.getRequestURI().getPath(), "/web/api/operator/reviews/", "transitions");
        ReviewTransitionRequest request = readJson(exchange, ReviewTransitionRequest.class);
        ReviewStatus target = parseEnum(ReviewStatus.class, request.targetStatus(), "target_status");
        String actor = "web:" + session.subjectId();
        ReviewTransition transition = new ReviewTransition(
                caseId, requirePositiveVersion(request.expectedVersion()), target,
                bounded(request.reason(), "reason", 4_096),
                optionalText(request.recommendation(), "recommendation", 1_024), actor);
        OperatorAuditRecord audit = webAudit(
                actor, requestId, "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId,
                Map.of("target_status", target.name(), "expected_version", transition.expectedVersion()));
        writeJson(exchange, 200, reviewResponse(store.transitionReviewCase(transition, audit), requestId));
    }

    private void operatorPlayerTimeline(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        requireWebRole(exchange, WebRole.OPERATOR_VIEWER);
        UUID playerId = parsePortalPlayerTimelinePath(exchange.getRequestURI().getPath());
        int limit = parseTimelineLimit(exchange.getRequestURI());
        writeJson(exchange, 200,
                playerTimelineResponse(store.findPlayerTimeline(playerId, limit), limit, requestId));
    }

    private void playerSelfTimeline(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        UUID playerId = requirePlayerSession(exchange);
        int limit = parseTimelineLimit(exchange.getRequestURI());
        writeJson(exchange, 200,
                playerTimelineResponse(store.findPlayerTimeline(playerId, limit), limit, requestId));
    }

    private void playerCreateAppeal(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        requireWebOrigin(exchange);
        UUID playerId = requirePlayerSession(exchange);
        requireCsrf(exchange);
        PlayerAppealCreateRequest request = readJson(exchange, PlayerAppealCreateRequest.class);
        UUID appealId = parseUuid(request.appealId(), "appeal_id");
        String actor = "player:" + playerId;
        AppealDraft draft = new AppealDraft(
                appealId, parseUuid(request.caseId(), "case_id"), playerId,
                bounded(request.statement(), "statement", 8_192), actor);
        OperatorAuditRecord audit = webAudit(
                actor, requestId, "APPEAL_SUBMITTED", "APPEAL", appealId,
                Map.of("case_id", draft.caseId().toString(), "source", "PLAYER_SELF_SERVICE"));
        writeJson(exchange, 201, appealResponse(store.createAppeal(draft, audit), requestId));
    }

    private void playerNotifications(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        UUID playerId = requirePlayerSession(exchange);
        int limit = parseTimelineLimit(exchange.getRequestURI());
        writeJson(exchange, 200, Map.of(
                "notifications", webStore.findPlayerNotifications(playerId, limit).stream()
                        .map(CloudApiServer::notificationResponse).toList(),
                "request_id", requestId.toString()));
    }

    private void playerNotificationRead(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        requireWebOrigin(exchange);
        UUID playerId = requirePlayerSession(exchange);
        requireCsrf(exchange);
        UUID notificationId = parseNotificationReadPath(exchange.getRequestURI().getPath());
        webStore.markPlayerNotificationRead(playerId, notificationId, clock.instant());
        writeJson(exchange, 200, Map.of(
                "status", "read", "notification_id", notificationId.toString(),
                "request_id", requestId.toString()));
    }

    private void loginPage(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        serveResource(exchange, "/web/login.html", "text/html; charset=utf-8");
    }

    private void dashboardPage(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        serveResource(exchange, "/web/dashboard.html", "text/html; charset=utf-8");
    }

    private void appealPage(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        serveResource(exchange, "/web/appeal.html", "text/html; charset=utf-8");
    }

    private void webAsset(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        String path = exchange.getRequestURI().getPath();
        String name = path.substring("/assets/".length());
        if (!name.matches("[a-z0-9.-]{1,64}")) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        String contentType;
        if (name.endsWith(".css")) contentType = "text/css; charset=utf-8";
        else if (name.endsWith(".js")) contentType = "text/javascript; charset=utf-8";
        else throw new ApiException(404, "NOT_FOUND", "resource not found");
        serveResource(exchange, "/web/assets/" + name, contentType);
    }

    private void issueChallenge(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        ChallengeRequest request = readJson(exchange, ChallengeRequest.class);
        String serverId = bounded(request.serverId(), "server_id", 64);
        try {
            IssuedChallenge challenge = authentication.issue(serverId);
            writeJson(exchange, 201, Map.of(
                    "challenge_id", challenge.challengeId().toString(),
                    "signing_payload", Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(challenge.signingPayload()),
                    "expires_at", challenge.expiresAt().toString(),
                    "algorithm", "Ed25519",
                    "request_id", requestId.toString()));
        } catch (AuthenticationException exception) {
            throw new ApiException(401, "AUTHENTICATION_FAILED", "server authentication failed");
        }
    }

    private void exchangeToken(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        TokenRequest request = readJson(exchange, TokenRequest.class);
        try {
            String token = authentication.exchange(
                    parseUuid(request.challengeId(), "challenge_id"),
                    bounded(request.serverId(), "server_id", 64),
                    bounded(request.signature(), "signature", 256));
            AuthenticatedServer principal = authentication.authenticate(token);
            writeJson(exchange, 201, Map.of(
                    "access_token", token,
                    "token_type", "Bearer",
                    "expires_at", principal.expiresAt().toString(),
                    "scopes", principal.scopes().stream().map(Enum::name).sorted().toList(),
                    "request_id", requestId.toString()));
        } catch (AuthenticationException | IllegalArgumentException exception) {
            throw new ApiException(401, "AUTHENTICATION_FAILED", "server authentication failed");
        }
    }

    private void ingestRiskEvent(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.RISK_WRITE);
        RiskEventRequest request = readJson(exchange, RiskEventRequest.class);
        RiskEventType type = parseEnum(RiskEventType.class, request.type(), "type");
        ObservationOrigin origin = parseEnum(ObservationOrigin.class, request.origin(), "origin");
        Instant observedAt = boundedObservationTime(request.observedAt(), "observed_at");
        UUID playerId = parseUuid(request.playerUuid(), "player_uuid");
        JsonNode details = requireObject(request.details(), "details");
        String detailsJson = boundedJson(details, "details");
        RiskPolicyDeployment deployment = store.findRiskPolicyDeployment();
        int baselineWeight = deployment.baseline().weights().getOrDefault(type, 0);
        Integer candidateWeight = deployment.candidate() == null
                ? null : deployment.candidate().weights().getOrDefault(type, 0);
        int cohortBucket = deployment.candidatePolicyId() == null
                ? 0 : PolicyCohortAssigner.bucket(
                        playerId, deployment.candidatePolicyId());
        boolean candidateApplied = candidateWeight != null
                && deployment.stage().assignsCandidate()
                && cohortBucket < deployment.percentage() * 100;
        int weight = candidateApplied ? candidateWeight : baselineWeight;
        String appliedVersion = candidateApplied
                ? deployment.candidate().version() : deployment.baseline().version();
        RiskEventAuditRecord event = new RiskEventAuditRecord(
                parseUuid(request.eventId(), "event_id"),
                optionalText(request.sessionId(), "session_id", 256),
                playerId,
                type,
                weight,
                principal.serverId() + ":" + bounded(request.sourceComponent(), "source_component", 64),
                origin,
                requireBoolean(request.corroborated(), "corroborated"),
                observedAt,
                detailsJson);
        RiskPolicyEvaluation evaluation = new RiskPolicyEvaluation(
                event.eventId(), appliedVersion, deployment.baseline().version(),
                deployment.candidate() == null ? "" : deployment.candidate().version(),
                weight, baselineWeight, candidateWeight, deployment.rolloutId(), deployment.stage(),
                cohortBucket, clock.instant());
        store.appendCloudRiskEvent(event, evaluation);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("event_id", event.eventId().toString());
        response.put("assigned_weight", weight);
        response.put("applied_policy_version", appliedVersion);
        response.put("baseline_policy_version", deployment.baseline().version());
        response.put("candidate_policy_version",
                deployment.candidate() == null ? null : deployment.candidate().version());
        response.put("rollout_stage", deployment.stage().name());
        response.put("rollout_percentage", deployment.percentage());
        response.put("cohort_bucket", cohortBucket);
        response.put("enforcement_action", "NONE");
        response.put("request_id", requestId.toString());
        writeJson(exchange, 202, response);
    }

    private void ingestEvidenceMetadata(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.EVIDENCE_WRITE);
        EvidenceRequest request = readJson(exchange, EvidenceRequest.class);
        EvidenceType type = parseEnum(EvidenceType.class, request.evidenceType(), "evidence_type");
        if (type == EvidenceType.EVIDENCE_UNSPECIFIED || type == EvidenceType.UNRECOGNIZED) {
            throw new ApiException(400, "INVALID_REQUEST", "evidence_type has an unsupported value");
        }
        ObservationOrigin origin = parseEnum(ObservationOrigin.class, request.origin(), "origin");
        if (request.contentSize() == null) {
            throw new ApiException(400, "INVALID_REQUEST", "content_size is required");
        }
        long contentSize = request.contentSize();
        if (contentSize < 0 || contentSize > MAX_EVIDENCE_BYTES) {
            throw new ApiException(400, "INVALID_REQUEST", "content_size is outside the allowed range");
        }
        byte[] contentHash = parseSha256(request.contentSha256());
        String storageUri = validateStorageUri(request.storageUri());
        EvidenceMetadataDraft draft = new EvidenceMetadataDraft(
                parseUuid(request.evidenceId(), "evidence_id"),
                parseUuid(request.playerUuid(), "player_uuid"),
                optionalText(request.sessionId(), "session_id", 256),
                type,
                origin,
                boundedObservationTime(request.capturedAt(), "captured_at"),
                contentSize,
                contentHash,
                storageUri,
                principal.serverId());
        StoredEvidenceMetadata stored = store.appendEvidence(draft);
        writeJson(exchange, 201, Map.of(
                "evidence_id", draft.evidenceId().toString(),
                "chain_sequence", stored.chainSequence(),
                "chain_sha256", HexFormat.of().formatHex(stored.chainSha256()),
                "signature", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(stored.serverSignature()),
                "signer_key_id", stored.signerKeyId(),
                "request_id", requestId.toString()));
    }

    private void revocations(HttpExchange exchange, UUID requestId) throws Exception {
        if ("GET".equals(exchange.getRequestMethod())) {
            listRevocations(exchange, requestId);
        } else if ("POST".equals(exchange.getRequestMethod())) {
            createRevocation(exchange, requestId);
        } else {
            throw new ApiException(405, "METHOD_NOT_ALLOWED", "method not allowed");
        }
    }

    private void listRevocations(HttpExchange exchange, UUID requestId) throws Exception {
        requirePrincipal(exchange, ApiScope.REVOCATION_READ);
        long afterSequence = parseAfterSequence(exchange.getRequestURI());
        List<Map<String, Object>> entries = new ArrayList<>();
        for (StoredRevocation stored : store.findRevocationsAfter(afterSequence, clock.instant(), 500)) {
            RevocationDraft draft = stored.revocation();
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("sequence", stored.sequence());
            entry.put("revocation_id", draft.revocationId().toString());
            entry.put("subject_type", draft.subjectType().name());
            entry.put("subject_id", draft.subjectId());
            entry.put("reason_code", draft.reasonCode());
            entry.put("effective_at", draft.effectiveAt().toString());
            entry.put("expires_at", draft.expiresAt() == null ? null : draft.expiresAt().toString());
            entry.put("created_at", stored.createdAt().toString());
            entry.put("payload_sha256", HexFormat.of().formatHex(stored.payloadSha256()));
            entry.put("signature", Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(stored.serverSignature()));
            entry.put("signer_key_id", stored.signerKeyId());
            entries.add(entry);
        }
        writeJson(exchange, 200, Map.of(
                "revocations", entries,
                "enforcement_action", "CONSUMER_POLICY_DECISION",
                "request_id", requestId.toString()));
    }

    private void createRevocation(HttpExchange exchange, UUID requestId) throws Exception {
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.REVOCATION_WRITE);
        RevocationRequest request = readJson(exchange, RevocationRequest.class);
        String reviewTicket = bounded(request.reviewTicket(), "review_ticket", 128);
        String appealUri = validateHttpsUri(request.appealUri(), "appeal_uri");
        String reasonCode = bounded(request.reasonCode(), "reason_code", 64);
        if (!reasonCode.matches("[A-Z0-9_]{3,64}")) {
            throw new ApiException(400, "INVALID_REQUEST", "reason_code has an invalid format");
        }
        Instant effectiveAt = parseInstant(request.effectiveAt(), "effective_at");
        Instant expiresAt = request.expiresAt() == null
                ? null : parseInstant(request.expiresAt(), "expires_at");
        Instant now = clock.instant();
        if (effectiveAt.isBefore(now.minus(Duration.ofDays(30)))
                || effectiveAt.isAfter(now.plus(Duration.ofDays(30)))) {
            throw new ApiException(400, "INVALID_REQUEST", "effective_at is outside the accepted window");
        }
        if (expiresAt != null && !expiresAt.isAfter(effectiveAt)) {
            throw new ApiException(400, "INVALID_REQUEST", "expires_at must follow effective_at");
        }
        RevocationDraft draft = new RevocationDraft(
                parseUuid(request.revocationId(), "revocation_id"),
                parseEnum(RevocationSubjectType.class, request.subjectType(), "subject_type"),
                bounded(request.subjectId(), "subject_id", 256),
                reasonCode,
                effectiveAt,
                expiresAt,
                principal.serverId());
        String auditDetails = json.writeValueAsString(Map.of(
                "request_id", requestId.toString(),
                "review_ticket", reviewTicket,
                "appeal_uri", appealUri));
        OperatorAuditRecord audit = new OperatorAuditRecord(
                UUID.randomUUID(), principal.serverId(), "REVOCATION_CREATED",
                draft.subjectType().name(), draft.subjectId(), clock.instant(), auditDetails);
        StoredRevocation stored = store.appendRevocation(draft, audit);
        writeJson(exchange, 201, Map.of(
                "revocation_id", draft.revocationId().toString(),
                "sequence", stored.sequence(),
                "payload_sha256", HexFormat.of().formatHex(stored.payloadSha256()),
                "signature", Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(stored.serverSignature()),
                "signer_key_id", stored.signerKeyId(),
                "enforcement_action", "DISTRIBUTE_REVOCATION_ONLY",
                "request_id", requestId.toString()));
    }

    private void createReview(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.REVIEW_WRITE);
        ReviewCreateRequest request = readJson(exchange, ReviewCreateRequest.class);
        ReviewCaseDraft draft = new ReviewCaseDraft(
                parseUuid(request.caseId(), "case_id"),
                parseUuid(request.playerUuid(), "player_uuid"),
                bounded(request.title(), "title", 128),
                bounded(request.reason(), "reason", 4_096),
                principal.serverId());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "REVIEW_CREATED", "REVIEW_CASE",
                draft.caseId().toString(), Map.of("player_uuid", draft.playerId().toString()));
        writeJson(exchange, 201, reviewResponse(store.createReviewCase(draft, audit), requestId));
    }

    private void transitionReview(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.REVIEW_WRITE);
        UUID caseId = parseWorkflowPath(exchange.getRequestURI().getPath(), "/v1/reviews/", "transitions");
        ReviewTransitionRequest request = readJson(exchange, ReviewTransitionRequest.class);
        ReviewStatus target = parseEnum(ReviewStatus.class, request.targetStatus(), "target_status");
        String reason = bounded(request.reason(), "reason", 4_096);
        String recommendation = request.recommendation() == null
                ? "" : bounded(request.recommendation(), "recommendation", 1_024);
        ReviewTransition transition = new ReviewTransition(
                caseId, requirePositiveVersion(request.expectedVersion()), target,
                reason, recommendation, principal.serverId());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId.toString(),
                Map.of("target_status", target.name(), "expected_version", transition.expectedVersion()));
        writeJson(exchange, 200, reviewResponse(store.transitionReviewCase(transition, audit), requestId));
    }

    private void createAppeal(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.APPEAL_WRITE);
        AppealCreateRequest request = readJson(exchange, AppealCreateRequest.class);
        AppealDraft draft = new AppealDraft(
                parseUuid(request.appealId(), "appeal_id"),
                parseUuid(request.caseId(), "case_id"),
                parseUuid(request.playerUuid(), "player_uuid"),
                bounded(request.statement(), "statement", 8_192),
                principal.serverId());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "APPEAL_SUBMITTED", "APPEAL", draft.appealId().toString(),
                Map.of("case_id", draft.caseId().toString(), "player_uuid", draft.playerId().toString()));
        writeJson(exchange, 201, appealResponse(store.createAppeal(draft, audit), requestId));
    }

    private void transitionAppeal(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.APPEAL_WRITE);
        UUID appealId = parseWorkflowPath(exchange.getRequestURI().getPath(), "/v1/appeals/", "transitions");
        AppealTransitionRequest request = readJson(exchange, AppealTransitionRequest.class);
        AppealStatus target = parseEnum(AppealStatus.class, request.targetStatus(), "target_status");
        AppealTransition transition = new AppealTransition(
                appealId, requirePositiveVersion(request.expectedVersion()), target,
                bounded(request.reason(), "reason", 4_096), principal.serverId());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "APPEAL_TRANSITIONED", "APPEAL", appealId.toString(),
                Map.of("target_status", target.name(), "expected_version", transition.expectedVersion()));
        writeJson(exchange, 200, appealResponse(store.transitionAppeal(transition, audit), requestId));
    }

    private void playerTimeline(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        requirePrincipal(exchange, ApiScope.TIMELINE_READ);
        UUID playerId = parseTimelinePath(exchange.getRequestURI().getPath());
        int limit = parseTimelineLimit(exchange.getRequestURI());
        PlayerTimeline timeline = store.findPlayerTimeline(playerId, limit);
        writeJson(exchange, 200, playerTimelineResponse(timeline, limit, requestId));
    }

    private Map<String, Object> playerTimelineResponse(
            PlayerTimeline timeline, int limit, UUID requestId) {
        UUID playerId = timeline.playerId();
        List<TimelineEntry> entries = new ArrayList<>();
        Map<UUID, RiskPolicyEvaluation> evaluations = new LinkedHashMap<>();
        timeline.policyEvaluations().forEach(value -> evaluations.put(value.eventId(), value));
        timeline.sessions().forEach(value -> entries.add(new TimelineEntry(value.updatedAt(), Map.ofEntries(
                Map.entry("kind", "SESSION"),
                Map.entry("id", value.sessionId()),
                Map.entry("occurred_at", value.updatedAt().toString()),
                Map.entry("provenance", "SERVER_PERSISTED"),
                Map.entry("server_id", value.serverId()),
                Map.entry("trust_level", value.trustLevel().name()),
                Map.entry("admission_status", value.admissionStatus().name()),
                Map.entry("risk_score", value.riskScore())))));
        timeline.riskEvents().forEach(value -> entries.add(new TimelineEntry(
                value.observedAt(), riskTimelineEntry(value, evaluations.get(value.eventId())))));
        timeline.evidence().forEach(value -> entries.add(new TimelineEntry(value.evidence().capturedAt(), Map.ofEntries(
                Map.entry("kind", "EVIDENCE_METADATA"),
                Map.entry("id", value.evidence().evidenceId().toString()),
                Map.entry("occurred_at", value.evidence().capturedAt().toString()),
                Map.entry("provenance", value.evidence().origin().name()),
                Map.entry("evidence_type", value.evidence().type().name()),
                Map.entry("chain_sequence", value.chainSequence()),
                Map.entry("content_sha256", HexFormat.of().formatHex(value.evidence().contentSha256())),
                Map.entry("signer_key_id", value.signerKeyId())))));
        timeline.workflowEvents().forEach(value -> entries.add(new TimelineEntry(
                value.occurredAt(), workflowTimelineEntry(value))));
        entries.sort(Comparator.comparing(TimelineEntry::occurredAt).reversed()
                .thenComparing(value -> value.body().get("id").toString()));
        return Map.of(
                "player_uuid", playerId.toString(),
                "generated_at", clock.instant().toString(),
                "per_category_limit", limit,
                "events", entries.stream().map(TimelineEntry::body).toList(),
                "current_reviews", timeline.reviews().stream().map(CloudApiServer::reviewTimelineEntry).toList(),
                "current_appeals", timeline.appeals().stream().map(CloudApiServer::appealTimelineEntry).toList(),
                "request_id", requestId.toString());
    }

    private OperatorAuditRecord workflowAudit(
            AuthenticatedServer principal,
            UUID requestId,
            String action,
            String targetType,
            String targetId,
            Map<String, Object> details) throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>(details);
        payload.put("request_id", requestId.toString());
        return new OperatorAuditRecord(
                UUID.randomUUID(), principal.serverId(), action, targetType, targetId,
                clock.instant(), json.writeValueAsString(payload));
    }

    private static Map<String, Object> reviewResponse(StoredReviewCase value, UUID requestId) {
        Map<String, Object> response = new LinkedHashMap<>(reviewTimelineEntry(value));
        response.put("created_at", value.createdAt().toString());
        response.put("request_id", requestId.toString());
        response.put("enforcement_action", "NONE_REVIEW_ONLY");
        return response;
    }

    private static Map<String, Object> appealResponse(StoredAppeal value, UUID requestId) {
        Map<String, Object> response = new LinkedHashMap<>(appealTimelineEntry(value));
        response.put("created_at", value.createdAt().toString());
        response.put("request_id", requestId.toString());
        response.put("enforcement_action", "NONE_APPEAL_DECISION_ONLY");
        return response;
    }

    private static Map<String, Object> reviewTimelineEntry(StoredReviewCase value) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("kind", "REVIEW_CASE");
        entry.put("id", value.draft().caseId().toString());
        entry.put("player_uuid", value.draft().playerId().toString());
        entry.put("occurred_at", value.updatedAt().toString());
        entry.put("provenance", "OPERATOR_AUDIT");
        entry.put("created_by", value.draft().createdBy());
        entry.put("title", value.draft().title());
        entry.put("reason", value.draft().reason());
        entry.put("status", value.status().name());
        entry.put("recommendation", value.recommendation());
        entry.put("resolution", value.resolution());
        entry.put("version", value.version());
        return entry;
    }

    private static Map<String, Object> appealTimelineEntry(StoredAppeal value) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("kind", "APPEAL");
        entry.put("id", value.draft().appealId().toString());
        entry.put("case_id", value.draft().caseId().toString());
        entry.put("player_uuid", value.draft().playerId().toString());
        entry.put("occurred_at", value.updatedAt().toString());
        entry.put("provenance", "TRUSTED_APPEAL_PORTAL");
        entry.put("submitted_by", value.draft().submittedBy());
        entry.put("statement", value.draft().statement());
        entry.put("status", value.status().name());
        entry.put("decision_reason", value.decisionReason());
        entry.put("version", value.version());
        return entry;
    }

    private static Map<String, Object> workflowTimelineEntry(WorkflowTimelineEvent value) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("kind", value.kind());
        entry.put("id", value.eventId().toString());
        entry.put("subject_id", value.subjectId().toString());
        entry.put("occurred_at", value.occurredAt().toString());
        entry.put("provenance", "OPERATOR_AUDIT");
        entry.put("actor_id", value.actorId());
        entry.put("from_status", value.fromStatus());
        entry.put("to_status", value.toStatus());
        entry.put("reason", value.reason());
        entry.put("recommendation", value.recommendation());
        return entry;
    }

    private static Map<String, Object> riskTimelineEntry(
            RiskEventAuditRecord value, RiskPolicyEvaluation evaluation) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("kind", "RISK_EVENT");
        entry.put("id", value.eventId().toString());
        entry.put("occurred_at", value.observedAt().toString());
        entry.put("provenance", value.origin().name());
        entry.put("source", value.source());
        entry.put("corroborated", value.corroborated());
        entry.put("event_type", value.type().name());
        entry.put("weight", value.weight());
        if (evaluation != null) {
            entry.put("applied_policy_version", evaluation.appliedPolicyVersion());
            entry.put("baseline_policy_version", evaluation.baselinePolicyVersion());
            entry.put("candidate_policy_version", evaluation.candidatePolicyVersion().isEmpty()
                    ? null : evaluation.candidatePolicyVersion());
            entry.put("rollout_stage", evaluation.stage().name());
            entry.put("cohort_bucket", evaluation.cohortBucket());
        }
        return entry;
    }

    private void riskPolicies(HttpExchange exchange, UUID requestId) throws Exception {
        if ("GET".equals(exchange.getRequestMethod())) {
            requirePrincipal(exchange, ApiScope.POLICY_READ);
            List<Map<String, Object>> releases = store.findRiskPolicyReleases(500).stream()
                    .map(CloudApiServer::riskPolicyResponse)
                    .toList();
            writeJson(exchange, 200, Map.of(
                    "policies", releases,
                    "request_id", requestId.toString()));
            return;
        }
        if (!"POST".equals(exchange.getRequestMethod())) {
            throw new ApiException(405, "METHOD_NOT_ALLOWED", "method not allowed");
        }
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.POLICY_WRITE);
        PolicyCreateRequest request = readJson(exchange, PolicyCreateRequest.class);
        RiskPolicy policy = new RiskPolicy(
                bounded(request.version(), "version", 64),
                readPolicyWeights(request.weights()),
                requireInteger(request.watchThreshold(), "watch_threshold", 0, 100_000),
                requireInteger(request.restrictedThreshold(), "restricted_threshold", 1, 100_000),
                requireInteger(request.investigationThreshold(), "investigation_threshold", 2, 100_000));
        RiskPolicyReleaseDraft draft = new RiskPolicyReleaseDraft(
                parseUuid(request.policyId(), "policy_id"), policy,
                bounded(request.description(), "description", 1_024), principal.serverId());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "RISK_POLICY_CREATED", "RISK_POLICY", draft.policyId().toString(),
                Map.of("version", policy.version()));
        StoredRiskPolicyRelease stored = store.createRiskPolicyRelease(draft, audit);
        Map<String, Object> response = new LinkedHashMap<>(riskPolicyResponse(stored));
        response.put("request_id", requestId.toString());
        response.put("enforcement_action", "NONE_IMMUTABLE_POLICY_ONLY");
        writeJson(exchange, 201, response);
    }

    private void policyRollouts(HttpExchange exchange, UUID requestId) throws Exception {
        if ("GET".equals(exchange.getRequestMethod())) {
            requirePrincipal(exchange, ApiScope.POLICY_READ);
            long after = parseAfterSequence(exchange.getRequestURI());
            List<Map<String, Object>> rollouts = store.findPolicyRolloutsAfter(after, 500).stream()
                    .map(CloudApiServer::policyRolloutResponse)
                    .toList();
            writeJson(exchange, 200, Map.of(
                    "rollouts", rollouts,
                    "request_id", requestId.toString()));
            return;
        }
        if (!"POST".equals(exchange.getRequestMethod())) {
            throw new ApiException(405, "METHOD_NOT_ALLOWED", "method not allowed");
        }
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.POLICY_WRITE);
        PolicyRolloutRequest request = readJson(exchange, PolicyRolloutRequest.class);
        PolicyRolloutDraft draft = new PolicyRolloutDraft(
                parseUuid(request.rolloutId(), "rollout_id"),
                parseUuid(request.policyId(), "policy_id"),
                parseEnum(PolicyRolloutStage.class, request.stage(), "stage"),
                requireInteger(request.percentage(), "percentage", 0, 100),
                bounded(request.reason(), "reason", 4_096), principal.serverId());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "POLICY_ROLLOUT_APPENDED", "POLICY_ROLLOUT",
                draft.rolloutId().toString(), Map.of(
                        "policy_id", draft.policyId().toString(),
                        "stage", draft.stage().name(),
                        "percentage", draft.percentage()));
        StoredPolicyRollout stored = store.appendPolicyRollout(draft, audit);
        Map<String, Object> response = new LinkedHashMap<>(policyRolloutResponse(stored));
        response.put("request_id", requestId.toString());
        response.put("enforcement_action", "NONE_POLICY_ASSIGNMENT_ONLY");
        writeJson(exchange, 201, response);
    }

    private void riskFeedback(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "POST");
        AuthenticatedServer principal = requirePrincipal(exchange, ApiScope.FEEDBACK_WRITE);
        RiskFeedbackRequest request = readJson(exchange, RiskFeedbackRequest.class);
        RiskFeedbackDraft feedback = new RiskFeedbackDraft(
                parseUuid(request.feedbackId(), "feedback_id"),
                parseUuid(request.eventId(), "event_id"),
                parseUuid(request.reviewCaseId(), "review_case_id"),
                parseEnum(RiskFeedbackLabel.class, request.label(), "label"),
                bounded(request.notes(), "notes", 4_096), principal.serverId(), clock.instant());
        OperatorAuditRecord audit = workflowAudit(
                principal, requestId, "RISK_FEEDBACK_RECORDED", "RISK_FEEDBACK",
                feedback.feedbackId().toString(), Map.of(
                        "event_id", feedback.eventId().toString(),
                        "review_case_id", feedback.reviewCaseId().toString(),
                        "label", feedback.label().name()));
        store.appendRiskFeedback(feedback, audit);
        writeJson(exchange, 201, Map.of(
                "feedback_id", feedback.feedbackId().toString(),
                "label", feedback.label().name(),
                "enforcement_action", "NONE_METRICS_ONLY",
                "request_id", requestId.toString()));
    }

    private void policyMetrics(HttpExchange exchange, UUID requestId) throws Exception {
        requireMethod(exchange, "GET");
        requirePrincipal(exchange, ApiScope.METRICS_READ);
        Map<String, String> query = parseQueryParameters(exchange.getRequestURI());
        if (!query.keySet().equals(java.util.Set.of("version", "from", "to"))) {
            throw new ApiException(400, "INVALID_REQUEST", "version, from, and to are required");
        }
        String version = bounded(query.get("version"), "version", 64);
        Instant from = parseInstant(query.get("from"), "from");
        Instant to = parseInstant(query.get("to"), "to");
        PolicyMetrics metrics = store.policyMetrics(version, from, to);
        long decided = metrics.confirmedSignals() + metrics.falsePositives();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("policy_version", metrics.policyVersion());
        response.put("from", metrics.from().toString());
        response.put("to", metrics.to().toString());
        response.put("evaluated_events", metrics.evaluatedEvents());
        response.put("applied_events", metrics.appliedEvents());
        response.put("shadow_events", metrics.shadowEvents());
        response.put("corroborated_events", metrics.corroboratedEvents());
        response.put("labeled_events", metrics.labeledEvents());
        response.put("confirmed_signals", metrics.confirmedSignals());
        response.put("false_positives", metrics.falsePositives());
        response.put("inconclusive", metrics.inconclusive());
        response.put("false_positive_rate", decided == 0
                ? null : (double) metrics.falsePositives() / decided);
        response.put("minimum_sample_met", decided >= 30);
        response.put("enforcement_action", "NONE_OBSERVABILITY_ONLY");
        response.put("request_id", requestId.toString());
        writeJson(exchange, 200, response);
    }

    private static Map<String, Object> riskPolicyResponse(StoredRiskPolicyRelease stored) {
        Map<String, Integer> weights = new LinkedHashMap<>();
        for (RiskEventType type : RiskEventType.values()) {
            weights.put(type.name(), stored.draft().policy().weights().get(type));
        }
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("policy_id", stored.draft().policyId().toString());
        response.put("version", stored.draft().policy().version());
        response.put("description", stored.draft().description());
        response.put("weights", weights);
        response.put("watch_threshold", stored.draft().policy().watchThreshold());
        response.put("restricted_threshold", stored.draft().policy().restrictedThreshold());
        response.put("investigation_threshold", stored.draft().policy().investigationThreshold());
        response.put("created_by", stored.draft().createdBy());
        response.put("created_at", stored.createdAt().toString());
        response.put("release_sha256", HexFormat.of().formatHex(stored.releaseSha256()));
        return response;
    }

    private static Map<String, Object> policyRolloutResponse(StoredPolicyRollout stored) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sequence", stored.sequence());
        response.put("rollout_id", stored.draft().rolloutId().toString());
        response.put("policy_id", stored.draft().policyId().toString());
        response.put("stage", stored.draft().stage().name());
        response.put("percentage", stored.draft().percentage());
        response.put("reason", stored.draft().reason());
        response.put("created_by", stored.draft().createdBy());
        response.put("created_at", stored.createdAt().toString());
        return response;
    }

    private static Map<RiskEventType, Integer> readPolicyWeights(JsonNode node) throws ApiException {
        if (node == null || !node.isObject()) {
            throw new ApiException(400, "INVALID_REQUEST", "weights must be a JSON object");
        }
        EnumMap<RiskEventType, Integer> weights = new EnumMap<>(RiskEventType.class);
        for (var field : node.properties()) {
            RiskEventType type;
            try {
                type = RiskEventType.valueOf(field.getKey());
            } catch (IllegalArgumentException exception) {
                throw new ApiException(400, "INVALID_REQUEST", "weights contains an unknown event type");
            }
            if (!field.getValue().canConvertToInt() || field.getValue().asInt() < 0
                    || field.getValue().asInt() > 100_000) {
                throw new ApiException(400, "INVALID_REQUEST", "weights contains an invalid value");
            }
            weights.put(type, field.getValue().asInt());
        }
        if (weights.size() != RiskEventType.values().length) {
            throw new ApiException(400, "INVALID_REQUEST", "weights must define every risk event type");
        }
        return Map.copyOf(weights);
    }

    private Map<String, Object> handoffResponse(IssuedWebHandoff handoff, UUID requestId) {
        String loginUrl = webPublicOrigin.resolve("/login").toString() + "#code=" + handoff.code();
        return Map.of(
                "login_url", loginUrl,
                "expires_at", handoff.expiresAt().toString(),
                "one_time", true,
                "request_id", requestId.toString());
    }

    private static Set<WebRole> parseOperatorRoles(Set<String> values) throws ApiException {
        if (values == null || values.isEmpty() || values.size() > 3) {
            throw new ApiException(400, "INVALID_REQUEST", "roles must contain operator roles");
        }
        java.util.EnumSet<WebRole> roles = java.util.EnumSet.noneOf(WebRole.class);
        for (String value : values) {
            WebRole role = parseEnum(WebRole.class, value, "roles");
            if (role == WebRole.PLAYER) {
                throw new ApiException(400, "INVALID_REQUEST", "roles must contain operator roles");
            }
            roles.add(role);
        }
        if (!roles.contains(WebRole.OPERATOR_VIEWER)) {
            throw new ApiException(400, "INVALID_REQUEST", "operator roles require OPERATOR_VIEWER");
        }
        return Set.copyOf(roles);
    }

    private StoredWebSession requireWebSession(HttpExchange exchange) throws Exception {
        return webPortal.authenticate(requireCookie(exchange, "__Host-MCAce-Session"));
    }

    private StoredWebSession requireWebRole(HttpExchange exchange, WebRole role) throws Exception {
        StoredWebSession session = requireWebSession(exchange);
        if (session.principalType() != WebPrincipalType.OPERATOR || !session.permits(role)) {
            throw new ApiException(403, "INSUFFICIENT_ROLE", "the web session lacks the required role");
        }
        return session;
    }

    private UUID requirePlayerSession(HttpExchange exchange) throws Exception {
        StoredWebSession session = requireWebSession(exchange);
        if (session.principalType() != WebPrincipalType.PLAYER
                || !session.permits(WebRole.PLAYER)) {
            throw new ApiException(403, "PLAYER_SELF_ONLY", "a player self-service session is required");
        }
        return UUID.fromString(session.subjectId());
    }

    private void requireWebOrigin(HttpExchange exchange) throws ApiException {
        List<String> origins = exchange.getRequestHeaders().get("Origin");
        if (origins == null || origins.size() != 1 || !webPublicOrigin.toString().equals(origins.getFirst())) {
            throw new ApiException(403, "ORIGIN_REJECTED", "request origin is not permitted");
        }
    }

    private static void requireCsrf(HttpExchange exchange) throws ApiException, WebPortalException {
        List<String> headers = exchange.getRequestHeaders().get("X-MCAce-CSRF");
        if (headers == null || headers.size() != 1) {
            throw new ApiException(403, "CSRF_REJECTED", "CSRF validation failed");
        }
        WebPortalService.requireCsrf(
                requireCookie(exchange, "__Host-MCAce-CSRF"), headers.getFirst());
    }

    private static String requireCookie(HttpExchange exchange, String name) throws ApiException {
        String found = null;
        List<String> headers = exchange.getRequestHeaders().get("Cookie");
        if (headers != null) {
            for (String header : headers) {
                for (String part : header.split(";")) {
                    int separator = part.indexOf('=');
                    if (separator <= 0) continue;
                    String key = part.substring(0, separator).strip();
                    if (!name.equals(key)) continue;
                    String value = part.substring(separator + 1).strip();
                    if (found != null || value.isEmpty() || value.length() > 256) {
                        throw new ApiException(401, "UNAUTHORIZED", "valid web session is required");
                    }
                    found = value;
                }
            }
        }
        if (found == null) {
            throw new ApiException(401, "UNAUTHORIZED", "valid web session is required");
        }
        return found;
    }

    private static void setWebCookies(
            HttpExchange exchange, String sessionToken, String csrfToken, long maxAge) {
        exchange.getResponseHeaders().add("Set-Cookie",
                "__Host-MCAce-Session=" + sessionToken
                        + "; Path=/; Max-Age=" + maxAge + "; Secure; HttpOnly; SameSite=Strict");
        exchange.getResponseHeaders().add("Set-Cookie",
                "__Host-MCAce-CSRF=" + csrfToken
                        + "; Path=/; Max-Age=" + maxAge + "; Secure; SameSite=Strict");
    }

    private static void clearWebCookies(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Set-Cookie",
                "__Host-MCAce-Session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
        exchange.getResponseHeaders().add("Set-Cookie",
                "__Host-MCAce-CSRF=; Path=/; Max-Age=0; Secure; SameSite=Strict");
    }

    private static Map<String, Object> webSessionResponse(StoredWebSession session, UUID requestId) {
        return Map.of(
                "principal_type", session.principalType().name(),
                "subject_id", session.subjectId(),
                "roles", session.roles().stream().map(Enum::name).sorted().toList(),
                "expires_at", session.expiresAt().toString(),
                "request_id", requestId.toString());
    }

    private static Map<String, Object> notificationResponse(PlayerNotification value) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("notification_id", value.notificationId().toString());
        response.put("type", value.type());
        response.put("subject_id", value.subjectId());
        response.put("title", value.title());
        response.put("message", value.message());
        response.put("created_at", value.createdAt().toString());
        response.put("read", value.read());
        response.put("read_at", value.readAt() == null ? null : value.readAt().toString());
        return response;
    }

    private OperatorAuditRecord webAudit(
            String actor,
            UUID requestId,
            String action,
            String targetType,
            UUID targetId,
            Map<String, Object> details) throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>(details);
        payload.put("request_id", requestId.toString());
        payload.put("channel", "WEB_PORTAL");
        return new OperatorAuditRecord(
                UUID.randomUUID(), actor, action, targetType, targetId.toString(),
                clock.instant(), json.writeValueAsString(payload));
    }

    private static UUID parsePortalPlayerTimelinePath(String path) throws ApiException {
        String prefix = "/web/api/operator/players/";
        String suffix = "/timeline";
        if (!path.startsWith(prefix) || !path.endsWith(suffix)) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        String player = path.substring(prefix.length(), path.length() - suffix.length());
        if (player.endsWith("/") || player.indexOf('/') >= 0) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        return parseUuid(player, "player_uuid");
    }

    private static UUID parseNotificationReadPath(String path) throws ApiException {
        String prefix = "/web/api/player/notifications/";
        String suffix = "/read";
        if (!path.startsWith(prefix) || !path.endsWith(suffix)) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        String notification = path.substring(prefix.length(), path.length() - suffix.length());
        if (notification.endsWith("/") || notification.indexOf('/') >= 0) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        return parseUuid(notification, "notification_id");
    }

    private AuthenticatedServer requirePrincipal(HttpExchange exchange, ApiScope scope) throws ApiException {
        List<String> values = exchange.getRequestHeaders().get("Authorization");
        if (values == null || values.size() != 1 || !values.getFirst().startsWith("Bearer ")) {
            throw new ApiException(401, "UNAUTHORIZED", "valid bearer authentication is required");
        }
        String token = values.getFirst().substring("Bearer ".length());
        try {
            AuthenticatedServer principal = authentication.authenticate(token);
            if (!principal.permits(scope)) {
                throw new ApiException(403, "INSUFFICIENT_SCOPE", "the token lacks the required scope");
            }
            return principal;
        } catch (AuthenticationException exception) {
            throw new ApiException(401, "UNAUTHORIZED", "valid bearer authentication is required");
        }
    }

    private <T> T readJson(HttpExchange exchange, Class<T> type) throws IOException, ApiException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
            throw new ApiException(415, "UNSUPPORTED_MEDIA_TYPE", "application/json is required");
        }
        byte[] body = readBounded(exchange);
        if (body.length == 0) throw new ApiException(400, "INVALID_REQUEST", "request body is required");
        try {
            return json.readValue(body, type);
        } catch (com.fasterxml.jackson.core.JacksonException exception) {
            throw new ApiException(400, "INVALID_JSON", "request JSON is invalid");
        }
    }

    private static byte[] readBounded(HttpExchange exchange) throws IOException, ApiException {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8_192];
            int total = 0;
            int read;
            while ((read = exchange.getRequestBody().read(buffer)) != -1) {
                total += read;
                if (total > MAX_REQUEST_BYTES) {
                    throw new ApiException(413, "PAYLOAD_TOO_LARGE", "request body is too large");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private void writeJson(HttpExchange exchange, int status, Object value) throws IOException {
        byte[] encoded = json.writeValueAsBytes(value);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=utf-8");
        setSecurityHeaders(headers);
        exchange.sendResponseHeaders(status, encoded.length);
        exchange.getResponseBody().write(encoded);
        exchange.close();
    }

    private static void serveResource(HttpExchange exchange, String resource, String contentType)
            throws IOException, ApiException {
        byte[] body;
        try (InputStream input = CloudApiServer.class.getResourceAsStream(resource)) {
            if (input == null) throw new ApiException(404, "NOT_FOUND", "resource not found");
            body = input.readAllBytes();
        }
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        setSecurityHeaders(headers);
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static void setSecurityHeaders(Headers headers) {
        headers.set("Cache-Control", "no-store");
        headers.set("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                        + "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
        headers.set("Cross-Origin-Opener-Policy", "same-origin");
        headers.set("Cross-Origin-Resource-Policy", "same-origin");
        headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
    }

    private void writeError(HttpExchange exchange, ApiException exception, UUID requestId) throws IOException {
        writeJson(exchange, exception.status(), Map.of("error", Map.of(
                "code", exception.code(),
                "message", exception.getMessage(),
                "request_id", requestId.toString())));
    }

    private static void requireMethod(HttpExchange exchange, String method) throws ApiException {
        if (!method.equals(exchange.getRequestMethod())) {
            throw new ApiException(405, "METHOD_NOT_ALLOWED", "method not allowed");
        }
    }

    private Instant boundedObservationTime(String value, String field) throws ApiException {
        Instant parsed = parseInstant(value, field);
        Instant now = clock.instant();
        if (parsed.isBefore(now.minus(MAX_PAST_OBSERVATION)) || parsed.isAfter(now.plus(MAX_FUTURE_SKEW))) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is outside the accepted time window");
        }
        return parsed;
    }

    private static UUID parseUuid(String value, String field) throws ApiException {
        try {
            return UUID.fromString(Objects.requireNonNull(value, field));
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is not a valid UUID");
        }
    }

    private static Instant parseInstant(String value, String field) throws ApiException {
        try {
            return Instant.parse(Objects.requireNonNull(value, field));
        } catch (DateTimeParseException | NullPointerException exception) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is not a valid timestamp");
        }
    }

    private static <T extends Enum<T>> T parseEnum(Class<T> type, String value, String field)
            throws ApiException {
        try {
            return Enum.valueOf(type, Objects.requireNonNull(value, field));
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new ApiException(400, "INVALID_REQUEST", field + " has an unsupported value");
        }
    }

    private static String bounded(String value, String field, int maximumLength) throws ApiException {
        if (value == null || value.isBlank() || value.length() > maximumLength) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is blank or too long");
        }
        return value;
    }

    private static String optionalText(String value, String field, int maximumLength) throws ApiException {
        if (value == null) return "";
        if (value.length() > maximumLength) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is too long");
        }
        return value;
    }

    private static boolean requireBoolean(Boolean value, String field) throws ApiException {
        if (value == null) throw new ApiException(400, "INVALID_REQUEST", field + " is required");
        return value;
    }

    private static JsonNode requireObject(JsonNode value, String field) throws ApiException {
        if (value == null || !value.isObject()) {
            throw new ApiException(400, "INVALID_REQUEST", field + " must be a JSON object");
        }
        return value;
    }

    private String boundedJson(JsonNode value, String field) throws IOException, ApiException {
        String encoded = json.writeValueAsString(value);
        if (encoded.getBytes(StandardCharsets.UTF_8).length > 16_384) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is too large");
        }
        return encoded;
    }

    private static byte[] parseSha256(String value) throws ApiException {
        try {
            byte[] decoded = HexFormat.of().parseHex(Objects.requireNonNull(value, "content_sha256"));
            if (decoded.length != 32) throw new IllegalArgumentException("invalid digest length");
            return decoded;
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new ApiException(400, "INVALID_REQUEST", "content_sha256 must be 64 hexadecimal characters");
        }
    }

    private static String validateStorageUri(String value) throws ApiException {
        String bounded = bounded(value, "storage_uri", 1_024);
        URI uri;
        try {
            uri = URI.create(bounded);
        } catch (IllegalArgumentException exception) {
            throw new ApiException(400, "INVALID_REQUEST", "storage_uri is invalid");
        }
        String scheme = uri.getScheme();
        if (scheme == null || !List.of("s3", "gs", "az", "https").contains(scheme.toLowerCase(Locale.ROOT))
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new ApiException(400, "INVALID_REQUEST", "storage_uri uses a forbidden form");
        }
        return bounded;
    }

    private static String validateHttpsUri(String value, String field) throws ApiException {
        String bounded = bounded(value, field, 1_024);
        URI uri;
        try {
            uri = URI.create(bounded);
        } catch (IllegalArgumentException exception) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is invalid");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null) {
            throw new ApiException(400, "INVALID_REQUEST", field + " must be an HTTPS URL");
        }
        return bounded;
    }

    private static long parseAfterSequence(URI uri) throws ApiException {
        String query = uri.getRawQuery();
        if (query == null || query.isBlank()) return 0;
        if (!query.startsWith("after_sequence=") || query.indexOf('&') >= 0) {
            throw new ApiException(400, "INVALID_REQUEST", "unsupported revocation query");
        }
        try {
            long value = Long.parseLong(query.substring("after_sequence=".length()));
            if (value < 0) throw new NumberFormatException("negative");
            return value;
        } catch (NumberFormatException exception) {
            throw new ApiException(400, "INVALID_REQUEST", "after_sequence is invalid");
        }
    }

    private static UUID parseWorkflowPath(String path, String prefix, String suffix) throws ApiException {
        String expectedSuffix = "/" + suffix;
        if (!path.startsWith(prefix) || !path.endsWith(expectedSuffix)) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        String identifier = path.substring(prefix.length(), path.length() - expectedSuffix.length());
        if (identifier.isBlank() || identifier.indexOf('/') >= 0) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        return parseUuid(identifier, prefix.contains("appeals") ? "appeal_id" : "case_id");
    }

    private static UUID parseTimelinePath(String path) throws ApiException {
        String prefix = "/v1/players/";
        String suffix = "/timeline";
        if (!path.startsWith(prefix) || !path.endsWith(suffix)) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        String identifier = path.substring(prefix.length(), path.length() - suffix.length());
        if (identifier.isBlank() || identifier.indexOf('/') >= 0) {
            throw new ApiException(404, "NOT_FOUND", "resource not found");
        }
        return parseUuid(identifier, "player_uuid");
    }

    private static int parseTimelineLimit(URI uri) throws ApiException {
        String query = uri.getRawQuery();
        if (query == null || query.isBlank()) return 100;
        if (!query.startsWith("limit=") || query.indexOf('&') >= 0) {
            throw new ApiException(400, "INVALID_REQUEST", "unsupported timeline query");
        }
        try {
            int value = Integer.parseInt(query.substring("limit=".length()));
            if (value <= 0 || value > 500) throw new NumberFormatException("outside range");
            return value;
        } catch (NumberFormatException exception) {
            throw new ApiException(400, "INVALID_REQUEST", "limit must be between 1 and 500");
        }
    }

    private static long requirePositiveVersion(Long value) throws ApiException {
        if (value == null || value <= 0) {
            throw new ApiException(400, "INVALID_REQUEST", "expected_version must be positive");
        }
        return value;
    }

    private static int requireInteger(Integer value, String field, int minimum, int maximum)
            throws ApiException {
        if (value == null || value < minimum || value > maximum) {
            throw new ApiException(400, "INVALID_REQUEST", field + " is outside the allowed range");
        }
        return value;
    }

    private static Map<String, String> parseQueryParameters(URI uri) throws ApiException {
        String raw = uri.getRawQuery();
        if (raw == null || raw.isBlank() || raw.length() > 2_048) {
            throw new ApiException(400, "INVALID_REQUEST", "query parameters are required");
        }
        Map<String, String> values = new LinkedHashMap<>();
        try {
            for (String part : raw.split("&", -1)) {
                int separator = part.indexOf('=');
                if (separator <= 0 || separator == part.length() - 1) {
                    throw new ApiException(400, "INVALID_REQUEST", "query parameter is malformed");
                }
                String key = URLDecoder.decode(part.substring(0, separator), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(part.substring(separator + 1), StandardCharsets.UTF_8);
                if (values.putIfAbsent(key, value) != null) {
                    throw new ApiException(400, "INVALID_REQUEST", "duplicate query parameter");
                }
            }
            return Map.copyOf(values);
        } catch (IllegalArgumentException exception) {
            throw new ApiException(400, "INVALID_REQUEST", "query parameter encoding is invalid");
        }
    }

    private static ObjectMapper createJsonMapper() {
        JsonFactory factory = JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder()
                        .maxNestingDepth(16)
                        .maxStringLength(16_384)
                        .maxNumberLength(64)
                        .build())
                .build();
        return JsonMapper.builder(factory)
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .build();
    }

    private final class SafeHandler implements HttpHandler {
        private final String path;
        private final boolean prefix;
        private final ExchangeHandler handler;

        private SafeHandler(String path, boolean prefix, ExchangeHandler handler) {
            this.path = path;
            this.prefix = prefix;
            this.handler = handler;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            UUID requestId = UUID.randomUUID();
            exchange.getResponseHeaders().set("X-Request-Id", requestId.toString());
            try {
                if (prefix ? !exchange.getRequestURI().getPath().startsWith(path)
                        : !path.equals(exchange.getRequestURI().getPath())) {
                    throw new ApiException(404, "NOT_FOUND", "resource not found");
                }
                handler.handle(exchange, requestId);
            } catch (ApiException exception) {
                writeError(exchange, exception, requestId);
            } catch (SecurityPersistenceException exception) {
                writeError(exchange, new ApiException(
                        503, "STORAGE_UNAVAILABLE", "control-plane storage is unavailable"), requestId);
            } catch (WorkflowConflictException exception) {
                int status = exception.kind() == WorkflowConflictException.Kind.NOT_FOUND ? 404 : 409;
                String code = exception.kind() == WorkflowConflictException.Kind.NOT_FOUND
                        ? "WORKFLOW_NOT_FOUND" : "WORKFLOW_CONFLICT";
                writeError(exchange, new ApiException(status, code, exception.getMessage()), requestId);
            } catch (WebPortalException exception) {
                int status = exception.kind() == WebPortalException.Kind.CSRF_REJECTED ? 403 : 401;
                String code = switch (exception.kind()) {
                    case INVALID_HANDOFF -> "INVALID_HANDOFF";
                    case INVALID_SESSION -> "UNAUTHORIZED";
                    case CSRF_REJECTED -> "CSRF_REJECTED";
                };
                writeError(exchange, new ApiException(status, code, exception.getMessage()), requestId);
            } catch (IllegalArgumentException exception) {
                writeError(exchange, new ApiException(
                        400, "INVALID_REQUEST", "request validation failed"), requestId);
            } catch (Exception exception) {
                writeError(exchange, new ApiException(
                        500, "INTERNAL_ERROR", "request could not be completed"), requestId);
            }
        }
    }

    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange, UUID requestId) throws Exception;
    }

    private static final class ApiException extends Exception {
        private static final long serialVersionUID = 1L;

        private final int status;
        private final String code;

        private ApiException(int status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }

        private int status() { return status; }
        private String code() { return code; }
    }

    private record ChallengeRequest(String serverId) { }
    private record TokenRequest(String challengeId, String serverId, String signature) { }
    private record OperatorWebHandoffRequest(
            String subjectId, Set<String> roles, String redirectPath) { }
    private record PlayerWebHandoffRequest(String playerUuid, String redirectPath) { }
    private record WebSessionExchangeRequest(String code) { }
    private record PlayerAppealCreateRequest(String appealId, String caseId, String statement) { }
    private record RiskEventRequest(
            String eventId,
            String sessionId,
            String playerUuid,
            String type,
            String sourceComponent,
            String origin,
            Boolean corroborated,
            String observedAt,
            JsonNode details) { }
    private record EvidenceRequest(
            String evidenceId,
            String playerUuid,
            String sessionId,
            String evidenceType,
            String origin,
            String capturedAt,
            Long contentSize,
            String contentSha256,
            String storageUri) { }
    private record RevocationRequest(
            String revocationId,
            String subjectType,
            String subjectId,
            String reasonCode,
            String effectiveAt,
            String expiresAt,
            String reviewTicket,
            String appealUri) { }
    private record ReviewCreateRequest(String caseId, String playerUuid, String title, String reason) { }
    private record ReviewTransitionRequest(
            Long expectedVersion, String targetStatus, String reason, String recommendation) { }
    private record AppealCreateRequest(String appealId, String caseId, String playerUuid, String statement) { }
    private record AppealTransitionRequest(Long expectedVersion, String targetStatus, String reason) { }
    private record PolicyCreateRequest(
            String policyId,
            String version,
            JsonNode weights,
            Integer watchThreshold,
            Integer restrictedThreshold,
            Integer investigationThreshold,
            String description) { }
    private record PolicyRolloutRequest(
            String rolloutId, String policyId, String stage, Integer percentage, String reason) { }
    private record RiskFeedbackRequest(
            String feedbackId, String eventId, String reviewCaseId, String label, String notes) { }
    private record TimelineEntry(Instant occurredAt, Map<String, Object> body) { }
}
