package com.ellan.mcace.cloudclient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public final class CloudRiskEventClient implements AutoCloseable {
    private static final Duration TOKEN_SAFETY_MARGIN = Duration.ofSeconds(10);
    private static final int MAX_JSON_BYTES = 65_536;

    private final CloudClientConfiguration configuration;
    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final Consumer<String> diagnosticSink;
    private final ArrayBlockingQueue<CloudRiskEvent> queue;
    private final ExecutorService worker;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong delivered = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private volatile AccessToken accessToken;

    public CloudRiskEventClient(CloudClientConfiguration configuration, Consumer<String> diagnosticSink) {
        this(configuration,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
                new ObjectMapper(), Clock.systemUTC(), diagnosticSink);
    }

    CloudRiskEventClient(
            CloudClientConfiguration configuration,
            HttpClient httpClient,
            ObjectMapper mapper,
            Clock clock,
            Consumer<String> diagnosticSink) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.diagnosticSink = Objects.requireNonNull(diagnosticSink, "diagnosticSink");
        this.queue = new ArrayBlockingQueue<>(configuration.queueCapacity());
        this.worker = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "mcace-cloud-risk-uploader");
            thread.setDaemon(true);
            return thread;
        });
        worker.submit(this::runWorker);
    }

    public boolean submit(CloudRiskEvent event) {
        Objects.requireNonNull(event, "event");
        if (!running.get() || !queue.offer(event)) {
            dropped.incrementAndGet();
            return false;
        }
        accepted.incrementAndGet();
        return true;
    }

    public Statistics statistics() {
        return new Statistics(accepted.get(), dropped.get(), delivered.get(), failed.get(), queue.size());
    }

    @Override
    public void close() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        worker.shutdown();
        try {
            if (!worker.awaitTermination(5, TimeUnit.SECONDS)) {
                worker.shutdownNow();
            }
        } catch (InterruptedException exception) {
            worker.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void runWorker() {
        while (running.get() || !queue.isEmpty()) {
            try {
                CloudRiskEvent event = queue.poll(250, TimeUnit.MILLISECONDS);
                if (event != null) {
                    deliver(event);
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return;
            } catch (RuntimeException exception) {
                failed.incrementAndGet();
                diagnosticSink.accept("MCAce Cloud risk upload failed: " + safeMessage(exception));
            }
        }
    }

    private void deliver(CloudRiskEvent event) {
        try {
            CloudResponse response = sendRiskEvent(event, token());
            if (response.statusCode() == 401) {
                accessToken = null;
                response = sendRiskEvent(event, token());
            }
            if (response.statusCode() != 202) {
                throw new CloudClientException("risk endpoint returned HTTP " + response.statusCode());
            }
            JsonNode body = mapper.readTree(response.body());
            if (!"NONE".equals(body.path("enforcement_action").asText())) {
                throw new CloudClientException("cloud returned an unsupported enforcement action");
            }
            delivered.incrementAndGet();
        } catch (IOException | InterruptedException | GeneralSecurityException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            failed.incrementAndGet();
            diagnosticSink.accept("MCAce Cloud risk upload failed: " + safeMessage(exception));
        }
    }

    private CloudResponse sendRiskEvent(CloudRiskEvent event, String token)
            throws IOException, InterruptedException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("event_id", event.eventId().toString());
        if (!event.sessionId().isEmpty()) {
            payload.put("session_id", event.sessionId());
        }
        payload.put("player_uuid", event.playerId().toString());
        payload.put("type", event.type().name());
        payload.put("source_component", event.sourceComponent());
        payload.put("origin", event.origin().name());
        payload.put("corroborated", event.corroborated());
        payload.put("observed_at", event.observedAt().toString());
        payload.put("details", event.details());
        return post("/v1/risk-events", mapper.writeValueAsString(payload), token);
    }

    private synchronized String token()
            throws IOException, InterruptedException, GeneralSecurityException {
        Instant now = clock.instant();
        AccessToken cached = accessToken;
        if (cached != null && now.plus(TOKEN_SAFETY_MARGIN).isBefore(cached.expiresAt())) {
            return cached.value();
        }
        CloudResponse challengeResponse = post(
                "/v1/auth/challenges",
                mapper.writeValueAsString(Map.of("server_id", configuration.serverId())), null);
        if (challengeResponse.statusCode() != 201) {
            throw new CloudClientException("challenge endpoint returned HTTP " + challengeResponse.statusCode());
        }
        JsonNode challenge = mapper.readTree(challengeResponse.body());
        byte[] payload = decodeBase64Url(challenge.path("signing_payload").asText());
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(configuration.privateKey());
        signer.update(payload);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        Map<String, String> request = Map.of(
                "challenge_id", challenge.path("challenge_id").asText(),
                "server_id", configuration.serverId(),
                "signature", signature);
        CloudResponse tokenResponse = post(
                "/v1/auth/tokens", mapper.writeValueAsString(request), null);
        if (tokenResponse.statusCode() != 201) {
            throw new CloudClientException("token endpoint returned HTTP " + tokenResponse.statusCode());
        }
        JsonNode tokenBody = mapper.readTree(tokenResponse.body());
        AccessToken issued = new AccessToken(
                requiredText(tokenBody, "access_token"),
                Instant.parse(requiredText(tokenBody, "expires_at")));
        accessToken = issued;
        return issued.value();
    }

    private CloudResponse post(String path, String json, String token)
            throws IOException, InterruptedException {
        URI uri = configuration.endpoint().resolve(path);
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        if (body.length > MAX_JSON_BYTES) {
            throw new CloudClientException("cloud JSON request exceeds " + MAX_JSON_BYTES + " bytes");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(configuration.requestTimeout())
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        HttpResponse<InputStream> response = httpClient.send(
                builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream input = response.body()) {
            byte[] responseBody = input.readNBytes(MAX_JSON_BYTES + 1);
            if (responseBody.length > MAX_JSON_BYTES) {
                throw new CloudClientException("cloud JSON response exceeds " + MAX_JSON_BYTES + " bytes");
            }
            return new CloudResponse(response.statusCode(), new String(responseBody, StandardCharsets.UTF_8));
        }
    }

    private static String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText();
        if (value.isBlank()) {
            throw new CloudClientException("cloud response omitted " + field);
        }
        return value;
    }

    private static byte[] decodeBase64Url(String value) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException exception) {
            throw new CloudClientException("invalid cloud challenge payload");
        }
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }

    public record Statistics(long accepted, long dropped, long delivered, long failed, int queued) { }

    private record AccessToken(String value, Instant expiresAt) { }

    private record CloudResponse(int statusCode, String body) { }

    private static final class CloudClientException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private CloudClientException(String message) {
            super(message);
        }
    }
}
