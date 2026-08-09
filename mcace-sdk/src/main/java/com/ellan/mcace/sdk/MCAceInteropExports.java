package com.ellan.mcace.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;

/**
 * Creates the JDK-only provider function used by {@link MCAceInterop} discovery.
 *
 * <p>Server plugins may expose the exact public method documented on {@link MCAceInterop} and return
 * {@code MCAceInteropExports.from(api)}. The returned function is read-only; it has no action, evidence
 * content, storage, or punishment operation.</p>
 *
 * @since 1.0
 */
public final class MCAceInteropExports {
    private MCAceInteropExports() {
    }

    /**
     * Creates a JDK-only interop provider for an MCAce API implementation.
     *
     * @param api source API
     * @return function suitable for the public {@code mcaceInteropV1()} provider method
     */
    public static Function<Map<String, Object>, Map<String, Object>> from(MCAceApi api) {
        Objects.requireNonNull(api, "api");
        return request -> respond(api, request);
    }

    private static Map<String, Object> respond(MCAceApi api, Map<String, Object> request) {
        Map<String, Object> safeRequest = MCAceInteropPayload.requireSafeRequest(request);
        String operation = MCAceInteropPayload.string(safeRequest, MCAceInterop.OPERATION);
        Map<String, Object> response = switch (operation) {
            case MCAceInterop.DESCRIPTOR_OPERATION -> descriptor(api.descriptor());
            case MCAceInterop.SNAPSHOT_OPERATION -> snapshot(api, playerId(safeRequest));
            case MCAceInterop.SESSION_OPERATION -> session(api, playerId(safeRequest));
            case MCAceInterop.EVIDENCE_OPERATION -> evidence(api, playerId(safeRequest));
            default -> Map.of(MCAceInterop.STATUS, MCAceInterop.STATUS_NOT_SUPPORTED);
        };
        return MCAceInteropPayload.requireSafeResponse(response);
    }

    private static UUID playerId(Map<String, Object> request) {
        Object playerId = request.get(MCAceInterop.PLAYER_ID);
        if (!(playerId instanceof UUID uuid)) {
            throw new MCAceInteropException("player_id must be a java.util.UUID");
        }
        return uuid;
    }

    private static Map<String, Object> descriptor(MCAceSdkDescriptor descriptor) {
        List<String> capabilities = descriptor.capabilities().stream()
                .map(Enum::name)
                .sorted()
                .toList();
        return Map.of(
                MCAceInterop.STATUS, MCAceInterop.STATUS_OK,
                "api_major", descriptor.apiVersion().major(),
                "api_minor", descriptor.apiVersion().minor(),
                "capabilities", capabilities);
    }

    private static Map<String, Object> snapshot(MCAceApi api, UUID playerId) {
        return api.snapshot(playerId).<Map<String, Object>>map(snapshot -> {
            List<Map<String, Object>> reasons = new ArrayList<>();
            for (RiskReason reason : snapshot.reasons()) {
                reasons.add(Map.of(
                        "code", reason.code(),
                        "weight", reason.weight(),
                        "source", reason.source(),
                        "observed_at_epoch_ms", reason.observedAt().toEpochMilli(),
                        "corroborated", reason.corroborated()));
            }
            Map<String, Object> response = new LinkedHashMap<>();
            response.put(MCAceInterop.STATUS, MCAceInterop.STATUS_OK);
            response.put(MCAceInterop.PLAYER_ID, snapshot.playerId());
            response.put("trust_level", snapshot.trustLevel().name());
            response.put("admission_status", snapshot.admissionStatus().name());
            response.put("risk_score", snapshot.riskScore());
            response.put("risk_band", snapshot.riskBand().name());
            response.put("policy_version", snapshot.policyVersion());
            response.put("evaluated_at_epoch_ms", snapshot.evaluatedAt().toEpochMilli());
            response.put("reasons", List.copyOf(reasons));
            return Map.copyOf(response);
        }).orElseGet(() -> Map.of(MCAceInterop.STATUS, MCAceInterop.STATUS_NOT_FOUND));
    }

    private static Map<String, Object> session(MCAceApi api, UUID playerId) {
        return api.session(playerId).<Map<String, Object>>map(session -> Map.of(
                MCAceInterop.STATUS, MCAceInterop.STATUS_OK,
                MCAceInterop.PLAYER_ID, session.playerId(),
                "session_id", session.sessionId(),
                "state", session.state().name(),
                "trust_level", session.trustLevel().name(),
                "started_at_epoch_ms", session.startedAt().toEpochMilli(),
                "last_observed_at_epoch_ms", session.lastObservedAt().toEpochMilli()))
                .orElseGet(() -> supports(api, MCAceCapability.SESSION_SUMMARY)
                        ? Map.of(MCAceInterop.STATUS, MCAceInterop.STATUS_NOT_FOUND)
                        : Map.of(MCAceInterop.STATUS, MCAceInterop.STATUS_NOT_SUPPORTED));
    }

    private static Map<String, Object> evidence(MCAceApi api, UUID playerId) {
        EvidenceSummaryPage page = api.evidence(playerId);
        if (page.availability() == EvidenceSummaryAvailability.NOT_SUPPORTED) {
            return Map.of(MCAceInterop.STATUS, MCAceInterop.STATUS_NOT_SUPPORTED);
        }
        List<Map<String, Object>> summaries = new ArrayList<>();
        for (EvidenceSummary summary : page.summaries()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("evidence_id", summary.evidenceId());
            item.put(MCAceInterop.PLAYER_ID, summary.playerId());
            item.put("type", summary.type().name());
            item.put("state", summary.state().name());
            item.put("client_reported", summary.clientReported());
            if (summary.capturedAt() != null) {
                item.put("captured_at_epoch_ms", summary.capturedAt().toEpochMilli());
            }
            if (summary.expiresAt() != null) {
                item.put("expires_at_epoch_ms", summary.expiresAt().toEpochMilli());
            }
            summaries.add(Map.copyOf(item));
        }
        return Map.of(
                MCAceInterop.STATUS, MCAceInterop.STATUS_OK,
                "availability", page.availability().name(),
                "summaries", List.copyOf(summaries));
    }

    private static boolean supports(MCAceApi api, MCAceCapability capability) {
        return api.descriptor().capabilities().contains(capability);
    }
}
