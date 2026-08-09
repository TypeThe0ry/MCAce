package com.ellan.mcace.sdk;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Internal bounded parser for the JDK-only interop wire maps. */
final class MCAceInteropPayload {
    private static final int MAX_MAP_ENTRIES = 32;
    private static final int MAX_LIST_ENTRIES = SdkValidation.MAX_SUMMARIES;
    private static final int MAX_TEXT_LENGTH = SdkValidation.MAX_TEXT_LENGTH;
    private static final int MAX_DEPTH = 4;

    private MCAceInteropPayload() {
    }

    static Map<String, Object> requireSafeRequest(Map<String, Object> request) {
        return safeMap(Objects.requireNonNull(request, "request"), 0);
    }

    static Map<String, Object> requireSafeResponse(Object response) {
        if (!(response instanceof Map<?, ?> map)) {
            throw new MCAceInteropException("interop response must be a java.util.Map");
        }
        return safeMap(map, 0);
    }

    static MCAceSdkDescriptor readDescriptor(Map<String, Object> response) {
        requireOk(response);
        int major = integer(response, "api_major");
        int minor = integer(response, "api_minor");
        Object rawCapabilities = response.get("capabilities");
        if (!(rawCapabilities instanceof List<?> list)) {
            throw new MCAceInteropException("interop descriptor capabilities must be a list");
        }
        Set<MCAceCapability> capabilities = new HashSet<>();
        for (Object value : list) {
            if (!(value instanceof String name)) {
                throw new MCAceInteropException("interop descriptor capability must be text");
            }
            try {
                capabilities.add(MCAceCapability.valueOf(name));
            } catch (IllegalArgumentException exception) {
                throw new MCAceInteropException("unknown interop capability: " + name, exception);
            }
        }
        return new MCAceSdkDescriptor(new MCAceSdkVersion(major, minor), capabilities);
    }

    static MCAceInteropSnapshot readSnapshot(Map<String, Object> response) {
        requireOk(response);
        return new MCAceInteropSnapshot(
                uuid(response, MCAceInterop.PLAYER_ID),
                string(response, "trust_level"),
                string(response, "admission_status"),
                integer(response, "risk_score"),
                string(response, "risk_band"),
                string(response, "policy_version"),
                nonNegativeLong(response, "evaluated_at_epoch_ms"),
                readReasons(response));
    }

    static MCAceInteropSessionSummary readSession(Map<String, Object> response) {
        requireOk(response);
        return new MCAceInteropSessionSummary(
                uuid(response, MCAceInterop.PLAYER_ID),
                uuid(response, "session_id"),
                string(response, "state"),
                string(response, "trust_level"),
                nonNegativeLong(response, "started_at_epoch_ms"),
                nonNegativeLong(response, "last_observed_at_epoch_ms"));
    }

    static EvidenceSummaryPage readEvidence(Map<String, Object> response) {
        String status = status(response);
        if (MCAceInterop.STATUS_NOT_SUPPORTED.equals(status)) {
            return EvidenceSummaryPage.notSupported();
        }
        requireOk(response);
        String availabilityName = string(response, "availability");
        EvidenceSummaryAvailability availability;
        try {
            availability = EvidenceSummaryAvailability.valueOf(availabilityName);
        } catch (IllegalArgumentException exception) {
            throw new MCAceInteropException("unknown evidence availability: " + availabilityName, exception);
        }
        Object rawSummaries = response.get("summaries");
        if (!(rawSummaries instanceof List<?> list)) {
            throw new MCAceInteropException("evidence summaries must be a list");
        }
        List<EvidenceSummary> summaries = new ArrayList<>();
        for (Object rawSummary : list) {
            if (!(rawSummary instanceof Map<?, ?> map)) {
                throw new MCAceInteropException("evidence summary must be a map");
            }
            Map<String, Object> summary = safeMap(map, 1);
            summaries.add(new EvidenceSummary(
                    uuid(summary, "evidence_id"),
                    uuid(summary, MCAceInterop.PLAYER_ID),
                    enumValue(summary, "type", EvidenceType.class),
                    enumValue(summary, "state", EvidenceState.class),
                    bool(summary, "client_reported"),
                    optionalEpoch(summary, "captured_at_epoch_ms"),
                    optionalEpoch(summary, "expires_at_epoch_ms")));
        }
        return new EvidenceSummaryPage(availability, summaries);
    }

    static String status(Map<String, Object> response) {
        return string(response, MCAceInterop.STATUS);
    }

    static String string(Map<String, Object> value, String key) {
        Object field = value.get(key);
        if (!(field instanceof String text)) {
            throw new MCAceInteropException(key + " must be text");
        }
        return requireText(text, key);
    }

    static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        return SdkValidation.boundedText(value, name);
    }

    static String requireToken(String value, String name) {
        value = requireText(value, name);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(character >= 'A' && character <= 'Z')
                    && !(character >= '0' && character <= '9')
                    && character != '_') {
                throw new IllegalArgumentException(name + " must be an uppercase token");
            }
        }
        return value;
    }

    private static List<MCAceInteropRiskReason> readReasons(Map<String, Object> response) {
        Object rawReasons = response.get("reasons");
        if (!(rawReasons instanceof List<?> list)) {
            throw new MCAceInteropException("reasons must be a list");
        }
        List<MCAceInteropRiskReason> reasons = new ArrayList<>();
        for (Object rawReason : list) {
            if (!(rawReason instanceof Map<?, ?> map)) {
                throw new MCAceInteropException("reason must be a map");
            }
            Map<String, Object> reason = safeMap(map, 1);
            reasons.add(new MCAceInteropRiskReason(
                    string(reason, "code"),
                    integer(reason, "weight"),
                    string(reason, "source"),
                    nonNegativeLong(reason, "observed_at_epoch_ms"),
                    bool(reason, "corroborated")));
        }
        return List.copyOf(reasons);
    }

    private static void requireOk(Map<String, Object> response) {
        if (!MCAceInterop.STATUS_OK.equals(status(response))) {
            throw new MCAceInteropException("expected an ok interop response");
        }
    }

    private static int integer(Map<String, Object> value, String key) {
        Object field = value.get(key);
        if (!(field instanceof Integer integer)) {
            throw new MCAceInteropException(key + " must be an Integer");
        }
        if (integer < 0) {
            throw new MCAceInteropException(key + " must not be negative");
        }
        return integer;
    }

    private static long nonNegativeLong(Map<String, Object> value, String key) {
        Object field = value.get(key);
        if (!(field instanceof Long number) || number < 0) {
            throw new MCAceInteropException(key + " must be a non-negative Long");
        }
        return number;
    }

    private static java.time.Instant optionalEpoch(Map<String, Object> value, String key) {
        if (!value.containsKey(key)) {
            return null;
        }
        try {
            return java.time.Instant.ofEpochMilli(nonNegativeLong(value, key));
        } catch (java.time.DateTimeException exception) {
            throw new MCAceInteropException(key + " is outside Instant range", exception);
        }
    }

    private static UUID uuid(Map<String, Object> value, String key) {
        Object field = value.get(key);
        if (!(field instanceof UUID uuid)) {
            throw new MCAceInteropException(key + " must be a java.util.UUID");
        }
        return uuid;
    }

    private static boolean bool(Map<String, Object> value, String key) {
        Object field = value.get(key);
        if (!(field instanceof Boolean bool)) {
            throw new MCAceInteropException(key + " must be a Boolean");
        }
        return bool;
    }

    private static <T extends Enum<T>> T enumValue(Map<String, Object> value, String key, Class<T> enumType) {
        try {
            return Enum.valueOf(enumType, string(value, key));
        } catch (IllegalArgumentException exception) {
            throw new MCAceInteropException("unknown " + key, exception);
        }
    }

    private static Map<String, Object> safeMap(Map<?, ?> raw, int depth) {
        if (depth > MAX_DEPTH || raw.size() > MAX_MAP_ENTRIES) {
            throw new MCAceInteropException("interop map exceeds its budget");
        }
        Map<String, Object> safe = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (!(entry.getKey() instanceof String key) || key.isBlank() || key.length() > MAX_TEXT_LENGTH) {
                throw new MCAceInteropException("interop map keys must be bounded non-blank text");
            }
            safe.put(key, safeValue(entry.getValue(), depth + 1));
        }
        return Map.copyOf(safe);
    }

    private static Object safeValue(Object value, int depth) {
        if (value instanceof String text) {
            return requireText(text, "interop text");
        }
        if (value instanceof Integer || value instanceof Long || value instanceof Boolean || value instanceof UUID) {
            return value;
        }
        if (value instanceof Map<?, ?> map) {
            return safeMap(map, depth);
        }
        if (value instanceof List<?> list) {
            if (depth > MAX_DEPTH || list.size() > MAX_LIST_ENTRIES) {
                throw new MCAceInteropException("interop list exceeds its budget");
            }
            List<Object> safe = new ArrayList<>();
            for (Object item : list) {
                safe.add(safeValue(item, depth + 1));
            }
            return List.copyOf(safe);
        }
        throw new MCAceInteropException("interop payload contains a non-JDK or unsupported value");
    }
}
