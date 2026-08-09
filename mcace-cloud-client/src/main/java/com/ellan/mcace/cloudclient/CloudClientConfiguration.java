package com.ellan.mcace.cloudclient;

import java.net.InetAddress;
import java.net.URI;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.Objects;

public record CloudClientConfiguration(
        URI endpoint,
        String serverId,
        PrivateKey privateKey,
        int queueCapacity,
        Duration requestTimeout) {
    public CloudClientConfiguration {
        Objects.requireNonNull(endpoint, "endpoint");
        serverId = requireBounded(serverId, "serverId", 64);
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(requestTimeout, "requestTimeout");
        if (queueCapacity < 1 || queueCapacity > 65_536) {
            throw new IllegalArgumentException("queueCapacity must be between 1 and 65536");
        }
        if (requestTimeout.isNegative() || requestTimeout.isZero() || requestTimeout.compareTo(Duration.ofMinutes(1)) > 0) {
            throw new IllegalArgumentException("requestTimeout must be between 1 ms and 1 minute");
        }
        validateEndpoint(endpoint);
    }

    private static void validateEndpoint(URI endpoint) {
        if (endpoint.getUserInfo() != null || endpoint.getFragment() != null || endpoint.getQuery() != null) {
            throw new IllegalArgumentException("cloud endpoint must not contain credentials, query, or fragment");
        }
        if (endpoint.getPath() != null && !endpoint.getPath().isEmpty() && !"/".equals(endpoint.getPath())) {
            throw new IllegalArgumentException("cloud endpoint must not contain a path");
        }
        String scheme = endpoint.getScheme();
        if ("https".equalsIgnoreCase(scheme)) {
            return;
        }
        if (!"http".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("cloud endpoint must use HTTPS");
        }
        try {
            InetAddress address = InetAddress.getByName(endpoint.getHost());
            if (!address.isLoopbackAddress()) {
                throw new IllegalArgumentException("plain HTTP is only allowed for loopback test endpoints");
            }
        } catch (Exception exception) {
            if (exception instanceof IllegalArgumentException illegalArgumentException) {
                throw illegalArgumentException;
            }
            throw new IllegalArgumentException("cloud endpoint host cannot be resolved", exception);
        }
    }

    private static String requireBounded(String value, String field, int maximum) {
        Objects.requireNonNull(value, field);
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > maximum) {
            throw new IllegalArgumentException(field + " must contain 1-" + maximum + " characters");
        }
        return normalized;
    }
}
