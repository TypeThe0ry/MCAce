package com.ellan.mcace.cloud;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

record CloudConfiguration(
        InetSocketAddress bind,
        Path dataDirectory,
        Path serverRegistry,
        String jdbcUrl,
        String databaseUsername,
        String databasePassword,
        Optional<AuditAnchorConfiguration> auditAnchor,
        Optional<URI> webPublicOrigin) {
    CloudConfiguration {
        Objects.requireNonNull(bind, "bind");
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        Objects.requireNonNull(serverRegistry, "serverRegistry");
        Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        Objects.requireNonNull(databaseUsername, "databaseUsername");
        Objects.requireNonNull(databasePassword, "databasePassword");
        auditAnchor = Objects.requireNonNull(auditAnchor, "auditAnchor");
        webPublicOrigin = Objects.requireNonNull(webPublicOrigin, "webPublicOrigin");
    }

    @Override
    public String toString() {
        return "CloudConfiguration[bind=" + bind + ", dataDirectory=" + dataDirectory
                + ", serverRegistry=" + serverRegistry + ", jdbcUrl=" + jdbcUrl
                + ", databaseUsername=" + databaseUsername + ", databasePassword=<redacted>"
                + ", auditAnchor=" + auditAnchor + ", webPublicOrigin=" + webPublicOrigin + "]";
    }

    static CloudConfiguration fromEnvironment(Map<String, String> environment) {
        String host = environment.getOrDefault("MCACE_CLOUD_BIND", "127.0.0.1");
        int port = parsePort(environment.getOrDefault("MCACE_CLOUD_PORT", "8088"));
        InetAddress address;
        try {
            address = InetAddress.getByName(host);
        } catch (UnknownHostException exception) {
            throw new IllegalArgumentException("MCACE_CLOUD_BIND cannot be resolved", exception);
        }
        boolean allowRemote = Boolean.parseBoolean(
                environment.getOrDefault("MCACE_CLOUD_ALLOW_PLAINTEXT_REMOTE", "false"));
        if (!address.isLoopbackAddress() && !allowRemote) {
            throw new IllegalArgumentException(
                    "remote plaintext binding is disabled; use a loopback TLS reverse proxy or explicitly opt in");
        }
        Path data = Path.of(environment.getOrDefault("MCACE_CLOUD_DATA", "data")).toAbsolutePath().normalize();
        Path registry = Path.of(environment.getOrDefault(
                "MCACE_CLOUD_SERVER_REGISTRY", data.resolve("servers.registry").toString()))
                .toAbsolutePath().normalize();
        String jdbcUrl = require(environment, "MCACE_DATABASE_URL");
        String username = require(environment, "MCACE_DATABASE_USERNAME");
        String passwordVariable = environment.getOrDefault(
                "MCACE_DATABASE_PASSWORD_ENV", "MCACE_DATABASE_PASSWORD");
        if (!passwordVariable.matches("[A-Z][A-Z0-9_]{2,63}")) {
            throw new IllegalArgumentException("MCACE_DATABASE_PASSWORD_ENV is invalid");
        }
        String password = require(environment, passwordVariable);
        Optional<AuditAnchorConfiguration> auditAnchor = parseAuditAnchor(environment);
        Optional<URI> webPublicOrigin = parseWebPublicOrigin(environment);
        return new CloudConfiguration(
                new InetSocketAddress(address, port), data, registry, jdbcUrl, username, password,
                auditAnchor, webPublicOrigin);
    }

    private static Optional<URI> parseWebPublicOrigin(Map<String, String> environment) {
        String value = environment.getOrDefault("MCACE_WEB_PUBLIC_ORIGIN", "").strip();
        if (value.isEmpty()) return Optional.empty();
        URI origin;
        try {
            origin = URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("MCACE_WEB_PUBLIC_ORIGIN is invalid", exception);
        }
        if (!"https".equalsIgnoreCase(origin.getScheme()) || origin.getHost() == null
                || origin.getUserInfo() != null || origin.getQuery() != null || origin.getFragment() != null
                || (!origin.getPath().isEmpty() && !"/".equals(origin.getPath()))) {
            throw new IllegalArgumentException(
                    "MCACE_WEB_PUBLIC_ORIGIN must be an HTTPS origin without path, credentials, query, or fragment");
        }
        String host = origin.getHost().toLowerCase(java.util.Locale.ROOT);
        if (host.indexOf(':') >= 0) host = "[" + host + "]";
        int port = origin.getPort();
        String normalized = "https://" + host + (port < 0 || port == 443 ? "" : ":" + port);
        return Optional.of(URI.create(normalized));
    }

    private static Optional<AuditAnchorConfiguration> parseAuditAnchor(Map<String, String> environment) {
        String endpoint = environment.getOrDefault("MCACE_AUDIT_ANCHOR_URL", "").strip();
        if (endpoint.isEmpty()) {
            return Optional.empty();
        }
        String bearerVariable = environment.getOrDefault("MCACE_AUDIT_ANCHOR_BEARER_ENV", "").strip();
        String bearer = "";
        if (!bearerVariable.isEmpty()) {
            if (!bearerVariable.matches("[A-Z][A-Z0-9_]{2,63}")) {
                throw new IllegalArgumentException("MCACE_AUDIT_ANCHOR_BEARER_ENV is invalid");
            }
            bearer = require(environment, bearerVariable);
        }
        Duration interval = Duration.ofSeconds(parseLong(
                environment, "MCACE_AUDIT_ANCHOR_INTERVAL_SECONDS", 300L, 30L, 86_400L));
        Duration timeout = Duration.ofSeconds(parseLong(
                environment, "MCACE_AUDIT_ANCHOR_TIMEOUT_SECONDS", 10L, 1L, 30L));
        Duration lease = Duration.ofSeconds(Math.max(30L, timeout.toSeconds() * 3L));
        Duration retry = Duration.ofSeconds(parseLong(
                environment, "MCACE_AUDIT_ANCHOR_RETRY_SECONDS", 60L, 1L, 3_600L));
        return Optional.of(new AuditAnchorConfiguration(
                URI.create(endpoint), bearer, interval, timeout, lease, retry));
    }

    private static long parseLong(
            Map<String, String> environment, String name, long defaultValue, long minimum, long maximum) {
        String value = environment.getOrDefault(name, Long.toString(defaultValue));
        try {
            long parsed = Long.parseLong(value);
            if (parsed < minimum || parsed > maximum) {
                throw new NumberFormatException("outside range");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " is invalid", exception);
        }
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65_535) throw new NumberFormatException("port range");
            return port;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("MCACE_CLOUD_PORT is invalid", exception);
        }
    }

    private static String require(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }
}
