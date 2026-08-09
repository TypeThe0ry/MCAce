package com.ellan.mcace.cloud;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

record AuditAnchorConfiguration(
        URI endpoint,
        String bearerToken,
        Duration interval,
        Duration requestTimeout,
        Duration leaseDuration,
        Duration retryDelay) {
    AuditAnchorConfiguration {
        Objects.requireNonNull(endpoint, "endpoint");
        bearerToken = bearerToken == null ? "" : bearerToken;
        Objects.requireNonNull(interval, "interval");
        Objects.requireNonNull(requestTimeout, "requestTimeout");
        Objects.requireNonNull(leaseDuration, "leaseDuration");
        Objects.requireNonNull(retryDelay, "retryDelay");
    }

    @Override
    public String toString() {
        return "AuditAnchorConfiguration[endpoint=" + endpoint + ", bearerToken=<redacted>, interval="
                + interval + ", requestTimeout=" + requestTimeout + ", leaseDuration="
                + leaseDuration + ", retryDelay=" + retryDelay + "]";
    }
}
