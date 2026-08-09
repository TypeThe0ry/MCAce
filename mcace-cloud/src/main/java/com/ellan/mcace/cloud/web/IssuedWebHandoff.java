package com.ellan.mcace.cloud.web;

import java.time.Instant;
import java.util.Objects;

public record IssuedWebHandoff(String code, String redirectPath, Instant expiresAt) {
    public IssuedWebHandoff {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(redirectPath, "redirectPath");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }
}
