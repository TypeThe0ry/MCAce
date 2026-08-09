package com.ellan.mcace.cloud.web;

import com.ellan.mcace.core.persistence.StoredWebSession;
import java.util.Objects;

public record EstablishedWebSession(
        StoredWebSession session,
        String cookieToken,
        String csrfToken,
        String redirectPath) {
    public EstablishedWebSession {
        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(cookieToken, "cookieToken");
        Objects.requireNonNull(csrfToken, "csrfToken");
        Objects.requireNonNull(redirectPath, "redirectPath");
    }
}
