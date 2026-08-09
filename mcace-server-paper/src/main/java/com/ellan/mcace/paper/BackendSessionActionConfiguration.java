package com.ellan.mcace.paper;

import java.util.Locale;
import java.util.Objects;

/** Explicit, backend-local session-action configuration. The safe default is observational. */
record BackendSessionActionConfiguration(Mode mode, String limitedMessage) {
    static final String DEFAULT_LIMITED_MESSAGE = "MCAce: this session has limited access. Please reconnect or contact staff.";

    BackendSessionActionConfiguration {
        Objects.requireNonNull(mode, "mode");
        limitedMessage = Objects.requireNonNull(limitedMessage, "limitedMessage").strip();
        if (limitedMessage.isEmpty() || limitedMessage.length() > 160
                || limitedMessage.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("session-actions.limited-message must be 1..160 printable characters");
        }
    }

    static BackendSessionActionConfiguration monitor() {
        return new BackendSessionActionConfiguration(Mode.MONITOR, DEFAULT_LIMITED_MESSAGE);
    }

    static BackendSessionActionConfiguration parse(String mode, String limitedMessage) {
        String normalized = mode == null ? "MONITOR" : mode.strip().toUpperCase(Locale.ROOT);
        return new BackendSessionActionConfiguration(Mode.valueOf(normalized),
                limitedMessage == null || limitedMessage.isBlank() ? DEFAULT_LIMITED_MESSAGE : limitedMessage);
    }

    enum Mode { MONITOR, SESSION_ACTIONS }
}
