package com.ellan.mcace.core.session;

public enum SessionStage {
    CONNECTING,
    CHALLENGE_SENT,
    CLIENT_IDENTIFIED,
    AUTHENTICATED,
    EXPIRED,
    REJECTED
}
