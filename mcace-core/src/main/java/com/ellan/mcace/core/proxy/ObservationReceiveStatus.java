package com.ellan.mcace.core.proxy;

/** Transport status only; no value is an admission, routing, kick, or punishment instruction. */
public enum ObservationReceiveStatus {
    START_ACCEPTED,
    CHUNK_ACCEPTED,
    COMPLETED,
    REJECTED_SESSION,
    REJECTED_REPLAY,
    REJECTED_ORDER,
    REJECTED_LIMIT,
    REJECTED_INTEGRITY,
    REJECTED_PAYLOAD
}
