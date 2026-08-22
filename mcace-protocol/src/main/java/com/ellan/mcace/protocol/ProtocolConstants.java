package com.ellan.mcace.protocol;

import java.time.Duration;

public final class ProtocolConstants {
    public static final int CURRENT_VERSION = 1;
    public static final int NONCE_BYTES = 32;
    public static final int MAX_PAYLOAD_BYTES = 1024 * 1024;
    public static final int MAX_EVIDENCE_CHUNK_BYTES = 16 * 1024;
    /** Lowest common Velocity/Bungee plugin-message frame budget, including signed envelope. */
    public static final int MAX_PROXY_PLUGIN_FRAME_BYTES = 30 * 1024;
    /** Backend context is intentionally tiny and contains no artifact or evidence material. */
    public static final int MAX_BACKEND_CONTEXT_FRAME_BYTES = 4 * 1024;
    /** A backend authority frame is content-free and must stay below plugin-message budgets. */
    public static final int MAX_BACKEND_AUTHORITY_FRAME_BYTES = 8 * 1024;
    public static final int MAX_BOUNDED_PAYLOAD_CHUNK_BYTES = 16 * 1024;
    public static final long MAX_AUTH_REQUEST_TRANSFER_BYTES = 1024L * 1024L;
    public static final int MAX_AUTH_REQUEST_TRANSFER_CHUNKS = 64;
    public static final long MAX_ARTIFACT_OBSERVATION_TRANSFER_BYTES = 256L * 1024L;
    public static final int MAX_ARTIFACT_OBSERVATION_TRANSFER_CHUNKS = 16;
    public static final int MAX_ARTIFACT_OBSERVATION_COUNT = 512;
    /** Bound for the signed list of Minecraft resource/shader pack IDs enabled at runtime. */
    public static final int MAX_SELECTED_PACKS = 64;
    public static final int MAX_SELECTED_PACK_ID_CHARS = 256;
    /** Dynamic snapshots are deliberately low-frequency and never run on the render thread. */
    public static final Duration ARTIFACT_OBSERVATION_INTERVAL = Duration.ofMinutes(5);
    public static final Duration MAX_ARTIFACT_OBSERVATION_AGE = Duration.ofMinutes(1);
    public static final Duration DEFAULT_BOUNDED_PAYLOAD_TTL = Duration.ofMinutes(1);
    public static final Duration HEARTBEAT_INTERVAL = Duration.ofSeconds(30);
    public static final Duration HEARTBEAT_STALE_AFTER = HEARTBEAT_INTERVAL.multipliedBy(2);
    public static final Duration HEARTBEAT_MISSING_AFTER = HEARTBEAT_INTERVAL.multipliedBy(3);
    public static final int MAX_HEARTBEAT_CURRENT_SERVER_CHARS = 128;
    public static final long MAX_EVIDENCE_TOTAL_BYTES = 16L * 1024 * 1024;
    public static final long MAX_EVIDENCE_PIXELS = 4_000_000L;
    public static final int MAX_EVIDENCE_CHUNKS = (int) ((MAX_EVIDENCE_TOTAL_BYTES + MAX_EVIDENCE_CHUNK_BYTES - 1)
            / MAX_EVIDENCE_CHUNK_BYTES);
    public static final Duration MAX_EVIDENCE_REQUEST_TTL = Duration.ofMinutes(2);
    public static final long MAX_EVIDENCE_RETENTION_SECONDS = Duration.ofHours(24).toSeconds();
    public static final int MAX_EVIDENCE_RETENTION_POLICY_ID_CHARS = 128;
    public static final int MAX_EVIDENCE_RETENTION_PURPOSE_CHARS = 256;
    /** One outstanding evidence request can consume begin + 1,024 chunks + commit nonces. */
    public static final int MAX_EVIDENCE_REPLAY_ENTRIES_PER_REQUEST = MAX_EVIDENCE_CHUNKS + 2;
    public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(30);
    public static final Duration DEFAULT_REPLAY_WINDOW = Duration.ofMinutes(5);
    /** Enough for 1,000 sessions at 30-second heartbeats over a five-minute window, with headroom. */
    public static final int MAX_NONCE_REPLAY_ENTRIES = 100_000;
    /** 1 + 64 AUTH_REQUEST chunks + BEGIN/COMMIT + ten heartbeats + headroom. */
    public static final int MAX_NONCE_REPLAY_ENTRIES_PER_SESSION = 128;
    public static final Duration AUTH_RESULT_TTL = Duration.ofMinutes(2);
    public static final String HANDSHAKE_CHANNEL = "mcace:handshake";
    public static final String ADMISSION_CHANNEL = "mcace:admission";
    public static final String BACKEND_CONTEXT_CHANNEL = "mcace:context";
    /** Reserved for the disabled-by-default backend authority protocol library. */
    public static final String BACKEND_AUTHORITY_CHANNEL = "mcace:authority";
    public static final String PAYLOAD_CHANNEL = "mcace:payload";
    public static final int FEDERATION_SCHEMA_VERSION = 1;
    public static final Duration MAX_FEDERATION_ASSERTION_TTL = Duration.ofMinutes(5);
    /** Presentation is deliberately well below the common proxy plugin-message budget. */
    public static final int MAX_FEDERATION_PRESENTATION_BYTES = 8 * 1024;
    public static final int MAX_FEDERATION_ID_CHARS = 128;
    public static final int MAX_FEDERATION_DISCLOSURE_CHARS = 256;
    public static final int MAX_FEDERATION_REPLAY_ENTRIES = 10_000;
    public static final Duration MAX_FEDERATION_PRESENTATION_PROOF_AGE = Duration.ofSeconds(30);
    public static final int BACKEND_AUTHORITY_SCHEMA_VERSION = 1;
    public static final Duration MAX_BACKEND_AUTHORITY_TTL = Duration.ofSeconds(30);
    public static final Duration MAX_BACKEND_AUTHORITY_OBSERVATION_AGE = Duration.ofSeconds(30);
    public static final int MAX_BACKEND_AUTHORITY_PROVIDERS = 8;
    public static final int MAX_BACKEND_AUTHORITY_TEXT_CHARS = 128;

    private ProtocolConstants() {
    }
}
