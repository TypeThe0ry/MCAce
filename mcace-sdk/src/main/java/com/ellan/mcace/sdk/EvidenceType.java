package com.ellan.mcace.sdk;

/** Content category for content-free evidence metadata. @since 1.0 */
public enum EvidenceType {
    /** A game-rendered frame voluntarily supplied through the MCAce client flow. */
    GAME_RENDER_FRAME,
    /** A client-reported integrity or configuration summary. */
    CLIENT_INTEGRITY_SUMMARY,
    /** A server-authenticated protocol or admission record. */
    SERVER_AUTH_RECORD
}
