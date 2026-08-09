package com.ellan.mcace.bungeecord;

import com.ellan.mcace.protocol.ProtocolConstants;

/**
 * Plugin-message channels owned by the MCAce proxy adapter.
 *
 * <p>The adapter consumes client handshake frames locally and forwards only proxy-signed,
 * short-lived admission snapshots to the current backend. A client-originated admission frame is
 * never treated as authoritative.</p>
 */
public final class BungeeMCAceChannels {
    public static final String HANDSHAKE = ProtocolConstants.HANDSHAKE_CHANNEL;
    public static final String ADMISSION = ProtocolConstants.ADMISSION_CHANNEL;
    public static final String PAYLOAD = ProtocolConstants.PAYLOAD_CHANNEL;

    private BungeeMCAceChannels() {
    }
}
