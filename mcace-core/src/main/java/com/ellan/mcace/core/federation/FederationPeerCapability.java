package com.ellan.mcace.core.federation;

/** Least-privilege direction granted to one offline-pinned peer. */
public enum FederationPeerCapability {
    /** This local network may issue a client-carried grant addressed to the peer. */
    ISSUE_TO,
    /** This local network may accept and observe a client-carried grant signed by the peer. */
    ACCEPT_FROM
}
