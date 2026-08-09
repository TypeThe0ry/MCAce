package com.ellan.mcace.core.session;

import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.List;
import java.util.Optional;

public record HandshakeAction(
        List<byte[]> outboundFrames,
        Optional<PlayerSecuritySnapshot> snapshot,
        boolean protocolViolation) {
    public HandshakeAction {
        outboundFrames = outboundFrames.stream().map(byte[]::clone).toList();
        snapshot = snapshot == null ? Optional.empty() : snapshot;
    }

    @Override
    public List<byte[]> outboundFrames() {
        return outboundFrames.stream().map(byte[]::clone).toList();
    }

    public static HandshakeAction none() {
        return new HandshakeAction(List.of(), Optional.empty(), false);
    }
}
