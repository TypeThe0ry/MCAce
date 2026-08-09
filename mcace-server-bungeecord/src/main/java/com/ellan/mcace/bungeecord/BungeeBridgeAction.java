package com.ellan.mcace.bungeecord;

import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** A proxy-transport-neutral result produced by an MCAce session bridge. */
public record BungeeBridgeAction(
        List<byte[]> outboundFrames,
        Optional<PlayerSecuritySnapshot> snapshot,
        boolean protocolViolation) {
    public BungeeBridgeAction {
        Objects.requireNonNull(outboundFrames, "outboundFrames");
        outboundFrames = outboundFrames.stream()
                .map(frame -> Objects.requireNonNull(frame, "outbound frame").clone())
                .toList();
        Objects.requireNonNull(snapshot, "snapshot");
    }

    @Override
    public List<byte[]> outboundFrames() {
        return outboundFrames.stream().map(byte[]::clone).toList();
    }

    public static BungeeBridgeAction none() {
        return new BungeeBridgeAction(List.of(), Optional.empty(), false);
    }
}
