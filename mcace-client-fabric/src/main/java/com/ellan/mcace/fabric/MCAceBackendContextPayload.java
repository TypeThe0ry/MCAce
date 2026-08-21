package com.ellan.mcace.fabric;

import com.ellan.mcace.protocol.ProtocolConstants;
import io.netty.buffer.ByteBuf;
import java.util.Objects;
import net.minecraft.network.RegistryByteBuf;
import net.minecraft.network.codec.PacketCodec;
import net.minecraft.network.packet.CustomPayload;
import net.minecraft.util.Identifier;

/**
 * Advertises the backend-to-proxy context channel without granting the client any authority over it.
 * A correctly configured proxy consumes these frames before they can reach this receiver.
 */
public record MCAceBackendContextPayload(byte[] data) implements CustomPayload {
    public static final Id<MCAceBackendContextPayload> ID = new Id<>(Identifier.of("mcace", "context"));
    public static final PacketCodec<RegistryByteBuf, MCAceBackendContextPayload> CODEC =
            CustomPayload.codecOf(MCAceBackendContextPayload::write, MCAceBackendContextPayload::new);

    public MCAceBackendContextPayload {
        Objects.requireNonNull(data, "data");
        if (data.length > ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce backend context exceeds maximum size");
        }
        data = data.clone();
    }

    private MCAceBackendContextPayload(RegistryByteBuf buffer) {
        this(readFrame(buffer));
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    private static byte[] readFrame(ByteBuf buffer) {
        int length = buffer.readableBytes();
        if (length > ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce backend context exceeds maximum size");
        }
        byte[] frame = new byte[length];
        buffer.readBytes(frame);
        return frame;
    }

    private void write(RegistryByteBuf buffer) {
        buffer.writeBytes(data);
    }

    @Override
    public Id<? extends CustomPayload> getId() {
        return ID;
    }
}
