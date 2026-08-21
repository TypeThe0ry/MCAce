package com.ellan.mcace.fabric;

import com.ellan.mcace.protocol.ProtocolConstants;
import io.netty.buffer.ByteBuf;
import java.util.Objects;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/**
 * Advertises the backend-to-proxy context channel without granting the client any authority over it.
 * A correctly configured proxy consumes these frames before they can reach this receiver.
 */
public record MCAceBackendContextPayload(byte[] data) implements CustomPacketPayload {
    public static final Type<MCAceBackendContextPayload> ID =
            new Type<>(Identifier.fromNamespaceAndPath("mcace", "context"));
    public static final StreamCodec<RegistryFriendlyByteBuf, MCAceBackendContextPayload> CODEC =
            CustomPacketPayload.codec(MCAceBackendContextPayload::write, MCAceBackendContextPayload::new);

    public MCAceBackendContextPayload {
        Objects.requireNonNull(data, "data");
        if (data.length > ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce backend context exceeds maximum size");
        }
        data = data.clone();
    }

    private MCAceBackendContextPayload(RegistryFriendlyByteBuf buffer) {
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

    private void write(RegistryFriendlyByteBuf buffer) {
        buffer.writeBytes(data);
    }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return ID;
    }
}
