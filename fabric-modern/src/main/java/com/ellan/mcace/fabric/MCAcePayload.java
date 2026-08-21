package com.ellan.mcace.fabric;

import com.ellan.mcace.protocol.ProtocolConstants;
import io.netty.buffer.ByteBuf;
import java.util.Objects;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

public record MCAcePayload(byte[] data) implements CustomPacketPayload {
    public static final Type<MCAcePayload> ID =
            new Type<>(Identifier.fromNamespaceAndPath("mcace", "handshake"));
    public static final StreamCodec<RegistryFriendlyByteBuf, MCAcePayload> CODEC =
            CustomPacketPayload.codec(MCAcePayload::write, MCAcePayload::new);
    static final int MAX_FRAME_BYTES = ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES;

    public MCAcePayload {
        Objects.requireNonNull(data, "data");
        if (data.length > MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce frame exceeds maximum size");
        }
        data = data.clone();
    }

    private MCAcePayload(RegistryFriendlyByteBuf buffer) {
        this(readFrame(buffer));
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    private void write(RegistryFriendlyByteBuf buffer) {
        writeFrame(buffer, data);
    }

    static byte[] readFrame(ByteBuf buffer) {
        int length = buffer.readableBytes();
        if (length > MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce frame exceeds maximum size");
        }
        byte[] frame = new byte[length];
        buffer.readBytes(frame);
        return frame;
    }

    static void writeFrame(ByteBuf buffer, byte[] frame) {
        Objects.requireNonNull(frame, "frame");
        if (frame.length > MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce frame exceeds maximum size");
        }
        buffer.writeBytes(frame);
    }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return ID;
    }
}
