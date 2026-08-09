package com.ellan.mcace.fabric;

import com.ellan.mcace.protocol.ProtocolConstants;
import io.netty.buffer.ByteBuf;
import java.util.Objects;
import net.minecraft.network.RegistryByteBuf;
import net.minecraft.network.codec.PacketCodec;
import net.minecraft.network.packet.CustomPayload;
import net.minecraft.util.Identifier;

public record MCAcePayload(byte[] data) implements CustomPayload {
    public static final Id<MCAcePayload> ID = new Id<>(Identifier.of("mcace", "handshake"));
    public static final PacketCodec<RegistryByteBuf, MCAcePayload> CODEC =
            CustomPayload.codecOf(MCAcePayload::write, MCAcePayload::new);
    static final int MAX_FRAME_BYTES = ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES;

    public MCAcePayload {
        Objects.requireNonNull(data, "data");
        if (data.length > MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce frame exceeds maximum size");
        }
        data = data.clone();
    }

    private MCAcePayload(RegistryByteBuf buffer) {
        this(readFrame(buffer));
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    private void write(RegistryByteBuf buffer) {
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
    public Id<? extends CustomPayload> getId() {
        return ID;
    }
}
