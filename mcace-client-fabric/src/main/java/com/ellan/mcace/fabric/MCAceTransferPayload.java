package com.ellan.mcace.fabric;

import io.netty.buffer.ByteBuf;
import java.util.Objects;
import net.minecraft.network.RegistryByteBuf;
import net.minecraft.network.codec.PacketCodec;
import net.minecraft.network.packet.CustomPayload;
import net.minecraft.util.Identifier;

/** Bounded payload fragments; deliberately separate from the legacy handshake channel. */
public record MCAceTransferPayload(byte[] data) implements CustomPayload {
    public static final Id<MCAceTransferPayload> ID = new Id<>(Identifier.of("mcace", "payload"));
    public static final PacketCodec<RegistryByteBuf, MCAceTransferPayload> CODEC =
            CustomPayload.codecOf(MCAceTransferPayload::write, MCAceTransferPayload::new);

    public MCAceTransferPayload {
        Objects.requireNonNull(data, "data");
        if (data.length == 0 || data.length > MCAcePayload.MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce payload fragment exceeds maximum size");
        }
        data = data.clone();
    }

    private MCAceTransferPayload(RegistryByteBuf buffer) {
        this(MCAcePayload.readFrame(buffer));
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    private void write(RegistryByteBuf buffer) {
        MCAcePayload.writeFrame(buffer, data);
    }

    @Override
    public Id<? extends CustomPayload> getId() {
        return ID;
    }
}
