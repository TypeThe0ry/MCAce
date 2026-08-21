package com.ellan.mcace.fabric;

import io.netty.buffer.ByteBuf;
import java.util.Objects;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/** Bounded payload fragments; deliberately separate from the legacy handshake channel. */
public record MCAceTransferPayload(byte[] data) implements CustomPacketPayload {
    public static final Type<MCAceTransferPayload> ID =
            new Type<>(Identifier.fromNamespaceAndPath("mcace", "payload"));
    public static final StreamCodec<RegistryFriendlyByteBuf, MCAceTransferPayload> CODEC =
            CustomPacketPayload.codec(MCAceTransferPayload::write, MCAceTransferPayload::new);

    public MCAceTransferPayload {
        Objects.requireNonNull(data, "data");
        if (data.length == 0 || data.length > MCAcePayload.MAX_FRAME_BYTES) {
            throw new IllegalArgumentException("MCAce payload fragment exceeds maximum size");
        }
        data = data.clone();
    }

    private MCAceTransferPayload(RegistryFriendlyByteBuf buffer) {
        this(MCAcePayload.readFrame(buffer));
    }

    @Override
    public byte[] data() {
        return data.clone();
    }

    private void write(RegistryFriendlyByteBuf buffer) {
        MCAcePayload.writeFrame(buffer, data);
    }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return ID;
    }
}
