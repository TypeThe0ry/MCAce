package com.ellan.mcace.protocol.transport;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.BoundedPayloadBegin;
import com.ellan.mcace.protocol.generated.BoundedPayloadChunk;
import com.ellan.mcace.protocol.generated.BoundedPayloadCommit;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Creates deterministic bounded fragments; EnvelopeCodec supplies the per-frame signature/nonce. */
public final class BoundedPayloadTransferSender {
    public List<byte[]> send(BoundedPayloadKind kind, String sessionId, byte[] content, byte[] manifestRootSha256,
            long startSequence, EnvelopeCodec codec, PrivateKey privateKey) throws BoundedPayloadException, EnvelopeException {
        Objects.requireNonNull(kind, "kind"); Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(content, "content"); Objects.requireNonNull(manifestRootSha256, "manifestRootSha256");
        Objects.requireNonNull(codec, "codec"); Objects.requireNonNull(privateKey, "privateKey");
        if (sessionId.isBlank() || manifestRootSha256.length != 32 || startSequence <= 0) {
            throw new BoundedPayloadException("invalid bounded payload sender input");
        }
        int chunks = (int) ((content.length + ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES - 1L)
                / ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES);
        BoundedPayloadTransferLimits.validateShape(kind, content.length, chunks);
        if (startSequence > Long.MAX_VALUE - chunks - 1L) throw new BoundedPayloadException("transfer sequence would overflow");
        String transferId = UUID.randomUUID().toString();
        List<byte[]> pieces = new ArrayList<>(chunks); List<byte[]> hashes = new ArrayList<>(chunks);
        for (int offset = 0; offset < content.length; offset += ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES) {
            int length = Math.min(ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES, content.length - offset);
            byte[] piece = java.util.Arrays.copyOfRange(content, offset, offset + length);
            pieces.add(piece); hashes.add(BoundedPayloadTransferLimits.sha256(piece));
        }
        byte[] contentHash = BoundedPayloadTransferLimits.sha256(content);
        byte[] merkle = BoundedPayloadTransferLimits.merkleRoot(hashes);
        List<byte[]> frames = new ArrayList<>(chunks + 2);
        frames.add(frame(codec.sign(PacketType.PAYLOAD_BEGIN, sessionId, BoundedPayloadBegin.newBuilder().setTransferId(transferId)
                .setPayloadKind(kind).setTransportSequence(startSequence).setManifestRootSha256(ByteString.copyFrom(manifestRootSha256))
                .setTotalBytes(content.length).setTotalChunks(chunks).setContentSha256(ByteString.copyFrom(contentHash))
                .setMerkleRootSha256(ByteString.copyFrom(merkle)).build().toByteArray(), privateKey)));
        for (int index = 0; index < chunks; index++) frames.add(frame(codec.sign(PacketType.PAYLOAD_CHUNK, sessionId,
                BoundedPayloadChunk.newBuilder().setTransferId(transferId).setPayloadKind(kind).setTransportSequence(startSequence + index + 1L)
                        .setChunkIndex(index).setContent(ByteString.copyFrom(pieces.get(index))).setChunkSha256(ByteString.copyFrom(hashes.get(index))).build().toByteArray(), privateKey)));
        frames.add(frame(codec.sign(PacketType.PAYLOAD_COMMIT, sessionId, BoundedPayloadCommit.newBuilder().setTransferId(transferId)
                .setPayloadKind(kind).setTransportSequence(startSequence + chunks + 1L).setTotalBytes(content.length).setTotalChunks(chunks)
                .setContentSha256(ByteString.copyFrom(contentHash)).setMerkleRootSha256(ByteString.copyFrom(merkle)).build().toByteArray(), privateKey)));
        return List.copyOf(frames);
    }
    private static byte[] frame(SignedEnvelope envelope) throws BoundedPayloadException {
        byte[] encoded = envelope.toByteArray(); BoundedPayloadTransferLimits.validateFrameBytes(encoded.length); return encoded;
    }
}
