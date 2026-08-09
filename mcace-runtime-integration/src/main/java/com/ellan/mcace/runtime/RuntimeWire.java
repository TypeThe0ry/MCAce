package com.ellan.mcace.runtime;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Objects;

final class RuntimeWire {
    static final int MAX_FRAME_BYTES = 2 * 1024 * 1024;

    private RuntimeWire() {
    }

    static void write(DataOutputStream output, byte[] frame) throws IOException {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(frame, "frame");
        if (frame.length == 0 || frame.length > MAX_FRAME_BYTES) {
            throw new IOException("runtime frame length is outside the allowed range");
        }
        output.writeInt(frame.length);
        output.write(frame);
        output.flush();
    }

    static byte[] read(DataInputStream input) throws IOException {
        Objects.requireNonNull(input, "input");
        int length = input.readInt();
        if (length <= 0 || length > MAX_FRAME_BYTES) {
            throw new IOException("runtime frame length is outside the allowed range: " + length);
        }
        byte[] frame = input.readNBytes(length);
        if (frame.length != length) {
            throw new EOFException("runtime frame ended before its declared length");
        }
        return frame;
    }
}
