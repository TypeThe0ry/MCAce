package com.ellan.mcace.client.observation;

import com.ellan.mcace.client.integrity.IntegrityScanCancellation;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Reads only the small Fabric identity document; it never enumerates a mod archive. */
record FabricModMetadata(String identifier, String version, String status) {
    private static final int MAX_METADATA_BYTES = 64 * 1024;
    private static final int MAX_JSON_DEPTH = 16;
    private static final String UNKNOWN = "unknown";

    static FabricModMetadata read(Path file) {
        try {
            return read(file, IntegrityScanCancellation.NONE);
        } catch (IntegrityScanException impossible) {
            return unavailable("invalid");
        }
    }

    static FabricModMetadata read(Path file, IntegrityScanCancellation cancellation)
            throws IntegrityScanException {
        cancellation.check();
        try (ZipFile archive = new ZipFile(file.toFile())) {
            cancellation.check();
            ZipEntry metadata = archive.getEntry("fabric.mod.json");
            if (metadata == null || metadata.isDirectory()) {
                return unavailable("absent");
            }
            if (metadata.getSize() > MAX_METADATA_BYTES) {
                return unavailable("invalid");
            }
            cancellation.check();
            String json = decode(readBounded(archive.getInputStream(metadata), cancellation));
            cancellation.check();
            return parse(json);
        } catch (IOException | IllegalArgumentException exception) {
            return unavailable("invalid");
        }
    }

    private static FabricModMetadata parse(String json) {
        try {
            JsonObjectReader reader = new JsonObjectReader(json);
            String id = reader.requiredString("id");
            String version = reader.requiredString("version");
            reader.requireEnd();
            if (!id.matches("[a-z][a-z0-9_-]{0,63}") || !safeVersion(version)) {
                return unavailable("invalid");
            }
            return new FabricModMetadata(id, version, "present");
        } catch (IllegalArgumentException exception) {
            return unavailable("invalid");
        }
    }

    private static boolean safeVersion(String version) {
        return !version.isBlank() && version.length() <= 128
                && version.codePoints().allMatch(codePoint -> codePoint >= 0x20 && codePoint != 0x7f);
    }

    private static byte[] readBounded(InputStream input, IntegrityScanCancellation cancellation)
            throws IOException, IntegrityScanException {
        try (input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int total = 0;
            int read;
            while (true) {
                cancellation.check();
                read = input.read(buffer);
                if (read < 0) {
                    break;
                }
                total += read;
                if (total > MAX_METADATA_BYTES) {
                    throw new IOException("Fabric metadata exceeds its size limit");
                }
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        }
    }

    private static String decode(byte[] data) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(data))
                .toString();
    }

    private static FabricModMetadata unavailable(String status) {
        return new FabricModMetadata(UNKNOWN, UNKNOWN, status);
    }

    /** Small, bounded JSON reader which preserves only root id and version strings. */
    private static final class JsonObjectReader {
        private final String input;
        private int index;
        private boolean parsed;
        private String id;
        private String version;

        private JsonObjectReader(String input) {
            this.input = input;
        }

        String requiredString(String key) {
            parseRoot();
            String value = switch (key) {
                case "id" -> id;
                case "version" -> version;
                default -> null;
            };
            if (value == null) {
                throw new IllegalArgumentException("missing Fabric metadata field");
            }
            return value;
        }

        void requireEnd() {
            parseRoot();
            whitespace();
            if (index != input.length()) {
                throw new IllegalArgumentException("trailing JSON data");
            }
        }

        private void parseRoot() {
            if (parsed) {
                return;
            }
            parsed = true;
            whitespace();
            expect('{');
            whitespace();
            Set<String> names = new HashSet<>();
            if (peek('}')) {
                index++;
                return;
            }
            while (true) {
                String name = string();
                if (!names.add(name)) {
                    throw new IllegalArgumentException("duplicate Fabric metadata field");
                }
                whitespace();
                expect(':');
                whitespace();
                if ("id".equals(name) || "version".equals(name)) {
                    String value = string();
                    if ("id".equals(name)) {
                        id = value;
                    } else {
                        version = value;
                    }
                } else {
                    value(0);
                }
                whitespace();
                if (peek('}')) {
                    index++;
                    return;
                }
                expect(',');
                whitespace();
            }
        }

        private void value(int depth) {
            if (depth > MAX_JSON_DEPTH) {
                throw new IllegalArgumentException("Fabric metadata nesting exceeds limit");
            }
            if (peek('"')) {
                string();
            } else if (peek('{')) {
                index++;
                whitespace();
                if (!peek('}')) {
                    while (true) {
                        string();
                        whitespace();
                        expect(':');
                        whitespace();
                        value(depth + 1);
                        whitespace();
                        if (peek('}')) {
                            break;
                        }
                        expect(',');
                        whitespace();
                    }
                }
                expect('}');
            } else if (peek('[')) {
                index++;
                whitespace();
                if (!peek(']')) {
                    while (true) {
                        value(depth + 1);
                        whitespace();
                        if (peek(']')) {
                            break;
                        }
                        expect(',');
                        whitespace();
                    }
                }
                expect(']');
            } else {
                int start = index;
                while (index < input.length() && !Character.isWhitespace(input.charAt(index))
                        && input.charAt(index) != ',' && input.charAt(index) != '}' && input.charAt(index) != ']') {
                    index++;
                }
                String literal = input.substring(start, index);
                if (!("true".equals(literal) || "false".equals(literal) || "null".equals(literal)
                        || literal.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))) {
                    throw new IllegalArgumentException("invalid JSON value");
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder value = new StringBuilder();
            while (index < input.length()) {
                char character = input.charAt(index++);
                if (character == '"') {
                    return value.toString();
                }
                if (character < 0x20) {
                    throw new IllegalArgumentException("control character in JSON string");
                }
                if (character != '\\') {
                    value.append(character);
                    continue;
                }
                if (index >= input.length()) {
                    throw new IllegalArgumentException("unterminated JSON escape");
                }
                char escaped = input.charAt(index++);
                switch (escaped) {
                    case '"', '\\', '/' -> value.append(escaped);
                    case 'b' -> value.append('\b');
                    case 'f' -> value.append('\f');
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    case 'u' -> value.append(unicode());
                    default -> throw new IllegalArgumentException("invalid JSON escape");
                }
            }
            throw new IllegalArgumentException("unterminated JSON string");
        }

        private char unicode() {
            if (index + 4 > input.length()) {
                throw new IllegalArgumentException("short JSON unicode escape");
            }
            String hexadecimal = input.substring(index, index + 4);
            index += 4;
            try {
                return (char) Integer.parseInt(hexadecimal, 16);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("invalid JSON unicode escape", exception);
            }
        }

        private void whitespace() {
            while (index < input.length() && Character.isWhitespace(input.charAt(index))) {
                index++;
            }
        }

        private boolean peek(char expected) {
            return index < input.length() && input.charAt(index) == expected;
        }

        private void expect(char expected) {
            if (!peek(expected)) {
                throw new IllegalArgumentException("malformed Fabric metadata JSON");
            }
            index++;
        }
    }
}
