package com.ellan.mcace.sdk;

/** Internal validation shared by immutable SDK values. */
final class SdkValidation {
    static final int MAX_TEXT_LENGTH = 512;
    static final int MAX_SUMMARIES = 64;

    private SdkValidation() {
    }

    static String boundedText(String value, String name) {
        if (value == null) {
            throw new NullPointerException(name);
        }
        if (value.isBlank() || value.length() > MAX_TEXT_LENGTH) {
            throw new IllegalArgumentException(name + " must be non-blank and at most " + MAX_TEXT_LENGTH + " characters");
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) {
                throw new IllegalArgumentException(name + " must not contain ISO control characters");
            }
        }
        return value;
    }

    static <T> void boundedSize(Iterable<T> values, String name) {
        int size = 0;
        for (T ignored : values) {
            if (++size > MAX_SUMMARIES) {
                throw new IllegalArgumentException(name + " must contain at most " + MAX_SUMMARIES + " entries");
            }
        }
    }
}
