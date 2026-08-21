package com.ellan.mcace.fabric;

/** Pure safety and scrolling helpers shared by visible consent screens. */
final class ConsentUiSupport {
    private ConsentUiSupport() { }

    static String safeDisplay(String value) {
        StringBuilder sanitized = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            int type = Character.getType(codePoint);
            if (Character.isISOControl(codePoint)
                    || type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) {
                sanitized.append('\uFFFD');
            } else {
                sanitized.appendCodePoint(codePoint);
            }
        });
        return sanitized.toString();
    }

    static int contentHeight(int lineStep, int totalLines, int paragraphCount, int paragraphGap) {
        int safeLineStep = Math.max(1, lineStep);
        int safeLines = Math.max(1, totalLines);
        int safeParagraphs = Math.max(1, paragraphCount);
        return Math.addExact(Math.multiplyExact(safeLines, safeLineStep),
                Math.multiplyExact(Math.max(0, safeParagraphs - 1), Math.max(0, paragraphGap)));
    }

    static int maxScroll(int contentHeight, int viewportHeight) {
        return Math.max(0, contentHeight - Math.max(0, viewportHeight));
    }

    static int clampScroll(int offset, int maxScroll) {
        return Math.max(0, Math.min(offset, Math.max(0, maxScroll)));
    }

    static int wheelScroll(int offset, int maxScroll, double verticalAmount, int lineStep) {
        int delta = (int) Math.round(-verticalAmount * Math.max(1, lineStep) * 3.0d);
        if (delta == 0 && verticalAmount != 0.0d) {
            delta = verticalAmount > 0.0d ? -1 : 1;
        }
        return clampScroll(offset + delta, maxScroll);
    }
}
