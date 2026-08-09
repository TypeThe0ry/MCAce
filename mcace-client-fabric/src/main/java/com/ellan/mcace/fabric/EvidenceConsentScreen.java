package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedEvidenceRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.Text;
import net.minecraft.text.OrderedText;

/** A per-request, visible consent prompt. Closing the prompt is always a decline. */
final class EvidenceConsentScreen extends Screen {
    private static final int CONTENT_MARGIN = 24;
    private static final int MAX_CONTENT_WIDTH = 420;
    private static final int PARAGRAPH_GAP = 3;
    private static final int BUTTON_GAP = 12;
    private static final int BUTTON_HEIGHT = 20;
    private static final int BOTTOM_MARGIN = 8;

    private final Screen previous;
    private final VerifiedEvidenceRequest request;
    private final Consumer<Boolean> decision;

    EvidenceConsentScreen(Screen previous, VerifiedEvidenceRequest request, Consumer<Boolean> decision) {
        super(Text.literal("MCAce evidence request"));
        this.previous = previous;
        this.request = Objects.requireNonNull(request, "request");
        this.decision = Objects.requireNonNull(decision, "decision");
    }

    Screen previous() {
        return previous;
    }

    @Override
    protected void init() {
        ConsentLayout layout = layout();
        int center = width / 2;
        addDrawableChild(ButtonWidget.builder(Text.literal("Allow once"), button -> decide(true))
                .dimensions(center - 155, layout.buttonTop(), 150, BUTTON_HEIGHT)
                .build());
        addDrawableChild(ButtonWidget.builder(Text.literal("Decline"), button -> decide(false))
                .dimensions(center + 5, layout.buttonTop(), 150, BUTTON_HEIGHT)
                .build());
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        renderBackground(context, mouseX, mouseY, delta);
        int center = width / 2;
        ConsentLayout layout = layout();
        int y = layout.contentTop();
        List<List<OrderedText>> paragraphs = wrappedParagraphs(layout.maxWidth());
        for (int paragraphIndex = 0; paragraphIndex < paragraphs.size(); paragraphIndex++) {
            for (OrderedText line : paragraphs.get(paragraphIndex)) {
                context.drawCenteredTextWithShadow(textRenderer, line, center, y, paragraphIndex < 3 ? 0xFFFFFF : 0xAAAAAA);
                y += layout.lineStep();
            }
            if (paragraphIndex + 1 < paragraphs.size()) {
                y += PARAGRAPH_GAP;
            }
        }
        super.render(context, mouseX, mouseY, delta);
    }

    private List<Text> paragraphs() {
        return consentParagraphTexts(request).stream().map(text -> (Text) Text.literal(text)).toList();
    }

    /** Builds UI text only from the verified, signed request disclosure. */
    static List<String> consentParagraphTexts(VerifiedEvidenceRequest request) {
        Objects.requireNonNull(request, "request");
        List<String> paragraphs = new ArrayList<>();
        paragraphs.add("The server requests one Minecraft game-render frame.");
        paragraphs.add("Only this one game frame is captured; no desktop, window, files, or other apps.");
        if (request.rawContentRetained()) {
            paragraphs.add("If allowed, raw content may be retained for up to "
                    + retentionDuration(request.retentionSeconds()) + ".");
            paragraphs.add("Retention policy: " + safeDisplay(request.retentionPolicyId()));
            paragraphs.add("Retention purpose: " + safeDisplay(request.retentionPurpose()));
            paragraphs.add("The server must not retain raw content beyond this signed retention period.");
        } else {
            paragraphs.add("Raw content is not retained after this request is processed.");
            paragraphs.add("The server must not retain raw content for this request.");
        }
        paragraphs.add("No response is treated as a refusal and is not a cheat finding.");
        paragraphs.add("Case: " + (request.caseId().isBlank() ? "(not supplied)" : safeDisplay(request.caseId())));
        paragraphs.add("Request expires: " + Instant.ofEpochMilli(request.expiresAtEpochMs()));
        return List.copyOf(paragraphs);
    }

    private static String retentionDuration(long seconds) {
        long safeSeconds = Math.max(0L, seconds);
        return Duration.ofSeconds(safeSeconds) + " (" + safeSeconds + " seconds)";
    }

    private static String safeDisplay(String value) {
        StringBuilder sanitized = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            if (Character.isISOControl(codePoint) || codePoint == 0x2028 || codePoint == 0x2029) {
                sanitized.append('\uFFFD');
            } else {
                sanitized.appendCodePoint(codePoint);
            }
        });
        return sanitized.toString();
    }

    private List<List<OrderedText>> wrappedParagraphs(int maxWidth) {
        List<List<OrderedText>> wrapped = new ArrayList<>();
        for (Text paragraph : paragraphs()) {
            wrapped.add(textRenderer.wrapLines(paragraph, maxWidth));
        }
        return wrapped;
    }

    private ConsentLayout layout() {
        int maxWidth = Math.max(1, Math.min(MAX_CONTENT_WIDTH, width - (CONTENT_MARGIN * 2)));
        List<List<OrderedText>> wrapped = wrappedParagraphs(maxWidth);
        int totalLines = wrapped.stream().mapToInt(List::size).sum();
        return layoutFor(width, height, textRenderer.fontHeight, totalLines, wrapped.size());
    }

    /** Pure geometry helper kept package-private for deterministic layout regression tests. */
    static ConsentLayout layoutFor(int screenWidth, int screenHeight, int fontHeight,
            int totalLines, int paragraphCount) {
        int safeFontHeight = Math.max(1, fontHeight);
        int lineStep = safeFontHeight + 2;
        int safeLines = Math.max(1, totalLines);
        int safeParagraphs = Math.max(1, paragraphCount);
        int contentHeight = (safeLines * lineStep) - 2
                + (Math.max(0, safeParagraphs - 1) * PARAGRAPH_GAP);
        int maxWidth = Math.max(1, Math.min(MAX_CONTENT_WIDTH, screenWidth - (CONTENT_MARGIN * 2)));
        int buttonTop = Math.max(0, screenHeight - BOTTOM_MARGIN - BUTTON_HEIGHT);
        int contentTop = Math.max(0, buttonTop - BUTTON_GAP - contentHeight);
        int centeredTop = (screenHeight - contentHeight - BUTTON_GAP - BUTTON_HEIGHT) / 2;
        if (centeredTop >= 0 && centeredTop + contentHeight + BUTTON_GAP + BUTTON_HEIGHT <= screenHeight - BOTTOM_MARGIN) {
            contentTop = centeredTop;
            buttonTop = contentTop + contentHeight + BUTTON_GAP;
        }
        return new ConsentLayout(maxWidth, contentTop, contentTop + contentHeight, buttonTop, lineStep);
    }

    record ConsentLayout(int maxWidth, int contentTop, int contentBottom, int buttonTop, int lineStep) {}

    @Override
    public void close() {
        decide(false);
    }

    private void decide(boolean allowed) {
        decision.accept(allowed);
    }
}
