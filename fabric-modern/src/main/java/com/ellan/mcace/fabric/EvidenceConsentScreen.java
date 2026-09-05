package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedEvidenceRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.util.FormattedCharSequence;
import org.lwjgl.glfw.GLFW;

/** A per-request, visible consent prompt. Closing the prompt is always a decline. */
final class EvidenceConsentScreen extends Screen {
    private static final int CONTENT_MARGIN = 24;
    private static final int MAX_CONTENT_WIDTH = 420;
    private static final int PARAGRAPH_GAP = 3;
    private static final int BUTTON_GAP = 12;
    private static final int BUTTON_HEIGHT = 20;
    private static final int BOTTOM_MARGIN = 8;
    private static final int TOP_MARGIN = 8;

    private final Screen previous;
    private final VerifiedEvidenceRequest request;
    private final Consumer<Boolean> decision;
    private final OneShotRenderMarker firstRender;
    private int scrollOffset;

    EvidenceConsentScreen(Screen previous, VerifiedEvidenceRequest request, Runnable rendered,
            Consumer<Boolean> decision) {
        super(Component.literal("MCAce evidence request"));
        this.previous = previous;
        this.request = Objects.requireNonNull(request, "request");
        this.decision = Objects.requireNonNull(decision, "decision");
        this.firstRender = new OneShotRenderMarker(rendered);
    }

    Screen previous() {
        return previous;
    }

    @Override
    protected void init() {
        ActionRow actions = actionRow(width, height);
        addRenderableWidget(Button.builder(Component.literal("Allow once"), button -> decide(true))
                .bounds(actions.left(), actions.y(), actions.buttonWidth(), BUTTON_HEIGHT)
                .build());
        addRenderableWidget(Button.builder(Component.literal("Decline"), button -> decide(false))
                .bounds(actions.right(), actions.y(), actions.buttonWidth(), BUTTON_HEIGHT)
                .build());
        scrollOffset = ConsentUiSupport.clampScroll(scrollOffset, layout().maxScroll());
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor context, int mouseX, int mouseY, float delta) {
        // The Screen wrapper already extracts the background once per frame.
        // Repeating it here causes the 26.2 blur extractor to throw when the
        // evidence prompt is displayed after another screen.
        int center = width / 2;
        ConsentLayout layout = layout();
        scrollOffset = ConsentUiSupport.clampScroll(scrollOffset, layout.maxScroll());
        int y = layout.maxScroll() == 0 ? layout.contentTop() : layout.viewportTop() - scrollOffset;
        List<List<FormattedCharSequence>> paragraphs = wrappedParagraphs(layout.maxWidth());
        context.enableScissor(0, layout.viewportTop(), width, layout.viewportBottom());
        for (int paragraphIndex = 0; paragraphIndex < paragraphs.size(); paragraphIndex++) {
            for (FormattedCharSequence line : paragraphs.get(paragraphIndex)) {
                context.centeredText(font, line, center, y,
                        paragraphIndex < 3 ? 0xFFFFFF : 0xAAAAAA);
                y += layout.lineStep();
            }
            if (paragraphIndex + 1 < paragraphs.size()) {
                y += PARAGRAPH_GAP;
            }
        }
        context.disableScissor();
        super.extractRenderState(context, mouseX, mouseY, delta);
        firstRender.markRendered();
    }

    private List<Component> paragraphs() {
        return consentParagraphTexts(request).stream().map(text -> (Component) Component.literal(text)).toList();
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
        return ConsentUiSupport.safeDisplay(value);
    }

    private List<List<FormattedCharSequence>> wrappedParagraphs(int maxWidth) {
        List<List<FormattedCharSequence>> wrapped = new ArrayList<>();
        for (Component paragraph : paragraphs()) {
            wrapped.add(font.split(paragraph, maxWidth));
        }
        return wrapped;
    }

    private ConsentLayout layout() {
        int maxWidth = Math.max(1, Math.min(MAX_CONTENT_WIDTH, width - (CONTENT_MARGIN * 2)));
        List<List<FormattedCharSequence>> wrapped = wrappedParagraphs(maxWidth);
        int totalLines = wrapped.stream().mapToInt(List::size).sum();
        return layoutFor(width, height, font.lineHeight, totalLines, wrapped.size());
    }

    /** Pure geometry helper kept package-private for deterministic layout regression tests. */
    static ConsentLayout layoutFor(int screenWidth, int screenHeight, int fontHeight,
            int totalLines, int paragraphCount) {
        int safeFontHeight = Math.max(1, fontHeight);
        int lineStep = safeFontHeight + 2;
        int contentHeight = ConsentUiSupport.contentHeight(
                lineStep, totalLines, paragraphCount, PARAGRAPH_GAP);
        int maxWidth = Math.max(1, Math.min(MAX_CONTENT_WIDTH, screenWidth - (CONTENT_MARGIN * 2)));
        int buttonTop = Math.max(0, screenHeight - BOTTOM_MARGIN - BUTTON_HEIGHT);
        int viewportTop = Math.min(TOP_MARGIN, buttonTop);
        int viewportBottom = Math.max(viewportTop, buttonTop - BUTTON_GAP);
        int viewportHeight = viewportBottom - viewportTop;
        int contentTop = viewportTop;
        if (contentHeight < viewportHeight) {
            contentTop += (viewportHeight - contentHeight) / 2;
        }
        return new ConsentLayout(maxWidth, contentTop, contentTop + contentHeight, buttonTop, lineStep,
                viewportTop, viewportBottom, contentHeight,
                ConsentUiSupport.maxScroll(contentHeight, viewportHeight));
    }

    static ActionRow actionRow(int screenWidth, int screenHeight) {
        int available = Math.max(2, screenWidth - 16);
        int gap = Math.min(6, Math.max(0, available - 2));
        int buttonWidth = Math.max(1, Math.min(150, (available - gap) / 2));
        int totalWidth = (buttonWidth * 2) + gap;
        int left = Math.max(0, (screenWidth - totalWidth) / 2);
        return new ActionRow(left, left + buttonWidth + gap, buttonWidth,
                Math.max(0, screenHeight - BOTTOM_MARGIN - BUTTON_HEIGHT));
    }

    @Override
    public boolean mouseScrolled(double mouseX, double mouseY,
            double horizontalAmount, double verticalAmount) {
        ConsentLayout layout = layout();
        int next = ConsentUiSupport.wheelScroll(
                scrollOffset, layout.maxScroll(), verticalAmount, layout.lineStep());
        if (next != scrollOffset) {
            scrollOffset = next;
            return true;
        }
        return super.mouseScrolled(mouseX, mouseY, horizontalAmount, verticalAmount);
    }

    @Override
    public boolean keyPressed(KeyEvent input) {
        ConsentLayout layout = layout();
        int next = switch (input.key()) {
            case GLFW.GLFW_KEY_PAGE_UP -> ConsentUiSupport.clampScroll(
                    scrollOffset - (layout.viewportBottom() - layout.viewportTop()), layout.maxScroll());
            case GLFW.GLFW_KEY_PAGE_DOWN -> ConsentUiSupport.clampScroll(
                    scrollOffset + (layout.viewportBottom() - layout.viewportTop()), layout.maxScroll());
            case GLFW.GLFW_KEY_HOME -> 0;
            case GLFW.GLFW_KEY_END -> layout.maxScroll();
            default -> scrollOffset;
        };
        if (next != scrollOffset) {
            scrollOffset = next;
            return true;
        }
        return super.keyPressed(input);
    }

    record ConsentLayout(int maxWidth, int contentTop, int contentBottom, int buttonTop, int lineStep,
                         int viewportTop, int viewportBottom, int totalContentHeight, int maxScroll) { }

    record ActionRow(int left, int right, int buttonWidth, int y) { }

    @Override
    public void onClose() {
        decide(false);
    }

    private void decide(boolean allowed) {
        decision.accept(allowed);
    }
}
