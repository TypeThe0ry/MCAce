package com.ellan.mcace.fabric;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.util.FormattedCharSequence;
import net.minecraft.network.chat.Component;
import org.lwjgl.glfw.GLFW;

/** Visible, paged disclosure for signed-policy explicit files. Closing always declines. */
final class ExplicitFileConsentScreen extends Screen {
    private static final int FILES_PER_PAGE = 3;
    private static final int MAX_CONTENT_WIDTH = 440;
    private static final int CONTENT_MARGIN = 16;
    private static final int TOP_MARGIN = 8;
    private static final int PARAGRAPH_GAP = 3;
    private static final int BUTTON_HEIGHT = 20;
    private static final int BUTTON_GAP = 6;
    private static final int BUTTON_ROW_GAP = 4;
    private static final int BOTTOM_MARGIN = 8;
    private final Screen previous;
    private final VerifiedPolicy policy;
    private final List<String> files;
    private final Consumer<Boolean> decision;
    private final OneShotRenderMarker firstRender;
    private final boolean enablement;
    private int page;
    private int scrollOffset;

    ExplicitFileConsentScreen(Screen previous, VerifiedPolicy policy, List<String> files,
            Runnable rendered, Consumer<Boolean> decision) {
        this(previous, policy, files, rendered, decision, false);
    }

    private ExplicitFileConsentScreen(Screen previous, VerifiedPolicy policy, List<String> files,
            Runnable rendered, Consumer<Boolean> decision, boolean enablement) {
        super(Component.literal(enablement ? "MCAce enablement" : "MCAce explicit file request"));
        this.previous = previous;
        this.policy = Objects.requireNonNull(policy, "policy");
        this.files = List.copyOf(files);
        this.decision = Objects.requireNonNull(decision, "decision");
        this.firstRender = new OneShotRenderMarker(rendered);
        this.enablement = enablement;
    }

    static ExplicitFileConsentScreen forEnablement(Screen previous, VerifiedPolicy policy,
            List<String> requestedFiles, Runnable rendered, Consumer<Boolean> decision) {
        return new ExplicitFileConsentScreen(previous, policy, requestedFiles, rendered, decision, true);
    }

    Screen previous() { return previous; }

    @Override
    protected void init() {
        int pages = displayedPageCount();
        boolean hasBack = page > 0;
        boolean lastPage = page + 1 >= pages;
        ButtonLayout buttons = buttonLayout(width, height, hasBack, lastPage);
        int buttonIndex = 0;
        if (page > 0) {
            ButtonBounds bounds = buttons.buttons().get(buttonIndex++);
            addRenderableWidget(Button.builder(Component.literal("Back"), button -> changePage(-1))
                    .bounds(bounds.x(), bounds.y(), bounds.width(), BUTTON_HEIGHT).build());
        }
        ButtonBounds primary = buttons.buttons().get(buttonIndex++);
        if (!lastPage) {
            addRenderableWidget(Button.builder(Component.literal("Next"), button -> changePage(1))
                    .bounds(primary.x(), primary.y(), primary.width(), BUTTON_HEIGHT).build());
        } else {
            String label = enablement ? "Enable MCAce" : "Allow while connected";
            addRenderableWidget(Button.builder(Component.literal(label), button -> decide(true))
                    .bounds(primary.x(), primary.y(), primary.width(), BUTTON_HEIGHT).build());
        }
        ButtonBounds decline = buttons.buttons().get(buttonIndex);
        addRenderableWidget(Button.builder(Component.literal("Decline"), button -> decide(false))
                .bounds(decline.x(), decline.y(), decline.width(), BUTTON_HEIGHT).build());
        scrollOffset = ConsentUiSupport.clampScroll(scrollOffset, layout().maxScroll());
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor context, int mouseX, int mouseY, float delta) {
        extractBackground(context, mouseX, mouseY, delta);
        ExplicitLayout layout = layout();
        scrollOffset = ConsentUiSupport.clampScroll(scrollOffset, layout.maxScroll());
        int y = layout.maxScroll() == 0 ? layout.contentTop() : layout.viewportTop() - scrollOffset;
        context.enableScissor(0, layout.viewportTop(), width, layout.viewportBottom());
        List<List<FormattedCharSequence>> paragraphs = wrappedParagraphs(layout.maxWidth());
        for (int paragraphIndex = 0; paragraphIndex < paragraphs.size(); paragraphIndex++) {
            for (FormattedCharSequence line : paragraphs.get(paragraphIndex)) {
                context.centeredText(font, line, width / 2, y, 0xFFFFFF);
                y += font.lineHeight + 2;
            }
            if (paragraphIndex + 1 < paragraphs.size()) {
                y += PARAGRAPH_GAP;
            }
        }
        context.disableScissor();
        super.extractRenderState(context, mouseX, mouseY, delta);
        firstRender.markRendered();
    }

    static List<String> pageParagraphs(VerifiedPolicy verified, List<String> requested, int page) {
        Objects.requireNonNull(verified, "verified");
        Objects.requireNonNull(requested, "requested");
        int pages = pageCount(requested.size());
        int safePage = Math.max(0, Math.min(page, pages - 1));
        int from = safePage * FILES_PER_PAGE;
        int to = Math.min(requested.size(), from + FILES_PER_PAGE);
        List<String> paragraphs = new ArrayList<>();
        paragraphs.add("Pinned server " + safe(verified.policy().getServerId())
                + " requests explicit Minecraft files (page " + (safePage + 1) + "/" + pages + ").");
        paragraphs.add("Authorization lasts only for this connection. MCAce may re-read the listed files for signed manifest refreshes while connected.");
        paragraphs.add("Only relative path, byte size, and SHA-256 are sent. Raw file contents are never uploaded.");
        for (int index = from; index < to; index++) {
            paragraphs.add("- " + safe(requested.get(index)));
        }
        paragraphs.add("Declining or closing sends no explicit-file manifest and is not a cheat finding or permanent punishment.");
        return List.copyOf(paragraphs);
    }

    static List<String> enablementParagraphs(VerifiedPolicy verified, List<String> requested) {
        Objects.requireNonNull(verified, "verified");
        Objects.requireNonNull(requested, "requested");
        List<String> paragraphs = new ArrayList<>();
        paragraphs.add("Pinned server " + safe(verified.policy().getServerId())
                + " requests MCAce enablement for this connection.");
        paragraphs.add("One approval enables the signed MCAce handshake and content-free mod, resource-pack, shader-pack, and integrity metadata while connected.");
        paragraphs.add("If the signed policy names explicit files, only relative path, byte size, and SHA-256 are sent; raw file contents are never uploaded.");
        paragraphs.add("A signed server may request one in-game render frame later. Only the Minecraft frame is captured; never the desktop, window, files, or other applications.");
        paragraphs.add("A signed federation handoff may present one short-lived, memory-only token to the pinned target server.");
        if (requested.isEmpty()) {
            paragraphs.add("This connection has no explicit-file request.");
        } else {
            paragraphs.add("Explicit files covered by this single approval:");
            requested.stream().sorted().forEach(path -> paragraphs.add("- " + safe(path)));
        }
        paragraphs.add("Approval is connection-bound, is not persisted, and ends on disconnect.");
        paragraphs.add("Declining or closing keeps MCAce disabled and sends no MCAce handshake, manifest, evidence, or federation frames.");
        return List.copyOf(paragraphs);
    }

    static int pageCount(int fileCount) {
        return Math.max(1, (Math.max(0, fileCount) + FILES_PER_PAGE - 1) / FILES_PER_PAGE);
    }

    @Override
    public void onClose() { decide(false); }

    private void changePage(int delta) {
        page = Math.max(0, Math.min(page + delta, displayedPageCount() - 1));
        scrollOffset = 0;
        rebuildWidgets();
    }

    private void decide(boolean allowed) { decision.accept(allowed); }

    private static String safe(String value) {
        return ConsentUiSupport.safeDisplay(value);
    }

    private List<List<FormattedCharSequence>> wrappedParagraphs(int maxWidth) {
        List<List<FormattedCharSequence>> wrapped = new ArrayList<>();
        List<String> source = enablement
                ? enablementParagraphs(policy, files)
                : pageParagraphs(policy, files, page);
        for (String paragraph : source) {
            wrapped.add(font.split(Component.literal(paragraph), maxWidth));
        }
        return wrapped;
    }

    private ExplicitLayout layout() {
        ButtonLayout buttons = buttonLayout(
                width, height, page > 0, page + 1 >= displayedPageCount());
        int maxWidth = Math.max(1, Math.min(MAX_CONTENT_WIDTH, width - (CONTENT_MARGIN * 2)));
        List<List<FormattedCharSequence>> wrapped = wrappedParagraphs(maxWidth);
        int totalLines = wrapped.stream().mapToInt(List::size).sum();
        return layoutFor(width, height, font.lineHeight, totalLines, wrapped.size(), buttons.areaTop());
    }

    private int displayedPageCount() {
        return enablement ? 1 : pageCount(files.size());
    }

    static ExplicitLayout layoutFor(int screenWidth, int screenHeight, int fontHeight,
            int totalLines, int paragraphCount, int buttonAreaTop) {
        int lineStep = Math.max(1, fontHeight) + 2;
        int contentHeight = ConsentUiSupport.contentHeight(
                lineStep, totalLines, paragraphCount, PARAGRAPH_GAP);
        int maxWidth = Math.max(1, Math.min(MAX_CONTENT_WIDTH, screenWidth - (CONTENT_MARGIN * 2)));
        int viewportTop = Math.min(TOP_MARGIN, Math.max(0, screenHeight));
        int viewportBottom = Math.max(viewportTop, buttonAreaTop - BUTTON_GAP);
        int viewportHeight = viewportBottom - viewportTop;
        int contentTop = viewportTop;
        if (contentHeight < viewportHeight) {
            contentTop += (viewportHeight - contentHeight) / 2;
        }
        return new ExplicitLayout(maxWidth, contentTop, contentTop + contentHeight,
                viewportTop, viewportBottom, lineStep, contentHeight,
                ConsentUiSupport.maxScroll(contentHeight, viewportHeight));
    }

    static ButtonLayout buttonLayout(int screenWidth, int screenHeight,
            boolean hasBack, boolean lastPage) {
        List<Integer> preferred = new ArrayList<>();
        if (hasBack) preferred.add(90);
        preferred.add(lastPage ? 180 : 100);
        preferred.add(100);
        int bottomY = Math.max(0, screenHeight - BOTTOM_MARGIN - BUTTON_HEIGHT);
        int available = Math.max(1, screenWidth - (BOTTOM_MARGIN * 2));
        int preferredTotal = preferred.stream().mapToInt(Integer::intValue).sum()
                + (Math.max(0, preferred.size() - 1) * BUTTON_GAP);
        if (preferred.size() == 3 && preferredTotal > available) {
            int upperY = Math.max(0, bottomY - BUTTON_HEIGHT - BUTTON_ROW_GAP);
            List<ButtonBounds> result = new ArrayList<>();
            result.addAll(row(screenWidth, upperY, preferred.subList(0, 1)));
            result.addAll(row(screenWidth, bottomY, preferred.subList(1, 3)));
            return new ButtonLayout(List.copyOf(result), upperY);
        }
        return new ButtonLayout(row(screenWidth, bottomY, preferred), bottomY);
    }

    private static List<ButtonBounds> row(int screenWidth, int y, List<Integer> preferred) {
        int available = Math.max(1, screenWidth - (BOTTOM_MARGIN * 2));
        int gaps = Math.max(0, preferred.size() - 1) * BUTTON_GAP;
        int desired = preferred.stream().mapToInt(Integer::intValue).sum() + gaps;
        List<Integer> widths;
        if (desired <= available) {
            widths = List.copyOf(preferred);
        } else {
            int equalWidth = Math.max(1, (available - gaps) / Math.max(1, preferred.size()));
            widths = java.util.Collections.nCopies(preferred.size(), equalWidth);
        }
        int total = widths.stream().mapToInt(Integer::intValue).sum() + gaps;
        int x = Math.max(0, (screenWidth - total) / 2);
        List<ButtonBounds> bounds = new ArrayList<>();
        for (int buttonWidth : widths) {
            bounds.add(new ButtonBounds(x, y, buttonWidth));
            x += buttonWidth + BUTTON_GAP;
        }
        return List.copyOf(bounds);
    }

    @Override
    public boolean mouseScrolled(double mouseX, double mouseY,
            double horizontalAmount, double verticalAmount) {
        ExplicitLayout layout = layout();
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
        ExplicitLayout layout = layout();
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

    record ExplicitLayout(int maxWidth, int contentTop, int contentBottom,
                          int viewportTop, int viewportBottom, int lineStep,
                          int totalContentHeight, int maxScroll) { }

    record ButtonLayout(List<ButtonBounds> buttons, int areaTop) {
        ButtonLayout {
            buttons = List.copyOf(buttons);
        }
    }

    record ButtonBounds(int x, int y, int width) { }
}
