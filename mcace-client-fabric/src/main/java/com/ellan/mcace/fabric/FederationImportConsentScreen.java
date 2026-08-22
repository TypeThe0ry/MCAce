package com.ellan.mcace.fabric;

import com.ellan.mcace.client.federation.FederationTokenVault.PreparedPresentation;
import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.OrderedText;
import net.minecraft.text.Text;

/** Visible consent for importing one already-prepared federation observation at the target. */
final class FederationImportConsentScreen extends Screen {
    private static final int WIDTH = 440;
    private final Screen previous;
    private final PreparedPresentation presentation;
    private final Consumer<Boolean> decision;
    private final OneShotRenderMarker firstRender;
    private boolean decided;

    FederationImportConsentScreen(Screen previous, PreparedPresentation presentation,
            Runnable firstRendered, Consumer<Boolean> decision) {
        super(Text.literal("MCAce federation import"));
        this.previous = previous;
        this.presentation = Objects.requireNonNull(presentation, "presentation");
        this.firstRender = new OneShotRenderMarker(firstRendered);
        this.decision = Objects.requireNonNull(decision, "decision");
    }

    Screen previous() { return previous; }

    @Override
    protected void init() {
        int y = Math.max(20, height - 32);
        addDrawableChild(ButtonWidget.builder(Text.literal("Allow once"), button -> decide(true))
                .dimensions(width / 2 - 155, y, 150, 20).build());
        addDrawableChild(ButtonWidget.builder(Text.literal("Decline"), button -> decide(false))
                .dimensions(width / 2 + 5, y, 150, 20).build());
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        // 1.21.11 rejects a second blur submission in the same frame.
        renderInGameBackground(context);
        int contentWidth = Math.max(1, Math.min(WIDTH, width - 40));
        int y = 24;
        for (String paragraph : displayLines(presentation)) {
            for (OrderedText line : textRenderer.wrapLines(Text.literal(paragraph), contentWidth)) {
                context.drawCenteredTextWithShadow(textRenderer, line, width / 2, y, 0xFFFFFF);
                y += textRenderer.fontHeight + 2;
            }
            y += 4;
        }
        super.render(context, mouseX, mouseY, delta);
        firstRender.markRendered();
    }

    static List<String> displayLines(PreparedPresentation prepared) {
        Objects.requireNonNull(prepared, "prepared");
        List<String> lines = new ArrayList<>();
        lines.add("One-time MCAce federation target import");
        lines.add("Your local authentication to this target was accepted first. This choice cannot change local admission.");
        lines.add("Source: " + ConsentUiSupport.safeDisplay(prepared.sourceNetworkId())
                + " (key fingerprint " + fingerprint(prepared.sourceKeyId()) + ")");
        lines.add("Target: " + ConsentUiSupport.safeDisplay(prepared.targetNetworkId())
                + " (key fingerprint " + fingerprint(prepared.targetKeyId()) + ")");
        lines.add("Disclosed profile: " + ConsentUiSupport.safeDisplay(prepared.disclosure())
                + ". It is observation-only, not transferable verification.");
        lines.add("Allow once sends only this exact prepared presentation on the current MCAce plugin channel.");
        lines.add("No mods, files, storage, screenshots, desktop or window capture, IP, device, risk score, or evidence is imported.");
        long seconds = Math.max(0L, Math.min(ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.toSeconds(),
                (prepared.expiresAtEpochMs() - prepared.issuedAtEpochMs()) / 1000L));
        lines.add("Maximum lifetime: " + Duration.ofSeconds(seconds) + "; presentation expires "
                + Instant.ofEpochMilli(prepared.expiresAtEpochMs()) + ".");
        lines.add("Closing, ignoring, or declining is not a cheat finding and causes no player action.");
        return List.copyOf(lines);
    }

    @Override
    public void close() { decide(false); }

    private void decide(boolean allow) {
        if (decided) return;
        decided = true;
        decision.accept(allow);
    }

    private static String fingerprint(byte[] bytes) {
        if (bytes == null || bytes.length != 32) return "invalid key";
        return HexFormat.of().formatHex(bytes, 0, 8) + "…";
    }
}
