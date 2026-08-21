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
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.util.FormattedCharSequence;

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
        super(Component.literal("MCAce federation import"));
        this.previous = previous;
        this.presentation = Objects.requireNonNull(presentation, "presentation");
        this.firstRender = new OneShotRenderMarker(firstRendered);
        this.decision = Objects.requireNonNull(decision, "decision");
    }

    Screen previous() { return previous; }

    @Override
    protected void init() {
        int y = Math.max(20, height - 32);
        addRenderableWidget(Button.builder(Component.literal("Allow once"), button -> decide(true))
                .bounds(width / 2 - 155, y, 150, 20).build());
        addRenderableWidget(Button.builder(Component.literal("Decline"), button -> decide(false))
                .bounds(width / 2 + 5, y, 150, 20).build());
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor context, int mouseX, int mouseY, float delta) {
        extractBackground(context, mouseX, mouseY, delta);
        int contentWidth = Math.max(1, Math.min(WIDTH, width - 40));
        int y = 24;
        for (String paragraph : displayLines(presentation)) {
            for (FormattedCharSequence line : font.split(Component.literal(paragraph), contentWidth)) {
                context.centeredText(font, line, width / 2, y, 0xFFFFFF);
                y += font.lineHeight + 2;
            }
            y += 4;
        }
        super.extractRenderState(context, mouseX, mouseY, delta);
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
    public void onClose() { decide(false); }

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
