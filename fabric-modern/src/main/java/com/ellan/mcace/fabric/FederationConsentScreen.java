package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedFederationConsentRequest;
import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.components.Button;
import net.minecraft.util.FormattedCharSequence;
import net.minecraft.network.chat.Component;

/** A non-overlaying target-specific prompt. Closing it is exactly the same as Decline. */
final class FederationConsentScreen extends Screen {
    private static final int WIDTH = 440;
    private final Screen previous;
    private final VerifiedFederationConsentRequest request;
    private final Consumer<Boolean> decision;
    private final OneShotRenderMarker firstRender;
    private boolean decided;

    FederationConsentScreen(Screen previous, VerifiedFederationConsentRequest request,
            Runnable firstRendered, Consumer<Boolean> decision) {
        super(Component.literal("MCAce federation request"));
        this.previous = previous;
        this.request = Objects.requireNonNull(request, "request");
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
        for (String paragraph : displayLines(request)) {
            for (FormattedCharSequence line : font.split(Component.literal(paragraph), contentWidth)) {
                context.centeredText(font, line, width / 2, y, 0xFFFFFF);
                y += font.lineHeight + 2;
            }
            y += 4;
        }
        super.extractRenderState(context, mouseX, mouseY, delta);
        firstRender.markRendered();
    }

    static List<String> displayLines(VerifiedFederationConsentRequest verified) {
        Objects.requireNonNull(verified, "verified");
        var request = verified.request();
        List<String> lines = new ArrayList<>();
        lines.add("One-time MCAce federation request");
        lines.add("Source: " + ConsentUiSupport.safeDisplay(request.getSourceNetworkId()) + " (key fingerprint "
                + fingerprint(request.getSourceKeyIdSha256().toByteArray()) + ")");
        lines.add("Target: " + ConsentUiSupport.safeDisplay(request.getTargetNetworkId()) + " (key fingerprint "
                + fingerprint(request.getTargetKeyIdSha256().toByteArray()) + ")");
        lines.add("Purpose: show only an observation that this source saw your current MCAce session.");
        lines.add("Disclosed profile: " + ConsentUiSupport.safeDisplay(request.getDisclosure()) + ". No mods, files, screenshots, desktop or window capture, IP, device, risk score, or evidence is transferred.");
        lines.add("It is observation-only, not transferable verification, and cannot change local admission.");
        long seconds = Math.max(0L, Math.min(ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.toSeconds(),
                (request.getExpiresAtEpochMs() - request.getIssuedAtEpochMs()) / 1000L));
        lines.add("Maximum lifetime: " + Duration.ofSeconds(seconds) + "; request expires "
                + Instant.ofEpochMilli(request.getExpiresAtEpochMs()) + ".");
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
