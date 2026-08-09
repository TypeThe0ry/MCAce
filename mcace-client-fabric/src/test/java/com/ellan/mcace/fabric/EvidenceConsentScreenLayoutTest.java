package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedEvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.util.List;
import org.junit.jupiter.api.Test;

final class EvidenceConsentScreenLayoutTest {
    @Test
    void wrapsContentWithinAvailableWidthAndKeepsButtonsBelowIt() {
        EvidenceConsentScreen.ConsentLayout layout =
                EvidenceConsentScreen.layoutFor(320, 240, 9, 11, 7);

        assertTrue(layout.maxWidth() <= 320 - 48);
        assertTrue(layout.contentBottom() + 12 <= layout.buttonTop());
        assertTrue(layout.buttonTop() + 20 <= 240 - 8);
        assertTrue(layout.lineStep() > 9);
    }

    @Test
    void showsExplicitNoRetentionForLegacyRequest() {
        List<String> paragraphs = EvidenceConsentScreen.consentParagraphTexts(request(
                false, 0L, "", ""));

        assertTrue(paragraphs.stream().anyMatch(text -> text.contains("Raw content is not retained")));
        assertTrue(paragraphs.stream().anyMatch(text -> text.contains("must not retain raw content")));
        assertFalse(paragraphs.stream().anyMatch(text -> text.contains("Retention policy:")));
    }

    @Test
    void showsAccurateRetentionDisclosureAndSanitizesDynamicText() {
        List<String> paragraphs = EvidenceConsentScreen.consentParagraphTexts(request(
                true, 3661L, "policy\nid", "review\r\n purpose"));
        String rendered = String.join("\n", paragraphs);

        assertTrue(rendered.contains("PT1H1M1S"));
        assertTrue(rendered.contains("3661 seconds"));
        assertTrue(rendered.contains("policy�id"));
        assertTrue(rendered.contains("review�� purpose"));
        assertTrue(rendered.contains("must not retain raw content beyond this signed retention period"));
        assertFalse(paragraphs.stream()
                .flatMapToInt(String::codePoints)
                .anyMatch(Character::isISOControl));
    }

    @Test
    void staleConsentCallbackCannotActOnTheReplacedRequestGeneration() {
        Object oldGeneration = new Object();
        Object currentGeneration = new Object();

        assertTrue(EvidenceCaptureController.isCurrentConsentGeneration(
                currentGeneration, currentGeneration));
        assertFalse(EvidenceCaptureController.isCurrentConsentGeneration(
                currentGeneration, oldGeneration));
        assertFalse(EvidenceCaptureController.isCurrentConsentGeneration(null, oldGeneration));
    }

    @Test
    void resizeInvalidatesTheArmedFramebufferBeforeAnyPixelCopy() {
        assertTrue(EvidenceCaptureController.isStableFramebuffer(1920, 1080, 1920, 1080));
        assertFalse(EvidenceCaptureController.isStableFramebuffer(1920, 1080, 1280, 720));
        assertFalse(EvidenceCaptureController.isStableFramebuffer(1920, 1080, 0, 1080));
    }

    private static VerifiedEvidenceRequest request(boolean retained, long seconds,
            String policyId, String purpose) {
        return new VerifiedEvidenceRequest(
                "evidence-ui", "request-ui", "9f2e62d4-13f8-45fb-a6d6-6b1f0b6f71be",
                EvidenceType.SCREENSHOT, EvidenceCaptureScope.GAME_RENDER_FRAME,
                1_900_000_000_000L, "case-ui", retained, seconds, policyId, purpose);
    }
}
