package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class ExplicitFileConsentScreenTest {
    @Test
    void disclosureListsEveryPathAcrossPagesAndDescribesConnectionBoundMetadataOnlyAccess() {
        List<String> files = List.of("config/a.txt", "config/b.txt", "config/c.txt", "options.txt");

        String first = String.join("\n", ExplicitFileConsentScreen.pageParagraphs(policy(), files, 0));
        String second = String.join("\n", ExplicitFileConsentScreen.pageParagraphs(policy(), files, 1));

        assertTrue(first.contains("pinned-network"));
        assertTrue(first.contains("config/a.txt"));
        assertTrue(first.contains("config/b.txt"));
        assertTrue(first.contains("config/c.txt"));
        assertFalse(first.contains("options.txt"));
        assertTrue(second.contains("options.txt"));
        assertTrue(first.contains("only for this connection"));
        assertTrue(first.contains("byte size, and SHA-256"));
        assertTrue(first.contains("Raw file contents are never uploaded"));
        assertTrue(first.contains("not a cheat finding or permanent punishment"));
        assertTrue(ExplicitFileConsentScreen.pageCount(files.size()) == 2);
    }

    @Test
    void controllerRejectsUndisplayableRequestsAndUsesIdentityForStaleCallbacks() {
        Object active = new Object();
        assertTrue(ExplicitFileConsentController.isCurrent(active, active));
        assertFalse(ExplicitFileConsentController.isCurrent(active, new Object()));
        assertTrue(ExplicitFileConsentController.validDisplayRequest(List.of("options.txt")));
        assertFalse(ExplicitFileConsentController.validDisplayRequest(List.of("bad\npath.txt")));
        assertFalse(ExplicitFileConsentController.validDisplayRequest(List.of("x".repeat(513))));
    }

    @Test
    void completedRenderMarkerEmitsExactlyOnce() {
        AtomicInteger callbacks = new AtomicInteger();
        OneShotRenderMarker marker = new OneShotRenderMarker(callbacks::incrementAndGet);

        assertFalse(marker.emitted());
        marker.markRendered();
        marker.markRendered();

        assertTrue(marker.emitted());
        assertTrue(callbacks.get() == 1);
    }

    @Test
    void compactMaximumPathContentKeepsEveryButtonVisibleAndScrollable() {
        ExplicitFileConsentScreen.ButtonLayout buttons =
                ExplicitFileConsentScreen.buttonLayout(320, 240, true, true);
        ExplicitFileConsentScreen.ExplicitLayout layout = ExplicitFileConsentScreen.layoutFor(
                320, 240, 9, 90, 7, buttons.areaTop());

        assertEquals(3, buttons.buttons().size());
        assertTrue(buttons.areaTop() < buttons.buttons().getLast().y());
        for (ExplicitFileConsentScreen.ButtonBounds button : buttons.buttons()) {
            assertTrue(button.x() >= 8);
            assertTrue(button.x() + button.width() <= 312);
            assertTrue(button.y() >= 0 && button.y() + 20 <= 240);
        }
        assertTrue(layout.viewportBottom() < buttons.areaTop());
        assertTrue(layout.maxScroll() > 0);
        assertEquals(layout.maxScroll(), ConsentUiSupport.clampScroll(Integer.MAX_VALUE, layout.maxScroll()));
    }

    @Test
    void maximumLengthDynamicPathReplacesBidiAndLineFormattingCharacters() {
        String hostile = "a".repeat(250) + "\u202E" + "b".repeat(250) + "\u2066\u2028tail-tail";
        String rendered = String.join("\n",
                ExplicitFileConsentScreen.pageParagraphs(policy(), List.of(hostile), 0));

        assertEquals(512, hostile.length());
        assertTrue(rendered.contains("�"));
        assertFalse(ExplicitFileConsentScreen.pageParagraphs(policy(), List.of(hostile), 0).stream()
                .flatMapToInt(String::codePoints)
                .anyMatch(codePoint -> Character.isISOControl(codePoint)
                        || Character.getType(codePoint) == Character.FORMAT
                        || Character.getType(codePoint) == Character.LINE_SEPARATOR
                        || Character.getType(codePoint) == Character.PARAGRAPH_SEPARATOR));
    }

    private static VerifiedPolicy policy() {
        return new VerifiedPolicy(
                SecurityPolicy.newBuilder().setServerId("pinned-network").build(),
                SignedPolicyDocument.getDefaultInstance(), new byte[32], 0L, false);
    }
}
