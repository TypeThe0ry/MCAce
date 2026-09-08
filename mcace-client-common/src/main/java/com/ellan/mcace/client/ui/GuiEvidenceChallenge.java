package com.ellan.mcace.client.ui;

import java.util.List;

/** Display-only correlation for an explicitly configured GUI evidence run. */
public final class GuiEvidenceChallenge {
    public static final String PROPERTY = "mcace.platform-smoke.gui-challenge";

    private GuiEvidenceChallenge() { }

    public static List<String> disclosure(String challenge) {
        if (challenge == null) return List.of();
        if (!challenge.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("GUI evidence challenge must be 64 lowercase hex characters");
        }
        // Short lines stay readable even at the default Minecraft GUI scale.
        return List.of("GUI evidence challenge (display only):",
                challenge.substring(0, 16), challenge.substring(16, 32),
                challenge.substring(32, 48), challenge.substring(48, 64));
    }
}
