package com.ellan.mcace.bungeecord;

import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.Objects;

/** Formats the non-sensitive status exposed by {@code /mcace check}. */
final class BungeeStatusRenderer {
    private BungeeStatusRenderer() {
    }

    static String noSession(String playerName) {
        return "MCAce: " + boundedPlayerName(playerName) + " has no verified session";
    }

    static String snapshot(String playerName, PlayerSecuritySnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        return "MCAce: " + boundedPlayerName(playerName)
                + " trust=" + snapshot.trustLevel()
                + " admission=" + snapshot.admissionStatus()
                + " risk=" + snapshot.riskScore()
                + " band=" + snapshot.riskBand();
    }

    static String disposition(BungeeDispositionStatus status) {
        Objects.requireNonNull(status, "status");
        return "MCAce: disposition status=" + status.refreshStatus()
                + " sequence=" + status.activeSequence().map(String::valueOf).orElse("none")
                + " (observational; no automatic punishment)";
    }

    private static String boundedPlayerName(String playerName) {
        Objects.requireNonNull(playerName, "playerName");
        if (playerName.length() > 16) {
            return playerName.substring(0, 16);
        }
        return playerName;
    }
}
