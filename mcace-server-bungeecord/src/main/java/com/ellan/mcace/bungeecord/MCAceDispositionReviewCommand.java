package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.proxy.AdministratorDispositionReviewRequest;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

/** Explicit operator review command; the active signed policy selects the action. */
final class MCAceDispositionReviewCommand extends Command {
    static final String PERMISSION = "mcace.admin.disposition.review";

    @FunctionalInterface
    interface Reviewer {
        ReviewResult review(String playerName, String operatorId, AdministratorDispositionReviewRequest request);
    }

    enum Status {
        AUTHORIZED,
        UNKNOWN_PLAYER,
        NO_CURRENT_AUTHENTICATED_SESSION,
        AUTHORIZATION_AUDIT_UNAVAILABLE,
        EXECUTION_QUEUE_UNAVAILABLE,
        FAILED
    }

    record ReviewResult(
            Status status,
            Optional<DispositionAction> action,
            Optional<String> ruleId,
            Optional<Long> policySequence,
            Optional<UUID> authorizationId) {
        ReviewResult {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(ruleId, "ruleId");
            Objects.requireNonNull(policySequence, "policySequence");
            Objects.requireNonNull(authorizationId, "authorizationId");
        }

        static ReviewResult status(Status status) {
            return new ReviewResult(status, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        }
    }

    private final Reviewer reviewer;

    MCAceDispositionReviewCommand(Reviewer reviewer) {
        super("mcacedisposition");
        this.reviewer = Objects.requireNonNull(reviewer, "reviewer");
    }

    @Override
    public void execute(CommandSender sender, String[] arguments) {
        if (!sender.hasPermission(PERMISSION)) {
            send(sender, "MCAce: missing permission " + PERMISSION);
            return;
        }
        if (arguments.length != 7 || !"review".equalsIgnoreCase(arguments[0])) {
            usage(sender);
            return;
        }
        AdministratorDispositionReviewRequest request;
        try {
            ArtifactType type = AdministratorDispositionReviewRequest.parseArtifactType(arguments[3]);
            request = new AdministratorDispositionReviewRequest(
                    arguments[2], type, arguments[4], arguments[5], arguments[6]);
        } catch (IllegalArgumentException exception) {
            send(sender, "MCAce: disposition review rejected; use bounded tokens and an exact SHA-256");
            return;
        }
        String operatorId = sender instanceof ProxiedPlayer player
                ? "player:" + player.getUniqueId() : "console";
        ReviewResult result = reviewer.review(arguments[1], operatorId, request);
        if (result.status() == Status.AUTHORIZED) {
            send(sender, "MCAce: disposition review authorized"
                    + " action=" + result.action().orElseThrow()
                    + " rule=" + result.ruleId().orElse("none")
                    + " policy-sequence=" + result.policySequence().map(Object::toString).orElse("none")
                    + " authorization=" + result.authorizationId().orElseThrow()
                    + " session-bound=true execution-context-bound=true execution-queued=true");
            return;
        }
        send(sender, "MCAce: disposition review not authorized status=" + result.status());
    }

    private static void usage(CommandSender sender) {
        send(sender, "Usage: /mcacedisposition review <player> <ticket>"
                + " <mod|resource-pack|shader-pack|config> <identifier> <version> <sha256>");
    }

    private static void send(CommandSender sender, String text) {
        sender.sendMessage(new TextComponent(text));
    }
}
