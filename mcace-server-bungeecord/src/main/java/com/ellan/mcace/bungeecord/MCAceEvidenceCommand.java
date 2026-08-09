package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.evidence.EvidenceAdminService;
import com.ellan.mcace.core.evidence.EvidenceStoreStatus;
import com.ellan.mcace.core.evidence.LoopbackEvidenceReviewService;
import com.ellan.mcace.core.evidence.EvidenceReviewCommandInput;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.time.Clock;
import java.util.function.Supplier;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

/** Admin request management; it returns only bounded identifiers and transport status. */
final class MCAceEvidenceCommand extends Command {
    private static final String PERMISSION = "mcace.admin.evidence";
    private final Supplier<BungeeSessionBridge> bridge;
    private final RequestDispatcher requestDispatcher;

    @FunctionalInterface
    interface RequestDispatcher {
        BungeeEvidenceDispatch.Result request(
                ProxiedPlayer player, EvidenceCaptureScope scope, String caseId, String operatorId);
    }

    MCAceEvidenceCommand(Supplier<BungeeSessionBridge> bridge, RequestDispatcher requestDispatcher) {
        super("mcaceevidence");
        this.bridge = Objects.requireNonNull(bridge, "bridge");
        this.requestDispatcher = Objects.requireNonNull(requestDispatcher, "requestDispatcher");
    }

    @Override
    public void execute(CommandSender sender, String[] arguments) {
        if (!sender.hasPermission(PERMISSION)) {
            send(sender, "MCAce: missing permission " + PERMISSION);
            return;
        }
        if (arguments.length > 0 && "review".equalsIgnoreCase(arguments[0])) {
            review(sender, arguments);
            return;
        }
        if (arguments.length >= 2 && "storage".equalsIgnoreCase(arguments[0])) {
            storage(sender, arguments);
            return;
        }
        if (arguments.length < 3 || arguments.length > 4 || !"request".equalsIgnoreCase(arguments[0])) {
            send(sender, "Usage: /mcaceevidence request <player> <frame|window|desktop> [case-id]");
            return;
        }
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(arguments[1]);
        EvidenceCaptureScope scope = parseScope(arguments[2]);
        if (player == null || scope == null) {
            send(sender, "MCAce: unknown player or unsupported evidence scope");
            return;
        }
        String caseId = arguments.length == 4 ? arguments[3] : "manual";
        BungeeEvidenceDispatch.Result result = requestDispatcher.request(player, scope, caseId, operatorId(sender));
        if (result.status() == BungeeEvidenceDispatch.Status.DISPATCH_INITIATED) {
            send(sender, "MCAce: evidence request dispatch initiated id=" + result.requestId().orElseThrow()
                    + " scope=" + scope.name());
        } else if (result.status() == BungeeEvidenceDispatch.Status.UNAVAILABLE) {
            send(sender, "MCAce: evidence request unavailable (current session or concurrency bound)");
        } else {
            send(sender, "MCAce: evidence request failed; no content was collected");
        }
    }

    private void storage(CommandSender sender, String[] arguments) {
        EvidenceAdminService admin = bridge.get().evidenceAdmin()
                .orElseGet(() -> EvidenceAdminService.disabled(Clock.systemUTC(),
                        com.ellan.mcace.core.evidence.EvidenceAuditSink.noop()));
        if ("status".equalsIgnoreCase(arguments[1]) && arguments.length == 2) {
            EvidenceStoreStatus status = admin.status();
            send(sender, "MCAce: evidence storage enabled=" + status.enabled() + " state=" + status.state()
                    + " files=" + status.fileCount() + "/" + status.maxFiles()
                    + " bytes=" + status.totalBytes() + "/" + status.maxTotalBytes()
                    + " retentionSeconds=" + status.retentionSeconds()
                    + " policy=" + status.retentionPolicyId());
            return;
        }
        if ("delete".equalsIgnoreCase(arguments[1]) && arguments.length >= 4) {
            try {
                UUID evidenceId = UUID.fromString(arguments[2]);
                String reason = String.join(" ", java.util.Arrays.copyOfRange(arguments, 3, arguments.length));
                boolean deleted = admin.delete(evidenceId, reason, operatorId(sender));
                send(sender, "MCAce: evidence " + (deleted ? "deleted" : "not found") + " id=" + evidenceId);
            } catch (Exception exception) {
                send(sender, "MCAce: evidence deletion failed");
            }
            return;
        }
        send(sender, "Usage: /mcaceevidence storage status | storage delete <evidence-id> <reason>");
    }

    /** The review URL is deliberately console-only; no token can enter player chat. */
    private void review(CommandSender sender, String[] arguments) {
        EvidenceReviewCommandInput.Validation validation = EvidenceReviewCommandInput.validate(
                sender == ProxyServer.getInstance().getConsole(), arguments);
        if (validation.status() != EvidenceReviewCommandInput.Status.ACCEPTED) {
            reviewValidationMessage(sender, validation.status());
            return;
        }
        EvidenceReviewCommandInput.Request request = validation.request().orElseThrow();
        try {
            Optional<LoopbackEvidenceReviewService.ReviewLink> issued = bridge.get().evidenceReviewService()
                    .map(service -> service.issue(request.evidenceId(), "bungee-console", request.reason()));
            if (issued.isEmpty()) {
                send(sender, "MCAce: local evidence review is unavailable (disabled or no review-capable store)");
                return;
            }
            LoopbackEvidenceReviewService.ReviewLink link = issued.orElseThrow();
            send(sender, "MCAce local evidence review URL (single-use, expires " + link.expiresAt() + "): " + link.url());
        } catch (IllegalArgumentException exception) {
            send(sender, "MCAce: evidence is not eligible for local review");
        } catch (RuntimeException exception) {
            send(sender, "MCAce: local evidence review is unavailable");
        }
    }

    private static void reviewValidationMessage(CommandSender sender, EvidenceReviewCommandInput.Status status) {
        String message = switch (status) {
            case CONSOLE_ONLY -> "MCAce: local evidence review is console-only";
            case USAGE -> "Usage: /mcaceevidence review <evidence-uuid> <reason>";
            case INVALID_EVIDENCE_ID -> "MCAce: invalid evidence identifier";
            case INVALID_REASON -> "MCAce: invalid review reason";
            case ACCEPTED -> throw new IllegalStateException("accepted review request needs issuance");
        };
        send(sender, message);
    }

    private static EvidenceCaptureScope parseScope(String value) {
        return switch (value.toLowerCase(java.util.Locale.ROOT)) {
            case "frame", "game_render_frame" -> EvidenceCaptureScope.GAME_RENDER_FRAME;
            case "window", "game_window" -> EvidenceCaptureScope.GAME_WINDOW;
            case "desktop" -> EvidenceCaptureScope.DESKTOP;
            default -> null;
        };
    }

    private static void send(CommandSender sender, String message) {
        sender.sendMessage(new TextComponent(message));
    }

    private static String operatorId(CommandSender sender) {
        return sender instanceof ProxiedPlayer player
                ? "bungee-player:" + player.getUniqueId() : "bungee-console";
    }
}
