package com.ellan.mcace.velocity;

import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import com.ellan.mcace.core.evidence.EvidenceRequestSpec;
import com.ellan.mcace.core.evidence.EvidenceAdminService;
import com.ellan.mcace.core.evidence.EvidenceStoreStatus;
import com.ellan.mcace.core.evidence.LoopbackEvidenceReviewService;
import com.ellan.mcace.core.evidence.EvidenceReviewCommandInput;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.time.Clock;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

/** Admin request management; it returns only bounded identifiers and transport status. */
final class MCAceEvidenceCommand implements SimpleCommand {
    private static final String PERMISSION = "mcace.admin.evidence";

    @FunctionalInterface
    interface Issuer {
        Optional<EvidenceRequestRuntime.IssuedRequest> issue(
                Player player, EvidenceRequestSpec spec, String operatorId) throws EnvelopeException;

        default void cancel(Player player) { }
        default boolean isCurrent(Player player) { return true; }
        default boolean deliver(Player player, byte[] frame) {
            return isCurrent(player) && player.sendPluginMessage(MCAceVelocityChannels.HANDSHAKE, frame);
        }
        default EvidenceRequestSpec spec(EvidenceCaptureScope scope, String caseId) {
            return EvidenceRequestSpec.screenshot(scope, caseId);
        }
    }

    @FunctionalInterface
    interface ReviewIssuer {
        Optional<LoopbackEvidenceReviewService.ReviewLink> issue(UUID evidenceId, String operatorId, String reason);
    }

    private final ProxyServer server;
    private final Logger logger;
    private final Issuer issuer;
    private final EvidenceAdminService evidenceAdmin;
    private final ReviewIssuer reviewIssuer;

    MCAceEvidenceCommand(ProxyServer server, Logger logger, Issuer issuer) {
        this(server, logger, issuer, EvidenceAdminService.disabled(Clock.systemUTC(),
                com.ellan.mcace.core.evidence.EvidenceAuditSink.noop()), (ignored, operator, reason) -> Optional.empty());
    }

    MCAceEvidenceCommand(ProxyServer server, Logger logger, Issuer issuer, EvidenceAdminService evidenceAdmin) {
        this(server, logger, issuer, evidenceAdmin, (ignored, operator, reason) -> Optional.empty());
    }

    MCAceEvidenceCommand(ProxyServer server, Logger logger, Issuer issuer, EvidenceAdminService evidenceAdmin,
            ReviewIssuer reviewIssuer) {
        this.server = Objects.requireNonNull(server, "server");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.evidenceAdmin = Objects.requireNonNull(evidenceAdmin, "evidenceAdmin");
        this.reviewIssuer = Objects.requireNonNull(reviewIssuer, "reviewIssuer");
    }

    @Override
    public void execute(Invocation invocation) {
        if (!hasPermission(invocation)) {
            invocation.source().sendMessage(Component.text("MCAce: missing permission " + PERMISSION));
            return;
        }
        String[] arguments = invocation.arguments();
        if (arguments.length > 0 && "review".equalsIgnoreCase(arguments[0])) {
            review(invocation, arguments);
            return;
        }
        if (arguments.length >= 2 && "storage".equalsIgnoreCase(arguments[0])) {
            storage(invocation, arguments);
            return;
        }
        if (arguments.length < 3 || arguments.length > 4 || !"request".equalsIgnoreCase(arguments[0])) {
            invocation.source().sendMessage(
                    Component.text("Usage: /mcaceevidence request <player> <frame|window|desktop> [case-id]"));
            return;
        }
        Optional<Player> player = server.getPlayer(arguments[1]);
        EvidenceCaptureScope scope = parseScope(arguments[2]);
        if (player.isEmpty() || scope == null) {
            invocation.source().sendMessage(Component.text("MCAce: unknown player or unsupported evidence scope"));
            return;
        }
        String caseId = arguments.length == 4 ? arguments[3] : "manual";
        try {
            Optional<EvidenceRequestRuntime.IssuedRequest> issued = issuer.issue(
                    player.orElseThrow(), issuer.spec(scope, caseId),
                    operatorId(invocation));
            if (issued.isEmpty()) {
                invocation.source().sendMessage(
                        Component.text("MCAce: evidence request unavailable (session or concurrency bound)"));
                return;
            }
            EvidenceRequestRuntime.IssuedRequest request = issued.orElseThrow();
            if (!issuer.deliver(player.orElseThrow(), request.encodedFrame())) {
                issuer.cancel(player.orElseThrow());
                invocation.source().sendMessage(Component.text("MCAce: evidence request delivery failed"));
                return;
            }
            invocation.source().sendMessage(Component.text(
                    "MCAce: evidence request issued id=" + request.request().getRequestId()
                            + " scope=" + scope.name()));
        } catch (EnvelopeException | RuntimeException exception) {
            logger.warn("MCAce evidence request failed; no content was collected", exception);
            invocation.source().sendMessage(Component.text("MCAce: evidence request failed; no content was collected"));
        }
    }

    private void storage(Invocation invocation, String[] arguments) {
        if ("status".equalsIgnoreCase(arguments[1]) && arguments.length == 2) {
            EvidenceStoreStatus status = evidenceAdmin.status();
            invocation.source().sendMessage(Component.text(
                    "MCAce: evidence storage enabled=" + status.enabled() + " state=" + status.state()
                            + " files=" + status.fileCount() + "/" + status.maxFiles()
                            + " bytes=" + status.totalBytes() + "/" + status.maxTotalBytes()
                            + " retentionSeconds=" + status.retentionSeconds()
                            + " policy=" + status.retentionPolicyId()));
            return;
        }
        if ("delete".equalsIgnoreCase(arguments[1]) && arguments.length >= 4) {
            try {
                UUID evidenceId = UUID.fromString(arguments[2]);
                String reason = String.join(" ", java.util.Arrays.copyOfRange(arguments, 3, arguments.length));
                boolean deleted = evidenceAdmin.delete(evidenceId, reason, operatorId(invocation));
                invocation.source().sendMessage(Component.text(
                        "MCAce: evidence " + (deleted ? "deleted" : "not found") + " id=" + evidenceId));
            } catch (Exception exception) {
                logger.warn("MCAce evidence deletion failed", exception);
                invocation.source().sendMessage(Component.text("MCAce: evidence deletion failed"));
            }
            return;
        }
        invocation.source().sendMessage(Component.text(
                "Usage: /mcaceevidence storage status | storage delete <evidence-id> <reason>"));
    }

    /** The review URL is deliberately console-only; no token can enter player chat. */
    private void review(Invocation invocation, String[] arguments) {
        EvidenceReviewCommandInput.Validation validation = EvidenceReviewCommandInput.validate(
                invocation.source() == server.getConsoleCommandSource(), arguments);
        if (validation.status() != EvidenceReviewCommandInput.Status.ACCEPTED) {
            reviewValidationMessage(invocation, validation.status());
            return;
        }
        EvidenceReviewCommandInput.Request request = validation.request().orElseThrow();
        try {
            Optional<LoopbackEvidenceReviewService.ReviewLink> issued = reviewIssuer.issue(
                    request.evidenceId(), "velocity-console", request.reason());
            if (issued.isEmpty()) {
                invocation.source().sendMessage(Component.text(
                        "MCAce: local evidence review is unavailable (disabled or no review-capable store)"));
                return;
            }
            LoopbackEvidenceReviewService.ReviewLink link = issued.orElseThrow();
            invocation.source().sendMessage(Component.text(
                    "MCAce local evidence review URL (single-use, expires " + link.expiresAt() + "): " + link.url()));
        } catch (IllegalArgumentException exception) {
            invocation.source().sendMessage(Component.text("MCAce: evidence is not eligible for local review"));
        } catch (RuntimeException exception) {
            logger.warn("MCAce local evidence review issuance failed", exception);
            invocation.source().sendMessage(Component.text("MCAce: local evidence review is unavailable"));
        }
    }

    private static void reviewValidationMessage(Invocation invocation, EvidenceReviewCommandInput.Status status) {
        String message = switch (status) {
            case CONSOLE_ONLY -> "MCAce: local evidence review is console-only";
            case USAGE -> "Usage: /mcaceevidence review <evidence-uuid> <reason>";
            case INVALID_EVIDENCE_ID -> "MCAce: invalid evidence identifier";
            case INVALID_REASON -> "MCAce: invalid review reason";
            case ACCEPTED -> throw new IllegalStateException("accepted review request needs issuance");
        };
        invocation.source().sendMessage(Component.text(message));
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission(PERMISSION);
    }

    private static EvidenceCaptureScope parseScope(String value) {
        return switch (value.toLowerCase(java.util.Locale.ROOT)) {
            case "frame", "game_render_frame" -> EvidenceCaptureScope.GAME_RENDER_FRAME;
            case "window", "game_window" -> EvidenceCaptureScope.GAME_WINDOW;
            case "desktop" -> EvidenceCaptureScope.DESKTOP;
            default -> null;
        };
    }

    private static String operatorId(Invocation invocation) {
        return invocation.source() instanceof Player player
                ? "velocity-player:" + player.getUniqueId() : "velocity-console";
    }
}
