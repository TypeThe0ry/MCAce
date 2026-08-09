package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.proxy.ArtifactObservationAuditRecord;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditStatus;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.plugin.Command;

/** Read-only dynamic-observation operational view; it never exposes artifact identity or content. */
final class MCAceObservationCommand extends Command {
    private static final String PERMISSION = "mcace.admin.audit";
    private final ArtifactObservationAuditSink audit;
    MCAceObservationCommand(ArtifactObservationAuditSink audit) { super("mcaceobservation"); this.audit = Objects.requireNonNull(audit, "audit"); }
    @Override public void execute(CommandSender sender, String[] args) {
        if (!sender.hasPermission(PERMISSION)) { send(sender, "MCAce: missing permission " + PERMISSION); return; }
        if (args.length == 1 && "status".equalsIgnoreCase(args[0])) {
            ArtifactObservationAuditStatus status = audit.status();
            send(sender, "MCAce: dynamic audit enabled=" + status.enabled() + " records=" + status.recordCount()
                    + " bytes=" + status.storedBytes() + "/" + status.maxBytes() + " dropped=" + status.droppedCount()
                    + " failures=" + status.failureCount()); return;
        }
        if (args.length >= 2 && args.length <= 3 && "player".equalsIgnoreCase(args[0])) try {
            UUID player = UUID.fromString(args[1]); int limit = args.length == 3 ? Integer.parseInt(args[2]) : 10;
            List<ArtifactObservationAuditRecord> records = audit.recent(player, limit);
            send(sender, "MCAce: dynamic audit summaries=" + records.size());
            for (ArtifactObservationAuditRecord record : records) send(sender, "MCAce: observed=" + record.observedAt()
                    + " observations=" + record.observationCount() + " issues=" + record.consistencyIssueCount()
                    + " actions=" + record.actionCounts() + " policy=" + record.policyStatus());
            return;
        } catch (RuntimeException ignored) { send(sender, "MCAce: invalid player UUID or limit"); return; }
        send(sender, "Usage: /mcaceobservation status | player <uuid> [1-100]");
    }
    private static void send(CommandSender sender, String message) { sender.sendMessage(new TextComponent(message)); }
}
