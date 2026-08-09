package com.ellan.mcace.velocity;

import com.ellan.mcace.core.proxy.ArtifactObservationAuditRecord;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditStatus;
import com.velocitypowered.api.command.SimpleCommand;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import net.kyori.adventure.text.Component;

/** Read-only dynamic-observation operational view; it never exposes artifact identity or content. */
final class MCAceObservationCommand implements SimpleCommand {
    private static final String PERMISSION = "mcace.admin.audit";
    private final ArtifactObservationAuditSink audit;
    MCAceObservationCommand(ArtifactObservationAuditSink audit) { this.audit = Objects.requireNonNull(audit, "audit"); }
    @Override public void execute(Invocation invocation) {
        if (!hasPermission(invocation)) { invocation.source().sendMessage(Component.text("MCAce: missing permission " + PERMISSION)); return; }
        String[] args = invocation.arguments();
        if (args.length == 1 && "status".equalsIgnoreCase(args[0])) {
            ArtifactObservationAuditStatus status = audit.status();
            invocation.source().sendMessage(Component.text("MCAce: dynamic audit enabled=" + status.enabled()
                    + " records=" + status.recordCount() + " bytes=" + status.storedBytes() + "/" + status.maxBytes()
                    + " dropped=" + status.droppedCount() + " failures=" + status.failureCount()));
            return;
        }
        if (args.length >= 2 && args.length <= 3 && "player".equalsIgnoreCase(args[0])) {
            try {
                UUID player = UUID.fromString(args[1]); int limit = args.length == 3 ? Integer.parseInt(args[2]) : 10;
                List<ArtifactObservationAuditRecord> records = audit.recent(player, limit);
                invocation.source().sendMessage(Component.text("MCAce: dynamic audit summaries=" + records.size()));
                for (ArtifactObservationAuditRecord record : records) invocation.source().sendMessage(Component.text(
                        "MCAce: observed=" + record.observedAt() + " observations=" + record.observationCount()
                                + " issues=" + record.consistencyIssueCount() + " actions=" + record.actionCounts()
                                + " policy=" + record.policyStatus()));
            } catch (RuntimeException exception) { invocation.source().sendMessage(Component.text("MCAce: invalid player UUID or limit")); }
            return;
        }
        invocation.source().sendMessage(Component.text("Usage: /mcaceobservation status | player <uuid> [1-100]"));
    }
    @Override public boolean hasPermission(Invocation invocation) { return invocation.source().hasPermission(PERMISSION); }
}
