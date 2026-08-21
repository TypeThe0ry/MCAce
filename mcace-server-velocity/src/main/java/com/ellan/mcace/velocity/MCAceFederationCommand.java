package com.ellan.mcace.velocity;

import com.ellan.mcace.core.federation.FederationRuntimeState;
import com.ellan.mcace.core.federation.FederationRuntimeStatus;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import net.kyori.adventure.text.Component;

/** Content-free federation administration. No grant, key, nonce, signature, or hash is rendered. */
final class MCAceFederationCommand implements SimpleCommand {
    static final String PERMISSION = "mcace.admin.federation";

    interface Operations {
        FederationRuntimeState status();
        List<String> peers();
        FederationRuntimeStatus issue(UUID playerId, String targetNetworkId, String operatorId);
    }

    private final Operations operations;
    private final Function<String, Optional<UUID>> onlinePlayerLookup;

    MCAceFederationCommand(
            Operations operations, Function<String, Optional<UUID>> onlinePlayerLookup) {
        this.operations = Objects.requireNonNull(operations, "operations");
        this.onlinePlayerLookup = Objects.requireNonNull(onlinePlayerLookup, "onlinePlayerLookup");
    }

    @Override
    public void execute(Invocation invocation) {
        if (!hasPermission(invocation)) {
            send(invocation, "MCAce: missing permission " + PERMISSION);
            return;
        }
        String[] arguments = invocation.arguments();
        if (arguments.length == 1 && "status".equalsIgnoreCase(arguments[0])) {
            FederationRuntimeState status = operations.status();
            send(invocation, "MCAce: federation enabled=" + status.enabled()
                    + " configured=" + status.configuredEnabled()
                    + " audit=" + (status.auditHealthy() ? "HEALTHY" : "FAILED")
                    + " audit_backlog=" + status.auditBacklog()
                    + " audit_committed=" + status.auditCommitted()
                    + " audit_failures=" + status.auditFailures()
                    + " local=" + status.localNetworkId()
                    + " peers=" + status.pinnedPeers()
                    + " pending=" + status.pendingConsentRequests()
                    + " observations=" + status.activeObservations());
            return;
        }
        if (arguments.length == 1 && "peers".equalsIgnoreCase(arguments[0])) {
            List<String> peers = operations.peers();
            send(invocation, "MCAce: federation peers=" + peers.size());
            for (String peer : peers) {
                send(invocation, "MCAce: federation peer=" + peer);
            }
            return;
        }
        if (arguments.length == 3 && "issue".equalsIgnoreCase(arguments[0])) {
            Optional<UUID> player = onlinePlayerLookup.apply(arguments[1]);
            if (player.isEmpty()) {
                send(invocation, "MCAce: unknown online player");
                return;
            }
            FederationRuntimeStatus status = operations.issue(
                    player.orElseThrow(), arguments[2], operatorId(invocation));
            send(invocation, "MCAce: federation issue status=" + status.name());
            return;
        }
        send(invocation, "Usage: /mcacefederation status | peers | issue <player> <target>");
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission(PERMISSION);
    }

    private static void send(Invocation invocation, String message) {
        invocation.source().sendMessage(Component.text(message));
    }

    private static String operatorId(Invocation invocation) {
        return invocation.source() instanceof Player player
                ? "velocity-player:" + player.getUniqueId() : "velocity-console";
    }
}
