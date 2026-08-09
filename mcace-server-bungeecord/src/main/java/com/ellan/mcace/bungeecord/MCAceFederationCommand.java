package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.federation.FederationRuntimeState;
import com.ellan.mcace.core.federation.FederationRuntimeStatus;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

/** Content-free federation administration. No grant, key, nonce, signature, or hash is rendered. */
final class MCAceFederationCommand extends Command {
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
        super("mcacefederation");
        this.operations = Objects.requireNonNull(operations, "operations");
        this.onlinePlayerLookup = Objects.requireNonNull(onlinePlayerLookup, "onlinePlayerLookup");
    }

    @Override
    public void execute(CommandSender sender, String[] arguments) {
        if (!sender.hasPermission(PERMISSION)) {
            send(sender, "MCAce: missing permission " + PERMISSION);
            return;
        }
        if (arguments.length == 1 && "status".equalsIgnoreCase(arguments[0])) {
            FederationRuntimeState status = operations.status();
            send(sender, "MCAce: federation enabled=" + status.enabled()
                    + " local=" + status.localNetworkId()
                    + " peers=" + status.pinnedPeers()
                    + " pending=" + status.pendingConsentRequests()
                    + " observations=" + status.activeObservations());
            return;
        }
        if (arguments.length == 1 && "peers".equalsIgnoreCase(arguments[0])) {
            List<String> peers = operations.peers();
            send(sender, "MCAce: federation peers=" + peers.size());
            for (String peer : peers) {
                send(sender, "MCAce: federation peer=" + peer);
            }
            return;
        }
        if (arguments.length == 3 && "issue".equalsIgnoreCase(arguments[0])) {
            Optional<UUID> player = onlinePlayerLookup.apply(arguments[1]);
            if (player.isEmpty()) {
                send(sender, "MCAce: unknown online player");
                return;
            }
            FederationRuntimeStatus status = operations.issue(
                    player.orElseThrow(), arguments[2], operatorId(sender));
            send(sender, "MCAce: federation issue status=" + status.name());
            return;
        }
        send(sender, "Usage: /mcacefederation status | peers | issue <player> <target>");
    }

    private static void send(CommandSender sender, String message) {
        sender.sendMessage(new TextComponent(message));
    }

    private static String operatorId(CommandSender sender) {
        return sender instanceof ProxiedPlayer player
                ? "bungee-player:" + player.getUniqueId() : "bungee-console";
    }
}
