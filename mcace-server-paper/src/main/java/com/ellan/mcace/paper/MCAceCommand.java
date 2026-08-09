package com.ellan.mcace.paper;

import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.Arrays;
import java.util.Objects;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.jetbrains.annotations.NotNull;

final class MCAceCommand implements CommandExecutor {
    private final MCAceApi api;
    private final MCAceRuntimeScheduler scheduler;

    MCAceCommand(MCAceApi api, MCAceRuntimeScheduler scheduler) {
        this.api = Objects.requireNonNull(api, "api");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
    }

    @Override
    public boolean onCommand(
            @NotNull CommandSender sender,
            @NotNull Command command,
            @NotNull String label,
            @NotNull String[] arguments) {
        if (arguments.length != 2 || !arguments[0].equalsIgnoreCase("check")) {
            return false;
        }
        String target = arguments[1];
        scheduler.executeGlobal(() -> check(sender, target));
        return true;
    }

    private void check(CommandSender sender, String target) {
        OfflinePlayer player = Arrays.stream(Bukkit.getOfflinePlayers())
                .filter(candidate -> candidate.getName() != null && candidate.getName().equalsIgnoreCase(target))
                .findFirst()
                .orElse(null);
        if (player == null) {
            reply(sender, "MCAce: unknown player " + target);
            return;
        }
        PlayerSecuritySnapshot snapshot = api.snapshot(player.getUniqueId()).orElse(null);
        if (snapshot == null) {
            reply(sender, "MCAce: " + target + " has no verified session");
            return;
        }
        reply(sender, "MCAce: " + target
                + " trust=" + snapshot.trustLevel()
                + " admission=" + snapshot.admissionStatus()
                + " risk=" + snapshot.riskScore()
                + " band=" + snapshot.riskBand());
    }

    private void reply(CommandSender sender, String message) {
        if (sender instanceof Player player) {
            scheduler.executeForPlayer(player, () -> player.sendMessage(message), () -> { });
        } else {
            sender.sendMessage(message);
        }
    }
}
