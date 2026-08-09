package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Command;

/** Administrative status and signed-policy publication; it has no punishment subcommands. */
final class MCAceBungeeCommand extends Command {
    private static final String CHECK_PERMISSION = "mcace.admin.check";
    private static final String POLICY_PERMISSION = "mcace.admin.policy";

    private final MCAceApi api;
    private final Supplier<BungeeDispositionStatus> dispositionStatus;
    private final Supplier<Optional<BungeeDispositionPolicyPublisher>> dispositionPublisher;
    private final Supplier<BungeeDispositionExecutionMode> executionMode;

    MCAceBungeeCommand(MCAceApi api) {
        this(api, BungeeDispositionStatus::unavailable, Optional::empty);
    }

    MCAceBungeeCommand(MCAceApi api, Supplier<BungeeDispositionStatus> dispositionStatus) {
        this(api, dispositionStatus, Optional::empty);
    }

    MCAceBungeeCommand(
            MCAceApi api,
            Supplier<BungeeDispositionStatus> dispositionStatus,
            Supplier<Optional<BungeeDispositionPolicyPublisher>> dispositionPublisher) {
        this(api, dispositionStatus, dispositionPublisher, () -> BungeeDispositionExecutionMode.MONITOR);
    }

    MCAceBungeeCommand(
            MCAceApi api,
            Supplier<BungeeDispositionStatus> dispositionStatus,
            Supplier<Optional<BungeeDispositionPolicyPublisher>> dispositionPublisher,
            Supplier<BungeeDispositionExecutionMode> executionMode) {
        super("mcace");
        this.api = Objects.requireNonNull(api, "api");
        this.dispositionStatus = Objects.requireNonNull(dispositionStatus, "dispositionStatus");
        this.dispositionPublisher = Objects.requireNonNull(dispositionPublisher, "dispositionPublisher");
        this.executionMode = Objects.requireNonNull(executionMode, "executionMode");
    }

    @Override
    public void execute(CommandSender sender, String[] arguments) {
        if (arguments.length == 1 && "disposition".equalsIgnoreCase(arguments[0])) {
            if (!sender.hasPermission(CHECK_PERMISSION)) {
                send(sender, "MCAce: missing permission " + CHECK_PERMISSION);
                return;
            }
            send(sender, BungeeStatusRenderer.disposition(dispositionStatus.get()));
            return;
        }
        if (arguments.length == 2 && "disposition".equalsIgnoreCase(arguments[0])
                && "publish".equalsIgnoreCase(arguments[1])) {
            publishDisposition(sender);
            return;
        }
        String catalogOperation = catalogOperation(arguments);
        if (catalogOperation != null) {
            catalog(sender, catalogOperation);
            return;
        }
        if (arguments.length != 2 || !"check".equalsIgnoreCase(arguments[0])) {
            send(sender, "Usage: /mcace check <player> | /mcace disposition"
                    + " | /mcace disposition publish"
                    + " | /mcace disposition <preview|validate|list>"
                    + " | /mcace disposition catalog <preview|validate|list|publish>");
            return;
        }
        if (!sender.hasPermission(CHECK_PERMISSION)) {
            send(sender, "MCAce: missing permission " + CHECK_PERMISSION);
            return;
        }
        ProxiedPlayer player = ProxyServer.getInstance().getPlayer(arguments[1]);
        if (player == null) {
            send(sender, "MCAce: unknown online player " + arguments[1]);
            return;
        }
        PlayerSecuritySnapshot snapshot = api.snapshot(player.getUniqueId()).orElse(null);
        send(sender, snapshot == null
                ? BungeeStatusRenderer.noSession(player.getName())
                : BungeeStatusRenderer.snapshot(player.getName(), snapshot));
    }

    private void publishDisposition(CommandSender sender) {
        if (!sender.hasPermission(POLICY_PERMISSION)) {
            send(sender, "MCAce: missing permission " + POLICY_PERMISSION);
            return;
        }
        Optional<BungeeDispositionPolicyPublisher> publisher = dispositionPublisher.get();
        if (publisher.isEmpty()) {
            send(sender, "MCAce: disposition publishing is unavailable");
            return;
        }
        try {
            DispositionCatalogPreview preview = null;
            try {
                preview = publisher.orElseThrow().preview();
            } catch (com.ellan.mcace.protocol.policy.PolicyException ignored) {
                // Preserve the legacy publish path for custom bridges that predate preview().
            }
            BungeePublishedDispositionPolicy published = publisher.orElseThrow().publish();
            if (preview != null) {
                send(sender, BungeeDispositionCatalogSummary.render(
                        "publish", preview, Optional.of(published.version()),
                        dispositionStatus.get().activeSequence(), executionMode.get()));
            } else {
                send(sender, "MCAce: disposition policy published version="
                        + BungeeDispositionCatalogSummary.safeVersion(Optional.of(published.version()))
                        + " rules=" + published.ruleCount()
                        + " active-sequence=" + dispositionStatus.get().activeSequence()
                        .map(String::valueOf).orElse("none")
                        + " mode=" + executionMode.get().name()
                        + " high-impact=LIMITED_ROUTE_REQUIRED"
                        + " command-mode-unchanged=true");
            }
        } catch (Exception exception) {
            // The shared publisher atomically preserves the last valid document on every failure.
            send(sender, BungeeDispositionCatalogSummary.failure(
                    dispositionStatus.get().activeSequence(), executionMode.get()));
        }
    }

    private void catalog(CommandSender sender, String operation) {
        String permission = "publish".equals(operation) ? POLICY_PERMISSION : CHECK_PERMISSION;
        if (!sender.hasPermission(permission)) {
            send(sender, "MCAce: missing permission " + permission);
            return;
        }
        Optional<BungeeDispositionPolicyPublisher> publisher = dispositionPublisher.get();
        if (publisher.isEmpty()) {
            send(sender, "MCAce: disposition catalog " + operation + " unavailable"
                    + " active-sequence=" + dispositionStatus.get().activeSequence()
                    .map(String::valueOf).orElse("none")
                    + " mode=" + executionMode.get().name()
                    + " high-impact=LIMITED_ROUTE_REQUIRED"
                    + " command-mode-unchanged=true");
            return;
        }
        if ("publish".equals(operation)) {
            publishDisposition(sender);
            return;
        }
        try {
            DispositionCatalogPreview preview = publisher.orElseThrow().preview();
            send(sender, BungeeDispositionCatalogSummary.render(
                    operation, preview, Optional.empty(), dispositionStatus.get().activeSequence(), executionMode.get()));
            if ("list".equals(operation)) {
                BungeeDispositionCatalogSummary.listSources(preview).forEach(line -> send(sender, line));
            }
        } catch (Exception exception) {
            send(sender, "MCAce: disposition catalog " + operation + " rejected"
                    + " warnings=VALIDATION_FAILED"
                    + " active-sequence=" + dispositionStatus.get().activeSequence()
                    .map(String::valueOf).orElse("none")
                    + " mode=" + executionMode.get().name()
                    + " high-impact=LIMITED_ROUTE_REQUIRED"
                    + " command-mode-unchanged=true");
        }
    }

    private static String catalogOperation(String[] arguments) {
        if (arguments.length == 2 && "disposition".equalsIgnoreCase(arguments[0])
                && ("preview".equalsIgnoreCase(arguments[1])
                || "validate".equalsIgnoreCase(arguments[1]) || "list".equalsIgnoreCase(arguments[1]))) {
            return arguments[1].toLowerCase(java.util.Locale.ROOT);
        }
        if (arguments.length == 3 && "disposition".equalsIgnoreCase(arguments[0])
                && "catalog".equalsIgnoreCase(arguments[1])
                && ("preview".equalsIgnoreCase(arguments[2])
                || "validate".equalsIgnoreCase(arguments[2]) || "list".equalsIgnoreCase(arguments[2])
                || "publish".equalsIgnoreCase(arguments[2]))) {
            return arguments[2].toLowerCase(java.util.Locale.ROOT);
        }
        return null;
    }

    private static void send(CommandSender sender, String message) {
        sender.sendMessage(new TextComponent(message));
    }
}
