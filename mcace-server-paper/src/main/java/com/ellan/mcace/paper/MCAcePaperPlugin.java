package com.ellan.mcace.paper;

import com.ellan.mcace.cloudclient.CloudRiskEventClient;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.paper.behavior.BehaviorAlertCorrelator;
import com.ellan.mcace.paper.behavior.BehaviorAlertPipeline;
import com.ellan.mcace.paper.behavior.GrimBehaviorIntegration;
import com.ellan.mcace.paper.behavior.VulcanBehaviorIntegration;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.sdk.MCAceApi;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.bukkit.command.PluginCommand;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerRegisterChannelEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerChangedWorldEvent;
import org.bukkit.event.player.PlayerGameModeChangeEvent;
import org.bukkit.plugin.ServicePriority;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

public final class MCAcePaperPlugin extends JavaPlugin implements Listener {
    private final InMemoryMCAceApi api = new InMemoryMCAceApi();
    private final List<AutoCloseable> behaviorIntegrations = new ArrayList<>();
    private PaperAdmissionReceiver admissionReceiver;
    private CloudRiskEventClient cloudRiskClient;
    private BehaviorAlertPipeline behaviorPipeline;
    private MCAceRuntimeScheduler runtimeScheduler;
    private BackendLocalSessionActionAdapter sessionActions;
    private PaperBackendContextPublisher backendContextPublisher;
    private PaperServerAuthorityRuntime serverAuthorityRuntime;
    private PaperServerAuthorityChannelLease<PaperServerAuthorityRuntime> serverAuthorityLease;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        runtimeScheduler = PaperFoliaRuntimeScheduler.create(this);
        PaperIntegrationConfiguration integrationConfiguration = loadIntegrationConfiguration();
        BackendSessionActionConfiguration sessionActionConfiguration = integrationConfiguration == null
                ? BackendSessionActionConfiguration.monitor() : integrationConfiguration.sessionActions();
        BackendLocalSessionActionAdapter localSessionActions =
                new BackendLocalSessionActionAdapter(sessionActionConfiguration, getLogger());
        sessionActions = localSessionActions;
        backendContextPublisher = new PaperBackendContextPublisher(this, Clock.systemUTC(), getLogger());
        PublicKey proxyPublicKey;
        ProxyIdentityPinPaths.Selection selectedPin = ProxyIdentityPinPaths.select(getDataFolder().toPath());
        Path preferredProxyPin = getDataFolder().toPath().resolve(ProxyIdentityPinPaths.PREFERRED_FILE_NAME);
        Path legacyVelocityPin = getDataFolder().toPath().resolve(ProxyIdentityPinPaths.LEGACY_FILE_NAME);
        Path selectedProxyPin = selectedPin.path();
        try {
            proxyPublicKey = ProxyIdentityStore.load(selectedProxyPin);
        } catch (IOException exception) {
            throw new IllegalStateException(
                    "MCAce requires the trusted proxy identity/server-public-key.txt to be pinned as "
                            + preferredProxyPin + " (legacy Velocity pin also accepted at " + legacyVelocityPin + ")",
                    exception);
        }
        if (selectedPin.legacy()) {
            getLogger().warning("Using legacy velocity-public-key.txt; rename it to proxy-public-key.txt");
        }
        enableServerAuthority(proxyPublicKey);
        admissionReceiver = new PaperAdmissionReceiver(
                api, proxyPublicKey, Clock.systemUTC(), getLogger(), runtimeScheduler,
                new PaperAdmissionReceiver.AdmissionObserver() {
                    @Override public void accept(org.bukkit.entity.Player carrier,
                            PaperAdmissionReceiver.AcceptedAdmission update) {
                        localSessionActions.accept(carrier, update);
                        backendContextPublisher.accept(carrier, update);
                        if (serverAuthorityRuntime != null) {
                            serverAuthorityRuntime.acceptAdmission(carrier, update);
                        }
                    }
                    @Override public void remove(java.util.UUID playerId) {
                        localSessionActions.remove(playerId);
                        backendContextPublisher.remove(playerId);
                        if (serverAuthorityRuntime != null) {
                            serverAuthorityRuntime.remove(playerId);
                        }
                    }
                });
        getServer().getMessenger().registerIncomingPluginChannel(
                this, ProtocolConstants.ADMISSION_CHANNEL, admissionReceiver);
        getServer().getMessenger().registerOutgoingPluginChannel(
                this, ProtocolConstants.BACKEND_CONTEXT_CHANNEL);
        getServer().getPluginManager().registerEvents(this, this);
        runtimeScheduler.repeatGlobal(admissionReceiver::expire, 20L, 20L);
        if (serverAuthorityRuntime != null) {
            runtimeScheduler.repeatGlobal(serverAuthorityRuntime::expire, 20L, 20L);
        }
        getServer().getServicesManager().register(MCAceApi.class, api, this, ServicePriority.Normal);
        PluginCommand command = Objects.requireNonNull(getCommand("mcace"), "mcace command missing from plugin.yml");
        command.setExecutor(new MCAceCommand(api, runtimeScheduler));
        getLogger().info("MCAce signed proxy admission channel enabled; pinned key fingerprint="
                + ProxyIdentityStore.fingerprint(proxyPublicKey));
        getLogger().info("MCAce backend world/game-mode context channel enabled in shadow-only mode");
        getLogger().info("MCAce task runtime=" + runtimeScheduler.runtimeFlavor());
        getLogger().info("MCAce backend session actions mode=" + sessionActionConfiguration.mode());
        enableBehaviorIntegrations(integrationConfiguration);
    }

    @Override
    public void onDisable() {
        for (AutoCloseable integration : behaviorIntegrations.reversed()) {
            try {
                integration.close();
            } catch (Exception exception) {
                getLogger().warning("Failed to close MCAce behavior integration: " + exception.getMessage());
            }
        }
        behaviorIntegrations.clear();
        if (sessionActions != null) {
            sessionActions.clear();
            sessionActions = null;
        }
        if (cloudRiskClient != null) {
            cloudRiskClient.close();
            cloudRiskClient = null;
        }
        if (serverAuthorityLease != null) {
            try {
                serverAuthorityLease.close();
            } catch (IOException | RuntimeException | LinkageError exception) {
                getLogger().warning("Failed to close MCAce server authority channels/journal: "
                        + safeMessage(exception));
            }
            serverAuthorityLease = null;
            serverAuthorityRuntime = null;
        }
        getServer().getMessenger().unregisterIncomingPluginChannel(this);
        getServer().getMessenger().unregisterOutgoingPluginChannel(this);
        backendContextPublisher = null;
        if (runtimeScheduler != null) {
            runtimeScheduler.close();
            runtimeScheduler = null;
        }
        getServer().getServicesManager().unregisterAll(this);
    }

    /**
     * Returns the version-one, read-only SDK bridge using JDK types only.
     *
     * <p>Third-party plugins discover this method by name so their independently loaded MCAce SDK
     * copy never has to share Java type identity with this shaded plugin.</p>
     */
    public java.util.function.Function<java.util.Map<String, Object>, java.util.Map<String, Object>>
            mcaceInteropV1() {
        return com.ellan.mcace.sdk.MCAceInteropExports.from(api);
    }

    @EventHandler
    public void onPlayerRegisterChannel(PlayerRegisterChannelEvent event) {
        if (backendContextPublisher != null
                && ProtocolConstants.BACKEND_CONTEXT_CHANNEL.equals(event.getChannel())) {
            backendContextPublisher.channelRegistered(event.getPlayer());
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        if (runtimeScheduler == null) {
            return;
        }
        java.util.UUID playerId = event.getPlayer().getUniqueId();
        Runnable cleanup = () -> removePlayerState(playerId);
        runtimeScheduler.executeForPlayer(event.getPlayer(), cleanup, () -> runtimeScheduler.executeGlobal(cleanup));
    }

    @EventHandler
    public void onPlayerChangedWorld(PlayerChangedWorldEvent event) {
        if (backendContextPublisher != null) {
            backendContextPublisher.publishCurrent(event.getPlayer());
        }
    }

    @EventHandler
    public void onPlayerGameModeChange(PlayerGameModeChangeEvent event) {
        if (backendContextPublisher != null) {
            backendContextPublisher.publishGameMode(event.getPlayer(), event.getNewGameMode());
        }
    }

    private void removePlayerState(java.util.UUID playerId) {
        if (admissionReceiver != null) {
            admissionReceiver.remove(playerId);
        }
        if (backendContextPublisher != null) {
            backendContextPublisher.remove(playerId);
        }
        if (behaviorPipeline != null) {
            behaviorPipeline.remove(playerId);
        }
        if (serverAuthorityRuntime != null) {
            serverAuthorityRuntime.remove(playerId);
        }
        getLogger().info("MCAce player state cleanup completed for " + playerId);
    }

    private PaperIntegrationConfiguration loadIntegrationConfiguration() {
        try {
            return PaperIntegrationConfiguration.load(getConfig(), getDataFolder().toPath());
        } catch (Exception exception) {
            getLogger().severe("MCAce optional integrations and backend session actions are disabled due to invalid configuration: "
                    + safeMessage(exception));
            return null;
        }
    }

    private void enableBehaviorIntegrations(PaperIntegrationConfiguration configuration) {
        if (configuration == null) {
            return;
        }
        if (!configuration.behaviorEnabled()) {
            getLogger().info("MCAce behavior integrations are disabled by configuration");
            return;
        }
        if (configuration.cloud() == null && serverAuthorityRuntime == null) {
            getLogger().warning("MCAce behavior integrations have no Cloud or local authority sink; no adapters were registered");
            return;
        }
        cloudRiskClient = configuration.cloud() == null ? null
                : new CloudRiskEventClient(configuration.cloud(), getLogger()::warning);
        behaviorPipeline = new BehaviorAlertPipeline(
                cloudRiskClient == null ? null : new BehaviorAlertCorrelator(
                        configuration.minimumFlags(), configuration.window(), configuration.cooldown(),
                        configuration.maximumKeys()),
                cloudRiskClient,
                serverAuthorityRuntime == null
                        ? (ignoredPlayer, ignoredAlert) -> { }
                        : serverAuthorityRuntime::accept,
                getLogger());
        if (configuration.grimEnabled()) {
            enableGrim();
        }
        if (configuration.vulcanEnabled()) {
            enableVulcan();
        }
        if (behaviorIntegrations.isEmpty()) {
            getLogger().info("No supported behavior anti-cheat plugin is currently enabled");
        }
    }

    private void enableServerAuthority(PublicKey proxyPublicKey) {
        PaperServerAuthorityConfiguration authorityConfiguration;
        try {
            authorityConfiguration = PaperServerAuthorityConfiguration.load(
                    getConfig(), getDataFolder().toPath());
        } catch (IOException | RuntimeException exception) {
            getLogger().severe("MCAce signed backend authority is disabled because its configuration is invalid: "
                    + safeMessage(exception));
            return;
        }
        if (authorityConfiguration == null) {
            getLogger().info("MCAce signed backend authority is disabled by configuration");
            return;
        }
        PaperServerAuthorityChannelLease<PaperServerAuthorityRuntime> lease = null;
        try {
            lease = PaperServerAuthorityChannelLease.open(
                            () -> new PaperServerAuthorityRuntime(
                                    this, authorityConfiguration, proxyPublicKey, Clock.systemUTC(),
                                    runtimeScheduler, getLogger()),
                            new PaperServerAuthorityChannelLease.ChannelOperations<>() {
                                @Override
                                public void registerIncoming(PaperServerAuthorityRuntime runtime) {
                                    getServer().getMessenger().registerIncomingPluginChannel(
                                            MCAcePaperPlugin.this,
                                            ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, runtime);
                                }

                                @Override
                                public void unregisterIncoming(PaperServerAuthorityRuntime runtime) {
                                    getServer().getMessenger().unregisterIncomingPluginChannel(
                                            MCAcePaperPlugin.this,
                                            ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, runtime);
                                }

                                @Override
                                public void registerOutgoing() {
                                    getServer().getMessenger().registerOutgoingPluginChannel(
                                            MCAcePaperPlugin.this,
                                            ProtocolConstants.BACKEND_AUTHORITY_CHANNEL);
                                }

                                @Override
                                public void unregisterOutgoing() {
                                    getServer().getMessenger().unregisterOutgoingPluginChannel(
                                            MCAcePaperPlugin.this,
                                            ProtocolConstants.BACKEND_AUTHORITY_CHANNEL);
                                }
                            });
            PaperServerAuthorityRuntime runtime = lease.resource();
            getLogger().info("MCAce signed backend authority enabled in MONITOR mode; backend="
                    + authorityConfiguration.backendInstanceId() + " key="
                    + authorityConfiguration.backendKeyIdSha256() + " profile="
                    + authorityConfiguration.profile().sha256());
            serverAuthorityRuntime = runtime;
            serverAuthorityLease = lease;
        } catch (IOException | RuntimeException | LinkageError exception) {
            if (lease != null) {
                try {
                    lease.close();
                } catch (IOException | RuntimeException | LinkageError rollbackFailure) {
                    exception.addSuppressed(rollbackFailure);
                }
            }
            serverAuthorityLease = null;
            serverAuthorityRuntime = null;
            getLogger().severe("MCAce signed backend authority is disabled because its key/journal startup failed: "
                    + safeMessage(exception));
        }
    }

    private void enableGrim() {
        if (!getServer().getPluginManager().isPluginEnabled("GrimAC")) {
            return;
        }
        try {
            behaviorIntegrations.add(new GrimBehaviorIntegration(this, behaviorPipeline, Clock.systemUTC()));
            getLogger().info("MCAce Grim behavior adapter enabled (observational, no automatic punishment)");
        } catch (RuntimeException | LinkageError exception) {
            getLogger().warning("MCAce Grim adapter disabled due to API incompatibility: " + safeMessage(exception));
        }
    }

    private void enableVulcan() {
        Plugin vulcan = getServer().getPluginManager().getPlugin("Vulcan");
        if (vulcan == null || !vulcan.isEnabled()) {
            return;
        }
        try {
            behaviorIntegrations.add(new VulcanBehaviorIntegration(
                    this, vulcan, behaviorPipeline, Clock.systemUTC(), getLogger(), runtimeScheduler));
            getLogger().info("MCAce Vulcan behavior adapter enabled (observational, no automatic punishment)");
        } catch (ReflectiveOperationException | RuntimeException | LinkageError exception) {
            getLogger().warning("MCAce Vulcan adapter disabled due to API incompatibility: "
                    + safeMessage(exception));
        }
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }
}
