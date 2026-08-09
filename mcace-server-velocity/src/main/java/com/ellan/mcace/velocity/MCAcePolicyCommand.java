package com.ellan.mcace.velocity;

import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.protocol.policy.PolicyVerification;
import com.velocitypowered.api.command.SimpleCommand;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

final class MCAcePolicyCommand implements SimpleCommand {
    private static final String PERMISSION = "mcace.admin.policy";
    private static final String CHECK_PERMISSION = "mcace.admin.check";

    private final ServerPolicyManager policies;
    private final PublicKey rootKey;
    private final Clock clock;
    private final Logger logger;
    private final VelocityDispositionPolicyRuntime dispositionPolicies;
    private final VelocityDispositionPolicyPublisher dispositionPublisher;
    private final VelocityAdmissionConfig.Mode executionMode;

    MCAcePolicyCommand(
            ServerPolicyManager policies,
            PublicKey rootKey,
            Clock clock,
            Logger logger,
            VelocityDispositionPolicyRuntime dispositionPolicies,
            VelocityDispositionPolicyPublisher dispositionPublisher) {
        this(policies, rootKey, clock, logger, dispositionPolicies, dispositionPublisher,
                VelocityAdmissionConfig.Mode.MONITOR);
    }

    MCAcePolicyCommand(
            ServerPolicyManager policies,
            PublicKey rootKey,
            Clock clock,
            Logger logger,
            VelocityDispositionPolicyRuntime dispositionPolicies,
            VelocityDispositionPolicyPublisher dispositionPublisher,
            VelocityAdmissionConfig.Mode executionMode) {
        this.policies = policies;
        this.rootKey = rootKey;
        this.clock = clock;
        this.logger = logger;
        this.dispositionPolicies = dispositionPolicies;
        this.dispositionPublisher = dispositionPublisher;
        this.executionMode = executionMode;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!hasPermission(invocation)) {
            invocation.source().sendMessage(Component.text("MCAce: missing permission " + requiredPermission(invocation)));
            return;
        }
        String[] arguments = invocation.arguments();
        if (arguments.length == 1 && "status".equalsIgnoreCase(arguments[0])) {
            VelocityDispositionPolicyStatus status = dispositionPolicies.status();
            invocation.source().sendMessage(Component.text(
                    "MCAce disposition policy: status=" + status.refreshStatus()
                            + " sequence=" + status.activeSequence().map(Object::toString).orElse("none")
                            + " available=" + status.sourceAvailable()));
            return;
        }
        String catalogOperation = catalogOperation(arguments);
        if (catalogOperation != null) {
            catalog(invocation, catalogOperation);
            return;
        }
        if (arguments.length != 1) {
            usage(invocation);
            return;
        }
        if ("publish".equalsIgnoreCase(arguments[0])) {
            publishLegacy(invocation);
            return;
        }
        if (!"rotate".equalsIgnoreCase(arguments[0])) {
            usage(invocation);
            return;
        }
        try {
            SignedPolicyDocument document = policies.rotateDelegatedKey();
            PolicyVerification verified = PolicyDocuments.verifyDetailed(
                    document, rootKey, clock, Duration.ofSeconds(30));
            invocation.source().sendMessage(Component.text(
                    "MCAce policy key rotated; policy=" + verified.policy().getSequence()
                            + " trust=" + verified.trustSequence()));
            logger.warn("MCAce delegated policy key was manually rotated; policy sequence={} trust sequence={}",
                    verified.policy().getSequence(), verified.trustSequence());
        } catch (PolicyException exception) {
            invocation.source().sendMessage(Component.text("MCAce policy rotation failed; inspect proxy logs"));
            logger.error("Manual MCAce delegated policy-key rotation failed", exception);
        }
    }

    private void publishLegacy(Invocation invocation) {
        try {
            DispositionCatalogPreview preview = null;
            try {
                preview = dispositionPublisher.preview();
            } catch (PolicyException ignored) {
                // Preserve the legacy publish path for custom adapters that predate preview().
            }
            VelocityDispositionPolicyPublisher.PublishResult published = dispositionPublisher.publishAndRefresh();
            if (preview != null) {
                invocation.source().sendMessage(Component.text(VelocityDispositionCatalogSummary.render(
                        "publish", preview, java.util.Optional.of(published.version()),
                        published.status().activeSequence(), executionMode)));
            } else {
                invocation.source().sendMessage(Component.text(
                        "MCAce: disposition policy published version="
                                + VelocityDispositionCatalogSummary.safeVersion(java.util.Optional.of(published.version()))
                                + " rules=" + published.ruleCount()
                                + " active-sequence=" + published.status().activeSequence()
                                .map(String::valueOf).orElse("none")
                                + " mode=" + executionMode.name()
                                + " high-impact=LIMITED_ROUTE_REQUIRED"
                                + " command-mode-unchanged=true"));
            }
            logger.info("MCAce disposition policy published: sequence={} version={} rules={} status={}",
                    published.sequence(), published.version(), published.ruleCount(), published.status().refreshStatus());
        } catch (PolicyException | RuntimeException exception) {
            invocation.source().sendMessage(Component.text(VelocityDispositionCatalogSummary.failure(
                    dispositionPolicies.status().activeSequence(), executionMode)));
            logger.error("MCAce disposition policy publish failed; active signed policy was retained", exception);
        }
    }

    private void catalog(Invocation invocation, String operation) {
        try {
            if ("publish".equals(operation)) {
                publishLegacy(invocation);
                return;
            }
            DispositionCatalogPreview preview = dispositionPublisher.preview();
            invocation.source().sendMessage(Component.text(VelocityDispositionCatalogSummary.render(
                    operation, preview, java.util.Optional.empty(),
                    dispositionPolicies.status().activeSequence(), executionMode)));
            if ("list".equals(operation)) {
                VelocityDispositionCatalogSummary.listSources(preview).forEach(
                        line -> invocation.source().sendMessage(Component.text(line)));
            }
        } catch (PolicyException | RuntimeException exception) {
            invocation.source().sendMessage(Component.text(
                    "MCAce: disposition catalog " + operation + " rejected"
                            + " warnings=VALIDATION_FAILED"
                            + " active-sequence=" + dispositionPolicies.status().activeSequence()
                            .map(String::valueOf).orElse("none")
                            + " mode=" + executionMode.name()
                            + " high-impact=LIMITED_ROUTE_REQUIRED"
                            + " command-mode-unchanged=true"));
            logger.warn("MCAce disposition catalog {} rejected; active policy unchanged", operation);
        }
    }

    private static String catalogOperation(String[] arguments) {
        if (arguments.length == 1 && ("preview".equalsIgnoreCase(arguments[0])
                || "validate".equalsIgnoreCase(arguments[0]) || "list".equalsIgnoreCase(arguments[0]))) {
            return arguments[0].toLowerCase(java.util.Locale.ROOT);
        }
        if (arguments.length == 2 && "catalog".equalsIgnoreCase(arguments[0])
                && ("preview".equalsIgnoreCase(arguments[1])
                || "validate".equalsIgnoreCase(arguments[1]) || "list".equalsIgnoreCase(arguments[1])
                || "publish".equalsIgnoreCase(arguments[1]))) {
            return arguments[1].toLowerCase(java.util.Locale.ROOT);
        }
        return null;
    }

    private static void usage(Invocation invocation) {
        invocation.source().sendMessage(Component.text(
                "Usage: /mcacepolicy <rotate|status|publish|preview|validate|list>"
                        + " | /mcacepolicy catalog <preview|validate|list|publish>"));
    }

    private static String requiredPermission(Invocation invocation) {
        return isReadOnlyCatalogOperation(invocation.arguments())
                ? CHECK_PERMISSION : PERMISSION;
    }

    private static boolean isReadOnlyCatalogOperation(String[] arguments) {
        return (arguments.length == 1 && ("preview".equalsIgnoreCase(arguments[0])
                || "validate".equalsIgnoreCase(arguments[0]) || "list".equalsIgnoreCase(arguments[0])))
                || (arguments.length == 2 && "catalog".equalsIgnoreCase(arguments[0])
                && ("preview".equalsIgnoreCase(arguments[1])
                || "validate".equalsIgnoreCase(arguments[1]) || "list".equalsIgnoreCase(arguments[1])));
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        if (invocation.arguments().length == 0) {
            return List.of("rotate", "status", "publish", "preview", "validate", "list", "catalog");
        }
        if (invocation.arguments().length == 1 && "catalog".equalsIgnoreCase(invocation.arguments()[0])) {
            return List.of("preview", "validate", "list", "publish");
        }
        return List.of();
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission(requiredPermission(invocation));
    }

}
