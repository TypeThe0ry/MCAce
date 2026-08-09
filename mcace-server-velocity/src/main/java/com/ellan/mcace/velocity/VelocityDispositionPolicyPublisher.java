package com.ellan.mcace.velocity;

import com.ellan.mcace.core.proxy.FileDispositionPolicyPublisher;
import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.core.proxy.PublishedDispositionPolicy;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.util.Objects;

/**
 * Velocity's thin, testable adapter around the shared atomic policy publisher.
 *
 * <p>It owns no player or admission APIs.  Publishing can therefore only replace a validated
 * signed disposition policy; it cannot route, limit, disconnect, or ban players.
 */
final class VelocityDispositionPolicyPublisher {
    private final Path configurationPath;
    private final Publisher publisher;
    private final VelocityDispositionPolicyRuntime runtime;

    private VelocityDispositionPolicyPublisher(
            Path configurationPath, Publisher publisher, VelocityDispositionPolicyRuntime runtime) {
        this.configurationPath = Objects.requireNonNull(configurationPath, "configurationPath");
        this.publisher = Objects.requireNonNull(publisher, "publisher");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
    }

    static VelocityDispositionPolicyPublisher create(
            Path dataDirectory,
            Clock clock,
            KeyPair identity,
            VelocityDispositionPolicyRuntime runtime) {
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        Path policyDirectory = dataDirectory.toAbsolutePath().normalize().resolve("policy");
        Path policyPath = policyDirectory.resolve("signed-disposition-policy.pb");
        Path configurationPath = policyDirectory.resolve("disposition-policy.textproto");
        Publisher publisher;
        try {
            publisher = new CorePublisher(new FileDispositionPolicyPublisher(policyPath, clock, identity));
        } catch (PolicyException exception) {
            // Publishing is an optional administrative operation.  A local source setup problem
            // must not prevent handshake/admission startup or alter the current policy bytes.
            publisher = new UnavailablePublisher();
        }
        return new VelocityDispositionPolicyPublisher(
                configurationPath,
                publisher,
                runtime);
    }

    static VelocityDispositionPolicyPublisher forTesting(
            Path configurationPath, Publisher publisher, VelocityDispositionPolicyRuntime runtime) {
        return new VelocityDispositionPolicyPublisher(
                configurationPath.toAbsolutePath().normalize(), publisher, runtime);
    }

    /**
     * Creates an editable safe-default configuration only when no file exists.  An existing file,
     * including an invalid or symlinked one, is deliberately left untouched for operator review.
     */
    void createSafeDefaultConfigurationIfMissing() throws IOException {
        if (Files.exists(configurationPath, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.createDirectories(configurationPath.getParent());
        try {
            Files.writeString(
                    configurationPath,
                    publisher.safeDefaultConfiguration(),
                    StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException ignored) {
            // A concurrent operator/distributor supplied the file first. Never overwrite it.
        }
    }

    PublishResult publishAndRefresh() throws PolicyException {
        PublishedPolicy published = publisher.publish(configurationPath);
        VelocityDispositionPolicyStatus status = runtime.refresh();
        return new PublishResult(published.version(), published.sequence(), published.ruleCount(), status);
    }

    DispositionCatalogPreview preview() throws PolicyException {
        return publisher.preview(configurationPath);
    }

    Path configurationPath() {
        return configurationPath;
    }

    record PublishResult(
            String version, long sequence, int ruleCount, VelocityDispositionPolicyStatus status) {
        PublishResult {
            Objects.requireNonNull(version, "version");
            Objects.requireNonNull(status, "status");
            if (version.isBlank() || sequence < 1 || ruleCount < 0) {
                throw new IllegalArgumentException("invalid disposition publish result");
            }
        }
    }

    interface Publisher {
        PublishedPolicy publish(Path configurationPath) throws PolicyException;

        default DispositionCatalogPreview preview(Path configurationPath) throws PolicyException {
            throw new PolicyException("disposition catalog preview is unavailable");
        }

        String safeDefaultConfiguration();
    }

    record PublishedPolicy(String version, long sequence, int ruleCount) {
        PublishedPolicy {
            Objects.requireNonNull(version, "version");
            if (version.isBlank() || sequence < 1 || ruleCount < 0) {
                throw new IllegalArgumentException("invalid published disposition policy");
            }
        }
    }

    private record CorePublisher(FileDispositionPolicyPublisher delegate) implements Publisher {
        @Override
        public PublishedPolicy publish(Path configurationPath) throws PolicyException {
            PublishedDispositionPolicy published = delegate.publish(configurationPath);
            return new PublishedPolicy(published.version(), published.sequence(), published.ruleCount());
        }

        @Override
        public DispositionCatalogPreview preview(Path configurationPath) throws PolicyException {
            return delegate.preview(configurationPath);
        }

        @Override
        public String safeDefaultConfiguration() {
            return FileDispositionPolicyPublisher.safeDefaultConfiguration();
        }
    }

    private static final class UnavailablePublisher implements Publisher {
        @Override
        public PublishedPolicy publish(Path configurationPath) throws PolicyException {
            throw new PolicyException("disposition policy publisher is unavailable");
        }

        @Override
        public String safeDefaultConfiguration() {
            return FileDispositionPolicyPublisher.safeDefaultConfiguration();
        }
    }
}
