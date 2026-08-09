package com.ellan.mcace.velocity;

import com.ellan.mcace.core.federation.BoundedAsyncFederationAuditSink;
import com.ellan.mcace.core.federation.FederationConfiguration;
import com.ellan.mcace.core.federation.FederationRuntime;
import com.ellan.mcace.core.federation.FileFederationAuditSink;
import com.ellan.mcace.core.federation.FederationAuditSink;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Objects;
import java.util.function.Consumer;

/** Strict local federation configuration/audit lifecycle. It opens no network transport. */
final class VelocityFederationLifecycle implements AutoCloseable {
    private static final long AUDIT_BYTES = 8L * 1024L * 1024L;
    private final FederationRuntime runtime;
    private final Path configurationPath;
    private final BoundedAsyncFederationAuditSink auditQueue;

    private VelocityFederationLifecycle(
            FederationRuntime runtime, Path configurationPath,
            BoundedAsyncFederationAuditSink auditQueue) {
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.configurationPath = Objects.requireNonNull(configurationPath, "configurationPath");
        this.auditQueue = auditQueue;
    }

    static VelocityFederationLifecycle load(
            Path dataDirectory, Clock clock, SecureRandom random, KeyPair persistedIdentity)
            throws IOException {
        Objects.requireNonNull(dataDirectory, "dataDirectory");
        Path configurationPath = dataDirectory.resolve(FederationConfiguration.FILE_NAME);
        FederationConfiguration configuration = FederationConfiguration.loadOrCreate(configurationPath);
        BoundedAsyncFederationAuditSink auditQueue = new BoundedAsyncFederationAuditSink(
                new FileFederationAuditSink(dataDirectory.resolve("federation-audit.log"), AUDIT_BYTES),
                "mcace-velocity-federation-audit");
        try {
            return new VelocityFederationLifecycle(new FederationRuntime(
                    clock, random, persistedIdentity, configuration, auditQueue),
                    configurationPath, auditQueue);
        } catch (RuntimeException exception) {
            auditQueue.close();
            throw exception;
        }
    }

    static VelocityFederationLifecycle loadOrDisabled(
            Path dataDirectory, Clock clock, SecureRandom random, KeyPair persistedIdentity,
            String fallbackLocalNetworkId, Consumer<Exception> failureLogger) {
        Objects.requireNonNull(failureLogger, "failureLogger");
        try {
            return load(dataDirectory, clock, random, persistedIdentity);
        } catch (IOException | RuntimeException exception) {
            failureLogger.accept(exception);
            Path configurationPath = dataDirectory.resolve(FederationConfiguration.FILE_NAME);
            return new VelocityFederationLifecycle(new FederationRuntime(
                    clock, random, persistedIdentity,
                    FederationConfiguration.disabled(fallbackLocalNetworkId), FederationAuditSink.noop()),
                    configurationPath, null);
        }
    }

    /** Reloads a complete strict document atomically; failures leave the current configuration active. */
    boolean reload(Consumer<Exception> failureLogger) {
        Objects.requireNonNull(failureLogger, "failureLogger");
        try {
            runtime.reload(FederationConfiguration.loadOrCreate(configurationPath));
            return true;
        } catch (IOException | RuntimeException exception) {
            failureLogger.accept(exception);
            return false;
        }
    }

    FederationRuntime runtime() {
        return runtime;
    }

    @Override public void close() {
        if (auditQueue != null) auditQueue.close();
    }
}
