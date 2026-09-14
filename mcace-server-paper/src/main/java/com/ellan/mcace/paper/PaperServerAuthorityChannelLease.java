package com.ellan.mcace.paper;

import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;

/**
 * Owns the all-or-nothing registration of a Paper authority runtime and both of its plugin
 * channels.
 *
 * <p>The runtime opens and exclusively locks the durable issuance journal. Publishing a
 * partially registered runtime would therefore leak both a messenger callback and the journal
 * lock. This lease keeps construction, channel registration and rollback in one transaction and
 * publishes a usable resource only after both registrations have succeeded.</p>
 */
final class PaperServerAuthorityChannelLease<T extends Closeable> implements Closeable {
    @FunctionalInterface
    interface ResourceFactory<T extends Closeable> {
        T create() throws IOException;
    }

    interface ChannelOperations<T> {
        void registerIncoming(T resource);

        void unregisterIncoming(T resource);

        void registerOutgoing();

        void unregisterOutgoing();
    }

    private final T resource;
    private final ChannelOperations<T> channels;
    private boolean incomingRegistrationAttempted;
    private boolean outgoingRegistrationAttempted;
    private boolean closed;

    private PaperServerAuthorityChannelLease(T resource, ChannelOperations<T> channels) {
        this.resource = Objects.requireNonNull(resource, "resource");
        this.channels = Objects.requireNonNull(channels, "channels");
    }

    static <T extends Closeable> PaperServerAuthorityChannelLease<T> open(
            ResourceFactory<T> factory,
            ChannelOperations<T> channels) throws IOException {
        Objects.requireNonNull(factory, "factory");
        Objects.requireNonNull(channels, "channels");
        T resource = factory.create();
        PaperServerAuthorityChannelLease<T> lease =
                new PaperServerAuthorityChannelLease<>(resource, channels);
        try {
            // Registration APIs are allowed to mutate platform state and then throw. Mark the
            // compensating action as required before crossing either call boundary.
            lease.incomingRegistrationAttempted = true;
            channels.registerIncoming(resource);
            lease.outgoingRegistrationAttempted = true;
            channels.registerOutgoing();
            return lease;
        } catch (Throwable failure) {
            lease.rollback(failure);
            rethrow(failure);
            throw new AssertionError("unreachable");
        }
    }

    T resource() {
        if (closed) throw new IllegalStateException("authority channel lease is closed");
        return resource;
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        Throwable failure = null;
        if (outgoingRegistrationAttempted) {
            try {
                channels.unregisterOutgoing();
            } catch (Throwable exception) {
                failure = exception;
            } finally {
                outgoingRegistrationAttempted = false;
            }
        }
        if (incomingRegistrationAttempted) {
            try {
                channels.unregisterIncoming(resource);
            } catch (Throwable exception) {
                failure = addSuppressed(failure, exception);
            } finally {
                incomingRegistrationAttempted = false;
            }
        }
        try {
            resource.close();
        } catch (Throwable exception) {
            failure = addSuppressed(failure, exception);
        }
        if (failure != null) rethrowClose(failure);
    }

    private synchronized void rollback(Throwable original) {
        if (closed) return;
        closed = true;
        if (outgoingRegistrationAttempted) {
            try {
                channels.unregisterOutgoing();
            } catch (Throwable exception) {
                original.addSuppressed(exception);
            } finally {
                outgoingRegistrationAttempted = false;
            }
        }
        if (incomingRegistrationAttempted) {
            try {
                channels.unregisterIncoming(resource);
            } catch (Throwable exception) {
                original.addSuppressed(exception);
            } finally {
                incomingRegistrationAttempted = false;
            }
        }
        try {
            resource.close();
        } catch (Throwable exception) {
            original.addSuppressed(exception);
        }
    }

    private static Throwable addSuppressed(Throwable current, Throwable next) {
        if (current == null) return next;
        current.addSuppressed(next);
        return current;
    }

    private static void rethrow(Throwable failure) {
        if (failure instanceof Error error) throw error;
        if (failure instanceof RuntimeException exception) throw exception;
        throw new AssertionError(failure);
    }

    private static void rethrowClose(Throwable failure) throws IOException {
        if (failure instanceof Error error) throw error;
        if (failure instanceof RuntimeException exception) throw exception;
        if (failure instanceof IOException exception) throw exception;
        throw new IOException("authority channel lease cleanup failed", failure);
    }
}
