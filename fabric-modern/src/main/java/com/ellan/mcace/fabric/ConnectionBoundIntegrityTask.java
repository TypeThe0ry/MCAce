package com.ellan.mcace.fabric;

import com.ellan.mcace.client.integrity.IntegrityScanCancellation;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/** One replaceable virtual-thread integrity task whose cancellation is visible inside file reads. */
final class ConnectionBoundIntegrityTask implements AutoCloseable {
    @FunctionalInterface
    interface Task {
        void run(IntegrityScanCancellation cancellation);
    }

    private final ExecutorService executor;
    private Control current;
    private boolean closed;

    ConnectionBoundIntegrityTask() {
        this(Executors.newVirtualThreadPerTaskExecutor());
    }

    ConnectionBoundIntegrityTask(ExecutorService executor) {
        this.executor = Objects.requireNonNull(executor, "executor");
    }

    synchronized void submit(Task task) {
        Objects.requireNonNull(task, "task");
        if (closed) {
            throw new IllegalStateException("integrity task slot is closed");
        }
        cancelLocked();
        Control control = new Control();
        current = control;
        Future<?> future = executor.submit(() -> {
            control.bind(Thread.currentThread());
            try {
                task.run(control);
            } finally {
                completed(control);
            }
        });
        control.attach(future);
    }

    synchronized void cancel() {
        cancelLocked();
    }

    @Override
    public void close() {
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            cancelLocked();
        }
        executor.shutdownNow();
    }

    private synchronized void completed(Control control) {
        if (current == control) {
            current = null;
        }
    }

    private void cancelLocked() {
        Control active = current;
        current = null;
        if (active != null) {
            active.cancel();
        }
    }

    private static final class Control implements IntegrityScanCancellation {
        private final AtomicBoolean active = new AtomicBoolean(true);
        private volatile Future<?> future;
        private volatile Thread runner;

        @Override
        public boolean cancelled() {
            return !active.get() || Thread.currentThread().isInterrupted();
        }

        private void attach(Future<?> value) {
            future = value;
            if (!active.get()) {
                value.cancel(true);
            }
        }

        private void bind(Thread value) {
            runner = value;
            if (!active.get()) {
                value.interrupt();
            }
        }

        private void cancel() {
            active.set(false);
            Future<?> running = future;
            if (running != null) {
                running.cancel(true);
            }
            Thread thread = runner;
            if (thread != null) {
                thread.interrupt();
            }
        }
    }
}
