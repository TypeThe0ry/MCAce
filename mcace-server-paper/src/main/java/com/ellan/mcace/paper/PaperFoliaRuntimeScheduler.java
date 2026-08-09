package com.ellan.mcace.paper;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import io.papermc.paper.threadedregions.scheduler.ScheduledTask;
import org.bukkit.Server;
import org.bukkit.World;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.scheduler.BukkitScheduler;

/** Runtime-selected Paper/Folia task bridge. Folia APIs are resolved reflectively for Paper ABI use. */
final class PaperFoliaRuntimeScheduler implements MCAceRuntimeScheduler {
    private final Plugin plugin;
    private final BukkitScheduler paperScheduler;
    private final FoliaSchedulerAccess folia;
    private final List<CancellableTask> tasks = new ArrayList<>();
    private final AtomicBoolean closed = new AtomicBoolean();

    PaperFoliaRuntimeScheduler(
            Plugin plugin, BukkitScheduler paperScheduler, FoliaSchedulerAccess folia) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.paperScheduler = Objects.requireNonNull(paperScheduler, "paperScheduler");
        this.folia = folia;
    }

    static PaperFoliaRuntimeScheduler create(Plugin plugin) {
        Objects.requireNonNull(plugin, "plugin");
        Server server = plugin.getServer();
        FoliaSchedulerAccess folia = FoliaSchedulerAccess.createIfPresent(plugin, server);
        return new PaperFoliaRuntimeScheduler(plugin, server.getScheduler(), folia);
    }

    @Override
    public RuntimeFlavor runtimeFlavor() {
        return folia == null ? RuntimeFlavor.PAPER : RuntimeFlavor.FOLIA;
    }

    @Override
    public void executeGlobal(Runnable task) {
        Objects.requireNonNull(task, "task");
        if (folia == null) {
            paperScheduler.runTask(plugin, guard(task));
        } else {
            folia.executeGlobal(guard(task));
        }
    }

    @Override
    public void executeAtRegion(World world, int chunkX, int chunkZ, Runnable task) {
        Objects.requireNonNull(world, "world");
        Objects.requireNonNull(task, "task");
        if (folia == null) {
            paperScheduler.runTask(plugin, guard(task));
        } else {
            folia.executeAtRegion(world, chunkX, chunkZ, guard(task));
        }
    }

    @Override
    public void executeForPlayer(Player player, Runnable task, Runnable retired) {
        Objects.requireNonNull(player, "player");
        Objects.requireNonNull(task, "task");
        Objects.requireNonNull(retired, "retired");
        if (folia == null) {
            paperScheduler.runTask(plugin, guard(task));
        } else {
            folia.executeForPlayer(player, guard(task), guard(retired));
        }
    }

    @Override
    public void repeatGlobal(Runnable task, long initialDelayTicks, long periodTicks) {
        Objects.requireNonNull(task, "task");
        if (initialDelayTicks < 1L || periodTicks < 1L) {
            throw new IllegalArgumentException("initialDelayTicks and periodTicks must be positive");
        }
        if (folia == null) {
            register(paperScheduler.runTaskTimer(plugin, guard(task), initialDelayTicks, periodTicks)::cancel);
        } else {
            register(folia.repeatGlobal(guard(task), initialDelayTicks, periodTicks));
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            List<CancellableTask> pending;
            synchronized (tasks) {
                pending = List.copyOf(tasks);
                tasks.clear();
            }
            pending.forEach(PaperFoliaRuntimeScheduler::cancelQuietly);
        }
    }

    private Runnable guard(Runnable task) {
        return () -> {
            if (!closed.get()) {
                task.run();
            }
        };
    }

    private void register(CancellableTask task) {
        synchronized (tasks) {
            if (closed.get()) {
                cancelQuietly(task);
            } else {
                tasks.add(task);
            }
        }
    }

    private static void cancelQuietly(CancellableTask task) {
        try {
            task.cancel();
        } catch (RuntimeException ignored) {
            // Folia can already be halted while the plugin disable hook is running.
            // Cancellation is best-effort after the task has been removed from our registry.
        }
    }

    @FunctionalInterface
    interface CancellableTask {
        void cancel();
    }

    static final class FoliaSchedulerAccess {
        private static final String FOLIA_MARKER = "io.papermc.paper.threadedregions.RegionizedServer";

        private final Plugin plugin;
        private final Object globalScheduler;
        private final Object regionScheduler;

        private FoliaSchedulerAccess(Plugin plugin, Object globalScheduler, Object regionScheduler) {
            this.plugin = plugin;
            this.globalScheduler = globalScheduler;
            this.regionScheduler = regionScheduler;
        }

        static FoliaSchedulerAccess of(Plugin plugin, Object globalScheduler, Object regionScheduler) {
            return new FoliaSchedulerAccess(
                    Objects.requireNonNull(plugin, "plugin"),
                    Objects.requireNonNull(globalScheduler, "globalScheduler"),
                    Objects.requireNonNull(regionScheduler, "regionScheduler"));
        }

        static FoliaSchedulerAccess createIfPresent(Plugin plugin, Server server) {
            Objects.requireNonNull(plugin, "plugin");
            Objects.requireNonNull(server, "server");
            if (!FoliaRuntimeDetector.isFolia(server.getClass().getClassLoader())) {
                return null;
            }
            try {
                return new FoliaSchedulerAccess(
                        plugin,
                        invoke(server, "getGlobalRegionScheduler"),
                        invoke(server, "getRegionScheduler"));
            } catch (ReflectiveOperationException exception) {
                throw new IllegalStateException("Folia was detected but its scheduler API is unavailable", exception);
            }
        }

        CancellableTask executeGlobal(Runnable task) {
            return invokeTask(globalScheduler, "run", plugin, consumer(task));
        }

        CancellableTask repeatGlobal(Runnable task, long initialDelayTicks, long periodTicks) {
            return invokeTask(
                    globalScheduler, "runAtFixedRate", plugin, consumer(task), initialDelayTicks, periodTicks);
        }

        CancellableTask executeAtRegion(World world, int chunkX, int chunkZ, Runnable task) {
            return invokeTask(regionScheduler, "run", plugin, world, chunkX, chunkZ, consumer(task));
        }

        CancellableTask executeForPlayer(Player player, Runnable task, Runnable retired) {
            try {
                return invokeTask(invoke(player, "getScheduler"), "run", plugin, consumer(task), retired);
            } catch (ReflectiveOperationException exception) {
                throw new IllegalStateException("Unable to schedule MCAce task on the owning Folia entity", exception);
            }
        }

        private static Consumer<Object> consumer(Runnable task) {
            return ignored -> task.run();
        }

        private static CancellableTask invokeTask(Object receiver, String methodName, Object... arguments) {
            try {
                Object scheduled = invoke(receiver, methodName, arguments);
                if (!(scheduled instanceof ScheduledTask scheduledTask)) {
                    throw new IllegalStateException(
                            "Folia scheduler method " + methodName + " did not return ScheduledTask");
                }
                return () -> {
                    try {
                        scheduledTask.cancel();
                    } catch (RuntimeException exception) {
                        throw new IllegalStateException("Unable to cancel Folia MCAce task", exception);
                    }
                };
            } catch (ReflectiveOperationException exception) {
                throw new IllegalStateException("Unable to invoke Folia scheduler method " + methodName, exception);
            }
        }

        private static Object invoke(Object receiver, String methodName, Object... arguments)
                throws ReflectiveOperationException {
            for (Method method : receiver.getClass().getMethods()) {
                if (method.getName().equals(methodName) && method.getParameterCount() == arguments.length) {
                    try {
                        return method.invoke(receiver, arguments);
                    } catch (IllegalAccessException exception) {
                        throw exception;
                    } catch (InvocationTargetException exception) {
                        Throwable cause = exception.getCause();
                        if (cause instanceof ReflectiveOperationException reflective) {
                            throw reflective;
                        }
                        throw new ReflectiveOperationException("Folia scheduler invocation failed", cause);
                    }
                }
            }
            throw new NoSuchMethodException(receiver.getClass().getName() + "." + methodName);
        }
    }

    static final class FoliaRuntimeDetector {
        private FoliaRuntimeDetector() { }

        static boolean isFolia(ClassLoader classLoader) {
            try {
                Class.forName(FoliaSchedulerAccess.FOLIA_MARKER, false, classLoader);
                return true;
            } catch (ClassNotFoundException exception) {
                return false;
            }
        }
    }
}
