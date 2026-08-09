package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.function.Consumer;
import io.papermc.paper.threadedregions.scheduler.EntityScheduler;
import io.papermc.paper.threadedregions.scheduler.ScheduledTask;
import org.bukkit.World;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.scheduler.BukkitScheduler;
import org.junit.jupiter.api.Test;

final class PaperFoliaRuntimeSchedulerTest {
    @Test
    void reflectiveFoliaBridgeUsesGlobalRegionAndEntityOwners() {
        FakeGlobalScheduler global = new FakeGlobalScheduler();
        FakeRegionScheduler region = new FakeRegionScheduler();
        FakeEntityScheduler entity = new FakeEntityScheduler();
        Plugin plugin = proxy(Plugin.class, null);
        Player player = proxy(Player.class, entity);
        World world = proxy(World.class, null);
        PaperFoliaRuntimeScheduler.FoliaSchedulerAccess access =
                PaperFoliaRuntimeScheduler.FoliaSchedulerAccess.of(plugin, global, region);

        Counter counter = new Counter();
        PaperFoliaRuntimeScheduler.CancellableTask globalTask = access.executeGlobal(counter::increment);
        PaperFoliaRuntimeScheduler.CancellableTask repeatingTask = access.repeatGlobal(counter::increment, 5L, 20L);
        PaperFoliaRuntimeScheduler.CancellableTask regionTask = access.executeAtRegion(world, 3, -4, counter::increment);
        PaperFoliaRuntimeScheduler.CancellableTask entityTask = access.executeForPlayer(
                player, counter::increment, counter::increment);

        assertEquals(4, counter.value);
        assertEquals(5L, global.initialDelay);
        assertEquals(20L, global.period);
        assertEquals(3, region.chunkX);
        assertEquals(-4, region.chunkZ);
        assertTrue(entity.ran);
        globalTask.cancel();
        repeatingTask.cancel();
        regionTask.cancel();
        entityTask.cancel();
        assertEquals(4, global.cancelled + region.cancelled + entity.cancelled);
    }

    @Test
    void cancellationUsesPublicScheduledTaskContractForHiddenImplementation() {
        HiddenTaskScheduler global = new HiddenTaskScheduler();
        FakeRegionScheduler region = new FakeRegionScheduler();
        Plugin plugin = proxy(Plugin.class, null);
        PaperFoliaRuntimeScheduler.FoliaSchedulerAccess access =
                PaperFoliaRuntimeScheduler.FoliaSchedulerAccess.of(plugin, global, region);

        PaperFoliaRuntimeScheduler.CancellableTask task = access.repeatGlobal(() -> {}, 1L, 1L);

        assertDoesNotThrow(task::cancel);
        assertEquals(1, global.cancelled);
    }

    @Test
    void closeIsIdempotentWhenFoliaSchedulerHasAlreadyHalted() {
        HaltedTaskScheduler global = new HaltedTaskScheduler();
        FakeRegionScheduler region = new FakeRegionScheduler();
        Plugin plugin = proxy(Plugin.class, null);
        PaperFoliaRuntimeScheduler.FoliaSchedulerAccess access =
                PaperFoliaRuntimeScheduler.FoliaSchedulerAccess.of(plugin, global, region);
        PaperFoliaRuntimeScheduler scheduler = new PaperFoliaRuntimeScheduler(
                plugin, proxy(BukkitScheduler.class, null), access);

        scheduler.repeatGlobal(() -> {}, 1L, 1L);

        assertDoesNotThrow(scheduler::close);
        assertDoesNotThrow(scheduler::close);
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, Object scheduler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (ignored, method, arguments) -> {
            if (method.getName().equals("getScheduler")) {
                return scheduler;
            }
            if (method.getName().equals("toString")) {
                return type.getSimpleName();
            }
            throw new UnsupportedOperationException(method.getName());
        });
    }

    public static final class FakeGlobalScheduler {
        private long initialDelay;
        private long period;
        private int cancelled;

        public FakeTask run(Plugin plugin, Consumer<Object> task) {
            task.accept(null);
            return new FakeTask(this);
        }

        public FakeTask runAtFixedRate(Plugin plugin, Consumer<Object> task, long initialDelay, long period) {
            this.initialDelay = initialDelay;
            this.period = period;
            task.accept(null);
            return new FakeTask(this);
        }
    }

    public static final class HiddenTaskScheduler {
        private int cancelled;

        public ScheduledTask runAtFixedRate(
                Plugin plugin, Consumer<Object> task, long initialDelay, long period) {
            return new HiddenScheduledTask(this);
        }
    }

    public static final class HaltedTaskScheduler {
        public ScheduledTask runAtFixedRate(
                Plugin plugin, Consumer<Object> task, long initialDelay, long period) {
            return new HaltedScheduledTask();
        }
    }

    public static final class FakeRegionScheduler {
        private int chunkX;
        private int chunkZ;
        private int cancelled;

        public FakeTask run(Plugin plugin, World world, int chunkX, int chunkZ, Consumer<Object> task) {
            this.chunkX = chunkX;
            this.chunkZ = chunkZ;
            task.accept(null);
            return new FakeTask(this);
        }
    }

    public static final class FakeEntityScheduler implements EntityScheduler {
        private boolean ran;
        private int cancelled;

        @Override
        public boolean execute(Plugin plugin, Runnable run, Runnable retired, long delayTicks) {
            run.run();
            return true;
        }

        @Override
        public ScheduledTask run(Plugin plugin, Consumer<ScheduledTask> task, Runnable retired) {
            ran = true;
            FakeTask scheduled = new FakeTask(this);
            task.accept(scheduled);
            return scheduled;
        }

        @Override
        public ScheduledTask runDelayed(
                Plugin plugin, Consumer<ScheduledTask> task, Runnable retired, long delayTicks) {
            return run(plugin, task, retired);
        }

        @Override
        public ScheduledTask runAtFixedRate(
                Plugin plugin, Consumer<ScheduledTask> task, Runnable retired, long initialDelayTicks, long periodTicks) {
            return run(plugin, task, retired);
        }
    }

    public static final class FakeTask implements ScheduledTask {
        private final Object owner;

        private FakeTask(Object owner) {
            this.owner = owner;
        }

        @Override
        public CancelledState cancel() {
            if (owner instanceof FakeGlobalScheduler global) {
                global.cancelled++;
            } else if (owner instanceof FakeRegionScheduler region) {
                region.cancelled++;
            } else if (owner instanceof FakeEntityScheduler entity) {
                entity.cancelled++;
            }
            return CancelledState.CANCELLED_BY_CALLER;
        }

        @Override
        public Plugin getOwningPlugin() {
            return null;
        }

        @Override
        public boolean isRepeatingTask() {
            return false;
        }

        @Override
        public ExecutionState getExecutionState() {
            return ExecutionState.FINISHED;
        }
    }

    private static final class HiddenScheduledTask implements ScheduledTask {
        private final HiddenTaskScheduler owner;

        private HiddenScheduledTask(HiddenTaskScheduler owner) {
            this.owner = owner;
        }

        @Override
        public CancelledState cancel() {
            owner.cancelled++;
            return CancelledState.CANCELLED_BY_CALLER;
        }

        @Override
        public Plugin getOwningPlugin() {
            return null;
        }

        @Override
        public boolean isRepeatingTask() {
            return true;
        }

        @Override
        public ExecutionState getExecutionState() {
            return ExecutionState.FINISHED;
        }
    }

    private static final class HaltedScheduledTask implements ScheduledTask {
        @Override
        public CancelledState cancel() {
            throw new IllegalStateException("scheduler halted");
        }

        @Override
        public Plugin getOwningPlugin() {
            return null;
        }

        @Override
        public boolean isRepeatingTask() {
            return true;
        }

        @Override
        public ExecutionState getExecutionState() {
            return ExecutionState.FINISHED;
        }
    }

    private static final class Counter {
        private int value;

        private void increment() {
            value++;
        }
    }
}
