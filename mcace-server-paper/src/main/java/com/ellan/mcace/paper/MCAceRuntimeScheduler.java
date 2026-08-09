package com.ellan.mcace.paper;

import org.bukkit.World;
import org.bukkit.entity.Player;

/**
 * Schedules MCAce work on the ownership domain required by the active server runtime.
 *
 * <p>Paper executes all tasks through its normal main-thread scheduler. Folia separates global,
 * region and entity ownership, so callers must use the most specific method available instead of
 * retaining a {@link Player} and accessing it from an arbitrary task.</p>
 */
public interface MCAceRuntimeScheduler extends AutoCloseable {
    RuntimeFlavor runtimeFlavor();

    void executeGlobal(Runnable task);

    void executeAtRegion(World world, int chunkX, int chunkZ, Runnable task);

    void executeForPlayer(Player player, Runnable task, Runnable retired);

    void repeatGlobal(Runnable task, long initialDelayTicks, long periodTicks);

    @Override
    void close();

    enum RuntimeFlavor {
        PAPER,
        FOLIA
    }
}
