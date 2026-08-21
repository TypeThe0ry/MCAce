package me.frep.vulcan.api.event;

import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.HandlerList;

/** Test-only structural fixture; it is not a bundled Vulcan API. */
public final class VulcanFlagEvent extends Event {
    private static final HandlerList HANDLERS = new HandlerList();

    public Player getPlayer() {
        return null;
    }

    public VulcanCheck getCheck() {
        return new VulcanCheck();
    }

    public double getViolationLevel() {
        return 1.0D;
    }

    @Override
    public HandlerList getHandlers() {
        return HANDLERS;
    }

    public static HandlerList getHandlerList() {
        return HANDLERS;
    }

    public static final class VulcanCheck {
        public String getCheckName() {
            return "fixture";
        }

        public String getStableKey() {
            return "fixture-stable";
        }

        public double getVl() {
            return 1.0D;
        }
    }
}