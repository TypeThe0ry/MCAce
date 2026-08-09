package com.ellan.mcace.paper.behavior;

import com.ellan.mcace.paper.MCAceRuntimeScheduler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.EventPriority;
import org.bukkit.event.HandlerList;
import org.bukkit.event.Listener;
import org.bukkit.plugin.Plugin;

public final class VulcanBehaviorIntegration implements AutoCloseable {
    private static final List<String> EVENT_TYPES = List.of(
            "me.frep.vulcan.api.event.VulcanFlagEvent",
            "me.frep.vulcan.api.event.VulcanViolationEvent");

    private final Listener listener = new Listener() { };
    private final AtomicBoolean extractionWarningLogged = new AtomicBoolean();

    public VulcanBehaviorIntegration(
            Plugin owner, Plugin vulcan, BehaviorAlertPipeline pipeline, Clock clock, Logger logger,
            MCAceRuntimeScheduler scheduler)
            throws ReflectiveOperationException {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(vulcan, "vulcan");
        Objects.requireNonNull(pipeline, "pipeline");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(logger, "logger");
        Objects.requireNonNull(scheduler, "scheduler");
        Class<? extends Event> eventType = findEventType(vulcan);
        owner.getServer().getPluginManager().registerEvent(
                eventType, listener, EventPriority.MONITOR,
                (ignored, event) -> {
                    try {
                        ExtractedAlert extracted = extract(event, vulcan, clock);
                        scheduler.executeForPlayer(
                                extracted.player(), () -> pipeline.accept(extracted.alert()), () -> { });
                    } catch (ReflectiveOperationException | IllegalArgumentException exception) {
                        if (extractionWarningLogged.compareAndSet(false, true)) {
                            logger.warning("Vulcan API event is incompatible; behavior flags will be ignored: "
                                    + safeMessage(exception));
                        }
                    }
                }, owner, true);
    }

    @Override
    public void close() {
        HandlerList.unregisterAll(listener);
    }

    private static Class<? extends Event> findEventType(Plugin vulcan) throws ClassNotFoundException {
        ClassLoader loader = vulcan.getClass().getClassLoader();
        for (String candidate : EVENT_TYPES) {
            try {
                return Class.forName(candidate, false, loader).asSubclass(Event.class);
            } catch (ClassNotFoundException ignored) {
                // Try the next known API generation.
            }
        }
        throw new ClassNotFoundException("no supported Vulcan flag event was found");
    }

    private static ExtractedAlert extract(Event event, Plugin vulcan, Clock clock)
            throws ReflectiveOperationException {
        Object playerValue = invokeRequired(event, "getPlayer");
        if (!(playerValue instanceof Player player)) {
            throw new IllegalArgumentException("getPlayer did not return a Bukkit Player");
        }
        Object check = invokeRequired(event, "getCheck");
        String checkName = stringValue(check, List.of("getCheckName", "getName", "getType"), 64);
        String stableCheck = stringValue(check, List.of("getStableKey", "getIdentifier", "getName"), 96);
        double violation = numericValue(event, List.of("getViolationLevel", "getVl", "getVL"));
        if (violation == 0.0D) {
            violation = numericValue(check, List.of("getViolationLevel", "getVl", "getVL"));
        }
        return new ExtractedAlert(player, new BehaviorAlert(
                player.getUniqueId(), "vulcan", bounded(vulcan.getPluginMeta().getVersion(), 32),
                checkName, stableCheck, Math.max(0.0D, violation), false, clock.instant()));
    }

    private static Object invokeRequired(Object target, String name) throws ReflectiveOperationException {
        return invoke(target, name);
    }

    private static Object invoke(Object target, String name) throws ReflectiveOperationException {
        try {
            Method method = target.getClass().getMethod(name);
            return method.invoke(target);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof ReflectiveOperationException reflective) {
                throw reflective;
            }
            throw new ReflectiveOperationException("Vulcan accessor failed", cause);
        }
    }

    private static String stringValue(Object target, List<String> candidates, int maximum)
            throws ReflectiveOperationException {
        for (String candidate : candidates) {
            try {
                Object value = invoke(target, candidate);
                if (value != null && !value.toString().isBlank()) {
                    return bounded(value.toString(), maximum);
                }
            } catch (NoSuchMethodException ignored) {
                // Try the next supported accessor.
            }
        }
        throw new NoSuchMethodException("no supported Vulcan check-name accessor was found");
    }

    private static double numericValue(Object target, List<String> candidates)
            throws ReflectiveOperationException {
        for (String candidate : candidates) {
            try {
                Object value = invoke(target, candidate);
                if (value instanceof Number number && Double.isFinite(number.doubleValue())) {
                    return number.doubleValue();
                }
            } catch (NoSuchMethodException ignored) {
                // Try the next supported accessor.
            }
        }
        return 0.0D;
    }

    private static String bounded(String value, int maximum) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        String normalized = value.strip();
        return normalized.length() <= maximum ? normalized : normalized.substring(0, maximum);
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }

    private record ExtractedAlert(Player player, BehaviorAlert alert) { }
}
