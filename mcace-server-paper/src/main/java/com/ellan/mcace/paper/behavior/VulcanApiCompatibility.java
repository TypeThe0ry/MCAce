package com.ellan.mcace.paper.behavior;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Objects;
import org.bukkit.event.Event;

/** Structural preflight for the narrow reflective Vulcan event API consumed by MCAce. */
public final class VulcanApiCompatibility {
    private static final List<String> EVENT_TYPES = List.of(
            "me.frep.vulcan.api.event.VulcanFlagEvent",
            "me.frep.vulcan.api.event.VulcanViolationEvent");
    private static final List<String> CHECK_NAME_ACCESSORS = List.of("getCheckName", "getName", "getType");
    private static final List<String> STABLE_CHECK_ACCESSORS = List.of("getStableKey", "getIdentifier", "getName");
    private static final List<String> VIOLATION_ACCESSORS = List.of("getViolationLevel", "getVl", "getVL");

    private VulcanApiCompatibility() {
    }

    public static Contract inspect(ClassLoader loader) throws ReflectiveOperationException {
        Objects.requireNonNull(loader, "loader");
        Class<? extends Event> eventClass = findEventClass(loader);
        Method player = requireNoArg(eventClass, "getPlayer");
        Method check = requireNoArg(eventClass, "getCheck");
        Class<?> checkClass = check.getReturnType();
        Method checkName = firstNoArg(checkClass, CHECK_NAME_ACCESSORS);
        Method stableCheck = firstNoArg(checkClass, STABLE_CHECK_ACCESSORS);
        Method eventViolation = optionalNoArg(eventClass, VIOLATION_ACCESSORS);
        Method checkViolation = optionalNoArg(checkClass, VIOLATION_ACCESSORS);
        return new Contract(
                eventClass,
                player.getName(),
                check.getName(),
                checkName.getName(),
                stableCheck.getName(),
                eventViolation == null ? "none" : eventViolation.getName(),
                checkViolation == null ? "none" : checkViolation.getName());
    }

    private static Class<? extends Event> findEventClass(ClassLoader loader) throws ClassNotFoundException {
        for (String candidate : EVENT_TYPES) {
            try {
                Class<?> loaded = Class.forName(candidate, false, loader);
                if (!Event.class.isAssignableFrom(loaded)) {
                    throw new ClassNotFoundException(candidate + " is not a Bukkit Event");
                }
                return loaded.asSubclass(Event.class);
            } catch (ClassNotFoundException ignored) {
                // Try the next known API generation.
            }
        }
        throw new ClassNotFoundException("no supported Vulcan flag event was found");
    }

    private static Method requireNoArg(Class<?> type, String name) throws NoSuchMethodException {
        Method method = type.getMethod(name);
        if (method.getParameterCount() != 0 || method.getReturnType() == Void.TYPE) {
            throw new NoSuchMethodException(type.getName() + "." + name + " is not a value accessor");
        }
        return method;
    }

    private static Method firstNoArg(Class<?> type, List<String> candidates) throws NoSuchMethodException {
        Method method = optionalNoArg(type, candidates);
        if (method == null) {
            throw new NoSuchMethodException("no supported Vulcan accessor was found on " + type.getName());
        }
        return method;
    }

    private static Method optionalNoArg(Class<?> type, List<String> candidates) {
        for (String candidate : candidates) {
            try {
                return requireNoArg(type, candidate);
            } catch (NoSuchMethodException ignored) {
                // Try the next known accessor generation.
            }
        }
        return null;
    }

    public record Contract(
            Class<? extends Event> eventClass,
            String playerAccessor,
            String checkAccessor,
            String checkNameAccessor,
            String stableCheckAccessor,
            String eventViolationAccessor,
            String checkViolationAccessor) {
        public Contract {
            Objects.requireNonNull(eventClass, "eventClass");
            Objects.requireNonNull(playerAccessor, "playerAccessor");
            Objects.requireNonNull(checkAccessor, "checkAccessor");
            Objects.requireNonNull(checkNameAccessor, "checkNameAccessor");
            Objects.requireNonNull(stableCheckAccessor, "stableCheckAccessor");
            Objects.requireNonNull(eventViolationAccessor, "eventViolationAccessor");
            Objects.requireNonNull(checkViolationAccessor, "checkViolationAccessor");
        }
    }
}