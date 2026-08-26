package com.ellan.mcace.paper.behavior;

import com.ellan.mcace.paper.MCAceRuntimeScheduler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
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

    private final Listener listener = new Listener() { };
    private final AtomicBoolean extractionWarningLogged = new AtomicBoolean();
    private final ProviderEventIdentityCache eventIdentities = new ProviderEventIdentityCache();
    private final VulcanCallbackProvenanceLedger provenanceLedger;

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
        VulcanApiCompatibility.Contract contract = VulcanApiCompatibility.inspect(
                vulcan.getClass().getClassLoader());
        Class<? extends Event> eventType = contract.eventClass();
        provenanceLedger = VulcanCallbackProvenanceLedger.open(
                owner, vulcan, eventType, listener, clock);
        try {
            owner.getServer().getPluginManager().registerEvent(
                    eventType, listener, EventPriority.MONITOR,
                    (ignored, event) -> {
                        try {
                            ExtractedAlert extracted = extract(
                                    event, vulcan, clock, eventIdentities.identityFor(event), contract);
                            boolean provenanceRecorded = provenanceLedger.append(
                                    event,
                                    extracted.player().getUniqueId(),
                                    extracted.alert().providerEventIdSha256(),
                                    extracted.checkName(),
                                    extracted.stableCheck(),
                                    extracted.violation(),
                                    extracted.alert().observedAt(),
                                    extracted.accessors());
                            if (!provenanceRecorded) {
                                if (extractionWarningLogged.compareAndSet(false, true)) {
                                    logger.warning("Vulcan callback provenance write failed; behavior flag ignored");
                                }
                                return;
                            }
                            scheduler.executeForPlayer(
                                    extracted.player(),
                                    () -> pipeline.accept(extracted.player(), extracted.alert()),
                                    () -> { });
                        } catch (ReflectiveOperationException | IllegalArgumentException exception) {
                            if (extractionWarningLogged.compareAndSet(false, true)) {
                                logger.warning("Vulcan API event is incompatible; behavior flags will be ignored: "
                                        + safeMessage(exception));
                            }
                        }
                    }, owner, true);
            provenanceLedger.assertRegisteredHandlerIdentity();
        } catch (ReflectiveOperationException | RuntimeException exception) {
            provenanceLedger.close();
            HandlerList.unregisterAll(listener);
            throw exception;
        }
    }

    @Override
    public void close() {
        HandlerList.unregisterAll(listener);
        provenanceLedger.close();
    }

    private static ExtractedAlert extract(
            Event event, Plugin vulcan, Clock clock, String nativeEventIdentity,
            VulcanApiCompatibility.Contract contract)
            throws ReflectiveOperationException {
        Method playerMethod = requireMethod(event.getClass(), contract.playerAccessor());
        Method checkMethod = requireMethod(event.getClass(), contract.checkAccessor());
        Object playerValue = invoke(event, playerMethod);
        if (!(playerValue instanceof Player player)) {
            throw new IllegalArgumentException("getPlayer did not return a Bukkit Player");
        }
        Object check = invoke(event, checkMethod);
        Method checkNameMethod = requireMethod(check.getClass(), contract.checkNameAccessor());
        Method stableCheckMethod = requireMethod(check.getClass(), contract.stableCheckAccessor());
        String checkName = stringValue(check, checkNameMethod, 64);
        String stableCheck = stringValue(check, stableCheckMethod, 96);
        Method eventViolationMethod = optionalMethod(event.getClass(), contract.eventViolationAccessor());
        Method checkViolationMethod = optionalMethod(check.getClass(), contract.checkViolationAccessor());
        double violation = numericValue(event, eventViolationMethod);
        if (violation == 0.0D) {
            violation = numericValue(check, checkViolationMethod);
        }
        String providerVersion = exact(vulcan.getPluginMeta().getVersion(), 32);
        double normalizedViolation = Math.max(0.0D, violation);
        String providerEventId = BehaviorAlert.providerEventIdSha256(
                "vulcan", nativeEventIdentity, player.getUniqueId().toString(),
                providerVersion, stableCheck, checkName,
                Double.toHexString(normalizedViolation));
        Instant observedAt = clock.instant();
        List<Method> accessors = new ArrayList<>();
        accessors.add(playerMethod);
        accessors.add(checkMethod);
        accessors.add(checkNameMethod);
        accessors.add(stableCheckMethod);
        if (eventViolationMethod != null) accessors.add(eventViolationMethod);
        if (checkViolationMethod != null) accessors.add(checkViolationMethod);
        return new ExtractedAlert(player, new BehaviorAlert(
                player.getUniqueId(), providerEventId, "vulcan", providerVersion,
                checkName, stableCheck, normalizedViolation, false, observedAt),
                checkName, stableCheck, normalizedViolation, List.copyOf(accessors));
    }

    private static Method requireMethod(Class<?> type, String name) throws NoSuchMethodException {
        if (name == null || name.equals("none")) {
            throw new NoSuchMethodException("required accessor is absent");
        }
        return type.getMethod(name);
    }

    private static Method optionalMethod(Class<?> type, String name) throws NoSuchMethodException {
        return name == null || name.equals("none") ? null : type.getMethod(name);
    }

    private static Object invoke(Object target, Method method) throws ReflectiveOperationException {
        try {
            return method.invoke(target);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof ReflectiveOperationException reflective) {
                throw reflective;
            }
            throw new ReflectiveOperationException("Vulcan accessor failed", cause);
        }
    }

    private static String stringValue(Object target, Method method, int maximum)
            throws ReflectiveOperationException {
        Object value = invoke(target, method);
        if (value != null && !value.toString().isBlank()) {
            return exact(value.toString(), maximum);
        }
        throw new NoSuchMethodException("no supported Vulcan check-name accessor was found");
    }

    private static double numericValue(Object target, Method method)
            throws ReflectiveOperationException {
        if (method == null) return 0.0D;
        Object value = invoke(target, method);
        if (value instanceof Number number && Double.isFinite(number.doubleValue())) {
            return number.doubleValue();
        }
        return 0.0D;
    }

    private static String exact(String value, int maximum) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Vulcan provider identity is missing");
        }
        String normalized = value.strip();
        if (normalized.length() > maximum) {
            throw new IllegalArgumentException("Vulcan provider identity exceeds protocol bounds");
        }
        return normalized;
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }

    private record ExtractedAlert(
            Player player,
            BehaviorAlert alert,
            String checkName,
            String stableCheck,
            double violation,
            List<Method> accessors) { }
}
